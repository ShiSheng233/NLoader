//! Recover shared tables from repeated padding, without built-in key material.
use crate::{Error, Result, HEADER};
use std::collections::HashMap;

const WIDTH: usize = 256;
const MIN_FAMILY_SIZE: usize = 64;
const MAX_ITERATIONS: usize = 64;
type Table = [u8; WIDTH];
type Observation = (usize, usize, u8);

// Never derive Debug: these values are local key material.
pub(super) struct XorTables {
    pub(super) t1: Table,
    pub(super) t2: Table,
    pub(super) t3: Table,
}

impl XorTables {
    pub(super) fn decrypt(&self, raw: &[u8]) -> Vec<u8> {
        let mut result = raw.to_vec();
        for (index, byte) in result.iter_mut().skip(HEADER).enumerate().skip(32) {
            *byte ^=
                self.t1[index & 255] ^ self.t2[(index >> 8) & 255] ^ self.t3[(index >> 16) & 255];
        }
        result
    }
}

/// Reads explicitly supplied tables; the caller must validate them against
/// firmware contents before treating them as verified key material.
pub(super) fn from_json(bytes: &[u8]) -> Result<XorTables> {
    // Parser errors can include input values, so never propagate their text.
    let [t1, t2, t3]: [Vec<u8>; 3] = serde_json::from_slice(bytes).map_err(|_| Error::KeyFile)?;
    Ok(XorTables {
        t1: t1.try_into().map_err(|_| Error::KeyFile)?,
        t2: t2.try_into().map_err(|_| Error::KeyFile)?,
        t3: t3.try_into().map_err(|_| Error::KeyFile)?,
    })
}

pub(super) fn recover(images: &[&[u8]]) -> Result<XorTables> {
    if images.is_empty() {
        return Err(Error::Recovery("no input images"));
    }
    let mut family = None;
    for image in images {
        crate::check_scheme(image)?;
        let found = recover_family(&image[HEADER..])?;
        if family.is_some_and(|previous| previous != found) {
            return Err(Error::Recovery("input images disagree on the XOR family"));
        }
        family = Some(found);
    }
    let family = family.ok_or(Error::Recovery("no XOR family"))?;
    let t1 = fix_constant(&images[0][HEADER..], &family)?;
    // The directory is independent evidence of the family constant in every input.
    for image in &images[1..] {
        if fix_constant(&image[HEADER..], &family)? != t1 {
            return Err(Error::Recovery(
                "input directories disagree on the XOR constant",
            ));
        }
    }
    let observations = collect_observations(images, &t1);
    check_coverage(&observations)?;
    let (t2, mut t3) = solve_tables(&observations)?;
    correct_t3(images, &t1, &t2, &mut t3)?;
    let tables = XorTables { t1, t2, t3 };
    // Statistical evidence alone never authorizes a recovered key.
    for image in images {
        let plain = tables.decrypt(image);
        crate::validate_body(&plain[HEADER..])?;
    }
    Ok(tables)
}

fn recover_family(body: &[u8]) -> Result<Table> {
    let mut sectors = HashMap::<&[u8], usize>::new();
    for sector in body.chunks_exact(WIDTH) {
        *sectors.entry(sector).or_default() += 1;
    }
    let mut families = HashMap::<Table, usize>::new();
    for (sector, count) in sectors {
        if count > 1 {
            let normalized = std::array::from_fn(|index| sector[index] ^ sector[0]);
            *families.entry(normalized).or_default() += 1;
        }
    }
    let maximum = families.values().copied().max().unwrap_or(0);
    if maximum < MIN_FAMILY_SIZE {
        return Err(Error::Recovery(
            "insufficient repeated sectors for an XOR family",
        ));
    }
    let mut best = families.into_iter().filter(|(_, count)| *count == maximum);
    let (family, _) = best.next().ok_or(Error::Recovery("no XOR family"))?;
    if best.next().is_some() {
        return Err(Error::Recovery("ambiguous repeated-sector XOR family"));
    }
    Ok(family)
}

fn fix_constant(body: &[u8], normalized: &Table) -> Result<Table> {
    let first_sector = body
        .get(..WIDTH)
        .ok_or(Error::Recovery("truncated directory probe"))?;
    let mut candidate = None;
    for constant in 0..=u8::MAX {
        let plain: Table =
            std::array::from_fn(|index| first_sector[index] ^ normalized[index] ^ constant);
        if plausible_directory(&plain, body.len()) {
            if candidate.is_some() {
                return Err(Error::Recovery("ambiguous directory XOR constant"));
            }
            candidate = Some(normalized.map(|byte| byte ^ constant));
        }
    }
    candidate.ok_or(Error::Recovery("no XOR constant matches the directory"))
}

/// Only the first sector has the same unknown T2/T3 constant as its directory
/// header. A subsequent sector cannot be probed until T2 has been recovered.
fn plausible_directory(plain: &Table, body_length: usize) -> bool {
    let count = crate::u32_at(plain, 32);
    let directory_size = crate::u32_at(plain, 36);
    let Some(end) = body_length.checked_sub(crate::TRAILER) else {
        return false;
    };
    if !(1..=64).contains(&count)
        || directory_size != 48 + 32 * count
        || directory_size + 2 * count > end
        || plain[40..48] != [0; 8]
    {
        return false;
    }
    let mut expected = directory_size;
    for index in 0..count.min((WIDTH - 48) / 32) {
        let offset = 48 + 32 * index;
        let name = &plain[offset..offset + 16];
        let name_end = name
            .iter()
            .rposition(|byte| *byte != 0)
            .map_or(0, |i| i + 1);
        if name_end < 3
            || !name[0].is_ascii_alphanumeric() && name[0] != b'_'
            || !name[..name_end]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
        {
            return false;
        }
        let start = crate::u32_at(plain, offset + 16);
        let length = crate::u32_at(plain, offset + 20);
        if start != expected
            || length < 2
            || start.checked_add(length).is_none_or(|next| next > end)
            || plain[offset + 24..offset + 32] != [0; 8]
        {
            return false;
        }
        expected = start + length;
    }
    true
}

fn collect_observations(images: &[&[u8]], t1: &Table) -> Vec<Observation> {
    let mut counts = HashMap::<(usize, usize, u8), usize>::new();
    for image in images {
        for (sector_index, sector) in image[HEADER..].chunks_exact(WIDTH).enumerate() {
            let value = sector[0] ^ t1[0];
            if sector.iter().zip(t1).all(|(byte, key)| byte ^ key == value) {
                let cell = (sector_index & 255, (sector_index >> 8) & 255, value);
                *counts.entry(cell).or_default() += 1;
            }
        }
    }
    let mut winners = HashMap::<(usize, usize), (usize, u8)>::new();
    for ((a, b, value), count) in counts {
        let winner = winners.entry((a, b)).or_insert((0, 0));
        // Deterministic ties agree with the reference's sorted-cell majority.
        *winner = (*winner).max((count, value));
    }
    let mut observations: Vec<_> = winners
        .into_iter()
        .map(|((a, b), (_, value))| (a, b, value))
        .collect();
    observations.sort_unstable();
    observations
}

fn check_coverage(observations: &[Observation]) -> Result<()> {
    let mut covered = [false; WIDTH];
    for &(_, b, _) in observations {
        covered[b] = true;
    }
    let missing: Vec<u8> = covered
        .iter()
        .enumerate()
        .filter_map(|(index, present)| (!present).then_some(index as u8))
        .collect();
    if !missing.is_empty() {
        return Err(Error::RecoveryCoverage {
            covered: WIDTH - missing.len(),
            missing,
        });
    }
    Ok(())
}

fn majority(values: impl Iterator<Item = u8>) -> Option<u8> {
    let mut counts = [0_usize; WIDTH];
    for value in values {
        counts[value as usize] += 1;
    }
    // Prefer the lower byte on a tie; final CRC validation rejects wrong guesses.
    let maximum = counts.iter().copied().max().unwrap_or(0);
    (maximum != 0).then(|| counts.iter().position(|count| *count == maximum).unwrap() as u8)
}

fn solve_tables(observations: &[Observation]) -> Result<(Table, Table)> {
    let mut by_a: [Vec<(usize, u8)>; WIDTH] = std::array::from_fn(|_| Vec::new());
    let mut by_b: [Vec<(usize, u8)>; WIDTH] = std::array::from_fn(|_| Vec::new());
    for &(a, b, value) in observations {
        by_a[a].push((b, value));
        by_b[b].push((a, value));
    }
    let mut t2 = [None; WIDTH];
    let mut t3 = [None; WIDTH];
    t2[0] = Some(0);
    let mut converged = false;
    for _ in 0..MAX_ITERATIONS {
        let previous = (t2, t3);
        for (b, pairs) in by_b.iter().enumerate() {
            t3[b] = majority(
                pairs
                    .iter()
                    .filter_map(|&(a, value)| t2[a].map(|key| key ^ value)),
            );
        }
        for (a, pairs) in by_a.iter().enumerate() {
            t2[a] = majority(
                pairs
                    .iter()
                    .filter_map(|&(b, value)| t3[b].map(|key| key ^ value)),
            );
        }
        if (t2, t3) == previous {
            converged = true;
            break;
        }
    }
    if !converged {
        return Err(Error::Recovery("XOR majority propagation did not converge"));
    }
    if t2.iter().chain(&t3).any(Option::is_none) {
        return Err(Error::Recovery(
            "XOR observations do not connect all table entries",
        ));
    }
    Ok((t2.map(Option::unwrap), t3.map(Option::unwrap)))
}

fn correct_t3(images: &[&[u8]], t1: &Table, t2: &Table, t3: &mut Table) -> Result<()> {
    let mut counts = [[0_usize; WIDTH]; WIDTH];
    for image in images {
        // Include partial final sectors: their data must not be silently discarded.
        for (index, byte) in image[HEADER..].iter().enumerate().skip(32) {
            let value = byte ^ t1[index & 255] ^ t2[(index >> 8) & 255];
            counts[(index >> 16) & 255][value as usize] += 1;
        }
    }
    for (b, frequencies) in counts.iter().enumerate() {
        let mut best_pair = None;
        let mut best_count = 0;
        let mut ambiguous = false;
        for candidate in 0..128 {
            let count = frequencies[candidate] + frequencies[candidate ^ 255];
            if count > best_count {
                best_pair = Some(candidate);
                best_count = count;
                ambiguous = false;
            } else if count == best_count {
                ambiguous = true;
            }
        }
        let candidate = best_pair.ok_or(Error::Recovery("empty XOR correction block"))?;
        if ambiguous || frequencies[candidate] == frequencies[candidate ^ 255] {
            return Err(Error::Recovery("ambiguous XOR padding correction"));
        }
        t3[b] = if frequencies[candidate] > frequencies[candidate ^ 255] {
            candidate as u8
        } else {
            (candidate ^ 255) as u8
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_explicit_json_tables() {
        let expected = synthetic_tables();
        let bytes = serde_json::to_vec(&[
            expected.t1.as_slice(),
            expected.t2.as_slice(),
            expected.t3.as_slice(),
        ])
        .unwrap();
        let actual = from_json(&bytes).unwrap();
        assert!(actual.t1 == expected.t1);
        assert!(actual.t2 == expected.t2);
        assert!(actual.t3 == expected.t3);
    }

    #[test]
    fn rejects_wrong_json_table_dimensions() {
        for tables in [
            vec![vec![0_u8; WIDTH]; 2],
            vec![vec![0; WIDTH]; 4],
            vec![vec![0; WIDTH - 1]; 3],
            vec![vec![0; WIDTH + 1]; 3],
            vec![vec![0; WIDTH], vec![0; WIDTH], vec![0; WIDTH - 1]],
        ] {
            let bytes = serde_json::to_vec(&tables).unwrap();
            assert!(matches!(from_json(&bytes), Err(Error::KeyFile)));
        }
    }

    #[test]
    fn invalid_json_and_values_never_expose_input_in_errors() {
        for input in [
            "[[256],[],[]]",
            "[[-1],[],[]]",
            "[[1.5],[],[]]",
            "[[1.0],[],[]]",
            "[[true],[],[]]",
            "[[null],[],[]]",
            "[[\"private-table-value\"],[],[]]",
            "{\"private-table-value\": []}",
            "[[],[],[]] private-table-value",
        ] {
            let error = match from_json(input.as_bytes()) {
                Err(error) => error,
                Ok(_) => panic!("invalid table input was accepted"),
            };
            assert!(matches!(error, Error::KeyFile));
            assert_eq!(error.to_string(), "invalid local key file");
            assert_eq!(format!("{error:?}"), "KeyFile");
        }
    }

    fn synthetic_tables() -> XorTables {
        XorTables {
            t1: std::array::from_fn(|i| (i as u8).wrapping_mul(37).rotate_left(3) ^ 91),
            t2: std::array::from_fn(|i| (i as u8).wrapping_mul(53)),
            t3: std::array::from_fn(|i| (i as u8).wrapping_mul(73)),
        }
    }

    fn encrypted_fixture(tables: &XorTables, body_length: usize) -> Vec<u8> {
        let mut image = vec![0; HEADER + body_length];
        let body = &mut image[HEADER..];
        // Mix both common padding bytes without making any T2 or T3 entry
        // exclusively observe FF-filled sectors.
        for (index, sector) in body.chunks_mut(WIDTH).enumerate() {
            let a = index & 255;
            let b = (index >> 8) & 255;
            if (a * 37 + b * 73) % 7 == 0 {
                sector.fill(255);
            }
        }
        body[..112].fill(0);
        body[..32].fill(b' ');
        body[32..36].copy_from_slice(&2_u32.to_be_bytes());
        body[36..40].copy_from_slice(&112_u32.to_be_bytes());
        let end = body.len() - crate::TRAILER;
        body[end..].fill(0);
        for (index, (name, start, length)) in [
            (b"main.bin", 112_usize, 4096_usize),
            (b"data.bin", 4208, end - 4208),
        ]
        .into_iter()
        .enumerate()
        {
            let offset = 48 + 32 * index;
            body[offset..offset + name.len()].copy_from_slice(name);
            body[offset + 16..offset + 20].copy_from_slice(&(start as u32).to_be_bytes());
            body[offset + 20..offset + 24].copy_from_slice(&(length as u32).to_be_bytes());
            let crc_offset = start + length - 2;
            let crc = crate::crc16(&body[start..crc_offset]);
            body[crc_offset..crc_offset + 2].copy_from_slice(&crc.to_be_bytes());
        }
        let crc = crate::crc16(&body[..end]);
        body[end..end + 2].copy_from_slice(&crc.to_be_bytes());
        for (index, byte) in body.iter_mut().enumerate().skip(32) {
            *byte ^= tables.t1[index & 255]
                ^ tables.t2[(index >> 8) & 255]
                ^ tables.t3[(index >> 16) & 255];
        }
        image
    }

    #[test]
    fn recovers_synthetic_tables_and_rejects_corrupt_payload() {
        let expected = synthetic_tables();
        let mut image = encrypted_fixture(&expected, 1 << 24);
        let recovered = recover(&[&image]).unwrap();
        // Boolean comparisons avoid exposing table bytes on assertion failure.
        assert!(recovered.t1 == expected.t1);
        assert!(recovered.t2 == expected.t2);
        assert!(recovered.t3 == expected.t3);
        image[HEADER + 500] ^= 1;
        assert!(matches!(recover(&[&image]), Err(Error::Integrity(_))));
    }

    #[test]
    fn incomplete_image_reports_coverage_without_returning_tables() {
        let image = encrypted_fixture(&synthetic_tables(), 1 << 20);
        match recover(&[&image]) {
            Err(Error::RecoveryCoverage { covered, missing }) => {
                assert_eq!(covered, 16);
                assert_eq!(missing, (16..=255).collect::<Vec<u8>>());
            }
            _ => panic!("expected coverage error"),
        }
    }

    #[test]
    fn reports_all_missing_coverage_indices() {
        let error = check_coverage(&[(0, 0, 1), (1, 0, 2), (0, 255, 3)]).unwrap_err();
        match error {
            Error::RecoveryCoverage { covered, missing } => {
                assert_eq!(covered, 2);
                assert_eq!(missing, (1..255).collect::<Vec<u8>>());
            }
            _ => panic!("expected coverage error"),
        }
    }

    #[test]
    fn rejects_disconnected_tables_even_with_complete_coverage() {
        let observations: Vec<_> = (0..WIDTH).map(|b| (1, b, b as u8)).collect();
        assert!(check_coverage(&observations).is_ok());
        assert!(solve_tables(&observations).is_err());
    }

    fn repeated_family(t1: &Table) -> Vec<u8> {
        let mut body = Vec::new();
        for value in 0..MIN_FAMILY_SIZE as u8 {
            let sector = t1.map(|byte| byte ^ value);
            body.extend_from_slice(&sector);
            body.extend_from_slice(&sector);
        }
        body
    }

    #[test]
    fn rejects_conflicting_sector_families() {
        let first = synthetic_tables().t1;
        let second = std::array::from_fn(|i| first[i].rotate_left(1));
        let mut body = repeated_family(&first);
        body.extend(repeated_family(&second));
        assert!(matches!(recover_family(&body), Err(Error::Recovery(_))));
    }

    #[test]
    fn rejects_conflicting_input_families_before_directory_probe() {
        let first = synthetic_tables().t1;
        let second = std::array::from_fn(|i| first[i].rotate_left(1));
        let image = |table: &Table| {
            let mut image = vec![0; HEADER];
            image.extend([b' '; WIDTH]);
            image.extend(repeated_family(table));
            image
        };
        assert!(matches!(
            recover(&[&image(&first), &image(&second)]),
            Err(Error::Recovery("input images disagree on the XOR family"))
        ));
    }

    #[test]
    fn correction_resolves_arbitrary_offsets_and_ff_fill() {
        let tables = synthetic_tables();
        let mut image = vec![0; HEADER + (1 << 24)];
        for (index, byte) in image[HEADER..].iter_mut().enumerate().skip(32) {
            let fill = if index & 255 < 100 { 255 } else { 0 };
            *byte = fill
                ^ tables.t1[index & 255]
                ^ tables.t2[(index >> 8) & 255]
                ^ tables.t3[(index >> 16) & 255];
        }
        let mut t3 = tables.t3.map(|byte| byte ^ 37);
        correct_t3(&[&image], &tables.t1, &tables.t2, &mut t3).unwrap();
        assert!(t3 == tables.t3);
    }
}
