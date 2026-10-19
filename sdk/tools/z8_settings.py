"""z8_settings.py <eg2070_0311b0.bi> <settings-map.json> <items.json>: the Z 8 C3.11
settings map, read from the firmware's own tables, in the two inputs gen_props.py
takes.

The Z 6III map came from a menu study. On the Z 8 the firmware itself carries the
names: a table of 779 enum names ("eDSID_Setting_WbMode", ...) and, right after it,
the tagged store id of each (0x07000611: tag 7, item 0x0611). A dump routine walks
the id table in two parts, 699 scalar items then 80 blobs, which fixes the length.
The store's own group and item tables give each item's type and size. The
persistent-save table (1073 tagged ids) gives the tag of items that have no name;
where both tables carry an id they must agree.

Nothing is guessed: the module must be the stock C3.11 EG, the dump routine's
instructions must be the ones read here, every name must point at an "eDSID_"
string and every id must be a live store item. Anything else stops the tool.

  python3 sdk/tools/z8_settings.py firmware/unpacked/Z_8_0311/modules/eg2070_0311b0.bi \\
      build/z8-settings-map.json build/z8-items.json
  python3 sdk/tools/gen_props.py build/z8-settings-map.json build/z8-items.json \\
      sdk/z8/nlr_props.h "Z 8 C3.11"

A dev tool, like gen_props.py: nothing on the camera runs Python."""
import hashlib
import json
import os
import struct
import sys

EG_SHA256 = "2b43a31c9de838f84b12416de4348a7004e65be07f853ec56ec2b10f3a8e3853"
# file offset -> runtime address of the EG's three loaded segments
SEGMENTS = [(0, 0x40160000, 0x4b122e0), (0x4b13000, 0xa02808000, 0x2ad000),
            (0x4dc0000, 0xa02ab5000, 0x44950)]

# The dump routine 0x410dd158: for each id of the scalar table (x21 = 0xa0299cfc8,
# 0xaec bytes = 699 ids) it reads the item, then for each id of the blob table
# (x21 = 0xa0299dab4, 0x140 bytes = 80 ids) it reads the blob.
DUMP = 0x410dd174
DUMP_WORDS = {
    0x410dd174: 0xd299f915,  # mov  x21, #0xcfc8
    0x410dd178: 0xf2a05335,  # movk x21, #0x299, lsl #16
    0x410dd17c: 0xf2c00155,  # movk x21, #0xa, lsl #32
    0x410dd198: 0xf12bb29f,  # cmp  x20, #0xaec
    0x410dd1a0: 0xd29b5695,  # mov  x21, #0xdab4
    0x410dd1a4: 0xf2a05335,  # movk x21, #0x299, lsl #16
    0x410dd1a8: 0xf2c00155,  # movk x21, #0xa, lsl #32
    0x410dd1cc: 0xf105029f,  # cmp  x20, #0x140
}
SCALAR_IDS, SCALARS = 0xa0299cfc8, 0xaec // 4
BLOB_IDS, BLOBS = 0xa0299dab4, 0x140 // 4
NAMED = SCALARS + BLOBS
NAMES = SCALAR_IDS - 8 * NAMED  # the name pointers end where the ids begin

# The store (build/z8-c-20261017/D1-settings.md, declared in the profile's
# [services.platform.props]): 124 groups of 48 bytes, 4427 items of 24 bytes.
GROUPS, GROUP_COUNT, GROUP_BYTES = 0x440244c8, 124, 48
ITEMS, ITEM_COUNT, ITEM_BYTES = 0x4400a5c0, 4427, 24
# The persistent-save table walked by 0x41017690 (cmp x20, #0x431):
# {tagged id u32, image offset s32, width u32}, sorted by item.
SAVE, SAVE_COUNT = 0xa029592d8, 0x431

# store type -> gen_props.py type (the reader's jump table 0xa02a97e50: 0/1 ldrb,
# 2 ldrh, 3/7/9 ldr w, 5 ldrsb, 6 ldrsh; 10 is the blob path). A 32-bit value is
# read the same signed or not, so 3/7/9 are given as u32.
TYPES = {0: "u8", 1: "u8", 2: "u16", 3: "u32", 5: "s8", 6: "s16", 7: "u32", 9: "u32",
         10: "blob"}
WIDTH = {"u8": 1, "s8": 1, "u16": 2, "s16": 2, "u32": 4}


def fail(message):
    raise SystemExit("z8_settings: " + message)


def main():
    if len(sys.argv) != 4:
        fail("usage: z8_settings.py <eg2070_0311b0.bi> <settings-map.json> <items.json>")
    eg, map_out, items_out = sys.argv[1:]
    for path in (map_out, items_out):
        if os.path.exists(path):
            fail("refusing to replace " + path)
    data = open(eg, "rb").read()
    if hashlib.sha256(data).hexdigest() != EG_SHA256:
        fail("not the stock Z 8 C3.11 EG")

    def at(address, size):
        for offset, base, length in SEGMENTS:
            if base <= address and address + size <= base + length:
                return data[offset + address - base:offset + address - base + size]
        fail("address %#x is outside the module" % address)

    def u16(a): return struct.unpack("<H", at(a, 2))[0]
    def u32(a): return struct.unpack("<I", at(a, 4))[0]
    def s32(a): return struct.unpack("<i", at(a, 4))[0]
    def u64(a): return struct.unpack("<Q", at(a, 8))[0]

    for address, word in DUMP_WORDS.items():
        if u32(address) != word:
            fail("dump routine word at %#x is %#010x, not %#010x" % (address, u32(address), word))
    if BLOB_IDS != SCALAR_IDS + 4 * SCALARS:
        fail("the blob ids do not follow the scalar ids")

    def item(store_id):
        group, index = store_id >> 8, store_id & 0xff
        if group >= GROUP_COUNT:
            return None
        g = GROUPS + group * GROUP_BYTES
        first, count = u16(g + 0x18), u16(g + 0x1a)
        if not u32(g) or index >= count or first + index >= ITEM_COUNT:
            return None
        r = ITEMS + (first + index) * ITEM_BYTES
        return u32(r), u32(r + 4)

    names = []
    for n in range(NAMED):
        pointer = u64(NAMES + 8 * n)
        raw = at(pointer, 128).split(b"\0")[0]
        name = raw.decode("ascii")
        if not name.startswith("eDSID_") or not name.replace("_", "").isalnum():
            fail("name %d at %#x is not an eDSID_ name" % (n, pointer))
        names.append(name)
    if len(set(names)) != NAMED:
        fail("names repeat")
    before = u64(NAMES - 8)
    if any(base <= before < base + length and at(before, 6) == b"eDSID_"
           for _, base, length in SEGMENTS):
        fail("the name table starts earlier than its length says")

    save = {}
    for n in range(SAVE_COUNT):
        tagged = u32(SAVE + 12 * n)
        if tagged & 0xffff in save:
            fail("save table repeats item %#06x" % (tagged & 0xffff))
        if s32(SAVE + 12 * n + 4) < 0 or u32(SAVE + 12 * n + 8) not in (1, 2, 4):
            fail("save table entry %d is malformed" % n)
        if item(tagged & 0xffff) is None or tagged & 0x00ff0000:
            fail("save table entry %d names no store item" % n)
        save[tagged & 0xffff] = tagged >> 24

    entries, tags = [], {}
    for n in range(NAMED):
        tagged = u32(SCALAR_IDS + 4 * n)
        store_id, tag = tagged & 0xffff, tagged >> 24
        if tagged & 0x00ff0000:
            fail("%s: id %#x has bits 16..23 set" % (names[n], tagged))
        found = item(store_id)
        if found is None:
            fail("%s: %#06x is not a live store item" % (names[n], store_id))
        kind, size = found
        if kind not in TYPES:
            fail("%s: store type %d" % (names[n], kind))
        type_name = TYPES[kind]
        if (type_name == "blob") != (n >= SCALARS):
            fail("%s: a %s in the %s part" % (names[n], type_name,
                                              "blob" if n >= SCALARS else "scalar"))
        if type_name != "blob" and size != WIDTH[type_name]:
            fail("%s: %d bytes for a %s" % (names[n], size, type_name))
        if store_id in save and tag and save[store_id] != tag:
            fail("%s: tag %d here, %d in the save table" % (names[n], tag, save[store_id]))
        entries.append({"id": names[n], "status": "mapped", "en": "",
                        "store": {"0x%04x" % store_id: {"size": size, "type": type_name,
                                                        "codes": {}}}})
        if tag:
            tags[store_id] = tag
    if len({e["id"] for e in entries}) != NAMED or len(tags) > NAMED:
        fail("duplicate entries")
    for store_id, tag in save.items():
        if tags.setdefault(store_id, tag) != tag:
            fail("item %#06x: tag %d named, %d saved" % (store_id, tags[store_id], tag))

    source = {"firmware": "Z 8 C3.11", "eg_sha256": EG_SHA256,
              "names": "%#x" % NAMES, "ids": "%#x" % SCALAR_IDS, "save": "%#x" % SAVE}
    with open(map_out, "x") as out:
        json.dump(entries, out, indent=1)
        out.write("\n")
    with open(items_out, "x") as out:
        json.dump({"source": source,
                   "items": {"0x%04x" % k: {"tag": v} for k, v in sorted(tags.items())}},
                  out, indent=1)
        out.write("\n")
    print("%d named settings (%d scalar, %d blob), %d tagged items" %
          (NAMED, SCALARS, BLOBS, len(tags)))


if __name__ == "__main__":
    main()
