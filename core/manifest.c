#include "nlr/manifest.h"
#if NLR_HAS_NATIVE_CARD
#include "nlr/native_card.h"
#endif

/* The card directory is plain text written by hand, so every check here is
 * about rejecting a file we cannot display or load, with a reason the page
 * can state. Nothing is corrected, completed or guessed. */

static int is_space(uint8_t c)
{
    return c == ' ' || c == '\t';
}

/* Printable ASCII including spaces: display names. The page renders them
 * through the stock ASCII writer, so a byte it cannot draw is refused here
 * instead of reaching the screen as garbage. */
static int is_name_byte(uint8_t c)
{
    return c >= 0x20 && c < 0x7f;
}

static uint8_t lower(uint8_t c)
{
    return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 0x20) : c;
}

static int equals(const uint8_t *text, uint32_t len, const char *literal)
{
    uint32_t n = 0;
    while (n < len && literal[n] && text[n] == (uint8_t)literal[n])
        n++;
    return n == len && literal[n] == 0;
}

static int equals_fold(const uint8_t *a, uint32_t a_len, const uint8_t *b,
                       uint32_t b_len)
{
    if (a_len != b_len)
        return 0;
    for (uint32_t n = 0; n < a_len; n++)
        if (lower(a[n]) != lower(b[n]))
            return 0;
    return 1;
}

static uint32_t literal_length(const char *s)
{
    uint32_t n = 0;
    while (s && s[n])
        n++;
    return n;
}

static int reject(struct nlr_manifest *m, uint32_t reason, uint32_t line,
                  int result)
{
    m->error = reason;
    m->error_line = line;
    m->count = 0;
    m->usable = 0;
    return result;
}

/* One '|' separated field, already trimmed on both ends. */
struct field {
    const uint8_t *text;
    uint32_t len;
    uint32_t off;
};

static int parse_line(struct nlr_manifest *m, const uint8_t *line,
                      uint32_t line_off, uint32_t len, uint32_t number,
                      int may_repeat)
{
    int repeated = 0;
    struct field fields[7];
    uint32_t count = 0, start = 0;
    for (uint32_t n = 0; n <= len; n++) {
        if (n != len && line[n] != '|')
            continue;
        if (count == 7)
            return reject(m, NLR_MF_FIELDS, number, NLR_FORMAT);
        uint32_t from = start, to = n;
        while (from < to && is_space(line[from]))
            from++;
        while (to > from && is_space(line[to - 1]))
            to--;
        fields[count].text = line + from;
        fields[count].len = to - from;
        fields[count].off = line_off + from;
        count++;
        start = n + 1;
    }
    /* The support column may be omitted entirely or left empty. */
    if (count != 5 && count != 6)
        return reject(m, NLR_MF_FIELDS, number, NLR_FORMAT);

    const struct field *id = &fields[0], *kind = &fields[1];
    const struct field *name = &fields[2], *file = &fields[3];
    const struct field *abi = &fields[4];

    if (id->len == 0 || id->len > NLR_MANIFEST_ID_MAX)
        return reject(m, NLR_MF_ID, number, NLR_FORMAT);
    for (uint32_t n = 0; n < id->len; n++)
        if (!nlr_manifest_token_byte(id->text[n]))
            return reject(m, NLR_MF_ID, number, NLR_FORMAT);
    for (uint32_t n = 0; n < m->count; n++) {
        const struct nlr_manifest_entry *e = &m->entries[n];
        if (equals_fold(m->buffer + e->id_off, e->id_len, id->text, id->len)) {
            if (!may_repeat)
                return reject(m, NLR_MF_DUPLICATE, number, NLR_FORMAT);
            repeated = 1;
        }
    }

    uint8_t kind_code = NLR_KIND_NONE, shell = 0;
    if (equals(kind->text, kind->len, "resource_extension"))
        kind_code = NLR_KIND_RESOURCE_EXTENSION;
    else if (equals(kind->text, kind->len, "foreground"))
        kind_code = NLR_KIND_FOREGROUND;
    else if (equals(kind->text, kind->len, "shell")) {
        kind_code = NLR_KIND_FOREGROUND;
        shell = 1;
    } else
        return reject(m, NLR_MF_KIND, number, NLR_FORMAT);

    if (name->len == 0 || name->len > NLR_MANIFEST_NAME_MAX)
        return reject(m, NLR_MF_NAME, number, NLR_FORMAT);
    for (uint32_t n = 0; n < name->len; n++)
        if (!is_name_byte(name->text[n]))
            return reject(m, NLR_MF_NAME, number, NLR_FORMAT);

    if (file->len == 0 || file->len > NLR_MANIFEST_FILE_MAX)
        return reject(m, NLR_MF_FILE, number, NLR_FORMAT);
    for (uint32_t n = 0; n < file->len; n++)
        if (!nlr_manifest_token_byte(file->text[n]) || file->text[n] == ':')
            return reject(m, NLR_MF_FILE, number, NLR_FORMAT);
    /* The load stage only reads from the APPS directory (PLAN 6.1), and a
     * relative step would leave it. Both separators are accepted because the
     * file is written on a host. BUNDLE/ names a program of the release
     * bundle the firmware carries: read from memory,
     * never from the card. */
    int in_apps = (file->len > 5) &&
                  (lower(file->text[0]) == 'a' && lower(file->text[1]) == 'p' &&
                   lower(file->text[2]) == 'p' && lower(file->text[3]) == 's' &&
                   (file->text[4] == '/' || file->text[4] == '\\'));
    int in_bundle = (file->len > 7) &&
                    (lower(file->text[0]) == 'b' && lower(file->text[1]) == 'u' &&
                     lower(file->text[2]) == 'n' && lower(file->text[3]) == 'd' &&
                     lower(file->text[4]) == 'l' && lower(file->text[5]) == 'e' &&
                     (file->text[6] == '/' || file->text[6] == '\\'));
    if (!in_apps && !in_bundle)
        return reject(m, NLR_MF_FILE, number, NLR_FORMAT);
    for (uint32_t n = 0; n + 1 < file->len; n++)
        if (file->text[n] == '.' && file->text[n + 1] == '.')
            return reject(m, NLR_MF_FILE, number, NLR_FORMAT);

    if (abi->len == 0 || abi->len > 6)
        return reject(m, NLR_MF_ABI, number, NLR_FORMAT);
    uint32_t min_abi = 0;
    for (uint32_t n = 0; n < abi->len; n++) {
        if (abi->text[n] < '0' || abi->text[n] > '9')
            return reject(m, NLR_MF_ABI, number, NLR_FORMAT);
        min_abi = min_abi * 10 + (uint32_t)(abi->text[n] - '0');
    }

    uint32_t support_off = 0, support_len = 0;
    if (count == 6 && fields[5].len) {
        const struct field *support = &fields[5];
        if (support->len > NLR_MANIFEST_SUPPORT_MAX)
            return reject(m, NLR_MF_SUPPORT, number, NLR_FORMAT);
        /* Comma separated "model/firmware" tokens, each with exactly one
         * separator and both halves present. */
        uint32_t from = 0;
        for (uint32_t n = 0; n <= support->len; n++) {
            if (n != support->len && support->text[n] != ',')
                continue;
            uint32_t to = n, slashes = 0, slash_at = 0;
            while (from < to && is_space(support->text[from]))
                from++;
            while (to > from && is_space(support->text[to - 1]))
                to--;
            if (to == from)
                return reject(m, NLR_MF_SUPPORT, number, NLR_FORMAT);
            for (uint32_t k = from; k < to; k++) {
                if (support->text[k] == '/') {
                    slashes++;
                    slash_at = k;
                } else if (!nlr_manifest_token_byte(support->text[k])) {
                    return reject(m, NLR_MF_SUPPORT, number, NLR_FORMAT);
                }
            }
            if (slashes != 1 || slash_at == from || slash_at + 1 == to)
                return reject(m, NLR_MF_SUPPORT, number, NLR_FORMAT);
            from = n + 1;
        }
        support_off = support->off;
        support_len = support->len;
    }

    if (m->count == NLR_MANIFEST_MAX_ENTRIES)
        return reject(m, NLR_MF_COUNT, number, NLR_BOUNDS);

    struct nlr_manifest_entry *e = &m->entries[m->count];
    e->id_off = (uint16_t)id->off;
    e->id_len = (uint16_t)id->len;
    e->name_off = (uint16_t)name->off;
    e->name_len = (uint16_t)name->len;
    e->file_off = (uint16_t)file->off;
    e->file_len = (uint16_t)file->len;
    e->support_off = (uint16_t)support_off;
    e->support_len = (uint16_t)support_len;
    e->line = (uint16_t)number;
    e->kind = kind_code;
    e->shell = shell;
    /* no verdict until the gate runs; a repeated id has its own */
    e->gate = repeated ? NLR_GATE_DUPLICATE : NLR_GATE_UNKNOWN;
    e->min_abi = min_abi;
    m->count++;
    return NLR_OK;
}

/* A directive line: "#!" first, so a
 * loader that predates directives reads it as the comment it starts with
 * and lists everything, as it always did. The one directive is
 *
 *   #!hide <id>
 *
 * with blanks allowed after "#!" and around the id, and the id in the
 * MANIFEST token grammar. 0 for a plain comment, 1 for a hide (the id at
 * line[*id_at], *id_len bytes), -1 for a "#!" line this grammar does not
 * take: a misspelt directive is refused, never read as a comment. */
static int directive(const uint8_t *line, uint32_t len, uint32_t *id_at,
                     uint32_t *id_len)
{
    if (len < 2u || line[0] != '#' || line[1] != '!')
        return 0;
    uint32_t n = 2;
    while (n < len && is_space(line[n]))
        n++;
    uint32_t word = n;
    while (n < len && !is_space(line[n]))
        n++;
    if (!equals(line + word, n - word, "hide") || n == len)
        return -1;
    while (n < len && is_space(line[n]))
        n++;
    uint32_t from = n;
    while (n < len && nlr_manifest_token_byte(line[n]))
        n++;
    uint32_t to = n;
    while (n < len && is_space(line[n]))
        n++;
    if (n != len || to == from || to - from > NLR_MANIFEST_ID_MAX)
        return -1;
    *id_at = from;
    *id_len = to - from;
    return 1;
}

int nlr_manifest_hidden(const struct nlr_manifest *m, const uint8_t *id,
                        uint32_t len)
{
    if (!m || !m->buffer || !id || !len)
        return 0;
    const uint8_t *b = m->buffer;
    uint32_t start = 0;
    for (uint32_t n = 0; n <= m->bytes; n++) {
        if (n != m->bytes && b[n] != '\n')
            continue;
        uint32_t end = n;
        if (end > start && b[end - 1] == '\r')
            end--;
        uint32_t from = start;
        while (from < end && is_space(b[from]))
            from++;
        uint32_t at = 0, hidden_len = 0;
        if (directive(b + from, end - from, &at, &hidden_len) == 1 &&
            equals_fold(b + from + at, hidden_len, id, len))
            return 1;
        start = n + 1;
    }
    return 0;
}

uint32_t nlr_manifest_hide(struct nlr_manifest *m)
{
    if (!m || m->error != NLR_MF_OK)
        return 0;
    uint32_t kept = 0, dropped = 0;
    for (uint32_t n = 0; n < m->count; n++) {
        const struct nlr_manifest_entry *e = &m->entries[n];
        if (nlr_manifest_hidden(m, m->buffer + e->id_off, e->id_len)) {
            dropped++;
            continue;
        }
        if (kept != n) {
            /* field by field: no libc memcpy in the freestanding core */
            struct nlr_manifest_entry *to = &m->entries[kept];
            to->id_off = e->id_off;
            to->id_len = e->id_len;
            to->name_off = e->name_off;
            to->name_len = e->name_len;
            to->file_off = e->file_off;
            to->file_len = e->file_len;
            to->support_off = e->support_off;
            to->support_len = e->support_len;
            to->line = e->line;
            to->kind = e->kind;
            to->gate = e->gate;
            to->min_abi = e->min_abi;
            to->shell = e->shell;
        }
        kept++;
    }
    m->count = kept;
    return dropped;
}

int nlr_manifest_parse(struct nlr_manifest *m, const uint8_t *buffer,
                       uint32_t bytes)
{
    return nlr_manifest_parse_listed(m, buffer, bytes, UINT32_MAX);
}

int nlr_manifest_parse_listed(struct nlr_manifest *m, const uint8_t *buffer,
                              uint32_t bytes, uint32_t listed)
{
    if (!m || (!buffer && bytes))
        return NLR_NOT_READY;
    m->buffer = buffer;
    m->bytes = bytes;
    m->count = 0;
    m->usable = 0;
    m->error = NLR_MF_OK;
    m->error_line = 0;
    /* Offsets are 16 bit, so a buffer this parser can index is bounded. */
    if (bytes > 0xffffu)
        return reject(m, NLR_MF_SIZE, 0, NLR_BOUNDS);

    uint32_t start = 0, number = 0;
    for (uint32_t n = 0; n <= bytes; n++) {
        if (n != bytes && buffer[n] != '\n')
            continue;
        uint32_t end = n;
        if (end > start && buffer[end - 1] == '\r')
            end--;
        number++;
        uint32_t from = start;
        while (from < end && is_space(buffer[from]))
            from++;
        /* Blank lines and comments carry no entry but still count, so a
         * reported line number matches what the author sees. */
        if (from < end && buffer[from] != '#') {
            int status = parse_line(m, buffer + from, from, end - from, number,
                                    from >= listed);
            if (status != NLR_OK)
                return status;
        } else if (from < end) {
            uint32_t at = 0, len = 0;
            if (directive(buffer + from, end - from, &at, &len) < 0)
                return reject(m, NLR_MF_DIRECTIVE, number, NLR_FORMAT);
        }
        start = n + 1;
        if (start > bytes)
            break;
    }
    return NLR_OK;
}

int nlr_manifest_gate(struct nlr_manifest *m, const char *model,
                      const char *firmware)
{
    if (!m)
        return NLR_NOT_READY;
    m->usable = 0;
    uint32_t model_len = literal_length(model);
    uint32_t firmware_len = literal_length(firmware);
    for (uint32_t n = 0; n < m->count; n++) {
        struct nlr_manifest_entry *e = &m->entries[n];
        if (e->gate == NLR_GATE_DUPLICATE)
            continue; /* never loaded, whatever it declares */
        if (e->min_abi > NLR_ABI_VERSION || e->min_abi == 3u) {
            e->gate = NLR_GATE_ABI;
            continue;
        }
        if (!e->support_len) {
            /* No declaration: PLAN 6.2 allows the column to be omitted. */
            e->gate = NLR_GATE_OK;
            m->usable++;
            continue;
        }
        if (!model_len || !firmware_len) {
            /* A declaration exists but we were not told who we are, so it
             * cannot be confirmed. Reported, never assumed to match. */
            e->gate = NLR_GATE_UNKNOWN;
            continue;
        }
        const uint8_t *text = m->buffer + e->support_off;
        uint32_t len = e->support_len, from = 0;
        e->gate = NLR_GATE_MODEL;
        for (uint32_t k = 0; k <= len; k++) {
            if (k != len && text[k] != ',')
                continue;
            uint32_t to = k, slash = from;
            while (from < to && is_space(text[from]))
                from++;
            while (to > from && is_space(text[to - 1]))
                to--;
            slash = from;
            while (slash < to && text[slash] != '/')
                slash++;
            if (equals_fold(text + from, slash - from, (const uint8_t *)model,
                            model_len) &&
                slash < to &&
                equals_fold(text + slash + 1, to - slash - 1,
                            (const uint8_t *)firmware, firmware_len)) {
                e->gate = NLR_GATE_OK;
                m->usable++;
                break;
            }
            from = k + 1;
        }
    }
    return NLR_OK;
}

static int card_read(const struct nlr_services *svc, const char *path,
                     uint8_t *buffer, uint32_t capacity, uint32_t *bytes,
                     struct nlr_trace *trace, int prefix);

int nlr_master_off(const struct nlr_services *svc, struct nlr_trace *trace)
{
    /* A whole cache line of the stack: what the card reader invalidates
     * around (file_store.c reads its marker the same way). */
    _Alignas(NLR_CACHE_LINE) uint8_t frame[NLR_CACHE_LINE];
    uint32_t bytes = 0;
    if (!svc || nlr_card_read_prefix(svc, NLR_MASTER_PATH, frame, sizeof frame,
                                     &bytes, trace) != NLR_OK)
        return 0;
    return bytes >= 3u && frame[0] == 'o' && frame[1] == 'f' && frame[2] == 'f';
}

int nlr_card_read(const struct nlr_services *svc, const char *path,
                  uint8_t *buffer, uint32_t capacity, uint32_t *bytes,
                  struct nlr_trace *trace)
{
    return card_read(svc, path, buffer, capacity, bytes, trace, 0);
}

int nlr_card_read_prefix(const struct nlr_services *svc, const char *path,
                         uint8_t *buffer, uint32_t capacity, uint32_t *bytes,
                         struct nlr_trace *trace)
{
    return card_read(svc, path, buffer, capacity, bytes, trace, 1);
}

static int card_read(const struct nlr_services *svc, const char *path,
                     uint8_t *buffer, uint32_t capacity, uint32_t *bytes,
                     struct nlr_trace *trace, int prefix)
{
    if (!svc || !path || !bytes || !buffer || !capacity ||
        !nlr_cache_aligned(buffer, capacity) || !svc->file_open ||
        !svc->file_read || !svc->file_seek || !svc->file_close)
        return NLR_NOT_READY;
    *bytes = 0;
    int32_t fd = svc->file_open(path, 0, 0);
    if (fd < 0)
        return NLR_IO;
    uint32_t size = 0, position = 0;
    int result = NLR_IO;
    if (svc->file_seek(fd, NLR_SEEK_END, 0, &size) != 0 ||
        svc->file_seek(fd, NLR_SEEK_SET, 0, &position) != 0 || position != 0)
        goto close;
    if (prefix && size > capacity)
        size = capacity;
    if (size > capacity || size > 0xffffu) {
        result = NLR_BOUNDS;
        goto close;
    }
    uint32_t received = 0;
    while (received < size) {
        uint32_t chunk = size - received, filled = 0;
        if (chunk > NLR_LOAD_CHUNK)
            chunk = NLR_LOAD_CHUNK;
        /* Once per disjoint chunk, never again after a short read: the line
         * holding the last received bytes would be invalidated with them. */
        if (svc->cache_before_read)
            svc->cache_before_read(buffer + received, chunk);
        while (filled < chunk) {
            uint32_t done = 0;
            int32_t r = svc->file_read(fd, buffer + received + filled,
                                       chunk - filled, &done);
            if (r != 0 || done == 0 || done > chunk - filled) {
                nlr_trace_put(trace, 'F', NLR_IO);
                result = NLR_IO;
                goto close;
            }
            filled += done;
        }
        if (svc->cache_after_read)
            svc->cache_after_read(buffer + received, chunk);
        received += chunk;
    }
    *bytes = received;
    result = NLR_OK;
close:
    if (svc->file_close(fd) != 0 && result == NLR_OK)
        result = NLR_IO;
    if (result != NLR_OK)
        *bytes = 0;
    nlr_trace_put(trace, 'F', result == NLR_OK ? (int32_t)*bytes : result);
    return result;
}

int nlr_manifest_read(struct nlr_manifest *m, const struct nlr_services *svc,
                      uint8_t *buffer, uint32_t capacity,
                      struct nlr_trace *trace)
{
    if (!m || !svc || !buffer || !capacity ||
        !nlr_cache_aligned(buffer, capacity) || !svc->file_open ||
        !svc->file_read || !svc->file_seek || !svc->file_close)
        return NLR_NOT_READY;
#if NLR_HAS_NATIVE_CARD
    /* The card's one request is held elsewhere (a log write, the worker's
     * own request): nothing was asked, so the directory read before stays
     * as it is and the caller may ask again. */
    int guarded = svc->native_card ? nlr_native_card_safe_guard() : NLR_OK;
    if (svc->native_card && guarded == NLR_BUSY) {
        nlr_trace_put(trace, 'M', guarded);
        return NLR_BUSY;
    }
#endif
    m->buffer = 0;
    m->capacity = capacity;
    m->bytes = m->count = m->usable = m->error_line = 0;
    m->error = NLR_MF_OK;
    /* Native state has a reliable stat reason; do not infer absence from
     * a failed open when that capability is available. */
#if NLR_HAS_NATIVE_CARD
    if (svc->native_card) {
        if (guarded == NLR_NOT_READY) {
            /* No card mounted: the card cannot be read, as the legacy
             * reader answers it (a failed open), so the release bundle's
             * programs are still listed. */
            nlr_trace_put(trace, 'M', guarded);
            return NLR_IO;
        }
        if (guarded != NLR_OK) {
            nlr_trace_put(trace, 'M', guarded);
            return guarded;
        }
    } else
#endif
    {
        /* The legacy read-only service cannot distinguish absent from IO.
         * Autoload uses its reliable probe before reaching this reader. */
        int32_t guard = svc->file_open(NLR_SAFE_MODE_PATH, 0, 0);
        if (guard >= 0) {
            nlr_trace_put(trace, 'M', guard);
            int32_t closed = svc->file_close(guard);
            if (closed != 0) {
                nlr_trace_put(trace, 'C', closed);
                return NLR_IO;
            }
            return NLR_DISABLED;
        }
    }
    /* The NLoader switch, next to SAFE_MODE and meaning the same: a card
     * switched off is read no further. */
    if (nlr_master_off(svc, 0)) {
        m->error = NLR_MF_SWITCHED_OFF;
        return NLR_DISABLED;
    }
    uint32_t bytes = 0;
    int result = nlr_card_read(svc, NLR_MANIFEST_PATH, buffer, capacity,
                               &bytes, trace);
    if (result != NLR_OK) {
        if (result == NLR_BOUNDS)
            m->error = NLR_MF_SIZE;
        return result;
    }
    result = nlr_manifest_parse(m, buffer, bytes);
    nlr_trace_put(trace, 'P', result ? (int32_t)m->error : (int32_t)m->count);
    return result;
}

static int enabled_reject(struct nlr_enabled *e, uint32_t reason,
                           uint32_t line, int result)
{
    e->count = 0;
    e->error = reason;
    e->error_line = line;
    return result;
}

static int enabled_index(const struct nlr_enabled *e,
                          const struct nlr_manifest *m, uint32_t at,
                          uint8_t *out)
{
    uint32_t len = 0;
    while (len <= NLR_MANIFEST_ID_MAX && e->id[at][len])
        len++;
    if (!len || len > NLR_MANIFEST_ID_MAX)
        return NLR_FORMAT;
    uint32_t index = 0;
    while (index < m->count &&
           !equals_fold((const uint8_t *)e->id[at], len,
                        m->buffer + m->entries[index].id_off,
                        m->entries[index].id_len))
        index++;
    if (index == m->count ||
        m->entries[index].kind != NLR_KIND_RESOURCE_EXTENSION)
        return NLR_FORMAT;
    *out = (uint8_t)index;
    return NLR_OK;
}

int nlr_enabled_parse(struct nlr_enabled *e, const struct nlr_manifest *m,
                      const uint8_t *buffer, uint32_t bytes)
{
    if (!e || !m || (!buffer && bytes) || m->error != NLR_MF_OK ||
        (m->count && !m->buffer))
        return NLR_NOT_READY;
    e->count = e->error = e->error_line = 0;
    if (bytes > NLR_ENABLED_BYTES)
        return enabled_reject(e, NLR_EN_SIZE, 0, NLR_BOUNDS);
    uint32_t start = 0, line = 0;
    for (uint32_t n = 0; n <= bytes; n++) {
        if (n != bytes && buffer[n] != '\n')
            continue;
        uint32_t end = n;
        if (end > start && buffer[end - 1] == '\r' && n != bytes)
            end--;
        line++;
        if (end != start) {
            uint32_t len = end - start;
            if (len > NLR_MANIFEST_ID_MAX)
                return enabled_reject(e, NLR_EN_ID, line, NLR_FORMAT);
            for (uint32_t k = start; k < end; k++)
                if (!nlr_manifest_token_byte(buffer[k]))
                    return enabled_reject(e, NLR_EN_ID, line, NLR_FORMAT);
            uint32_t index = 0;
            while (index < m->count &&
                   !equals_fold(buffer + start, len,
                                m->buffer + m->entries[index].id_off,
                                m->entries[index].id_len))
                index++;
            if (index == m->count &&
                nlr_manifest_hidden(m, buffer + start, len)) {
                /* Hidden by MANIFEST (#!hide): not started, and not an
                 * error that would stop the rest of the list. */
                start = n + 1;
                continue;
            }
            if (index == m->count)
                return enabled_reject(e, NLR_EN_UNKNOWN, line, NLR_FORMAT);
            if (m->entries[index].kind != NLR_KIND_RESOURCE_EXTENSION)
                return enabled_reject(e, NLR_EN_KIND, line, NLR_FORMAT);
            for (uint32_t k = 0; k < e->count; k++)
                if (e->index[k] == index)
                    return enabled_reject(e, NLR_EN_DUPLICATE, line, NLR_FORMAT);
            if (e->count == NLR_MANIFEST_MAX_ENTRIES)
                return enabled_reject(e, NLR_EN_COUNT, line, NLR_BOUNDS);
            const struct nlr_manifest_entry *entry = &m->entries[index];
            for (uint32_t k = 0; k < entry->id_len; k++)
                e->id[e->count][k] = (char)m->buffer[entry->id_off + k];
            e->id[e->count][entry->id_len] = 0;
            e->index[e->count++] = (uint8_t)index;
        }
        start = n + 1;
    }
    return NLR_OK;
}

int nlr_enabled_encode(const struct nlr_enabled *e,
                       const struct nlr_manifest *m, uint8_t *buffer,
                       uint32_t capacity, uint32_t *bytes)
{
    if (!e || !m || !bytes || (!buffer && capacity) ||
        m->error != NLR_MF_OK || (m->count && !m->buffer))
        return NLR_NOT_READY;
    *bytes = 0;
    if (e->error != NLR_EN_OK)
        return NLR_FORMAT;
    if (e->count > NLR_MANIFEST_MAX_ENTRIES)
        return NLR_BOUNDS;
    uint32_t required = 0;
    uint8_t indices[NLR_MANIFEST_MAX_ENTRIES];
    /* Validate the whole list before writing anything into the output. */
    for (uint32_t n = 0; n < e->count; n++) {
        int result = enabled_index(e, m, n, &indices[n]);
        if (result != NLR_OK)
            return result;
        for (uint32_t k = 0; k < n; k++)
            if (indices[k] == indices[n])
                return NLR_FORMAT;
        required += m->entries[indices[n]].id_len + 1u;
    }
    if (required > capacity)
        return NLR_BOUNDS;
    uint32_t used = 0;
    for (uint32_t n = 0; n < e->count; n++) {
        const struct nlr_manifest_entry *entry = &m->entries[indices[n]];
        for (uint32_t k = 0; k < entry->id_len; k++)
            buffer[used++] = m->buffer[entry->id_off + k];
        buffer[used++] = '\n';
    }
    *bytes = used;
    return NLR_OK;
}

int nlr_enabled_save(struct nlr_enabled *saved,
                     const struct nlr_enabled *desired,
                     const struct nlr_manifest *m,
                     const struct nlr_card_store *store, uint8_t *buffer,
                     uint32_t capacity)
{
    if (!saved || !store || !store->replace)
        return NLR_NOT_READY;
    uint32_t bytes = 0;
    int result = nlr_enabled_encode(desired, m, buffer, capacity, &bytes);
    if (result != NLR_OK)
        return result;
    result = store->replace(NLR_ENABLED_PATH, buffer, bytes);
    if (result == NLR_OK)
        nlr_enabled_copy(saved, desired);
    return result;
}

/* ---- program metadata (NPLD v3) ---------------------- */

const uint8_t *nlr_meta_find(const uint8_t *meta, uint32_t bytes,
                             const char *key, uint32_t *length)
{
    if (!meta || !key)
        return 0;
    uint32_t at = 0;
    while (at < bytes && meta[at]) {
        uint32_t end = at;
        while (end < bytes && meta[end] && meta[end] != '\n')
            end++;
        uint32_t k = 0;
        while (key[k] && at + k < end && meta[at + k] == (uint8_t)key[k])
            k++;
        if (!key[k] && at + k < end && meta[at + k] == '=') {
            if (length)
                *length = end - (at + k + 1u);
            return meta + at + k + 1u;
        }
        at = end + 1u;
    }
    return 0;
}

uint32_t nlr_meta_memory(const uint8_t *meta, uint32_t bytes)
{
    uint32_t n = 0;
    const uint8_t *v = nlr_meta_find(meta, bytes, "memory", &n);
    if (!v || !n || n > 10u)
        return 0;
    uint64_t value = 0;
    uint32_t i = 0;
    for (; i < n && v[i] >= '0' && v[i] <= '9'; i++)
        value = value * 10u + (uint32_t)(v[i] - '0');
    if (!i)
        return 0;
    if (i + 1u == n && (v[i] == 'K' || v[i] == 'k'))
        value <<= 10;
    else if (i + 1u == n && (v[i] == 'M' || v[i] == 'm'))
        value <<= 20;
    else if (i != n)
        return 0;
    return value && value <= (64u << 20) ? (uint32_t)value : 0;
}

/* One field of a MANIFEST line: copied when every byte is one the line's
 * grammar takes there (a token: printable, no space; a name: printable,
 * spaces inside), else nothing is written. */
static uint32_t meta_field(const uint8_t *v, uint32_t n, int name, uint32_t max,
                           char *out, uint32_t room)
{
    if (!v || !n || n > max || n > room)
        return 0;
    if (name && (v[0] == ' ' || v[n - 1u] == ' '))
        return 0;
    for (uint32_t i = 0; i < n; i++) {
        uint8_t c = v[i];
        if (c == '|' || c < (name ? 0x20 : 0x21) || c > 0x7e)
            return 0;
        out[i] = (char)c;
    }
    return n;
}

static uint32_t meta_text(const char *s, char *out, uint32_t room)
{
    uint32_t n = 0;
    while (s[n] && n < room) {
        out[n] = s[n];
        n++;
    }
    return s[n] ? 0 : n;
}

uint32_t nlr_meta_line(const uint8_t *meta, uint32_t bytes, const char *file,
                       char *out, uint32_t capacity)
{
    if (!meta || !file || !out)
        return 0;
    uint32_t id_n = 0, kind_n = 0, name_n = 0, abi_n = 0, targets_n = 0;
    const uint8_t *id = nlr_meta_find(meta, bytes, "id", &id_n);
    const uint8_t *kind = nlr_meta_find(meta, bytes, "kind", &kind_n);
    const uint8_t *name = nlr_meta_find(meta, bytes, "name", &name_n);
    const uint8_t *abi = nlr_meta_find(meta, bytes, "min_abi", &abi_n);
    const uint8_t *targets = nlr_meta_find(meta, bytes, "targets", &targets_n);
    /* An app is a foreground program, a shell one that runs over the live
     * picture; a service is resident like an extension (its tasks are what
     * makes it a service). */
    const char *label = 0;
    if (kind && kind_n == 3 && kind[0] == 'a' && kind[1] == 'p' && kind[2] == 'p')
        label = "foreground";
    else if (kind && kind_n == 5 && kind[0] == 's' && kind[1] == 'h' &&
             kind[2] == 'e' && kind[3] == 'l' && kind[4] == 'l')
        label = "shell";
    else if (kind && kind_n == 9 && kind[0] == 'e' && kind[1] == 'x' && kind[8] == 'n')
        label = "resource_extension";
    else if (kind && kind_n == 7 && kind[0] == 's' && kind[1] == 'e' && kind[6] == 'e')
        label = "resource_extension";
    if (!label || !abi || !abi_n || abi_n > 3u)
        return 0;
    for (uint32_t i = 0; i < abi_n; i++)
        if (abi[i] < '0' || abi[i] > '9')
            return 0;
    uint32_t at = 0, n;
    if (!(n = meta_field(id, id_n, 0, NLR_MANIFEST_ID_MAX, out + at, capacity - at)))
        return 0;
    at += n;
    if (!(n = meta_text(" | ", out + at, capacity - at))) return 0;
    at += n;
    if (!(n = meta_text(label, out + at, capacity - at))) return 0;
    at += n;
    if (!(n = meta_text(" | ", out + at, capacity - at))) return 0;
    at += n;
    if (!(n = meta_field(name, name_n, 1, NLR_MANIFEST_NAME_MAX, out + at, capacity - at)))
        return 0;
    at += n;
    if (!(n = meta_text(" | ", out + at, capacity - at))) return 0;
    at += n;
    uint32_t file_n = 0;
    while (file[file_n])
        file_n++;
    if (!(n = meta_field((const uint8_t *)file, file_n, 0, NLR_MANIFEST_FILE_MAX,
                         out + at, capacity - at)))
        return 0;
    at += n;
    if (!(n = meta_text(" | ", out + at, capacity - at))) return 0;
    at += n;
    if (!(n = meta_field(abi, abi_n, 0, 3u, out + at, capacity - at)))
        return 0;
    at += n;
    if (targets && targets_n) {
        if (!(n = meta_text(" | ", out + at, capacity - at))) return 0;
        at += n;
        if (!(n = meta_field(targets, targets_n, 1, NLR_MANIFEST_SUPPORT_MAX,
                             out + at, capacity - at)))
            return 0;
        at += n;
    }
    if (at >= capacity)
        return 0;
    out[at++] = '\n';
    return at;
}
