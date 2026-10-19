/* Host tests for programs that describe themselves (NPLD v3 metadata):
 * the MANIFEST line a description stands for, and the
 * memory it declares. */
#include <stdio.h>
#include <string.h>

#include "nlr/manifest.h"

static int failures;
#define CHECK(c)                                                            \
    do {                                                                    \
        if (!(c)) {                                                         \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);            \
            failures++;                                                     \
        }                                                                   \
    } while (0)

static uint32_t line_of(const char *meta, const char *file, char *out, uint32_t cap)
{
    return nlr_meta_line((const uint8_t *)meta, (uint32_t)strlen(meta), file, out, cap);
}

int main(void)
{
    char out[256];
    const char *shell = "id=lvui\nkind=shell\nname=New UI\nname.zh=x\n"
                        "min_abi=5\ntargets=z6iii/2.00\nmemory=6M\n";
    uint32_t n = line_of(shell, "APPS/LVUI.NLB", out, sizeof out);
    out[n] = 0;
    CHECK(!strcmp(out, "lvui | shell | New UI | APPS/LVUI.NLB | 5 | z6iii/2.00\n"));
    /* the line it makes is one the MANIFEST parser takes: a shell is a
     * foreground program with the shell mark */
    struct nlr_manifest m;
    CHECK(nlr_manifest_parse(&m, (const uint8_t *)out, n) == NLR_OK && m.count == 1 &&
          m.entries[0].kind == NLR_KIND_FOREGROUND && m.entries[0].shell == 1 &&
          m.entries[0].min_abi == 5);
    CHECK(nlr_meta_memory((const uint8_t *)shell, (uint32_t)strlen(shell)) == 6u << 20);

    n = line_of("id=gyro\nkind=service\nname=Gyro log\nmin_abi=7\n", "APPS/GYRO.NLB", out, sizeof out);
    out[n] = 0;
    CHECK(!strcmp(out, "gyro | resource_extension | Gyro log | APPS/GYRO.NLB | 7\n"));
    n = line_of("id=t\nkind=extension\nname=T\nmin_abi=4\n", "APPS/T.NLB", out, sizeof out);
    CHECK(n && strstr(out, "| resource_extension |"));
    n = line_of("id=a\nkind=app\nname=A\nmin_abi=4\n", "APPS/A.NLB", out, sizeof out);
    CHECK(n && strstr(out, "| foreground |"));
    CHECK(nlr_manifest_parse(&m, (const uint8_t *)out, n) == NLR_OK && !m.entries[0].shell);

    /* fields the grammar refuses make no line */
    CHECK(!line_of("id=two words\nkind=app\nname=A\nmin_abi=4\n", "APPS/A.NLB", out, sizeof out));
    CHECK(!line_of("id=a\nkind=app\nname=pipe|name\nmin_abi=4\n", "APPS/A.NLB", out, sizeof out));
    CHECK(!line_of("id=a\nkind=app\nname=A name far longer than 24\nmin_abi=4\n", "APPS/A.NLB", out, sizeof out));
    CHECK(!line_of("id=a\nkind=daemon\nname=A\nmin_abi=4\n", "APPS/A.NLB", out, sizeof out));
    CHECK(!line_of("id=a\nkind=app\nname=A\nmin_abi=x\n", "APPS/A.NLB", out, sizeof out));
    CHECK(!line_of("id=a\nkind=app\nname=A\n", "APPS/A.NLB", out, sizeof out));
    CHECK(!line_of("kind=app\nname=A\nmin_abi=4\n", "APPS/A.NLB", out, sizeof out));
    CHECK(!line_of("id=a\nkind=app\nname= A\nmin_abi=4\n", "APPS/A.NLB", out, sizeof out));
    /* too small an output */
    CHECK(!line_of(shell, "APPS/LVUI.NLB", out, 20));
    /* a key is a whole key: "name.zh" is not "name" */
    CHECK(!line_of("id=a\nkind=app\nname.zh=A\nmin_abi=4\n", "APPS/A.NLB", out, sizeof out));
    /* NUL padding ends the block */
    {
        char padded[64] = "id=p\nkind=app\nname=P\nmin_abi=6\n";
        n = nlr_meta_line((const uint8_t *)padded, sizeof padded, "APPS/P.NLB", out, sizeof out);
        CHECK(n && out[n - 1] == '\n');
    }

    /* the release bundle's programs: BUNDLE/ is a file column too */
    {
        const char *bundled = "lvui | foreground | New UI | BUNDLE/LVUI.NLB | 7\n";
        const char *elsewhere = "lvui | foreground | New UI | OTHER/LVUI.NLB | 7\n";
        const char *short_dir = "lvui | foreground | New UI | BUNDLE/ | 7\n";
        CHECK(nlr_manifest_parse(&m, (const uint8_t *)bundled, (uint32_t)strlen(bundled)) == NLR_OK &&
              m.count == 1);
        CHECK(nlr_manifest_parse(&m, (const uint8_t *)elsewhere, (uint32_t)strlen(elsewhere)) != NLR_OK);
        CHECK(nlr_manifest_parse(&m, (const uint8_t *)short_dir, (uint32_t)strlen(short_dir)) != NLR_OK);
    }

    /* MANIFEST as an override: "#!hide <id>". */
    {
        const char *text =
            "# id | kind | name | file | min_abi\n"
            "#!hide lvui\n"
            "  #!  hide\tGyro  \r\n"
            "lvui | foreground | New UI | APPS/LVUI.NLB | 7\n"
            "gyro | resource_extension | Gyro | APPS/GYRO.NLB | 7\n"
            "keep | resource_extension | Keep | APPS/KEEP.NLB | 7\n"
            "boot | foreground | Boot | BUNDLE/BOOT.NLB | 7\n"
            "#!hide nothing-by-this-id\n";
        CHECK(nlr_manifest_parse(&m, (const uint8_t *)text, (uint32_t)strlen(text)) == NLR_OK);
        /* parsed whole first: a hidden line is still a line, ids stay unique */
        CHECK(m.count == 4);
        CHECK(nlr_manifest_hidden(&m, (const uint8_t *)"LVUI", 4));
        CHECK(nlr_manifest_hidden(&m, (const uint8_t *)"gyro", 4));
        CHECK(nlr_manifest_hidden(&m, (const uint8_t *)"nothing-by-this-id", 18));
        CHECK(!nlr_manifest_hidden(&m, (const uint8_t *)"keep", 4));
        CHECK(!nlr_manifest_hidden(&m, (const uint8_t *)"lvu", 3));
        CHECK(nlr_manifest_hide(&m) == 2 && m.count == 2);
        CHECK(m.entries[0].id_len == 4 && !memcmp(m.buffer + m.entries[0].id_off, "keep", 4) &&
              m.entries[0].line == 6 && m.entries[0].kind == NLR_KIND_RESOURCE_EXTENSION);
        CHECK(!memcmp(m.buffer + m.entries[1].id_off, "boot", 4) && m.entries[1].line == 7);
        CHECK(nlr_manifest_hide(&m) == 0 && m.count == 2);
        /* ENABLED naming a hidden id: passed over, the rest still holds */
        struct nlr_enabled en;
        const char *list = "gyro\nkeep\nGYRO\n";
        CHECK(nlr_enabled_parse(&en, &m, (const uint8_t *)list, (uint32_t)strlen(list)) == NLR_OK &&
              en.count == 1 && !strcmp(en.id[0], "keep") && en.index[0] == 0);
        /* an id neither listed nor hidden is still an error */
        const char *unknown = "keep\nother\n";
        CHECK(nlr_enabled_parse(&en, &m, (const uint8_t *)unknown, (uint32_t)strlen(unknown)) ==
                  NLR_FORMAT && en.error == NLR_EN_UNKNOWN && en.error_line == 2);
        /* the encoder writes only what is listed */
        uint8_t saved[64];
        uint32_t bytes = 0;
        CHECK(nlr_enabled_parse(&en, &m, (const uint8_t *)list, (uint32_t)strlen(list)) == NLR_OK &&
              nlr_enabled_encode(&en, &m, saved, sizeof saved, &bytes) == NLR_OK &&
              bytes == 5 && !memcmp(saved, "keep\n", 5));
        /* plain comments stay comments, "#!" lines must be a directive */
        const char *bad[] = {
            "#!hid lvui\n", "#!hide\n", "#!hide \n", "#!hide two ids\n",
            "#!hide a|b c\n", "#!HIDE lvui\n", "#!\n",
            "#!hide 123456789012345678901234567890123\n",
        };
        for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
            CHECK(nlr_manifest_parse(&m, (const uint8_t *)bad[i], (uint32_t)strlen(bad[i])) ==
                      NLR_FORMAT && m.error == NLR_MF_DIRECTIVE && m.error_line == 1);
        }
        const char *good[] = {"# !hide lvui\n", "#hide lvui\n", "#!hide 12345678901234567890123456789012\n"};
        for (unsigned i = 0; i < sizeof good / sizeof *good; i++)
            CHECK(nlr_manifest_parse(&m, (const uint8_t *)good[i], (uint32_t)strlen(good[i])) ==
                      NLR_OK && m.count == 0);
        CHECK(!nlr_manifest_hidden(&m, (const uint8_t *)"lvui", 4));
    }

    uint32_t len = 0;
    const uint8_t *v = nlr_meta_find((const uint8_t *)shell, (uint32_t)strlen(shell), "name.zh", &len);
    CHECK(v && len == 1 && v[0] == 'x');
    CHECK(!nlr_meta_find((const uint8_t *)shell, (uint32_t)strlen(shell), "nam", &len));

    const char *sizes[][2] = {
        {"memory=512K\n", "524288"}, {"memory=4096\n", "4096"}, {"memory=64M\n", "67108864"},
        {"memory=65M\n", "0"}, {"memory=6MB\n", "0"}, {"memory=\n", "0"}, {"memory=M\n", "0"},
        {"other=1\n", "0"},
    };
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        uint32_t want = 0;
        sscanf(sizes[i][1], "%u", &want);
        CHECK(nlr_meta_memory((const uint8_t *)sizes[i][0], (uint32_t)strlen(sizes[i][0])) == want);
    }
    if (failures) {
        printf("%d metadata checks failed\n", failures);
        return 1;
    }
    printf("metadata behavior tests passed\n");
    return 0;
}
