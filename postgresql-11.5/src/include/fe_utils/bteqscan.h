/*-------------------------------------------------------------------------
 *
 * psqlscan.h
 *      lexical scanner for SQL commands
 *
 * This lexer used to be part of psql, and that heritage is reflected in
 * the file name as well as function and typedef names, though it can now
 * be used by other frontend programs as well.  It's also possible to extend
 * this lexer with a compatible add-on lexer to handle program-specific
 * backslash commands.
 *
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/fe_utils/psqlscan.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef BTEQSCAN_H
#define BTEQSCAN_H

#include "pqexpbuffer.h"


/* Abstract type for lexer's internal state */
typedef struct BteqScanStateData *BteqScanState;

/* Termination states for bteq_scan() */
typedef enum
{
    PSCAN_BTEQ_SEMICOLON,             /* found command-ending semicolon */
    PSCAN_BTEQ_DOT,                   /* found dot command */
    PSCAN_BTEQ_INCOMPLETE,            /* end of line, SQL statement incomplete */
    PSCAN_BTEQ_EOL                    /* end of line, SQL possibly complete */
} BteqScanResult;

/* Prompt type returned by bteq_scan() */
typedef enum _promptStatusBteq
{
    PROMPT_BTEQ_READY,
    PROMPT_BTEQ_CONTINUE,
    PROMPT_BTEQ_COMMENT,
    PROMPT_BTEQ_SINGLEQUOTE,
    PROMPT_BTEQ_DOUBLEQUOTE,
    PROMPT_BTEQ_DOLLARQUOTE,
    PROMPT_BTEQ_PAREN,
    PROMPT_BTEQ_COPY
} promptStatus_bteq_t;

/* Quoting request types for get_variable() callback */
typedef enum
{
    PQUOTE_BTEQ_PLAIN,                /* just return the actual value */
    PQUOTE_BTEQ_SQL_LITERAL,            /* add quotes to make a valid SQL literal */
    PQUOTE_BTEQ_SQL_IDENT,            /* quote if needed to make a SQL identifier */
    PQUOTE_BTEQ_SHELL_ARG            /* quote if needed to be safe in a shell cmd */
} BteqScanQuoteType;

/* Callback functions to be used by the lexer */
typedef struct BteqScanCallbacks
{
    /* Fetch value of a variable, as a free'able string; NULL if unknown */
    /* This pointer can be NULL if no variable substitution is wanted */
    char       *(*get_variable) (const char *varname, BteqScanQuoteType quote,
                                 void *passthrough);
    /* Print an error message someplace appropriate */
    /* (very old gcc versions don't support attributes on function pointers) */
#if defined(__GNUC__) && __GNUC__ < 4
    void        (*write_error) (const char *fmt,...);
#else
    void        (*write_error) (const char *fmt,...) pg_attribute_printf(1, 2);
#endif
} BteqScanCallbacks;


extern BteqScanState bteq_scan_create(const BteqScanCallbacks *callbacks);
extern void bteq_scan_destroy(BteqScanState state);

extern void bteq_scan_set_passthrough(BteqScanState state, void *passthrough);

extern void bteq_scan_setup(BteqScanState state,
                const char *line, int line_len,
                int encoding, bool std_strings);
extern void bteq_scan_finish(BteqScanState state);

extern BteqScanResult bteq_scan(BteqScanState state,
          PQExpBuffer query_buf,
          promptStatus_bteq_t *prompt);

extern void bteq_scan_reset(BteqScanState state);

extern void bteq_scan_reselect_sql_lexer(BteqScanState state);

extern bool bteq_scan_in_quote(BteqScanState state);

#endif                            /* BTEQSCAN_H */
