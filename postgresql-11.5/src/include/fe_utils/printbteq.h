/*-------------------------------------------------------------------------
 *
 * Query-result printing support for frontend code
 *
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/fe_utils/printbteq.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef PRINT_BTEQ_H
#define PRINT_BTEQ_H

#include "libpq-fe.h"


/* This is not a particularly great place for this ... */
#ifndef __CYGWIN__
#define DEFAULT_PAGER "more"
#else
#define DEFAULT_PAGER "less"
#endif

enum printFormatBteq
{
    PRINT_NOTHING_BTEQ = 0,            /* to make sure someone initializes this */
    PRINT_UNALIGNED_BTEQ,
    PRINT_ALIGNED_BTEQ,
    PRINT_WRAPPED_BTEQ,
    PRINT_HTML_BTEQ,
    PRINT_ASCIIDOC_BTEQ,
    PRINT_LATEX_BTEQ,
    PRINT_LATEX_LONGTABLE_BTEQ,
    PRINT_TROFF_MS_BTEQ
    /* add your favourite output format here ... */
};

typedef struct printTextLineFormatBteq
{
    /* Line drawing characters to be used in various contexts */
    const char *hrule;            /* horizontal line character */
    const char *leftvrule;        /* left vertical line (+horizontal) */
    const char *midvrule;        /* intra-column vertical line (+horizontal) */
    const char *rightvrule;        /* right vertical line (+horizontal) */
} printTextLineFormatBteq;

typedef enum printTextRuleBteq
{
    /* Additional context for selecting line drawing characters */
    PRINT_RULE_TOP_BTEQ,                /* top horizontal line */
    PRINT_RULE_MIDDLE_BTEQ,            /* intra-data horizontal line */
    PRINT_RULE_BOTTOM_BTEQ,            /* bottom horizontal line */
    PRINT_RULE_DATA_BTEQ                /* data line (hrule is unused here) */
} printTextRuleBteq;

typedef enum printTextLineWrapBteq
{
    /* Line wrapping conditions */
    PRINT_LINE_WRAP_NONE_BTEQ,        /* No wrapping */
    PRINT_LINE_WRAP_WRAP_BTEQ,        /* Wraparound due to overlength line */
    PRINT_LINE_WRAP_NEWLINE_BTEQ        /* Newline in data */
} printTextLineWrapBteq;

typedef struct printTextFormatbteq
{
    /* A complete line style */
    const char *name;            /* for display purposes */
    printTextLineFormatBteq lrule[4];    /* indexed by enum printTextRuleBteq */
    const char *midvrule_nl;    /* vertical line for continue after newline */
    const char *midvrule_wrap;    /* vertical line for wrapped data */
    const char *midvrule_blank; /* vertical line for blank data */
    const char *header_nl_left; /* left mark after newline */
    const char *header_nl_right;    /* right mark for newline */
    const char *nl_left;        /* left mark after newline */
    const char *nl_right;        /* right mark for newline */
    const char *wrap_left;        /* left mark after wrapped data */
    const char *wrap_right;        /* right mark for wrapped data */
    bool        wrap_right_border;    /* use right-hand border for wrap marks
                                     * when border=0? */
} printTextFormatbteq;

typedef enum unicode_linestyle_bteq
{
    UNICODE_LINESTYLE_SINGLE_BTEQ = 0,
    UNICODE_LINESTYLE_DOUBLE_BTEQ
} unicode_linestyle_bteq;

struct separatorbteq
{
    char       *separator;
    bool        separator_zero;
};

typedef struct printTableOptBteq
{
    enum printFormatBteq format;    /* see enum above */
    unsigned short int expanded;    /* expanded/vertical output (if supported
                                     * by output format); 0=no, 1=yes, 2=auto */
    unsigned short int border;    /* Print a border around the table. 0=none,
                                 * 1=dividing lines, 2=full */
    unsigned short int pager;    /* use pager for output (if to stdout and
                                 * stdout is a tty) 0=off 1=on 2=always */
    int            table_width;
    int            pager_min_lines;    /* don't use pager unless there are at
                                     * least this many lines */
    bool        tuples_only;    /* don't output headers, row counts, etc. */
    bool        start_table;    /* print start decoration, eg <table> */
    bool        stop_table;        /* print stop decoration, eg </table> */
    bool        default_footer; /* allow "(xx rows)" default footer */
    unsigned long prior_records;    /* start offset for record counters */
    const printTextFormatbteq *line_style;    /* line style (NULL for default) */
    struct separatorbteq fieldSep;    /* field separatorbteq for unaligned text mode */
    struct separatorbteq recordSep; /* record separatorbteq for unaligned text mode */
    bool        numericLocale;    /* locale-aware numeric units separatorbteq and
                                 * decimal marker */
    char       *tableAttr;        /* attributes for HTML <table ...> */
    int            encoding;        /* character encoding */
    int            env_columns;    /* $COLUMNS on bteq start, 0 is unset */
    int            columns;        /* target width for wrapped format */
    unicode_linestyle_bteq unicode_border_linestyle;
    unicode_linestyle_bteq unicode_column_linestyle;
    unicode_linestyle_bteq unicode_header_linestyle;
} printTableOptBteq;

/*
 * Table footers are implemented as a singly-linked list.
 *
 * This is so that you don't need to know the number of footers in order to
 * initialise the printTableContentBteq struct, which is very convenient when
 * preparing complex footers (as in describeOneTableDetails).
 */
typedef struct printTableFooterBteq
{
    char       *data;
    struct printTableFooterBteq *next;
} printTableFooterBteq;

/*
 * The table content struct holds all the information which will be displayed
 * by printTablebteq().
 */
typedef struct printTableContentBteq
{
    const printTableOptBteq *opt;
    const char *title;            /* May be NULL */
    int            ncolumns;        /* Specified in Init() */
    int            nrows;            /* Specified in Init() */
    const char **headers;        /* NULL-terminated array of header strings */
    const char **header;        /* Pointer to the last added header */
    const char **cells;            /* NULL-terminated array of cell content
                                 * strings */
    int           table_width;
    const char **cell;            /* Pointer to the last added cell */
    long        cellsadded;        /* Number of cells added this far */
    bool       *cellmustfree;    /* true for cells that need to be free()d */
    printTableFooterBteq *footers;    /* Pointer to the first footer */
    printTableFooterBteq *footer;    /* Pointer to the last added footer */
    char       *aligns;            /* Array of alignment specifiers; 'l' or 'r',
                                 * one per column */
    char       *align;            /* Pointer to the last added alignment */
} printTableContentBteq;

typedef struct printQueryOptBteq
{
    printTableOptBteq topt;            /* the options above */
    char       *nullPrint;        /* how to print null entities */
    char       *title;            /* override title */
    char      **footers;        /* override footer (default is "(xx rows)") */
    bool        translate_header;    /* do gettext on column headers */
    const bool *translate_columns;    /* translate_columns[i-1] => do gettext on
                                     * col i */
    int            n_translate_columns;    /* length of translate_columns[] */
} printQueryOptBteq;


extern volatile bool cancel_pressed_bteq;

extern const printTextFormatbteq pg_asciiformat_bteq;
extern const printTextFormatbteq pg_asciiformat_old_bteq;
extern printTextFormatbteq pg_utf8format_bteq;    /* ideally would be const, but... */


extern void disable_sigpipe_trap_bteq(void);
extern void restore_sigpipe_trap_bteq(void);
extern void set_sigpipe_trap_state_bteq(bool ignore);

extern FILE *PageOutputbteq(int lines, const printTableOptBteq *topt);
extern void ClosePagerbteq(FILE *pagerpipe);

extern void html_escaped_print_bteq(const char *in, FILE *fout);

extern void printTableInitbteq(printTableContentBteq *const content,
               const printTableOptBteq *opt, const char *title,
               const int ncolumns, const int nrows);
extern void printTableAddHeaderbteq(printTableContentBteq *const content,
                    char *header, const bool translate, const char align);
extern void printTableAddCellbteq(printTableContentBteq *const content,
                  char *cell, const bool translate, const bool mustfree);
extern void printTableAddFooterbteq(printTableContentBteq *const content,
                    const char *footer);
extern void printTableSetFooterbteq(printTableContentBteq *const content,
                    const char *footer);
extern void printTableCleanupbteq(printTableContentBteq *const content);
extern void printTablebteq(const printTableContentBteq *cont,
           FILE *fout, bool is_pager, FILE *flog);
extern void printQuerybteq(const PGresult *result, const printQueryOptBteq *opt,
           FILE *fout, bool is_pager, FILE *flog);

extern char column_type_alignment_bteq(Oid);

extern void setDecimalLocalebteq(void);
extern const printTextFormatbteq *get_line_style_bteq(const printTableOptBteq *opt);
extern void refresh_utf8format_bteq(const printTableOptBteq *opt);

#endif                            /* PRINT_BTEQ_H */
