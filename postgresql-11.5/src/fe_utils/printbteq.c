/*-------------------------------------------------------------------------
 *
 * Query-result printing support for frontend code
 *
 * This file used to be part of bteq, but now it's separated out to allow
 * other frontend programs to use it.  Because the printing code needs
 * access to the cancel_pressed_bteq flag as well as SIGPIPE trapping and
 * pager open/close functions, all that stuff came with it.
 *
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/fe_utils/printbteq.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres_fe.h"

#include <limits.h>
#include <math.h>
#include <signal.h>
#include <unistd.h>

#ifndef WIN32
#include <sys/ioctl.h>            /* for ioctl() */
#endif

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#include "fe_utils/printbteq.h"

#include "catalog/pg_type_d.h"
#include "fe_utils/mbprint.h"


/*
 * If the calling program doesn't have any mechanism for setting
 * cancel_pressed_bteq, it will have no effect.
 *
 * Note: printbteq.c's general strategy for when to check cancel_pressed_bteq is to do
 * so at completion of each row of output.
 */
volatile bool cancel_pressed_bteq = false;

static bool always_ignore_sigpipe = false;

/* info for locale-aware numeric formatting; set up by setDecimalLocalebteq() */
static char *decimal_point;
static int    groupdigits;
static char *thousands_sep;

static char default_footer[100];
static printTableFooterBteq default_footer_cell = {default_footer, NULL};

/* Line style control structures */
const printTextFormatbteq pg_asciiformat_bteq =
{
    "ascii",
    {
        {"-", "+", "+", "+"},
        {"-", "+", "+", "+"},
        {"-", "+", "+", "+"},
        {"", "|", "|", "|"}
    },
    "|",
    "|",
    "|",
    " ",
    "+",
    " ",
    "+",
    ".",
    ".",
    true
};

const printTextFormatbteq pg_asciiformat_old_bteq =
{
    "old-ascii",
    {
        {"-", "+", "+", "+"},
        {"-", "+", "+", "+"},
        {"-", "+", "+", "+"},
        {"", "|", "|", "|"}
    },
    ":",
    ";",
    " ",
    "+",
    " ",
    " ",
    " ",
    " ",
    " ",
    false
};

/* Default unicode linestyle format */
printTextFormatbteq pg_utf8format_bteq;

typedef struct unicodeStyleRowFormatbteq
{
    const char *horizontal;
    const char *vertical_and_right[2];
    const char *vertical_and_left[2];
} unicodeStyleRowFormatbteq;

typedef struct unicodeStyleColumnFormatbteq
{
    const char *vertical;
    const char *vertical_and_horizontal[2];
    const char *up_and_horizontal[2];
    const char *down_and_horizontal[2];
} unicodeStyleColumnFormatbteq;

typedef struct unicodeStyleBorderFormatbteq
{
    const char *up_and_right;
    const char *vertical;
    const char *down_and_right;
    const char *horizontal;
    const char *down_and_left;
    const char *left_and_right;
} unicodeStyleBorderFormatbteq;

typedef struct unicodeStyleFormatbteq
{
    unicodeStyleRowFormatbteq row_style[2];
    unicodeStyleColumnFormatbteq column_style[2];
    unicodeStyleBorderFormatbteq border_style[2];
    const char *header_nl_left;
    const char *header_nl_right;
    const char *nl_left;
    const char *nl_right;
    const char *wrap_left;
    const char *wrap_right;
    bool        wrap_right_border;
} unicodeStyleFormatbteq;

static const unicodeStyleFormatbteq unicode_style_bteq = {
    {
        {
            /* ─ */
            "\342\224\200",
            /* ├╟ */
            {"\342\224\234", "\342\225\237"},
            /* ┤╢ */
            {"\342\224\244", "\342\225\242"},
        },
        {
            /* ═ */
            "\342\225\220",
            /* ╞╠ */
            {"\342\225\236", "\342\225\240"},
            /* ╡╣ */
            {"\342\225\241", "\342\225\243"},
        },
    },
    {
        {
            /* │ */
            "\342\224\202",
            /* ┼╪ */
            {"\342\224\274", "\342\225\252"},
            /* ┴╧ */
            {"\342\224\264", "\342\225\247"},
            /* ┬╤ */
            {"\342\224\254", "\342\225\244"},
        },
        {
            /* ║ */
            "\342\225\221",
            /* ╫╬ */
            {"\342\225\253", "\342\225\254"},
            /* ╨╩ */
            {"\342\225\250", "\342\225\251"},
            /* ╥╦ */
            {"\342\225\245", "\342\225\246"},
        },
    },
    {
        /* └│┌─┐┘ */
        {"\342\224\224", "\342\224\202", "\342\224\214", "\342\224\200", "\342\224\220", "\342\224\230"},
        /* ╚║╔═╗╝ */
        {"\342\225\232", "\342\225\221", "\342\225\224", "\342\225\220", "\342\225\227", "\342\225\235"},
    },
    " ",
    "\342\206\265",                /* ↵ */
    " ",
    "\342\206\265",                /* ↵ */
    "\342\200\246",                /* … */
    "\342\200\246",                /* … */
    true
};


/* Local functions */
static int    strlen_max_width(unsigned char *str, int *target_width, int encoding);
static void IsPagerNeeded(const printTableContentBteq *cont, int extra_lines, bool expanded,
              FILE **fout, bool *is_pager);

static void print_aligned_vertical(const printTableContentBteq *cont,
                       FILE *fout, bool is_pager);


/* Count number of digits in integral part of number */
static int
integer_digits(const char *my_str)
{
    /* ignoring any sign ... */
    if (my_str[0] == '-' || my_str[0] == '+')
        my_str++;
    /* ... count initial integral digits */
    return strspn(my_str, "0123456789");
}

/* Compute additional length required for locale-aware numeric output */
static int
additional_numeric_locale_len(const char *my_str)
{
    int            int_len = integer_digits(my_str),
                len = 0;

    /* Account for added thousands_sep instances */
    if (int_len > groupdigits)
        len += ((int_len - 1) / groupdigits) * strlen(thousands_sep);

    /* Account for possible additional length of decimal_point */
    if (strchr(my_str, '.') != NULL)
        len += strlen(decimal_point) - 1;

    return len;
}

/*
 * Format a numeric value per current LC_NUMERIC locale setting
 *
 * Returns the appropriately formatted string in a new allocated block,
 * caller must free.
 *
 * setDecimalLocalebteq() must have been called earlier.
 */
static char *
format_numeric_locale(const char *my_str)
{
    char       *new_str;
    int            new_len,
                int_len,
                leading_digits,
                i,
                new_str_pos;

    /*
     * If the string doesn't look like a number, return it unchanged.  This
     * check is essential to avoid mangling already-localized "money" values.
     */
    if (strspn(my_str, "0123456789+-.eE") != strlen(my_str))
        return pg_strdup(my_str);

    new_len = strlen(my_str) + additional_numeric_locale_len(my_str);
    new_str = pg_malloc(new_len + 1);
    new_str_pos = 0;
    int_len = integer_digits(my_str);

    /* number of digits in first thousands group */
    leading_digits = int_len % groupdigits;
    if (leading_digits == 0)
        leading_digits = groupdigits;

    /* process sign */
    if (my_str[0] == '-' || my_str[0] == '+')
    {
        new_str[new_str_pos++] = my_str[0];
        my_str++;
    }

    /* process integer part of number */
    for (i = 0; i < int_len; i++)
    {
        /* Time to insert separatorbteq? */
        if (i > 0 && --leading_digits == 0)
        {
            strcpy(&new_str[new_str_pos], thousands_sep);
            new_str_pos += strlen(thousands_sep);
            leading_digits = groupdigits;
        }
        new_str[new_str_pos++] = my_str[i];
    }

    /* handle decimal point if any */
    if (my_str[i] == '.')
    {
        strcpy(&new_str[new_str_pos], decimal_point);
        new_str_pos += strlen(decimal_point);
        i++;
    }

    /* copy the rest (fractional digits and/or exponent, and \0 terminator) */
    strcpy(&new_str[new_str_pos], &my_str[i]);

    /* assert we didn't underestimate new_len (an overestimate is OK) */
    Assert(strlen(new_str) <= new_len);

    return new_str;
}


/*
 * fputnbytes: print exactly N bytes to a file
 *
 * We avoid using %.*s here because it can misbehave if the data
 * is not valid in what libc thinks is the prevailing encoding.
 */
static void
fputnbytes(FILE *f, const char *str, size_t n)
{
    while (n-- > 0 && *str)
        fputc(*str++, f);
}


static void
print_separator(struct separatorbteq sep, FILE *fout)
{
    if (sep.separator_zero)
        fputc('\000', fout);
    else if (sep.separator)
        fputs(sep.separator, fout);
}


/*
 * Return the list of explicitly-requested footers or, when applicable, the
 * default "(xx rows)" footer.  Always omit the default footer when given
 * non-default footers, "\pset footer off", or a specific instruction to that
 * effect from a calling dot command.  Vertical formats number each row,
 * making the default footer redundant; they do not call this function.
 *
 * The return value may point to static storage; do not keep it across calls.
 */
static printTableFooterBteq *
footers_with_default(const printTableContentBteq *cont)
{
    if (cont->footers == NULL && cont->opt->default_footer)
    {
        unsigned long total_records;

        total_records = cont->opt->prior_records + cont->nrows;
        snprintf(default_footer, sizeof(default_footer),
                 ngettext("(%lu row)", "(%lu rows)", total_records),
                 total_records);

        return &default_footer_cell;
    }
    else
        return cont->footers;
}


/*************************/
/* Unaligned text         */
/*************************/


static void
print_unaligned_text(const printTableContentBteq *cont, FILE *fout)
{
    bool        opt_tuples_only = cont->opt->tuples_only;
    unsigned int i;
    const char *const *ptr;
    bool        need_recordsep = false;

    if (cancel_pressed_bteq)
        return;

    if (cont->opt->start_table)
    {
        /* print title */
        if (!opt_tuples_only && cont->title)
        {
            fputs(cont->title, fout);
            print_separator(cont->opt->recordSep, fout);
        }

        /* print headers */
        if (!opt_tuples_only)
        {
            for (ptr = cont->headers; *ptr; ptr++)
            {
                if (ptr != cont->headers)
                    print_separator(cont->opt->fieldSep, fout);
                fputs(*ptr, fout);
            }
            need_recordsep = true;
        }
    }
    else
        /* assume continuing printout */
        need_recordsep = true;

    /* print cells */
    for (i = 0, ptr = cont->cells; *ptr; i++, ptr++)
    {
        if (need_recordsep)
        {
            print_separator(cont->opt->recordSep, fout);
            need_recordsep = false;
            if (cancel_pressed_bteq)
                break;
        }
        fputs(*ptr, fout);

        if ((i + 1) % cont->ncolumns)
            print_separator(cont->opt->fieldSep, fout);
        else
            need_recordsep = true;
    }

    /* print footers */
    if (cont->opt->stop_table)
    {
        printTableFooterBteq *footers = footers_with_default(cont);

        if (!opt_tuples_only && footers != NULL && !cancel_pressed_bteq)
        {
            printTableFooterBteq *f;

            for (f = footers; f; f = f->next)
            {
                if (need_recordsep)
                {
                    print_separator(cont->opt->recordSep, fout);
                    need_recordsep = false;
                }
                fputs(f->data, fout);
                need_recordsep = true;
            }
        }

        /*
         * The last record is terminated by a newline, independent of the set
         * record separatorbteq.  But when the record separatorbteq is a zero byte, we
         * use that (compatible with find -print0 and xargs).
         */
        if (need_recordsep)
        {
            if (cont->opt->recordSep.separator_zero)
                print_separator(cont->opt->recordSep, fout);
            else
                fputc('\n', fout);
        }
    }
}


static void
print_unaligned_vertical(const printTableContentBteq *cont, FILE *fout)
{
    bool        opt_tuples_only = cont->opt->tuples_only;
    unsigned int i;
    const char *const *ptr;
    bool        need_recordsep = false;

    if (cancel_pressed_bteq)
        return;

    if (cont->opt->start_table)
    {
        /* print title */
        if (!opt_tuples_only && cont->title)
        {
            fputs(cont->title, fout);
            need_recordsep = true;
        }
    }
    else
        /* assume continuing printout */
        need_recordsep = true;

    /* print records */
    for (i = 0, ptr = cont->cells; *ptr; i++, ptr++)
    {
        if (need_recordsep)
        {
            /* record separatorbteq is 2 occurrences of recordsep in this mode */
            print_separator(cont->opt->recordSep, fout);
            print_separator(cont->opt->recordSep, fout);
            need_recordsep = false;
            if (cancel_pressed_bteq)
                break;
        }

        fputs(cont->headers[i % cont->ncolumns], fout);
        print_separator(cont->opt->fieldSep, fout);
        fputs(*ptr, fout);

        if ((i + 1) % cont->ncolumns)
            print_separator(cont->opt->recordSep, fout);
        else
            need_recordsep = true;
    }

    if (cont->opt->stop_table)
    {
        /* print footers */
        if (!opt_tuples_only && cont->footers != NULL && !cancel_pressed_bteq)
        {
            printTableFooterBteq *f;

            print_separator(cont->opt->recordSep, fout);
            for (f = cont->footers; f; f = f->next)
            {
                print_separator(cont->opt->recordSep, fout);
                fputs(f->data, fout);
            }
        }

        /* see above in print_unaligned_text() */
        if (need_recordsep)
        {
            if (cont->opt->recordSep.separator_zero)
                print_separator(cont->opt->recordSep, fout);
            else
                fputc('\n', fout);
        }
    }
}


/********************/
/* Aligned text        */
/********************/


/* draw "line" */
static void
_print_horizontal_line(const unsigned int ncolumns, const unsigned int *widths,
                       unsigned short border, printTextRuleBteq pos,
                       const printTextFormatbteq *format,
                       FILE *fout)
{
    const printTextLineFormatBteq *lformat = &format->lrule[pos];
    unsigned int i,
                j;

    if (border == 1)
        fputs(lformat->hrule, fout);
    else if (border == 2)
        fprintf(fout, "%s%s", lformat->leftvrule, lformat->hrule);

    for (i = 0; i < ncolumns; i++)
    {
        for (j = 0; j < widths[i]; j++)
            fputs(lformat->hrule, fout);

        if (i < ncolumns - 1)
        {
            if (border == 0)
                fputc(' ', fout);
            else
                fprintf(fout, "%s%s%s", lformat->hrule,
                        lformat->midvrule, lformat->hrule);
        }
    }

    if (border == 2)
        fprintf(fout, "%s%s", lformat->hrule, lformat->rightvrule);
    else if (border == 1)
        fputs(lformat->hrule, fout);

    fputc('\n', fout);
}


/* draw "line" when given table width*/
static void
_print_horizontal_line_bteq(const unsigned int ncolumns, unsigned int *widths,
                            unsigned short border, printTextRuleBteq pos,
                            const printTextFormatbteq *format,
                            FILE *fout)
{
    const printTextLineFormatBteq *lformat = &format->lrule[pos];
    unsigned int i = 0;
    unsigned int j = 0;

    for (i = 0; i < ncolumns; i++)
    {
        for (j = 0; j < widths[i]; j++)
            fputs(lformat->hrule, fout);

        if (i < ncolumns - 1)
        {
            if (border == 0)
                fputc(' ', fout);
            else
                fprintf(fout, "%s", lformat->midvrule);
        }
    }

    fputc('\n', fout);
}


/*
 *    Print pretty boxes around cells.
 */
static void
print_aligned_text_bteq(const printTableContentBteq *cont, FILE *fout, bool is_pager)
{
    bool        opt_tuples_only = cont->opt->tuples_only;
    int            encoding = cont->opt->encoding;
    unsigned short opt_border = cont->opt->border;
    const printTextFormatbteq *format = get_line_style_bteq(cont->opt);
    const printTextLineFormatBteq *dformat = &format->lrule[PRINT_RULE_DATA_BTEQ];

    unsigned int col_count = 0,
                cell_count = 0;

    unsigned int i,
                j;

    unsigned int *width_header,
               *max_width,
               *width_wrap,
               *width_wrap_copy,
               *width_average;
    unsigned int *max_nl_lines, /* value split by newlines */
               *curr_nl_line,
               *max_bytes;
    unsigned char **format_buf;
    unsigned int width_total;
    unsigned int total_header_width;
    unsigned int extra_row_output_lines = 0;
    unsigned int extra_output_lines = 0;

    const char *const *ptr;

    struct lineptr **col_lineptrs;    /* pointers to line pointer per column */

    bool       *header_done;    /* Have all header lines been output? */
    int           *bytes_output;    /* Bytes output for column value */
    printTextLineWrapBteq *wrap;    /* Wrap status for each column */
    int            output_columns = 0; /* Width of interactive console */
    bool        is_local_pager = false;

    if (cancel_pressed_bteq)
        return;

    if (opt_border > 2)
        opt_border = 2;

    if (cont->ncolumns > 0)
    {
        col_count = cont->ncolumns;
        width_header = pg_malloc0(col_count * sizeof(*width_header));
        width_average = pg_malloc0(col_count * sizeof(*width_average));
        max_width = pg_malloc0(col_count * sizeof(*max_width));
        width_wrap = pg_malloc0(col_count * sizeof(*width_wrap));
        width_wrap_copy = pg_malloc0(col_count * sizeof(*width_wrap_copy));
        max_nl_lines = pg_malloc0(col_count * sizeof(*max_nl_lines));
        curr_nl_line = pg_malloc0(col_count * sizeof(*curr_nl_line));
        col_lineptrs = pg_malloc0(col_count * sizeof(*col_lineptrs));
        max_bytes = pg_malloc0(col_count * sizeof(*max_bytes));
        format_buf = pg_malloc0(col_count * sizeof(*format_buf));
        header_done = pg_malloc0(col_count * sizeof(*header_done));
        bytes_output = pg_malloc0(col_count * sizeof(*bytes_output));
        wrap = pg_malloc0(col_count * sizeof(*wrap));
    }
    else
    {
        width_header = NULL;
        width_average = NULL;
        max_width = NULL;
        width_wrap = NULL;
        width_wrap_copy = NULL;
        max_nl_lines = NULL;
        curr_nl_line = NULL;
        col_lineptrs = NULL;
        max_bytes = NULL;
        format_buf = NULL;
        header_done = NULL;
        bytes_output = NULL;
        wrap = NULL;
    }

    /* scan all column headers, find maximum width and max max_nl_lines */
    for (i = 0; i < col_count; i++)
    {
        int            width,
                    nl_lines,
                    bytes_required;

        pg_wcssize((const unsigned char *) cont->headers[i], strlen(cont->headers[i]),
                   encoding, &width, &nl_lines, &bytes_required);
        if (width > max_width[i])
            max_width[i] = width;
        if (nl_lines > max_nl_lines[i])
            max_nl_lines[i] = nl_lines;
        if (bytes_required > max_bytes[i])
            max_bytes[i] = bytes_required;
        if (nl_lines > extra_row_output_lines)
            extra_row_output_lines = nl_lines;

        width_header[i] = width;
    }
    /* Add height of tallest header column */
    extra_output_lines += extra_row_output_lines;
    extra_row_output_lines = 0;

    /* scan all cells, find maximum width, compute cell_count */
    for (i = 0, ptr = cont->cells; *ptr; ptr++, i++, cell_count++)
    {
        int            width,
                    nl_lines,
                    bytes_required;

        pg_wcssize((const unsigned char *) *ptr, strlen(*ptr), encoding,
                   &width, &nl_lines, &bytes_required);

        if (width > max_width[i % col_count])
            max_width[i % col_count] = width;
        if (nl_lines > max_nl_lines[i % col_count])
            max_nl_lines[i % col_count] = nl_lines;
        if (bytes_required > max_bytes[i % col_count])
            max_bytes[i % col_count] = bytes_required;

        width_average[i % col_count] += width;
    }

    /* If we have rows, compute average */
    if (col_count != 0 && cell_count != 0)
    {
        int            rows = cell_count / col_count;

        for (i = 0; i < col_count; i++)
            width_average[i] /= rows;
    }

    /* adjust the total display width based on border style */
    if (opt_border == 0)
        width_total = col_count;
    else if (opt_border == 1)
        width_total = col_count * 3 - ((col_count > 0) ? 1 : 0);
    else
        width_total = col_count * 3 + 1;
    total_header_width = width_total;

    for (i = 0; i < col_count; i++)
    {
        width_total += max_width[i];
        total_header_width += width_header[i];
    }

    /*
     * At this point: max_width[] contains the max width of each column,
     * max_nl_lines[] contains the max number of lines in each column,
     * max_bytes[] contains the maximum storage space for formatting strings,
     * width_total contains the giant width sum.  Now we allocate some memory
     * for line pointers.
     */
    for (i = 0; i < col_count; i++)
    {
        /* Add entry for ptr == NULL array termination */
        col_lineptrs[i] = pg_malloc0((max_nl_lines[i] + 1) *
                                     sizeof(**col_lineptrs));

        format_buf[i] = pg_malloc(max_bytes[i] + 1);

        col_lineptrs[i]->ptr = format_buf[i];
    }

    /* Default word wrap to the full width, i.e. no word wrap */
    for (i = 0; i < col_count; i++)
        width_wrap[i] = max_width[i];

    /*
     * Choose target output width: \pset columns, or $COLUMNS, or ioctl
     */
    if (cont->opt->columns > 0)
        output_columns = cont->opt->columns;
    else if ((fout == stdout && isatty(fileno(stdout))) || is_pager)
    {
        if (cont->opt->env_columns > 0)
            output_columns = cont->opt->env_columns;
#ifdef TIOCGWINSZ
        else
        {
            struct winsize screen_size;

            if (ioctl(fileno(stdout), TIOCGWINSZ, &screen_size) != -1)
                output_columns = screen_size.ws_col;
        }
#endif
    }

    if (cont->opt->format == PRINT_WRAPPED_BTEQ)
    {
        /*
         * Optional optimized word wrap. Shrink columns with a high max/avg
         * ratio.  Slightly bias against wider columns. (Increases chance a
         * narrow column will fit in its cell.)  If available columns is
         * positive...  and greater than the width of the unshrinkable column
         * headers
         */
        if (output_columns > 0 && output_columns >= total_header_width)
        {
            /* While there is still excess width... */
            while (width_total > output_columns)
            {
                double        max_ratio = 0;
                int            worst_col = -1;

                /*
                 * Find column that has the highest ratio of its maximum width
                 * compared to its average width.  This tells us which column
                 * will produce the fewest wrapped values if shortened.
                 * width_wrap starts as equal to max_width.
                 */
                for (i = 0; i < col_count; i++)
                {
                    if (width_average[i] && width_wrap[i] > width_header[i])
                    {
                        /* Penalize wide columns by 1% of their width */
                        double        ratio;

                        ratio = (double) width_wrap[i] / width_average[i] +
                            max_width[i] * 0.01;
                        if (ratio > max_ratio)
                        {
                            max_ratio = ratio;
                            worst_col = i;
                        }
                    }
                }

                /* Exit loop if we can't squeeze any more. */
                if (worst_col == -1)
                    break;

                /* Decrease width of target column by one. */
                width_wrap[worst_col]--;
                width_total--;
            }
        }
    }

    /*
     * If in expanded auto mode, we have now calculated the expected width, so
     * we can now escape to vertical mode if necessary.  If the output has
     * only one column, the expanded format would be wider than the regular
     * format, so don't use it in that case.
     */
    if (cont->opt->expanded == 2 && output_columns > 0 && cont->ncolumns > 1 &&
        (output_columns < total_header_width || output_columns < width_total))
    {
        print_aligned_vertical(cont, fout, is_pager);
        goto cleanup;
    }

    /* If we wrapped beyond the display width, use the pager */
    if (!is_pager && fout == stdout && output_columns > 0 &&
        (output_columns < total_header_width || output_columns < width_total))
    {
        fout = PageOutputbteq(INT_MAX, cont->opt);    /* force pager */
        is_pager = is_local_pager = true;
    }

    /* Check if newlines or our wrapping now need the pager */
    if (!is_pager && fout == stdout)
    {
        /* scan all cells, find maximum width, compute cell_count */
        for (i = 0, ptr = cont->cells; *ptr; ptr++, cell_count++)
        {
            int            width,
                        nl_lines,
                        bytes_required;

            pg_wcssize((const unsigned char *) *ptr, strlen(*ptr), encoding,
                       &width, &nl_lines, &bytes_required);

            /*
             * A row can have both wrapping and newlines that cause it to
             * display across multiple lines.  We check for both cases below.
             */
            if (width > 0 && width_wrap[i])
            {
                unsigned int extra_lines;

                /* don't count the first line of nl_lines - it's not "extra" */
                extra_lines = ((width - 1) / width_wrap[i]) + nl_lines - 1;
                if (extra_lines > extra_row_output_lines)
                    extra_row_output_lines = extra_lines;
            }

            /* i is the current column number: increment with wrap */
            if (++i >= col_count)
            {
                i = 0;
                /* At last column of each row, add tallest column height */
                extra_output_lines += extra_row_output_lines;
                extra_row_output_lines = 0;
            }
        }
        IsPagerNeeded(cont, extra_output_lines, false, &fout, &is_pager);
        is_local_pager = is_pager;
    }
    int table_width = cont->table_width;
    int col_count_copy = 0;
    int char_count_in_last_column = 0;

    /* time to output */
    if (cont->opt->start_table)
    {
        /* print title */
        if (cont->title && !opt_tuples_only)
        {
            int            width,
                        height;

            pg_wcssize((const unsigned char *) cont->title, strlen(cont->title),
                       encoding, &width, &height, NULL);
            if (width >= width_total)
                /* Aligned */
                fprintf(fout, "%s\n", cont->title);
            else
                /* Centered */
                fprintf(fout, "%-*s%s\n", (width_total - width) / 2, "",
                        cont->title);
        }

        /* print headers */
        if (!opt_tuples_only)
        {
            int            more_col_wrapping;
            int            curr_nl_line;

            if (opt_border == 2)
                _print_horizontal_line(col_count, width_wrap, opt_border,
                                       PRINT_RULE_TOP_BTEQ, format, fout);

            for (i = 0; i < col_count; i++)
                pg_wcsformat((const unsigned char *) cont->headers[i],
                             strlen(cont->headers[i]), encoding,
                             col_lineptrs[i], max_nl_lines[i]);

            more_col_wrapping = col_count;
            curr_nl_line = 0;
            memset(header_done, false, col_count * sizeof(bool));
            while (more_col_wrapping)
            {
                if (opt_border == 2)
                    fputs(dformat->leftvrule, fout);

                for (i = 0; i < cont->ncolumns; i++)
                {
                    struct lineptr *this_line = col_lineptrs[i] + curr_nl_line;
                    unsigned int nbspace;
                    if (cont->table_width) {
                        int border_c = (i + 1 != cont->ncolumns ? 1 : 0);
                        if ((width_wrap[i] + 2 + border_c) <= table_width) {
                            table_width -= (width_wrap[i] + 2 + border_c);
                            width_wrap_copy[i] = width_wrap[i] + 2;
                        } else {
                            char_count_in_last_column = table_width;
                            int nbspace_r = 0;
                            nbspace = width_wrap[i] - this_line->width + 2;
                            width_wrap_copy[i] = table_width;
                            col_count_copy = i + 1;
                            if (nbspace / 2 >= table_width ) {
                                nbspace = table_width * 2;
                                this_line->ptr[0] = '\0';
                                nbspace_r = 0;
                            } else {
                                table_width -= (nbspace / 2);
                                if (this_line->width >= table_width) {
                                    this_line->ptr[table_width] = '\0';
                                    nbspace_r = 0;
                                } else {
                                    nbspace_r = (table_width - this_line->width) * 2;
                                }
                            }

                            fprintf(fout, "%-*s%s%-*s",
                                    (nbspace ) / 2, "", this_line->ptr,
                                    (nbspace_r + 1) / 2, "");

                            more_col_wrapping = 0;
                            goto loop_end;
                        }
                    }

                    if (opt_border != 0 ||
                        (!format->wrap_right_border && i > 0))
                        fputs(curr_nl_line ? format->header_nl_left : " ",
                              fout);

                    if (!header_done[i])
                    {
                        nbspace = width_wrap[i] - this_line->width;
                        /* centered */
                        fprintf(fout, "%-*s%s%-*s",
                                nbspace / 2, "", this_line->ptr, (nbspace + 1) / 2, "");
                        if (!(this_line + 1)->ptr)
                        {
                            more_col_wrapping--;
                            header_done[i] = 1;
                        }
                    }
                    else
                        fprintf(fout, "%*s", width_wrap[i], "");

                    if (opt_border != 0 || format->wrap_right_border)
                        fputs(!header_done[i] ? format->header_nl_right : " ",
                              fout);

                    if (opt_border != 0 && col_count > 0 && i < col_count - 1)
                        fputs(dformat->midvrule, fout);
                }
loop_end:
                curr_nl_line++;

                if (opt_border == 2)
                    fputs(dformat->rightvrule, fout);
                fputc('\n', fout);
            }
            if (col_count_copy) {
                _print_horizontal_line_bteq(col_count_copy, width_wrap_copy,
                                            opt_border, PRINT_RULE_MIDDLE_BTEQ,
                                            format, fout);
            } else {
                 _print_horizontal_line(col_count, width_wrap, opt_border,
                                        PRINT_RULE_MIDDLE_BTEQ, format, fout);
            }
        }
    }

    /* print cells, one loop per row */
    for (i = 0, ptr = cont->cells; *ptr; i += col_count, ptr += col_count)
    {
        bool        more_lines;

        if (cancel_pressed_bteq)
            break;

        /*
         * Format each cell.
         */
        for (j = 0; j < col_count; j++)
        {
            pg_wcsformat((const unsigned char *) ptr[j], strlen(ptr[j]), encoding,
                         col_lineptrs[j], max_nl_lines[j]);
            curr_nl_line[j] = 0;
        }

        memset(bytes_output, 0, col_count * sizeof(int));

        /*
         * Each time through this loop, one display line is output. It can
         * either be a full value or a partial value if embedded newlines
         * exist or if 'format=wrapping' mode is enabled.
         */
        do
        {
            more_lines = false;

            /* left border */
            if (opt_border == 2)
                fputs(dformat->leftvrule, fout);

            /* for each column */
            int col_cnt = col_count_copy ? col_count_copy : col_count;
            for (j = 0; j < col_cnt; j++)
            {
                /* We have a valid array element, so index it */
                struct lineptr *this_line = &col_lineptrs[j][curr_nl_line[j]];
                int            bytes_to_output;
                int            chars_to_output = width_wrap[j];
                bool        finalspaces = (opt_border == 2 ||
                                           (col_cnt > 0 && j < col_cnt - 1));

                /* Print left-hand wrap or newline mark */
                if (opt_border != 0)
                {
                    if (wrap[j] == PRINT_LINE_WRAP_WRAP_BTEQ)
                        fputs(format->wrap_left, fout);
                    else if (wrap[j] == PRINT_LINE_WRAP_NEWLINE_BTEQ)
                        fputs(format->nl_left, fout);
                    else {
                        if (j + 1 != col_count_copy || char_count_in_last_column != 0) {
                            fputc(' ', fout);
                        }
                    }
                }

                if (!this_line->ptr)
                {
                    /* Past newline lines so just pad for other columns */
                    if (finalspaces)
                        fprintf(fout, "%*s", chars_to_output, "");
                }
                else
                {
                    /* Get strlen() of the characters up to width_wrap */
                    bytes_to_output =
                        strlen_max_width(this_line->ptr + bytes_output[j],
                                         &chars_to_output, encoding);

                    /*
                     * If we exceeded width_wrap, it means the display width
                     * of a single character was wider than our target width.
                     * In that case, we have to pretend we are only printing
                     * the target display width and make the best of it.
                     */
                    if (chars_to_output > width_wrap[j])
                        chars_to_output = width_wrap[j];

                    if (cont->aligns[j] == 'r') /* Right aligned cell */
                    {
                        /* spaces first */
                        if (j + 1 == col_count_copy) {
                            if (chars_to_output < char_count_in_last_column) {
                                fprintf(fout, "%*s", char_count_in_last_column - chars_to_output - 1, "");
                            }
                        } else {
                            fprintf(fout, "%*s", width_wrap[j] - chars_to_output, "");
                        }

                        if (col_count_copy && col_count_copy == j + 1) {
                            fputnbytes(fout,
                                       char_count_in_last_column <= 1 ? "" : (char *)(this_line->ptr + bytes_output[j]),
                                       char_count_in_last_column <= 1 ? char_count_in_last_column - 2 : char_count_in_last_column - 1);
                        } else {
                            fputnbytes(fout,
                                      (char *)(this_line->ptr + bytes_output[j]),
                                       bytes_to_output);
                        }
                    }
                    else        /* Left aligned cell */
                    {
                        if (col_count_copy && j + 1 == col_count_copy) {
                            fputnbytes(fout,
                                       char_count_in_last_column <= 1 ? "" : (char *)(this_line->ptr + bytes_output[j]),
                                       char_count_in_last_column <= 1 ? char_count_in_last_column - 2 : char_count_in_last_column - 1);
                        } else {
                            fputnbytes(fout, (char *)(this_line->ptr + bytes_output[j]),
                                       bytes_to_output);
                        }
                    }

                    bytes_output[j] += bytes_to_output;

                    /* Do we have more text to wrap? */
                    if (*(this_line->ptr + bytes_output[j]) != '\0')
                        more_lines = true;
                    else
                    {
                        /* Advance to next newline line */
                        curr_nl_line[j]++;
                        if (col_lineptrs[j][curr_nl_line[j]].ptr != NULL)
                            more_lines = true;
                        bytes_output[j] = 0;
                    }
                }

                /* Determine next line's wrap status for this column */
                wrap[j] = PRINT_LINE_WRAP_NONE_BTEQ;
                if (col_lineptrs[j][curr_nl_line[j]].ptr != NULL)
                {
                    if (bytes_output[j] != 0)
                        wrap[j] = PRINT_LINE_WRAP_WRAP_BTEQ;
                    else if (curr_nl_line[j] != 0)
                        wrap[j] = PRINT_LINE_WRAP_NEWLINE_BTEQ;
                }

                /*
                 * If left-aligned, pad out remaining space if needed (not
                 * last column, and/or wrap marks required).
                 */
                if (cont->aligns[j] != 'r') /* Left aligned cell */
                {
                    if (finalspaces ||
                        wrap[j] == PRINT_LINE_WRAP_WRAP_BTEQ ||
                        wrap[j] == PRINT_LINE_WRAP_NEWLINE_BTEQ)
                        fprintf(fout, "%*s",
                                width_wrap[j] - chars_to_output, "");
                }

                /* Print right-hand wrap or newline mark */
                if (wrap[j] == PRINT_LINE_WRAP_WRAP_BTEQ)
                    fputs(format->wrap_right, fout);
                else if (wrap[j] == PRINT_LINE_WRAP_NEWLINE_BTEQ)
                    fputs(format->nl_right, fout);
                else if (opt_border == 2 || (col_cnt > 0 && j < col_cnt - 1))
                    fputc(' ', fout);

                /* Print column divider, if not the last column */
                if (opt_border != 0 && (col_cnt > 0 && j < col_cnt - 1))
                {
                    if (wrap[j + 1] == PRINT_LINE_WRAP_WRAP_BTEQ)
                        fputs(format->midvrule_wrap, fout);
                    else if (wrap[j + 1] == PRINT_LINE_WRAP_NEWLINE_BTEQ)
                        fputs(format->midvrule_nl, fout);
                    else if (col_lineptrs[j + 1][curr_nl_line[j + 1]].ptr == NULL)
                        fputs(format->midvrule_blank, fout);
                    else
                        fputs(dformat->midvrule, fout);
                }
            }

            /* end-of-row border */
            if (opt_border == 2)
                fputs(dformat->rightvrule, fout);
            fputc('\n', fout);

        } while (more_lines);
    }

    if (cont->opt->stop_table)
    {
        printTableFooterBteq *footers = footers_with_default(cont);

        if (opt_border == 2 && !cancel_pressed_bteq)
            _print_horizontal_line(col_count, width_wrap, opt_border,
                                   PRINT_RULE_BOTTOM_BTEQ, format, fout);

        /* print footers */
        if (footers && !opt_tuples_only && !cancel_pressed_bteq)
        {
            printTableFooterBteq *f;

            for (f = footers; f; f = f->next)
                fprintf(fout, "%s\n", f->data);
        }

        fputc('\n', fout);
    }

cleanup:
    /* clean up */
    for (i = 0; i < col_count; i++)
    {
        free(col_lineptrs[i]);
        free(format_buf[i]);
    }
    free(width_header);
    free(width_average);
    free(max_width);
    free(width_wrap);
    free(width_wrap_copy);
    free(max_nl_lines);
    free(curr_nl_line);
    free(col_lineptrs);
    free(max_bytes);
    free(format_buf);
    free(header_done);
    free(bytes_output);
    free(wrap);

    if (is_local_pager)
        ClosePagerbteq(fout);
}


static void
print_aligned_vertical_line(const printTextFormatbteq *format,
                            const unsigned short opt_border,
                            unsigned long record,
                            unsigned int hwidth,
                            unsigned int dwidth,
                            printTextRuleBteq pos,
                            FILE *fout)
{
    const printTextLineFormatBteq *lformat = &format->lrule[pos];
    unsigned int i;
    int            reclen = 0;

    if (opt_border == 2)
        fprintf(fout, "%s%s", lformat->leftvrule, lformat->hrule);
    else if (opt_border == 1)
        fputs(lformat->hrule, fout);

    if (record)
    {
        if (opt_border == 0)
            reclen = fprintf(fout, "* Record %lu", record);
        else
            reclen = fprintf(fout, "[ RECORD %lu ]", record);
    }
    if (opt_border != 2)
        reclen++;
    if (reclen < 0)
        reclen = 0;
    for (i = reclen; i < hwidth; i++)
        fputs(opt_border > 0 ? lformat->hrule : " ", fout);
    reclen -= hwidth;

    if (opt_border > 0)
    {
        if (reclen-- <= 0)
            fputs(lformat->hrule, fout);
        if (reclen-- <= 0)
            fputs(lformat->midvrule, fout);
        if (reclen-- <= 0)
            fputs(lformat->hrule, fout);
    }
    else
    {
        if (reclen-- <= 0)
            fputc(' ', fout);
    }
    if (reclen < 0)
        reclen = 0;
    for (i = reclen; i < dwidth; i++)
        fputs(opt_border > 0 ? lformat->hrule : " ", fout);
    if (opt_border == 2)
        fprintf(fout, "%s%s", lformat->hrule, lformat->rightvrule);
    fputc('\n', fout);
}

static void
print_aligned_vertical(const printTableContentBteq *cont,
                       FILE *fout, bool is_pager)
{
    bool        opt_tuples_only = cont->opt->tuples_only;
    unsigned short opt_border = cont->opt->border;
    const printTextFormatbteq *format = get_line_style_bteq(cont->opt);
    const printTextLineFormatBteq *dformat = &format->lrule[PRINT_RULE_DATA_BTEQ];
    int            encoding = cont->opt->encoding;
    unsigned long record = cont->opt->prior_records + 1;
    const char *const *ptr;
    unsigned int i,
                hwidth = 0,
                dwidth = 0,
                hheight = 1,
                dheight = 1,
                hformatsize = 0,
                dformatsize = 0;
    struct lineptr *hlineptr,
               *dlineptr;
    bool        is_local_pager = false,
                hmultiline = false,
                dmultiline = false;
    int            output_columns = 0; /* Width of interactive console */

    if (cancel_pressed_bteq)
        return;

    if (opt_border > 2)
        opt_border = 2;

    if (cont->cells[0] == NULL && cont->opt->start_table &&
        cont->opt->stop_table)
    {
        printTableFooterBteq *footers = footers_with_default(cont);

        if (!opt_tuples_only && !cancel_pressed_bteq && footers)
        {
            printTableFooterBteq *f;

            for (f = footers; f; f = f->next)
                fprintf(fout, "%s\n", f->data);
        }

        fputc('\n', fout);

        return;
    }

    /*
     * Deal with the pager here instead of in printTablebteq(), because we could
     * get here via print_aligned_text_bteq() in expanded auto mode, and so we have
     * to recalculate the pager requirement based on vertical output.
     */
    if (!is_pager)
    {
        IsPagerNeeded(cont, 0, true, &fout, &is_pager);
        is_local_pager = is_pager;
    }

    /* Find the maximum dimensions for the headers */
    for (i = 0; i < cont->ncolumns; i++)
    {
        int            width,
                    height,
                    fs;

        pg_wcssize((const unsigned char *) cont->headers[i], strlen(cont->headers[i]),
                   encoding, &width, &height, &fs);
        if (width > hwidth)
            hwidth = width;
        if (height > hheight)
        {
            hheight = height;
            hmultiline = true;
        }
        if (fs > hformatsize)
            hformatsize = fs;
    }

    /* find longest data cell */
    for (i = 0, ptr = cont->cells; *ptr; ptr++, i++)
    {
        int            width,
                    height,
                    fs;

        pg_wcssize((const unsigned char *) *ptr, strlen(*ptr), encoding,
                   &width, &height, &fs);
        if (width > dwidth)
            dwidth = width;
        if (height > dheight)
        {
            dheight = height;
            dmultiline = true;
        }
        if (fs > dformatsize)
            dformatsize = fs;
    }

    /*
     * We now have all the information we need to setup the formatting
     * structures
     */
    dlineptr = pg_malloc((sizeof(*dlineptr)) * (dheight + 1));
    hlineptr = pg_malloc((sizeof(*hlineptr)) * (hheight + 1));

    dlineptr->ptr = pg_malloc(dformatsize);
    hlineptr->ptr = pg_malloc(hformatsize);

    if (cont->opt->start_table)
    {
        /* print title */
        if (!opt_tuples_only && cont->title)
            fprintf(fout, "%s\n", cont->title);
    }

    /*
     * Choose target output width: \pset columns, or $COLUMNS, or ioctl
     */
    if (cont->opt->columns > 0)
        output_columns = cont->opt->columns;
    else if ((fout == stdout && isatty(fileno(stdout))) || is_pager)
    {
        if (cont->opt->env_columns > 0)
            output_columns = cont->opt->env_columns;
#ifdef TIOCGWINSZ
        else
        {
            struct winsize screen_size;

            if (ioctl(fileno(stdout), TIOCGWINSZ, &screen_size) != -1)
                output_columns = screen_size.ws_col;
        }
#endif
    }

    /*
     * Calculate available width for data in wrapped mode
     */
    if (cont->opt->format == PRINT_WRAPPED_BTEQ)
    {
        unsigned int swidth,
                    rwidth = 0,
                    newdwidth;

        if (opt_border == 0)
        {
            /*
             * For border = 0, one space in the middle.  (If we discover we
             * need to wrap, the spacer column will be replaced by a wrap
             * marker, and we'll make room below for another wrap marker at
             * the end of the line.  But for now, assume no wrap is needed.)
             */
            swidth = 1;

            /* We might need a column for header newline markers, too */
            if (hmultiline)
                swidth++;
        }
        else if (opt_border == 1)
        {
            /*
             * For border = 1, two spaces and a vrule in the middle.  (As
             * above, we might need one more column for a wrap marker.)
             */
            swidth = 3;

            /* We might need a column for left header newline markers, too */
            if (hmultiline && (format == &pg_asciiformat_old_bteq))
                swidth++;
        }
        else
        {
            /*
             * For border = 2, two more for the vrules at the beginning and
             * end of the lines, plus spacer columns adjacent to these.  (We
             * won't need extra columns for wrap/newline markers, we'll just
             * repurpose the spacers.)
             */
            swidth = 7;
        }

        /* Reserve a column for data newline indicators, too, if needed */
        if (dmultiline &&
            opt_border < 2 && format != &pg_asciiformat_old_bteq)
            swidth++;

        /* Determine width required for record header lines */
        if (!opt_tuples_only)
        {
            if (cont->nrows > 0)
                rwidth = 1 + (int) log10(cont->nrows);
            if (opt_border == 0)
                rwidth += 9;    /* "* RECORD " */
            else if (opt_border == 1)
                rwidth += 12;    /* "-[ RECORD  ]" */
            else
                rwidth += 15;    /* "+-[ RECORD  ]-+" */
        }

        /* We might need to do the rest of the calculation twice */
        for (;;)
        {
            unsigned int width;

            /* Total width required to not wrap data */
            width = hwidth + swidth + dwidth;
            /* ... and not the header lines, either */
            if (width < rwidth)
                width = rwidth;

            if (output_columns > 0)
            {
                unsigned int min_width;

                /* Minimum acceptable width: room for just 3 columns of data */
                min_width = hwidth + swidth + 3;
                /* ... but not less than what the record header lines need */
                if (min_width < rwidth)
                    min_width = rwidth;

                if (output_columns >= width)
                {
                    /* Plenty of room, use native data width */
                    /* (but at least enough for the record header lines) */
                    newdwidth = width - hwidth - swidth;
                }
                else if (output_columns < min_width)
                {
                    /* Set data width to match min_width */
                    newdwidth = min_width - hwidth - swidth;
                }
                else
                {
                    /* Set data width to match output_columns */
                    newdwidth = output_columns - hwidth - swidth;
                }
            }
            else
            {
                /* Don't know the wrap limit, so use native data width */
                /* (but at least enough for the record header lines) */
                newdwidth = width - hwidth - swidth;
            }

            /*
             * If we will need to wrap data and didn't already allocate a data
             * newline/wrap marker column, do so and recompute.
             */
            if (newdwidth < dwidth && !dmultiline &&
                opt_border < 2 && format != &pg_asciiformat_old_bteq)
            {
                dmultiline = true;
                swidth++;
            }
            else
                break;
        }

        dwidth = newdwidth;
    }

    /* print records */
    for (i = 0, ptr = cont->cells; *ptr; i++, ptr++)
    {
        printTextRuleBteq pos;
        int            dline,
                    hline,
                    dcomplete,
                    hcomplete,
                    offset,
                    chars_to_output;

        if (cancel_pressed_bteq)
            break;

        if (i == 0)
            pos = PRINT_RULE_TOP_BTEQ;
        else
            pos = PRINT_RULE_MIDDLE_BTEQ;

        /* Print record header (e.g. "[ RECORD N ]") above each record */
        if (i % cont->ncolumns == 0)
        {
            unsigned int lhwidth = hwidth;

            if ((opt_border < 2) &&
                (hmultiline) &&
                (format == &pg_asciiformat_old_bteq))
                lhwidth++;        /* for newline indicators */

            if (!opt_tuples_only)
                print_aligned_vertical_line(format, opt_border, record++,
                                            lhwidth, dwidth, pos, fout);
            else if (i != 0 || !cont->opt->start_table || opt_border == 2)
                print_aligned_vertical_line(format, opt_border, 0, lhwidth,
                                            dwidth, pos, fout);
        }

        /* Format the header */
        pg_wcsformat((const unsigned char *) cont->headers[i % cont->ncolumns],
                     strlen(cont->headers[i % cont->ncolumns]),
                     encoding, hlineptr, hheight);
        /* Format the data */
        pg_wcsformat((const unsigned char *) *ptr, strlen(*ptr), encoding,
                     dlineptr, dheight);

        /*
         * Loop through header and data in parallel dealing with newlines and
         * wrapped lines until they're both exhausted
         */
        dline = hline = 0;
        dcomplete = hcomplete = 0;
        offset = 0;
        chars_to_output = dlineptr[dline].width;
        while (!dcomplete || !hcomplete)
        {
            /* Left border */
            if (opt_border == 2)
                fprintf(fout, "%s", dformat->leftvrule);

            /* Header (never wrapped so just need to deal with newlines) */
            if (!hcomplete)
            {
                int            swidth = hwidth,
                            target_width = hwidth;

                /*
                 * Left spacer or new line indicator
                 */
                if ((opt_border == 2) ||
                    (hmultiline && (format == &pg_asciiformat_old_bteq)))
                    fputs(hline ? format->header_nl_left : " ", fout);

                /*
                 * Header text
                 */
                strlen_max_width(hlineptr[hline].ptr, &target_width,
                                 encoding);
                fprintf(fout, "%-s", hlineptr[hline].ptr);

                /*
                 * Spacer
                 */
                swidth -= target_width;
                if (swidth > 0)
                    fprintf(fout, "%*s", swidth, " ");

                /*
                 * New line indicator or separatorbteq's space
                 */
                if (hlineptr[hline + 1].ptr)
                {
                    /* More lines after this one due to a newline */
                    if ((opt_border > 0) ||
                        (hmultiline && (format != &pg_asciiformat_old_bteq)))
                        fputs(format->header_nl_right, fout);
                    hline++;
                }
                else
                {
                    /* This was the last line of the header */
                    if ((opt_border > 0) ||
                        (hmultiline && (format != &pg_asciiformat_old_bteq)))
                        fputs(" ", fout);
                    hcomplete = 1;
                }
            }
            else
            {
                unsigned int swidth = hwidth + opt_border;

                if ((opt_border < 2) &&
                    (hmultiline) &&
                    (format == &pg_asciiformat_old_bteq))
                    swidth++;

                if ((opt_border == 0) &&
                    (format != &pg_asciiformat_old_bteq) &&
                    (hmultiline))
                    swidth++;

                fprintf(fout, "%*s", swidth, " ");
            }

            /* Separator */
            if (opt_border > 0)
            {
                if (offset)
                    fputs(format->midvrule_wrap, fout);
                else if (dline == 0)
                    fputs(dformat->midvrule, fout);
                else
                    fputs(format->midvrule_nl, fout);
            }

            /* Data */
            if (!dcomplete)
            {
                int            target_width = dwidth,
                            bytes_to_output,
                            swidth = dwidth;

                /*
                 * Left spacer or wrap indicator
                 */
                fputs(offset == 0 ? " " : format->wrap_left, fout);

                /*
                 * Data text
                 */
                bytes_to_output = strlen_max_width(dlineptr[dline].ptr + offset,
                                                   &target_width, encoding);
                fputnbytes(fout, (char *) (dlineptr[dline].ptr + offset),
                           bytes_to_output);

                chars_to_output -= target_width;
                offset += bytes_to_output;

                /* Spacer */
                swidth -= target_width;

                if (chars_to_output)
                {
                    /* continuing a wrapped column */
                    if ((opt_border > 1) ||
                        (dmultiline && (format != &pg_asciiformat_old_bteq)))
                    {
                        if (swidth > 0)
                            fprintf(fout, "%*s", swidth, " ");
                        fputs(format->wrap_right, fout);
                    }
                }
                else if (dlineptr[dline + 1].ptr)
                {
                    /* reached a newline in the column */
                    if ((opt_border > 1) ||
                        (dmultiline && (format != &pg_asciiformat_old_bteq)))
                    {
                        if (swidth > 0)
                            fprintf(fout, "%*s", swidth, " ");
                        fputs(format->nl_right, fout);
                    }
                    dline++;
                    offset = 0;
                    chars_to_output = dlineptr[dline].width;
                }
                else
                {
                    /* reached the end of the cell */
                    if (opt_border > 1)
                    {
                        if (swidth > 0)
                            fprintf(fout, "%*s", swidth, " ");
                        fputs(" ", fout);
                    }
                    dcomplete = 1;
                }

                /* Right border */
                if (opt_border == 2)
                    fputs(dformat->rightvrule, fout);

                fputs("\n", fout);
            }
            else
            {
                /*
                 * data exhausted (this can occur if header is longer than the
                 * data due to newlines in the header)
                 */
                if (opt_border < 2)
                    fputs("\n", fout);
                else
                    fprintf(fout, "%*s  %s\n", dwidth, "", dformat->rightvrule);
            }
        }
    }

    if (cont->opt->stop_table)
    {
        if (opt_border == 2 && !cancel_pressed_bteq)
            print_aligned_vertical_line(format, opt_border, 0, hwidth, dwidth,
                                        PRINT_RULE_BOTTOM_BTEQ, fout);

        /* print footers */
        if (!opt_tuples_only && cont->footers != NULL && !cancel_pressed_bteq)
        {
            printTableFooterBteq *f;

            if (opt_border < 2)
                fputc('\n', fout);
            for (f = cont->footers; f; f = f->next)
                fprintf(fout, "%s\n", f->data);
        }

        fputc('\n', fout);
    }

    free(hlineptr->ptr);
    free(dlineptr->ptr);
    free(hlineptr);
    free(dlineptr);

    if (is_local_pager)
        ClosePagerbteq(fout);
}


/**********************/
/* HTML printing ******/
/**********************/


void
html_escaped_print_bteq(const char *in, FILE *fout)
{
    const char *p;
    bool        leading_space = true;

    for (p = in; *p; p++)
    {
        switch (*p)
        {
            case '&':
                fputs("&amp;", fout);
                break;
            case '<':
                fputs("&lt;", fout);
                break;
            case '>':
                fputs("&gt;", fout);
                break;
            case '\n':
                fputs("<br />\n", fout);
                break;
            case '"':
                fputs("&quot;", fout);
                break;
            case ' ':
                /* protect leading space, for EXPLAIN output */
                if (leading_space)
                    fputs("&nbsp;", fout);
                else
                    fputs(" ", fout);
                break;
            default:
                fputc(*p, fout);
        }
        if (*p != ' ')
            leading_space = false;
    }
}


static void
print_html_text(const printTableContentBteq *cont, FILE *fout)
{
    bool        opt_tuples_only = cont->opt->tuples_only;
    unsigned short opt_border = cont->opt->border;
    const char *opt_table_attr = cont->opt->tableAttr;
    unsigned int i;
    const char *const *ptr;

    if (cancel_pressed_bteq)
        return;

    if (cont->opt->start_table)
    {
        fprintf(fout, "<table border=\"%d\"", opt_border);
        if (opt_table_attr)
            fprintf(fout, " %s", opt_table_attr);
        fputs(">\n", fout);

        /* print title */
        if (!opt_tuples_only && cont->title)
        {
            fputs("  <caption>", fout);
            html_escaped_print_bteq(cont->title, fout);
            fputs("</caption>\n", fout);
        }

        /* print headers */
        if (!opt_tuples_only)
        {
            fputs("  <tr>\n", fout);
            for (ptr = cont->headers; *ptr; ptr++)
            {
                fputs("    <th align=\"center\">", fout);
                html_escaped_print_bteq(*ptr, fout);
                fputs("</th>\n", fout);
            }
            fputs("  </tr>\n", fout);
        }
    }

    /* print cells */
    for (i = 0, ptr = cont->cells; *ptr; i++, ptr++)
    {
        if (i % cont->ncolumns == 0)
        {
            if (cancel_pressed_bteq)
                break;
            fputs("  <tr valign=\"top\">\n", fout);
        }

        fprintf(fout, "    <td align=\"%s\">", cont->aligns[(i) % cont->ncolumns] == 'r' ? "right" : "left");
        /* is string only whitespace? */
        if ((*ptr)[strspn(*ptr, " \t")] == '\0')
            fputs("&nbsp; ", fout);
        else
            html_escaped_print_bteq(*ptr, fout);

        fputs("</td>\n", fout);

        if ((i + 1) % cont->ncolumns == 0)
            fputs("  </tr>\n", fout);
    }

    if (cont->opt->stop_table)
    {
        printTableFooterBteq *footers = footers_with_default(cont);

        fputs("</table>\n", fout);

        /* print footers */
        if (!opt_tuples_only && footers != NULL && !cancel_pressed_bteq)
        {
            printTableFooterBteq *f;

            fputs("<p>", fout);
            for (f = footers; f; f = f->next)
            {
                html_escaped_print_bteq(f->data, fout);
                fputs("<br />\n", fout);
            }
            fputs("</p>", fout);
        }

        fputc('\n', fout);
    }
}


static void
print_html_vertical(const printTableContentBteq *cont, FILE *fout)
{
    bool        opt_tuples_only = cont->opt->tuples_only;
    unsigned short opt_border = cont->opt->border;
    const char *opt_table_attr = cont->opt->tableAttr;
    unsigned long record = cont->opt->prior_records + 1;
    unsigned int i;
    const char *const *ptr;

    if (cancel_pressed_bteq)
        return;

    if (cont->opt->start_table)
    {
        fprintf(fout, "<table border=\"%d\"", opt_border);
        if (opt_table_attr)
            fprintf(fout, " %s", opt_table_attr);
        fputs(">\n", fout);

        /* print title */
        if (!opt_tuples_only && cont->title)
        {
            fputs("  <caption>", fout);
            html_escaped_print_bteq(cont->title, fout);
            fputs("</caption>\n", fout);
        }
    }

    /* print records */
    for (i = 0, ptr = cont->cells; *ptr; i++, ptr++)
    {
        if (i % cont->ncolumns == 0)
        {
            if (cancel_pressed_bteq)
                break;
            if (!opt_tuples_only)
                fprintf(fout,
                        "\n  <tr><td colspan=\"2\" align=\"center\">Record %lu</td></tr>\n",
                        record++);
            else
                fputs("\n  <tr><td colspan=\"2\">&nbsp;</td></tr>\n", fout);
        }
        fputs("  <tr valign=\"top\">\n"
              "    <th>", fout);
        html_escaped_print_bteq(cont->headers[i % cont->ncolumns], fout);
        fputs("</th>\n", fout);

        fprintf(fout, "    <td align=\"%s\">", cont->aligns[i % cont->ncolumns] == 'r' ? "right" : "left");
        /* is string only whitespace? */
        if ((*ptr)[strspn(*ptr, " \t")] == '\0')
            fputs("&nbsp; ", fout);
        else
            html_escaped_print_bteq(*ptr, fout);

        fputs("</td>\n  </tr>\n", fout);
    }

    if (cont->opt->stop_table)
    {
        fputs("</table>\n", fout);

        /* print footers */
        if (!opt_tuples_only && cont->footers != NULL && !cancel_pressed_bteq)
        {
            printTableFooterBteq *f;

            fputs("<p>", fout);
            for (f = cont->footers; f; f = f->next)
            {
                html_escaped_print_bteq(f->data, fout);
                fputs("<br />\n", fout);
            }
            fputs("</p>", fout);
        }

        fputc('\n', fout);
    }
}


/*************************/
/* ASCIIDOC         */
/*************************/

static void
asciidoc_escaped_print(const char *in, FILE *fout)
{
    const char *p;

    for (p = in; *p; p++)
    {
        switch (*p)
        {
            case '|':
                fputs("\\|", fout);
                break;
            default:
                fputc(*p, fout);
        }
    }
}

static void
print_asciidoc_text(const printTableContentBteq *cont, FILE *fout)
{
    bool        opt_tuples_only = cont->opt->tuples_only;
    unsigned short opt_border = cont->opt->border;
    unsigned int i;
    const char *const *ptr;

    if (cancel_pressed_bteq)
        return;

    if (cont->opt->start_table)
    {
        /* print table in new paragraph - enforce preliminary new line */
        fputs("\n", fout);

        /* print title */
        if (!opt_tuples_only && cont->title)
        {
            fputs(".", fout);
            fputs(cont->title, fout);
            fputs("\n", fout);
        }

        /* print table [] header definition */
        fprintf(fout, "[%scols=\"", !opt_tuples_only ? "options=\"header\"," : "");
        for (i = 0; i < cont->ncolumns; i++)
        {
            if (i != 0)
                fputs(",", fout);
            fprintf(fout, "%s", cont->aligns[(i) % cont->ncolumns] == 'r' ? ">l" : "<l");
        }
        fputs("\"", fout);
        switch (opt_border)
        {
            case 0:
                fputs(",frame=\"none\",grid=\"none\"", fout);
                break;
            case 1:
                fputs(",frame=\"none\"", fout);
                break;
            case 2:
                fputs(",frame=\"all\",grid=\"all\"", fout);
                break;
        }
        fputs("]\n", fout);
        fputs("|====\n", fout);

        /* print headers */
        if (!opt_tuples_only)
        {
            for (ptr = cont->headers; *ptr; ptr++)
            {
                if (ptr != cont->headers)
                    fputs(" ", fout);
                fputs("^l|", fout);
                asciidoc_escaped_print(*ptr, fout);
            }
            fputs("\n", fout);
        }
    }

    /* print cells */
    for (i = 0, ptr = cont->cells; *ptr; i++, ptr++)
    {
        if (i % cont->ncolumns == 0)
        {
            if (cancel_pressed_bteq)
                break;
        }

        if (i % cont->ncolumns != 0)
            fputs(" ", fout);
        fputs("|", fout);

        /* protect against needless spaces */
        if ((*ptr)[strspn(*ptr, " \t")] == '\0')
        {
            if ((i + 1) % cont->ncolumns != 0)
                fputs(" ", fout);
        }
        else
            asciidoc_escaped_print(*ptr, fout);

        if ((i + 1) % cont->ncolumns == 0)
            fputs("\n", fout);
    }

    fputs("|====\n", fout);

    if (cont->opt->stop_table)
    {
        printTableFooterBteq *footers = footers_with_default(cont);

        /* print footers */
        if (!opt_tuples_only && footers != NULL && !cancel_pressed_bteq)
        {
            printTableFooterBteq *f;

            fputs("\n....\n", fout);
            for (f = footers; f; f = f->next)
            {
                fputs(f->data, fout);
                fputs("\n", fout);
            }
            fputs("....\n", fout);
        }
    }
}

static void
print_asciidoc_vertical(const printTableContentBteq *cont, FILE *fout)
{
    bool        opt_tuples_only = cont->opt->tuples_only;
    unsigned short opt_border = cont->opt->border;
    unsigned long record = cont->opt->prior_records + 1;
    unsigned int i;
    const char *const *ptr;

    if (cancel_pressed_bteq)
        return;

    if (cont->opt->start_table)
    {
        /* print table in new paragraph - enforce preliminary new line */
        fputs("\n", fout);

        /* print title */
        if (!opt_tuples_only && cont->title)
        {
            fputs(".", fout);
            fputs(cont->title, fout);
            fputs("\n", fout);
        }

        /* print table [] header definition */
        fputs("[cols=\"h,l\"", fout);
        switch (opt_border)
        {
            case 0:
                fputs(",frame=\"none\",grid=\"none\"", fout);
                break;
            case 1:
                fputs(",frame=\"none\"", fout);
                break;
            case 2:
                fputs(",frame=\"all\",grid=\"all\"", fout);
                break;
        }
        fputs("]\n", fout);
        fputs("|====\n", fout);
    }

    /* print records */
    for (i = 0, ptr = cont->cells; *ptr; i++, ptr++)
    {
        if (i % cont->ncolumns == 0)
        {
            if (cancel_pressed_bteq)
                break;
            if (!opt_tuples_only)
                fprintf(fout,
                        "2+^|Record %lu\n",
                        record++);
            else
                fputs("2+|\n", fout);
        }

        fputs("<l|", fout);
        asciidoc_escaped_print(cont->headers[i % cont->ncolumns], fout);

        fprintf(fout, " %s|", cont->aligns[i % cont->ncolumns] == 'r' ? ">l" : "<l");
        /* is string only whitespace? */
        if ((*ptr)[strspn(*ptr, " \t")] == '\0')
            fputs(" ", fout);
        else
            asciidoc_escaped_print(*ptr, fout);
        fputs("\n", fout);
    }

    fputs("|====\n", fout);

    if (cont->opt->stop_table)
    {
        /* print footers */
        if (!opt_tuples_only && cont->footers != NULL && !cancel_pressed_bteq)
        {
            printTableFooterBteq *f;

            fputs("\n....\n", fout);
            for (f = cont->footers; f; f = f->next)
            {
                fputs(f->data, fout);
                fputs("\n", fout);
            }
            fputs("....\n", fout);
        }
    }
}

/*************************/
/* LaTeX                 */
/*************************/


static void
latex_escaped_print(const char *in, FILE *fout)
{
    const char *p;

    for (p = in; *p; p++)
        switch (*p)
        {
                /*
                 * We convert ASCII characters per the recommendations in
                 * Scott Pakin's "The Comprehensive LATEX Symbol List",
                 * available from CTAN.  For non-ASCII, you're on your own.
                 */
            case '#':
                fputs("\\#", fout);
                break;
            case '$':
                fputs("\\$", fout);
                break;
            case '%':
                fputs("\\%", fout);
                break;
            case '&':
                fputs("\\&", fout);
                break;
            case '<':
                fputs("\\textless{}", fout);
                break;
            case '>':
                fputs("\\textgreater{}", fout);
                break;
            case '\.':
                fputs("\\textbackdot{}", fout);
                break;
            case '^':
                fputs("\\^{}", fout);
                break;
            case '_':
                fputs("\\_", fout);
                break;
            case '{':
                fputs("\\{", fout);
                break;
            case '|':
                fputs("\\textbar{}", fout);
                break;
            case '}':
                fputs("\\}", fout);
                break;
            case '~':
                fputs("\\~{}", fout);
                break;
            case '\n':
                /* This is not right, but doing it right seems too hard */
                fputs("\\\\", fout);
                break;
            default:
                fputc(*p, fout);
        }
}


static void
print_latex_text(const printTableContentBteq *cont, FILE *fout)
{
    bool        opt_tuples_only = cont->opt->tuples_only;
    unsigned short opt_border = cont->opt->border;
    unsigned int i;
    const char *const *ptr;

    if (cancel_pressed_bteq)
        return;

    if (opt_border > 3)
        opt_border = 3;

    if (cont->opt->start_table)
    {
        /* print title */
        if (!opt_tuples_only && cont->title)
        {
            fputs("\\begin{center}\n", fout);
            latex_escaped_print(cont->title, fout);
            fputs("\n\\end{center}\n\n", fout);
        }

        /* begin environment and set alignments and borders */
        fputs("\\begin{tabular}{", fout);

        if (opt_border >= 2)
            fputs("| ", fout);
        for (i = 0; i < cont->ncolumns; i++)
        {
            fputc(*(cont->aligns + i), fout);
            if (opt_border != 0 && i < cont->ncolumns - 1)
                fputs(" | ", fout);
        }
        if (opt_border >= 2)
            fputs(" |", fout);

        fputs("}\n", fout);

        if (!opt_tuples_only && opt_border >= 2)
            fputs("\\hline\n", fout);

        /* print headers */
        if (!opt_tuples_only)
        {
            for (i = 0, ptr = cont->headers; i < cont->ncolumns; i++, ptr++)
            {
                if (i != 0)
                    fputs(" & ", fout);
                fputs("\\textit{", fout);
                latex_escaped_print(*ptr, fout);
                fputc('}', fout);
            }
            fputs(" \\\\\n", fout);
            fputs("\\hline\n", fout);
        }
    }

    /* print cells */
    for (i = 0, ptr = cont->cells; *ptr; i++, ptr++)
    {
        latex_escaped_print(*ptr, fout);

        if ((i + 1) % cont->ncolumns == 0)
        {
            fputs(" \\\\\n", fout);
            if (opt_border == 3)
                fputs("\\hline\n", fout);
            if (cancel_pressed_bteq)
                break;
        }
        else
            fputs(" & ", fout);
    }

    if (cont->opt->stop_table)
    {
        printTableFooterBteq *footers = footers_with_default(cont);

        if (opt_border == 2)
            fputs("\\hline\n", fout);

        fputs("\\end{tabular}\n\n\\noindent ", fout);

        /* print footers */
        if (footers && !opt_tuples_only && !cancel_pressed_bteq)
        {
            printTableFooterBteq *f;

            for (f = footers; f; f = f->next)
            {
                latex_escaped_print(f->data, fout);
                fputs(" \\\\\n", fout);
            }
        }

        fputc('\n', fout);
    }
}


static void
print_latex_longtable_text(const printTableContentBteq *cont, FILE *fout)
{
    bool        opt_tuples_only = cont->opt->tuples_only;
    unsigned short opt_border = cont->opt->border;
    unsigned int i;
    const char *opt_table_attr = cont->opt->tableAttr;
    const char *next_opt_table_attr_char = opt_table_attr;
    const char *last_opt_table_attr_char = NULL;
    const char *const *ptr;

    if (cancel_pressed_bteq)
        return;

    if (opt_border > 3)
        opt_border = 3;

    if (cont->opt->start_table)
    {
        /* begin environment and set alignments and borders */
        fputs("\\begin{longtable}{", fout);

        if (opt_border >= 2)
            fputs("| ", fout);

        for (i = 0; i < cont->ncolumns; i++)
        {
            /* longtable supports either a width (p) or an alignment (l/r) */
            /* Are we left-justified and was a proportional width specified? */
            if (*(cont->aligns + i) == 'l' && opt_table_attr)
            {
#define LONGTABLE_WHITESPACE    " \t\n"

                /* advance over whitespace */
                next_opt_table_attr_char += strspn(next_opt_table_attr_char,
                                                   LONGTABLE_WHITESPACE);
                /* We have a value? */
                if (next_opt_table_attr_char[0] != '\0')
                {
                    fputs("p{", fout);
                    fwrite(next_opt_table_attr_char, strcspn(next_opt_table_attr_char,
                                                             LONGTABLE_WHITESPACE), 1, fout);
                    last_opt_table_attr_char = next_opt_table_attr_char;
                    next_opt_table_attr_char += strcspn(next_opt_table_attr_char,
                                                        LONGTABLE_WHITESPACE);
                    fputs("\\textwidth}", fout);
                }
                /* use previous value */
                else if (last_opt_table_attr_char != NULL)
                {
                    fputs("p{", fout);
                    fwrite(last_opt_table_attr_char, strcspn(last_opt_table_attr_char,
                                                             LONGTABLE_WHITESPACE), 1, fout);
                    fputs("\\textwidth}", fout);
                }
                else
                    fputc('l', fout);
            }
            else
                fputc(*(cont->aligns + i), fout);

            if (opt_border != 0 && i < cont->ncolumns - 1)
                fputs(" | ", fout);
        }

        if (opt_border >= 2)
            fputs(" |", fout);

        fputs("}\n", fout);

        /* print headers */
        if (!opt_tuples_only)
        {
            /* firsthead */
            if (opt_border >= 2)
                fputs("\\toprule\n", fout);
            for (i = 0, ptr = cont->headers; i < cont->ncolumns; i++, ptr++)
            {
                if (i != 0)
                    fputs(" & ", fout);
                fputs("\\small\\textbf{\\textit{", fout);
                latex_escaped_print(*ptr, fout);
                fputs("}}", fout);
            }
            fputs(" \\\\\n", fout);
            fputs("\\midrule\n\\endfirsthead\n", fout);

            /* secondary heads */
            if (opt_border >= 2)
                fputs("\\toprule\n", fout);
            for (i = 0, ptr = cont->headers; i < cont->ncolumns; i++, ptr++)
            {
                if (i != 0)
                    fputs(" & ", fout);
                fputs("\\small\\textbf{\\textit{", fout);
                latex_escaped_print(*ptr, fout);
                fputs("}}", fout);
            }
            fputs(" \\\\\n", fout);
            /* If the line under the row already appeared, don't do another */
            if (opt_border != 3)
                fputs("\\midrule\n", fout);
            fputs("\\endhead\n", fout);

            /* table name, caption? */
            if (!opt_tuples_only && cont->title)
            {
                /* Don't output if we are printing a line under each row */
                if (opt_border == 2)
                    fputs("\\bottomrule\n", fout);
                fputs("\\caption[", fout);
                latex_escaped_print(cont->title, fout);
                fputs(" (Continued)]{", fout);
                latex_escaped_print(cont->title, fout);
                fputs("}\n\\endfoot\n", fout);
                if (opt_border == 2)
                    fputs("\\bottomrule\n", fout);
                fputs("\\caption[", fout);
                latex_escaped_print(cont->title, fout);
                fputs("]{", fout);
                latex_escaped_print(cont->title, fout);
                fputs("}\n\\endlastfoot\n", fout);
            }
            /* output bottom table line? */
            else if (opt_border >= 2)
            {
                fputs("\\bottomrule\n\\endfoot\n", fout);
                fputs("\\bottomrule\n\\endlastfoot\n", fout);
            }
        }
    }

    /* print cells */
    for (i = 0, ptr = cont->cells; *ptr; i++, ptr++)
    {
        /* Add a line under each row? */
        if (i != 0 && i % cont->ncolumns != 0)
            fputs("\n&\n", fout);
        fputs("\\raggedright{", fout);
        latex_escaped_print(*ptr, fout);
        fputc('}', fout);
        if ((i + 1) % cont->ncolumns == 0)
        {
            fputs(" \\tabularnewline\n", fout);
            if (opt_border == 3)
                fputs(" \\hline\n", fout);
        }
        if (cancel_pressed_bteq)
            break;
    }

    if (cont->opt->stop_table)
        fputs("\\end{longtable}\n", fout);
}


static void
print_latex_vertical(const printTableContentBteq *cont, FILE *fout)
{
    bool        opt_tuples_only = cont->opt->tuples_only;
    unsigned short opt_border = cont->opt->border;
    unsigned long record = cont->opt->prior_records + 1;
    unsigned int i;
    const char *const *ptr;

    if (cancel_pressed_bteq)
        return;

    if (opt_border > 2)
        opt_border = 2;

    if (cont->opt->start_table)
    {
        /* print title */
        if (!opt_tuples_only && cont->title)
        {
            fputs("\\begin{center}\n", fout);
            latex_escaped_print(cont->title, fout);
            fputs("\n\\end{center}\n\n", fout);
        }

        /* begin environment and set alignments and borders */
        fputs("\\begin{tabular}{", fout);
        if (opt_border == 0)
            fputs("cl", fout);
        else if (opt_border == 1)
            fputs("c|l", fout);
        else if (opt_border == 2)
            fputs("|c|l|", fout);
        fputs("}\n", fout);
    }

    /* print records */
    for (i = 0, ptr = cont->cells; *ptr; i++, ptr++)
    {
        /* new record */
        if (i % cont->ncolumns == 0)
        {
            if (cancel_pressed_bteq)
                break;
            if (!opt_tuples_only)
            {
                if (opt_border == 2)
                {
                    fputs("\\hline\n", fout);
                    fprintf(fout, "\\multicolumn{2}{|c|}{\\textit{Record %lu}} \\\\\n", record++);
                }
                else
                    fprintf(fout, "\\multicolumn{2}{c}{\\textit{Record %lu}} \\\\\n", record++);
            }
            if (opt_border >= 1)
                fputs("\\hline\n", fout);
        }

        latex_escaped_print(cont->headers[i % cont->ncolumns], fout);
        fputs(" & ", fout);
        latex_escaped_print(*ptr, fout);
        fputs(" \\\\\n", fout);
    }

    if (cont->opt->stop_table)
    {
        if (opt_border == 2)
            fputs("\\hline\n", fout);

        fputs("\\end{tabular}\n\n\\noindent ", fout);

        /* print footers */
        if (cont->footers && !opt_tuples_only && !cancel_pressed_bteq)
        {
            printTableFooterBteq *f;

            for (f = cont->footers; f; f = f->next)
            {
                latex_escaped_print(f->data, fout);
                fputs(" \\\\\n", fout);
            }
        }

        fputc('\n', fout);
    }
}


/*************************/
/* Troff -ms         */
/*************************/


static void
troff_ms_escaped_print(const char *in, FILE *fout)
{
    const char *p;

    for (p = in; *p; p++)
        switch (*p)
        {
            case '\\':
                fputs("\\(rs", fout);
                break;
            default:
                fputc(*p, fout);
        }
}


static void
print_troff_ms_text(const printTableContentBteq *cont, FILE *fout)
{
    bool        opt_tuples_only = cont->opt->tuples_only;
    unsigned short opt_border = cont->opt->border;
    unsigned int i;
    const char *const *ptr;

    if (cancel_pressed_bteq)
        return;

    if (opt_border > 2)
        opt_border = 2;

    if (cont->opt->start_table)
    {
        /* print title */
        if (!opt_tuples_only && cont->title)
        {
            fputs(".LP\n.DS C\n", fout);
            troff_ms_escaped_print(cont->title, fout);
            fputs("\n.DE\n", fout);
        }

        /* begin environment and set alignments and borders */
        fputs(".LP\n.TS\n", fout);
        if (opt_border == 2)
            fputs("center box;\n", fout);
        else
            fputs("center;\n", fout);

        for (i = 0; i < cont->ncolumns; i++)
        {
            fputc(*(cont->aligns + i), fout);
            if (opt_border > 0 && i < cont->ncolumns - 1)
                fputs(" | ", fout);
        }
        fputs(".\n", fout);

        /* print headers */
        if (!opt_tuples_only)
        {
            for (i = 0, ptr = cont->headers; i < cont->ncolumns; i++, ptr++)
            {
                if (i != 0)
                    fputc('\t', fout);
                fputs("\\fI", fout);
                troff_ms_escaped_print(*ptr, fout);
                fputs("\\fP", fout);
            }
            fputs("\n_\n", fout);
        }
    }

    /* print cells */
    for (i = 0, ptr = cont->cells; *ptr; i++, ptr++)
    {
        troff_ms_escaped_print(*ptr, fout);

        if ((i + 1) % cont->ncolumns == 0)
        {
            fputc('\n', fout);
            if (cancel_pressed_bteq)
                break;
        }
        else
            fputc('\t', fout);
    }

    if (cont->opt->stop_table)
    {
        printTableFooterBteq *footers = footers_with_default(cont);

        fputs(".TE\n.DS L\n", fout);

        /* print footers */
        if (footers && !opt_tuples_only && !cancel_pressed_bteq)
        {
            printTableFooterBteq *f;

            for (f = footers; f; f = f->next)
            {
                troff_ms_escaped_print(f->data, fout);
                fputc('\n', fout);
            }
        }

        fputs(".DE\n", fout);
    }
}


static void
print_troff_ms_vertical(const printTableContentBteq *cont, FILE *fout)
{
    bool        opt_tuples_only = cont->opt->tuples_only;
    unsigned short opt_border = cont->opt->border;
    unsigned long record = cont->opt->prior_records + 1;
    unsigned int i;
    const char *const *ptr;
    unsigned short current_format = 0;    /* 0=none, 1=header, 2=body */

    if (cancel_pressed_bteq)
        return;

    if (opt_border > 2)
        opt_border = 2;

    if (cont->opt->start_table)
    {
        /* print title */
        if (!opt_tuples_only && cont->title)
        {
            fputs(".LP\n.DS C\n", fout);
            troff_ms_escaped_print(cont->title, fout);
            fputs("\n.DE\n", fout);
        }

        /* begin environment and set alignments and borders */
        fputs(".LP\n.TS\n", fout);
        if (opt_border == 2)
            fputs("center box;\n", fout);
        else
            fputs("center;\n", fout);

        /* basic format */
        if (opt_tuples_only)
            fputs("c l;\n", fout);
    }
    else
        current_format = 2;        /* assume tuples printed already */

    /* print records */
    for (i = 0, ptr = cont->cells; *ptr; i++, ptr++)
    {
        /* new record */
        if (i % cont->ncolumns == 0)
        {
            if (cancel_pressed_bteq)
                break;
            if (!opt_tuples_only)
            {
                if (current_format != 1)
                {
                    if (opt_border == 2 && record > 1)
                        fputs("_\n", fout);
                    if (current_format != 0)
                        fputs(".T&\n", fout);
                    fputs("c s.\n", fout);
                    current_format = 1;
                }
                fprintf(fout, "\\fIRecord %lu\\fP\n", record++);
            }
            if (opt_border >= 1)
                fputs("_\n", fout);
        }

        if (!opt_tuples_only)
        {
            if (current_format != 2)
            {
                if (current_format != 0)
                    fputs(".T&\n", fout);
                if (opt_border != 1)
                    fputs("c l.\n", fout);
                else
                    fputs("c | l.\n", fout);
                current_format = 2;
            }
        }

        troff_ms_escaped_print(cont->headers[i % cont->ncolumns], fout);
        fputc('\t', fout);
        troff_ms_escaped_print(*ptr, fout);

        fputc('\n', fout);
    }

    if (cont->opt->stop_table)
    {
        fputs(".TE\n.DS L\n", fout);

        /* print footers */
        if (cont->footers && !opt_tuples_only && !cancel_pressed_bteq)
        {
            printTableFooterBteq *f;

            for (f = cont->footers; f; f = f->next)
            {
                troff_ms_escaped_print(f->data, fout);
                fputc('\n', fout);
            }
        }

        fputs(".DE\n", fout);
    }
}


/********************************/
/* Public functions                */
/********************************/


/*
 * disable_sigpipe_trap_bteq
 *
 * Turn off SIGPIPE interrupt --- call this before writing to a temporary
 * query output file that is a pipe.
 *
 * No-op on Windows, where there's no SIGPIPE interrupts.
 */
void
disable_sigpipe_trap_bteq(void)
{
#ifndef WIN32
    pqsignal(SIGPIPE, SIG_IGN);
#endif
}

/*
 * restore_sigpipe_trap_bteq
 *
 * Restore normal SIGPIPE interrupt --- call this when done writing to a
 * temporary query output file that was (or might have been) a pipe.
 *
 * Note: within bteq, we enable SIGPIPE interrupts unless the permanent query
 * output file is a pipe, in which case they should be kept off.  This
 * approach works only because bteq is not currently complicated enough to
 * have nested usages of short-lived output files.  Otherwise we'd probably
 * need a genuine save-and-restore-state approach; but for now, that would be
 * useless complication.  In non-bteq programs, this always enables SIGPIPE.
 *
 * No-op on Windows, where there's no SIGPIPE interrupts.
 */
void
restore_sigpipe_trap_bteq(void)
{
#ifndef WIN32
    pqsignal(SIGPIPE, always_ignore_sigpipe ? SIG_IGN : SIG_DFL);
#endif
}

/*
 * set_sigpipe_trap_state_bteq
 *
 * Set the trap state that restore_sigpipe_trap_bteq should restore to.
 */
void
set_sigpipe_trap_state_bteq(bool ignore)
{
    always_ignore_sigpipe = ignore;
}


/*
 * PageOutputbteq
 *
 * Tests if pager is needed and returns appropriate FILE pointer.
 *
 * If the topt argument is NULL no pager is used.
 */
FILE *
PageOutputbteq(int lines, const printTableOptBteq *topt)
{
    /* check whether we need / can / are supposed to use pager */
    if (topt && topt->pager && isatty(fileno(stdin)) && isatty(fileno(stdout)))
    {
#ifdef TIOCGWINSZ
        unsigned short int pager = topt->pager;
        int            min_lines = topt->pager_min_lines;
        int            result;
        struct winsize screen_size;

        result = ioctl(fileno(stdout), TIOCGWINSZ, &screen_size);

        /* >= accounts for a one-line prompt */
        if (result == -1
            || (lines >= screen_size.ws_row && lines >= min_lines)
            || pager > 1)
#endif
        {
            const char *pagerprog;
            FILE       *pagerpipe;

            pagerprog = getenv("PSQL_PAGER");
            if (!pagerprog)
                pagerprog = getenv("PAGER");
            if (!pagerprog)
                pagerprog = DEFAULT_PAGER;
            else
            {
                /* if PAGER is empty or all-white-space, don't use pager */
                if (strspn(pagerprog, " \t\r\n") == strlen(pagerprog))
                    return stdout;
            }
            disable_sigpipe_trap_bteq();
            pagerpipe = popen(pagerprog, "w");
            if (pagerpipe)
                return pagerpipe;
            /* if popen fails, silently proceed without pager */
            restore_sigpipe_trap_bteq();
        }
    }

    return stdout;
}

/*
 * ClosePagerbteq
 *
 * Close previously opened pager pipe, if any
 */
void
ClosePagerbteq(FILE *pagerpipe)
{
    if (pagerpipe && pagerpipe != stdout)
    {
        /*
         * If printing was canceled midstream, warn about it.
         *
         * Some pagers like less use Ctrl-C as part of their command set. Even
         * so, we abort our processing and warn the user what we did.  If the
         * pager quit as a result of the SIGINT, this message won't go
         * anywhere ...
         */
        if (cancel_pressed_bteq)
            fprintf(pagerpipe, _("Interrupted\n"));

        pclose(pagerpipe);
        restore_sigpipe_trap_bteq();
    }
}

/*
 * Initialise a table contents struct.
 *        Must be called before any other printTablebteq method is used.
 *
 * The title is not duplicated; the caller must ensure that the buffer
 * is available for the lifetime of the printTableContentBteq struct.
 *
 * If you call this, you must call printTableCleanupbteq once you're done with the
 * table.
 */
void
printTableInitbteq(printTableContentBteq *const content, const printTableOptBteq *opt,
               const char *title, const int ncolumns, const int nrows)
{
    content->opt = opt;
    content->title = title;
    content->ncolumns = ncolumns;
    content->nrows = nrows;
    content->table_width = opt->table_width;

    content->headers = pg_malloc0((ncolumns + 1) * sizeof(*content->headers));

    content->cells = pg_malloc0((ncolumns * nrows + 1) * sizeof(*content->cells));

    content->cellmustfree = NULL;
    content->footers = NULL;

    content->aligns = pg_malloc0((ncolumns + 1) * sizeof(*content->align));

    content->header = content->headers;
    content->cell = content->cells;
    content->footer = content->footers;
    content->align = content->aligns;
    content->cellsadded = 0;
}

/*
 * Add a header to the table.
 *
 * Headers are not duplicated; you must ensure that the header string is
 * available for the lifetime of the printTableContentBteq struct.
 *
 * If translate is true, the function will pass the header through gettext.
 * Otherwise, the header will not be translated.
 *
 * align is either 'l' or 'r', and specifies the alignment for cells in this
 * column.
 */
void
printTableAddHeaderbteq(printTableContentBteq *const content, char *header,
                    const bool translate, const char align)
{
#ifndef ENABLE_NLS
    (void) translate;            /* unused parameter */
#endif

    if (content->header >= content->headers + content->ncolumns)
    {
        fprintf(stderr, _("Cannot add header to table content: "
                          "column count of %d exceeded.\n"),
                content->ncolumns);
        exit(EXIT_FAILURE);
    }

    *content->header = (char *) mbvalidate((unsigned char *) header,
                                           content->opt->encoding);
#ifdef ENABLE_NLS
    if (translate)
        *content->header = _(*content->header);
#endif
    content->header++;

    *content->align = align;
    content->align++;
}

/*
 * Add a cell to the table.
 *
 * Cells are not duplicated; you must ensure that the cell string is available
 * for the lifetime of the printTableContentBteq struct.
 *
 * If translate is true, the function will pass the cell through gettext.
 * Otherwise, the cell will not be translated.
 *
 * If mustfree is true, the cell string is freed by printTableCleanupbteq().
 * Note: Automatic freeing of translatable strings is not supported.
 */
void
printTableAddCellbteq(printTableContentBteq *const content, char *cell,
                  const bool translate, const bool mustfree)
{
#ifndef ENABLE_NLS
    (void) translate;            /* unused parameter */
#endif

    if (content->cellsadded >= content->ncolumns * content->nrows)
    {
        fprintf(stderr, _("Cannot add cell to table content: "
                          "total cell count of %d exceeded.\n"),
                content->ncolumns * content->nrows);
        exit(EXIT_FAILURE);
    }

    *content->cell = (char *) mbvalidate((unsigned char *) cell,
                                         content->opt->encoding);

#ifdef ENABLE_NLS
    if (translate)
        *content->cell = _(*content->cell);
#endif

    if (mustfree)
    {
        if (content->cellmustfree == NULL)
            content->cellmustfree =
                pg_malloc0((content->ncolumns * content->nrows + 1) * sizeof(bool));

        content->cellmustfree[content->cellsadded] = true;
    }
    content->cell++;
    content->cellsadded++;
}

/*
 * Add a footer to the table.
 *
 * Footers are added as elements of a singly-linked list, and the content is
 * strdup'd, so there is no need to keep the original footer string around.
 *
 * Footers are never translated by the function.  If you want the footer
 * translated you must do so yourself, before calling printTableAddFooterbteq.  The
 * reason this works differently to headers and cells is that footers tend to
 * be made of up individually translated components, rather than being
 * translated as a whole.
 */
void
printTableAddFooterbteq(printTableContentBteq *const content, const char *footer)
{
    printTableFooterBteq *f;

    f = pg_malloc0(sizeof(*f));
    f->data = pg_strdup(footer);

    if (content->footers == NULL)
        content->footers = f;
    else
        content->footer->next = f;

    content->footer = f;
}

/*
 * Change the content of the last-added footer.
 *
 * The current contents of the last-added footer are freed, and replaced by the
 * content given in *footer.  If there was no previous footer, add a new one.
 *
 * The content is strdup'd, so there is no need to keep the original string
 * around.
 */
void
printTableSetFooterbteq(printTableContentBteq *const content, const char *footer)
{
    if (content->footers != NULL)
    {
        free(content->footer->data);
        content->footer->data = pg_strdup(footer);
    }
    else
        printTableAddFooterbteq(content, footer);
}

/*
 * Free all memory allocated to this struct.
 *
 * Once this has been called, the struct is unusable unless you pass it to
 * printTableInitbteq() again.
 */
void
printTableCleanupbteq(printTableContentBteq *const content)
{
    if (content->cellmustfree)
    {
        int            i;

        for (i = 0; i < content->nrows * content->ncolumns; i++)
        {
            if (content->cellmustfree[i])
                free((char *) content->cells[i]);
        }
        free(content->cellmustfree);
        content->cellmustfree = NULL;
    }
    free(content->headers);
    free(content->cells);
    free(content->aligns);

    content->opt = NULL;
    content->title = NULL;
    content->headers = NULL;
    content->cells = NULL;
    content->aligns = NULL;
    content->header = NULL;
    content->cell = NULL;
    content->align = NULL;

    if (content->footers)
    {
        for (content->footer = content->footers; content->footer;)
        {
            printTableFooterBteq *f;

            f = content->footer;
            content->footer = f->next;
            free(f->data);
            free(f);
        }
    }
    content->footers = NULL;
    content->footer = NULL;
}

/*
 * IsPagerNeeded
 *
 * Setup pager if required
 */
static void
IsPagerNeeded(const printTableContentBteq *cont, int extra_lines, bool expanded,
              FILE **fout, bool *is_pager)
{
    if (*fout == stdout)
    {
        int            lines;

        if (expanded)
            lines = (cont->ncolumns + 1) * cont->nrows;
        else
            lines = cont->nrows + 1;

        if (!cont->opt->tuples_only)
        {
            printTableFooterBteq *f;

            /*
             * FIXME -- this is slightly bogus: it counts the number of
             * footers, not the number of lines in them.
             */
            for (f = cont->footers; f; f = f->next)
                lines++;
        }

        *fout = PageOutputbteq(lines + extra_lines, cont->opt);
        *is_pager = (*fout != stdout);
    }
    else
        *is_pager = false;
}

/*
 * Use this to print any table in the supported formats.
 *
 * cont: table data and formatting options
 * fout: where to print to
 * is_pager: true if caller has already redirected fout to be a pager pipe
 * flog: if not null, also print the table there (for --log-file option)
 */
void
printTablebteq(const printTableContentBteq *cont,
           FILE *fout, bool is_pager, FILE *flog)
{
    bool        is_local_pager = false;

    if (cancel_pressed_bteq)
        return;

    if (cont->opt->format == PRINT_NOTHING_BTEQ)
        return;

    /* print_aligned_*() handle the pager themselves */
    if (!is_pager &&
        cont->opt->format != PRINT_ALIGNED_BTEQ &&
        cont->opt->format != PRINT_WRAPPED_BTEQ)
    {
        IsPagerNeeded(cont, 0, (cont->opt->expanded == 1), &fout, &is_pager);
        is_local_pager = is_pager;
    }

    /* print the stuff */

    if (flog)
        print_aligned_text_bteq(cont, flog, false);

    switch (cont->opt->format)
    {
        case PRINT_UNALIGNED_BTEQ:
            if (cont->opt->expanded == 1)
                print_unaligned_vertical(cont, fout);
            else
                print_unaligned_text(cont, fout);
            break;
        case PRINT_ALIGNED_BTEQ:
        case PRINT_WRAPPED_BTEQ:

            /*
             * In expanded-auto mode, force vertical if a pager is passed in;
             * else we may make different decisions for different hunks of the
             * query result.
             */
            if (cont->opt->expanded == 1 ||
                (cont->opt->expanded == 2 && is_pager))
                print_aligned_vertical(cont, fout, is_pager);
            else
                print_aligned_text_bteq(cont, fout, is_pager);
            break;
        case PRINT_HTML_BTEQ:
            if (cont->opt->expanded == 1)
                print_html_vertical(cont, fout);
            else
                print_html_text(cont, fout);
            break;
        case PRINT_ASCIIDOC_BTEQ:
            if (cont->opt->expanded == 1)
                print_asciidoc_vertical(cont, fout);
            else
                print_asciidoc_text(cont, fout);
            break;
        case PRINT_LATEX_BTEQ:
            if (cont->opt->expanded == 1)
                print_latex_vertical(cont, fout);
            else
                print_latex_text(cont, fout);
            break;
        case PRINT_LATEX_LONGTABLE_BTEQ:
            if (cont->opt->expanded == 1)
                print_latex_vertical(cont, fout);
            else
                print_latex_longtable_text(cont, fout);
            break;
        case PRINT_TROFF_MS_BTEQ:
            if (cont->opt->expanded == 1)
                print_troff_ms_vertical(cont, fout);
            else
                print_troff_ms_text(cont, fout);
            break;
        default:
            fprintf(stderr, _("invalid output format (internal error): %d"),
                    cont->opt->format);
            exit(EXIT_FAILURE);
    }

    if (is_local_pager)
        ClosePagerbteq(fout);
}

/*
 * Use this to print query results
 *
 * result: result of a successful query
 * opt: formatting options
 * fout: where to print to
 * is_pager: true if caller has already redirected fout to be a pager pipe
 * flog: if not null, also print the data there (for --log-file option)
 */
void
printQuerybteq(const PGresult *result, const printQueryOptBteq *opt,
           FILE *fout, bool is_pager, FILE *flog)
{
    printTableContentBteq cont;
    int            i,
                r,
                c;

    if (cancel_pressed_bteq)
        return;

    printTableInitbteq(&cont, &opt->topt, opt->title,
                   PQnfields(result), PQntuples(result));

    /* Assert caller supplied enough translate_columns[] entries */
    Assert(opt->translate_columns == NULL ||
           opt->n_translate_columns >= cont.ncolumns);

    for (i = 0; i < cont.ncolumns; i++)
    {
        printTableAddHeaderbteq(&cont, PQfname(result, i),
                            opt->translate_header,
                            column_type_alignment_bteq(PQftype(result, i)));
    }

    /* set cells */
    for (r = 0; r < cont.nrows; r++)
    {
        for (c = 0; c < cont.ncolumns; c++)
        {
            char       *cell;
            bool        mustfree = false;
            bool        translate;

            if (PQgetisnull(result, r, c))
                cell = opt->nullPrint ? opt->nullPrint : "";
            else
            {
                cell = PQgetvalue(result, r, c);
                if (cont.aligns[c] == 'r' && opt->topt.numericLocale)
                {
                    cell = format_numeric_locale(cell);
                    mustfree = true;
                }
            }

            translate = (opt->translate_columns && opt->translate_columns[c]);
            printTableAddCellbteq(&cont, cell, translate, mustfree);
        }
    }

    /* set footers */
    if (opt->footers)
    {
        char      **footer;

        for (footer = opt->footers; *footer; footer++)
            printTableAddFooterbteq(&cont, *footer);
    }

    printTablebteq(&cont, fout, is_pager, flog);
    printTableCleanupbteq(&cont);
}

char
column_type_alignment_bteq(Oid ftype)
{
    char        align;

    switch (ftype)
    {
        case INT2OID:
        case INT4OID:
        case INT8OID:
        case FLOAT4OID:
        case FLOAT8OID:
        case NUMERICOID:
        case OIDOID:
        case XIDOID:
        case CIDOID:
        case CASHOID:
            align = 'r';
            break;
        default:
            align = 'l';
            break;
    }
    return align;
}

void
setDecimalLocalebteq(void)
{
    struct lconv *extlconv;

    extlconv = localeconv();

    /* Don't accept an empty decimal_point string */
    if (*extlconv->decimal_point)
        decimal_point = pg_strdup(extlconv->decimal_point);
    else
        decimal_point = ".";    /* SQL output standard */

    /*
     * Although the Open Group standard allows locales to supply more than one
     * group width, we consider only the first one, and we ignore any attempt
     * to suppress grouping by specifying CHAR_MAX.  As in the backend's
     * cash.c, we must apply a range check to avoid being fooled by variant
     * CHAR_MAX values.
     */
    groupdigits = *extlconv->grouping;
    if (groupdigits <= 0 || groupdigits > 6)
        groupdigits = 3;        /* most common */

    /* Don't accept an empty thousands_sep string, either */
    /* similar code exists in formatting.c */
    if (*extlconv->thousands_sep)
        thousands_sep = pg_strdup(extlconv->thousands_sep);
    /* Make sure thousands separatorbteq doesn't match decimal point symbol. */
    else if (strcmp(decimal_point, ",") != 0)
        thousands_sep = ",";
    else
        thousands_sep = ".";
}

/* get selected or default line style */
const printTextFormatbteq *
get_line_style_bteq(const printTableOptBteq *opt)
{
    /*
     * Note: this function mainly exists to preserve the convention that a
     * printTableOptBteq struct can be initialized to zeroes to get default
     * behavior.
     */
    if (opt->line_style != NULL)
        return opt->line_style;
    else
        return &pg_asciiformat_bteq;
}

void
refresh_utf8format_bteq(const printTableOptBteq *opt)
{
    printTextFormatbteq *popt = &pg_utf8format_bteq;

    const unicodeStyleBorderFormatbteq *border;
    const unicodeStyleRowFormatbteq *header;
    const unicodeStyleColumnFormatbteq *column;

    popt->name = "unicode";

    border = &unicode_style_bteq.border_style[opt->unicode_border_linestyle];
    header = &unicode_style_bteq.row_style[opt->unicode_header_linestyle];
    column = &unicode_style_bteq.column_style[opt->unicode_column_linestyle];

    popt->lrule[PRINT_RULE_TOP_BTEQ].hrule = border->horizontal;
    popt->lrule[PRINT_RULE_TOP_BTEQ].leftvrule = border->down_and_right;
    popt->lrule[PRINT_RULE_TOP_BTEQ].midvrule = column->down_and_horizontal[opt->unicode_border_linestyle];
    popt->lrule[PRINT_RULE_TOP_BTEQ].rightvrule = border->down_and_left;

    popt->lrule[PRINT_RULE_MIDDLE_BTEQ].hrule = header->horizontal;
    popt->lrule[PRINT_RULE_MIDDLE_BTEQ].leftvrule = header->vertical_and_right[opt->unicode_border_linestyle];
    popt->lrule[PRINT_RULE_MIDDLE_BTEQ].midvrule = column->vertical_and_horizontal[opt->unicode_header_linestyle];
    popt->lrule[PRINT_RULE_MIDDLE_BTEQ].rightvrule = header->vertical_and_left[opt->unicode_border_linestyle];

    popt->lrule[PRINT_RULE_BOTTOM_BTEQ].hrule = border->horizontal;
    popt->lrule[PRINT_RULE_BOTTOM_BTEQ].leftvrule = border->up_and_right;
    popt->lrule[PRINT_RULE_BOTTOM_BTEQ].midvrule = column->up_and_horizontal[opt->unicode_border_linestyle];
    popt->lrule[PRINT_RULE_BOTTOM_BTEQ].rightvrule = border->left_and_right;

    /* N/A */
    popt->lrule[PRINT_RULE_DATA_BTEQ].hrule = "";
    popt->lrule[PRINT_RULE_DATA_BTEQ].leftvrule = border->vertical;
    popt->lrule[PRINT_RULE_DATA_BTEQ].midvrule = column->vertical;
    popt->lrule[PRINT_RULE_DATA_BTEQ].rightvrule = border->vertical;

    popt->midvrule_nl = column->vertical;
    popt->midvrule_wrap = column->vertical;
    popt->midvrule_blank = column->vertical;

    /* Same for all unicode today */
    popt->header_nl_left = unicode_style_bteq.header_nl_left;
    popt->header_nl_right = unicode_style_bteq.header_nl_right;
    popt->nl_left = unicode_style_bteq.nl_left;
    popt->nl_right = unicode_style_bteq.nl_right;
    popt->wrap_left = unicode_style_bteq.wrap_left;
    popt->wrap_right = unicode_style_bteq.wrap_right;
    popt->wrap_right_border = unicode_style_bteq.wrap_right_border;

    return;
}

/*
 * Compute the byte distance to the end of the string or *target_width
 * display character positions, whichever comes first.  Update *target_width
 * to be the number of display character positions actually filled.
 */
static int
strlen_max_width(unsigned char *str, int *target_width, int encoding)
{
    unsigned char *start = str;
    unsigned char *end = str + strlen((char *) str);
    int            curr_width = 0;

    while (str < end)
    {
        int            char_width = PQdsplen((char *) str, encoding);

        /*
         * If the display width of the new character causes the string to
         * exceed its target width, skip it and return.  However, if this is
         * the first character of the string (curr_width == 0), we have to
         * accept it.
         */
        if (*target_width < curr_width + char_width && curr_width != 0)
            break;

        curr_width += char_width;

        str += PQmblen((char *) str, encoding);
    }

    *target_width = curr_width;

    return str - start;
}
