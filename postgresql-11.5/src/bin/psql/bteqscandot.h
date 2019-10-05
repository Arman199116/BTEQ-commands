/*
 * bteq - the PostgreSQL interactive terminal
 *
 * Copyright (c) 2000-2018, PostgreSQL Global Development Group
 *
 * src/bin/psql/btqscandot.h
 */
#ifndef BTEQSCANDOT_H
#define BTEQSCANDOT_H

#include "fe_utils/bteqscan.h"


/* Different ways for scan_dot_option to handle parameter words */
enum dot_option_type
{
    OT_BTEQ_NORMAL,                    /* normal case */
    OT_BTEQ_SQLID,                    /* treat as SQL identifier */
    OT_BTEQ_SQLIDHACK,                /* SQL identifier, but don't downcase */
    OT_BTEQ_FILEPIPE,                /* it's a filename or pipe */
    OT_BTEQ_WHOLE_LINE                /* just snarf the rest of the line */
};


extern char *bteq_scan_dot_command(BteqScanState state);

extern char *bteq_scan_dot_option(BteqScanState state,
                       enum dot_option_type type,
                       char *quote,
                       bool semicolon);

extern void bteq_scan_dot_command_end(BteqScanState state);

extern int    bteq_scan_get_paren_depth(BteqScanState state);

extern void bteq_scan_set_paren_depth(BteqScanState state, int depth);

extern void dequote_downcase_identifier_bteq(char *str, bool downcase, int encoding);

#endif   /* BTEQSCANDOT_H */
