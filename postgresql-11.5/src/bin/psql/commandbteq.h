/*
 * bteq - the PostgreSQL interactive terminal
 *
 * Copyright (c) 2000-2018, PostgreSQL Global Development Group
 *
 * src/bin/psql/commandbteq.h
 */
#ifndef COMMAND_BTEQ_H
#define COMMAND_BTEQ_H

#include "fe_utils/printbteq.h"
#include "fe_utils/bteqscan.h"
#include "fe_utils/conditional.h"


typedef enum _dotResult
{
    BTEQ_CMD_UNKNOWN = 0,        /* not done parsing yet (internal only) */
    BTEQ_CMD_SEND,                /* query complete; send off */
    BTEQ_CMD_SKIP_LINE,            /* keep building query */
    BTEQ_CMD_TERMINATE,            /* quit program */
    BTEQ_CMD_NEWEDIT,            /* query buffer was changed (e.g., via \e) */
    BTEQ_CMD_ERROR                /* the execution of the dot command
                                 * resulted in an error */
} dotResult;


extern dotResult HandleDotCmds(BteqScanState scan_state,
                ConditionalStack cstack,
                PQExpBuffer query_buf,
                PQExpBuffer previous_buf);

extern void connection_warningsbteq(bool in_startup);
extern void SyncVariablesbteq(void);


#endif                            /* COMMAND_BTEQ_H */
