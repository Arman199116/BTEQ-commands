/*
 * bteq - the PostgreSQL interactive terminal
 *
 * Copyright (c) 2000-2018, PostgreSQL Global Development Group
 *
 * src/bin/psql/mainloopbteq.h
 */
#ifndef MAINLOOP_BTEQ_H
#define MAINLOOP_BTEQ_H

#include "fe_utils/bteqscan.h"

extern const BteqScanCallbacks bteqscan_callbacks;

extern int    MainLoopBteq(FILE *source);


#endif                            /* MAINLOOP_BTEQ_H */
