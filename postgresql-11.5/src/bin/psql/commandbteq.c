/*
 * bteq - the PostgreSQL interactive terminal
 *
 * Copyright (c) 2000-2018, PostgreSQL Global Development Group
 *
 * src/bin/psql/commandbteq.c
 */
#include "postgres_fe.h"
#include "commandbteq.h"

#include <ctype.h>
#include <time.h>
#include <pwd.h>
#ifndef WIN32
#include <sys/stat.h>            /* for stat() */
#include <fcntl.h>                /* open() flags */
#include <unistd.h>                /* for geteuid(), getpid(), stat() */
#else
#include <win32.h>
#include <io.h>
#include <fcntl.h>
#include <direct.h>
#include <sys/stat.h>            /* for stat() */
#endif

#include "catalog/pg_class_d.h"
#include "portability/instr_time.h"

#include "libpq-fe.h"
#include "pqexpbuffer.h"
#include "fe_utils/string_utils.h"

#include "common.h"
#include "copy.h"
#include "crosstabview.h"
#include "describe.h"
#include "help.h"
#include "input.h"
#include "large_obj.h"
#include "mainloopbteq.h"
#include "fe_utils/printbteq.h"
#include "bteqscandot.h"
#include "settings.h"
#include "variables.h"

/*
 * Editable database object types.
 */
typedef enum EditableObjectType
{
    EditableFunction,
    EditableView
} EditableObjectType;

/* local function declarations */
static dotResult exec_command(const char *cmd,
             BteqScanState scan_state,
             ConditionalStack cstack,
             PQExpBuffer query_buf,
             PQExpBuffer previous_buf);
static dotResult exec_command_logon(BteqScanState scan_state, bool active_branch);
static dotResult exec_command_quit(BteqScanState scan_state, bool active_branch);
static dotResult exec_command_set(BteqScanState scan_state, bool active_branch);
static void ignore_dot_options(BteqScanState scan_state);
static bool is_branching_command(const char *cmd);

static void copy_previous_query(PQExpBuffer query_buf, PQExpBuffer previous_buf);
static bool do_connect(enum trivalue reuse_previous_specification,
           char *dbname, char *user, char *host, char *port);

static void printSSLInfo(void);

#ifdef WIN32
static void checkWin32Codepage(void);
#endif



/*----------
 * HandleDotCmds:
 *
 * Handles all the different commands that start with '.'.
 * Ordinarily called by MainLoop().
 *
 * scan_state is a lexer working state that is set to continue scanning
 * just after the '.'.  The lexer is advanced past the command and all
 * arguments on return.
 *
 * cstack is the current \if stack state.  This will be examined, and
 * possibly modified by conditional commands.
 *
 * query_buf contains the query-so-far, which may be modified by
 * execution of the dot command (for example, \r clears it).
 *
 * previous_buf contains the query most recently sent to the server
 * (empty if none yet).  This should not be modified here, but some
 * commands copy its content into query_buf.
 *
 * query_buf and previous_buf will be NULL when executing a "-c"
 * command-line option.
 *
 * Returns a status code indicating what action is desired, see command.h.
 *----------
 */

dotResult
HandleDotCmds(BteqScanState scan_state,
                ConditionalStack cstack,
                PQExpBuffer query_buf,
                PQExpBuffer previous_buf)
{
    dotResult status;
    char       *cmd;
    char       *arg;
    printf("bteq1 command.c\n");
    Assert(scan_state != NULL);
    Assert(cstack != NULL);

    /* Parse off the command name */
    cmd = bteq_scan_dot_command(scan_state);

    /* And try to execute it */
    status = exec_command(cmd, scan_state, cstack, query_buf, previous_buf);

    if (status == BTEQ_CMD_UNKNOWN)
    {
        if (pset.cur_cmd_interactive)
            psql_error("Invalid command \\%s. Try \\? for help.\n", cmd);
        else
            psql_error("invalid command \\%s\n", cmd);
        status = BTEQ_CMD_ERROR;
    }

    if (status != BTEQ_CMD_ERROR)
    {
        /*
         * Eat any remaining arguments after a valid command.  We want to
         * suppress evaluation of backticks in this situation, so transiently
         * push an inactive conditional-stack entry.
         */
        bool        active_branch = conditional_active(cstack);

        conditional_stack_push(cstack, IFSTATE_IGNORED);
        while ((arg = bteq_scan_dot_option(scan_state,
                                             OT_BTEQ_NORMAL, NULL, false)))
        {
            if (active_branch)
                psql_error("\\%s: extra argument \"%s\" ignored\n", cmd, arg);
            free(arg);
        }
        conditional_stack_pop(cstack);
    }
    else
    {
        /* silently throw away rest of line after an erroneous command */
        while ((arg = bteq_scan_dot_option(scan_state,
                                             OT_BTEQ_WHOLE_LINE, NULL, false)))
            free(arg);
    }

    /* if there is a trailing \\, swallow it */
    bteq_scan_dot_command_end(scan_state);

    free(cmd);

    /* some commands write to queryFout, so make sure output is sent */
    fflush(pset.queryFout);

    return status;
}


/*
 * Subroutine to actually try to execute a dot command.
 *
 * The typical "success" result code is BTEQ_CMD_SKIP_LINE, although some
 * commands return something else.  Failure results are BTEQ_CMD_ERROR,
 * unless BTEQ_CMD_UNKNOWN is more appropriate.
 */


static dotResult
exec_command(const char *cmd,
             BteqScanState scan_state,
             ConditionalStack cstack,
             PQExpBuffer query_buf,
             PQExpBuffer previous_buf)
{
    dotResult status;
    bool        active_branch = conditional_active(cstack);

    /*
     * In interactive mode, warn when we're ignoring a command within a false
     * \if-branch.  But we continue on, so as to parse and discard the right
     * amount of parameter text.  Each individual dot command subroutine
     * is responsible for doing nothing after discarding appropriate
     * arguments, if !active_branch.
     */
    if (pset.cur_cmd_interactive && !active_branch &&
        !is_branching_command(cmd))
    {
        psql_error("\\%s command ignored; use \\endif or Ctrl-C to exit current \\if block\n",
                   cmd);
    }

    if (strcasecmp(cmd, "logon") == 0)
        status = exec_command_logon(scan_state, active_branch);
    else if (strcasecmp(cmd, "set") == 0)
        status = exec_command_set(scan_state, active_branch);
    else if (strcasecmp(cmd, "quit") == 0 || strcasecmp(cmd, "q") == 0)
        status = exec_command_quit(scan_state, active_branch);
    else
        status = BTEQ_CMD_UNKNOWN;

    /*
     * All the commands that return BTEQ_CMD_SEND want to execute previous_buf
     * if query_buf is empty.  For convenience we implement that here, not in
     * the individual command subroutines.
     */
    if (status == BTEQ_CMD_SEND)
        copy_previous_query(query_buf, previous_buf);

    return status;
}


/*
 * .logon -- toggle field alignment
 *
 * This makes little sense but we keep it around.
 */
static dotResult
exec_command_logon(BteqScanState scan_state, bool active_branch)
{
    printf(".logon bteq\n");

    return 1;
}


/*
 * \q or \quit -- exit BTEQ
 */
static dotResult
exec_command_quit(BteqScanState scan_state, bool active_branch)
{
    dotResult status = BTEQ_CMD_SKIP_LINE;

    if (active_branch)
        status = BTEQ_CMD_TERMINATE;

    return status;
}


/*
 * \set -- set variable
 */
static dotResult
exec_command_set(BteqScanState scan_state, bool active_branch)
{
    bool        success = true;

    if (active_branch)
    {
        char       *opt0 = bteq_scan_dot_option(scan_state,
                                                  OT_BTEQ_NORMAL, NULL, false);

        if (!opt0)
        {
            /* list all variables */
            PrintVariables(pset.vars);
            success = true;
        }
        else
        {
            /*
             * Set variable to the concatenation of the arguments.
             */
            char       *newval;
            char       *opt;

            opt = bteq_scan_dot_option(scan_state,
                                         OT_BTEQ_NORMAL, NULL, false);
            newval = pg_strdup(opt ? opt : "");
            free(opt);

            while ((opt = bteq_scan_dot_option(scan_state,
                                                 OT_BTEQ_NORMAL, NULL, false)))
            {
                newval = pg_realloc(newval, strlen(newval) + strlen(opt) + 1);
                strcat(newval, opt);
                free(opt);
            }

            if (!SetVariable(pset.vars, opt0, newval))
                success = false;

            free(newval);
        }
        free(opt0);
    }
    else
        ignore_dot_options(scan_state);

    return success ? BTEQ_CMD_SKIP_LINE : BTEQ_CMD_ERROR;
}

/*
 * Read and discard "normal" dot command options.
 *
 * This should be used for inactive-branch processing of any dot command
 * that eats one or more OT_BTEQ_NORMAL, OT_BTEQ_SQLID, or OT_BTEQ_SQLIDHACK parameters.
 * We don't need to worry about exactly how many it would eat, since the
 * cleanup logic in HandleDotCmds would silently discard any extras anyway.
 */
static void
ignore_dot_options(BteqScanState scan_state)
{
    char       *arg;

    while ((arg = bteq_scan_dot_option(scan_state,
                                         OT_BTEQ_NORMAL, NULL, false)) != NULL)
        free(arg);
}


/*
 * Return true if the command given is a branching command.
 */
static bool
is_branching_command(const char *cmd)
{
    return (strcmp(cmd, "if") == 0 ||
            strcmp(cmd, "elif") == 0 ||
            strcmp(cmd, "else") == 0 ||
            strcmp(cmd, "endif") == 0);
}


/*
 * If query_buf is empty, copy previous_buf into it.
 *
 * This is used by various dot commands for which re-execution of a
 * previous query is a common usage.  For convenience, we allow the
 * case of query_buf == NULL (and do nothing).
 */
static void
copy_previous_query(PQExpBuffer query_buf, PQExpBuffer previous_buf)
{
    if (query_buf && query_buf->len == 0)
        appendPQExpBufferStr(query_buf, previous_buf->data);
}


/*
 * Ask the user for a password; 'username' is the username the
 * password is for, if one has been explicitly specified. Returns a
 * malloc'd string.
 */


static char *
prompt_for_password(const char *username)
{
    char        buf[100];

    if (username == NULL || username[0] == '\0')
        simple_prompt("Password: ", buf, sizeof(buf), false);
    else
    {
        char       *prompt_text;

        prompt_text = psprintf(_("Password for user %s: "), username);
        simple_prompt(prompt_text, buf, sizeof(buf), false);
        free(prompt_text);
    }
    return pg_strdup(buf);
}

static bool
param_is_newly_set(const char *old_val, const char *new_val)
{
    if (new_val == NULL)
        return false;

    if (old_val == NULL || strcmp(old_val, new_val) != 0)
        return true;

    return false;
}

/*
 * do_connect -- handler for \connect
 *
 * Connects to a database with given parameters. Absent an established
 * connection, all parameters are required. Given -reuse-previous=off or a
 * connection string without -reuse-previous=on, NULL values will pass through
 * to PQconnectdbParams(), so the libpq defaults will be used. Otherwise, NULL
 * values will be replaced with the ones in the current connection.
 *
 * In interactive mode, if connection fails with the given parameters,
 * the old connection will be kept.
 */
static bool
do_connect(enum trivalue reuse_previous_specification,
           char *dbname, char *user, char *host, char *port)
{
    PGconn       *o_conn = pset.db,
               *n_conn;
    char       *password = NULL;
    bool        keep_password;
    bool        has_connection_string;
    bool        reuse_previous;
    PQExpBufferData connstr;

    if (!o_conn && (!dbname || !user || !host || !port))
    {
        /*
         * We don't know the supplied connection parameters and don't want to
         * connect to the wrong database by using defaults, so require all
         * parameters to be specified.
         */
        psql_error("All connection parameters must be supplied because no "
                   "database connection exists\n");
        return false;
    }

    has_connection_string = dbname ?
        recognized_connection_string(dbname) : false;
    switch (reuse_previous_specification)
    {
        case TRI_YES:
            reuse_previous = true;
            break;
        case TRI_NO:
            reuse_previous = false;
            break;
        default:
            reuse_previous = !has_connection_string;
            break;
    }
    /* Silently ignore arguments subsequent to a connection string. */
    if (has_connection_string)
    {
        user = NULL;
        host = NULL;
        port = NULL;
    }

    /* grab missing values from the old connection */
    if (!user && reuse_previous)
        user = PQuser(o_conn);
    if (!host && reuse_previous)
        host = PQhost(o_conn);
    if (!port && reuse_previous)
        port = PQport(o_conn);

    /*
     * Any change in the parameters read above makes us discard the password.
     * We also discard it if we're to use a conninfo rather than the
     * positional syntax.
     */
    if (has_connection_string)
        keep_password = false;
    else
        keep_password =
            (user && PQuser(o_conn) && strcmp(user, PQuser(o_conn)) == 0) &&
            (host && PQhost(o_conn) && strcmp(host, PQhost(o_conn)) == 0) &&
            (port && PQport(o_conn) && strcmp(port, PQport(o_conn)) == 0);

    /*
     * Grab missing dbname from old connection.  No password discard if this
     * changes: passwords aren't (usually) database-specific.
     */
    if (!dbname && reuse_previous)
    {
        initPQExpBuffer(&connstr);
        appendPQExpBuffer(&connstr, "dbname=");
        appendConnStrVal(&connstr, PQdb(o_conn));
        dbname = connstr.data;
        /* has_connection_string=true would be a dead store */
    }
    else
        connstr.data = NULL;

    /*
     * If the user asked to be prompted for a password, ask for one now. If
     * not, use the password from the old connection, provided the username
     * etc have not changed. Otherwise, try to connect without a password
     * first, and then ask for a password if needed.
     *
     * XXX: this behavior leads to spurious connection attempts recorded in
     * the postmaster's log.  But libpq offers no API that would let us obtain
     * a password and then continue with the first connection attempt.
     */
    if (pset.getPassword == TRI_YES)
    {
        /*
         * If a connstring or URI is provided, we can't be sure we know which
         * username will be used, since we haven't parsed that argument yet.
         * Don't risk issuing a misleading prompt.  As in startup.c, it does
         * not seem worth working harder, since this getPassword option is
         * normally only used in noninteractive cases.
         */
        password = prompt_for_password(has_connection_string ? NULL : user);
    }
    else if (o_conn && keep_password)
    {
        password = PQpass(o_conn);
        if (password && *password)
            password = pg_strdup(password);
        else
            password = NULL;
    }

    while (true)
    {
#define PARAMS_ARRAY_SIZE    8
        const char **keywords = pg_malloc(PARAMS_ARRAY_SIZE * sizeof(*keywords));
        const char **values = pg_malloc(PARAMS_ARRAY_SIZE * sizeof(*values));
        int            paramnum = -1;

        keywords[++paramnum] = "host";
        values[paramnum] = host;
        keywords[++paramnum] = "port";
        values[paramnum] = port;
        keywords[++paramnum] = "user";
        values[paramnum] = user;

        /*
         * Position in the array matters when the dbname is a connection
         * string, because settings in a connection string override earlier
         * array entries only.  Thus, user= in the connection string always
         * takes effect, but client_encoding= often will not.
         *
         * If you change this code, also change the initial-connection code in
         * main().  For no good reason, a connection string password= takes
         * precedence in main() but not here.
         */
        keywords[++paramnum] = "dbname";
        values[paramnum] = dbname;
        keywords[++paramnum] = "password";
        values[paramnum] = password;
        keywords[++paramnum] = "fallback_application_name";
        values[paramnum] = pset.progname;
        keywords[++paramnum] = "client_encoding";
        values[paramnum] = (pset.notty || getenv("PGCLIENTENCODING")) ? NULL : "auto";

        /* add array terminator */
        keywords[++paramnum] = NULL;
        values[paramnum] = NULL;

        n_conn = PQconnectdbParams(keywords, values, true);

        pg_free(keywords);
        pg_free(values);

        /* We can immediately discard the password -- no longer needed */
        if (password)
            pg_free(password);

        if (PQstatus(n_conn) == CONNECTION_OK)
            break;

        /*
         * Connection attempt failed; either retry the connection attempt with
         * a new password, or give up.
         */
        if (!password && PQconnectionNeedsPassword(n_conn) && pset.getPassword != TRI_NO)
        {
            /*
             * Prompt for password using the username we actually connected
             * with --- it might've come out of "dbname" rather than "user".
             */
            password = prompt_for_password(PQuser(n_conn));
            PQfinish(n_conn);
            continue;
        }

        /*
         * Failed to connect to the database. In interactive mode, keep the
         * previous connection to the DB; in scripting mode, close our
         * previous connection as well.
         */
        if (pset.cur_cmd_interactive)
        {
            psql_error("%s", PQerrorMessage(n_conn));

            /* pset.db is left unmodified */
            if (o_conn)
                psql_error("Previous connection kept\n");
        }
        else
        {
            psql_error("\\connect: %s", PQerrorMessage(n_conn));
            if (o_conn)
            {
                PQfinish(o_conn);
                pset.db = NULL;
            }
        }

        PQfinish(n_conn);
        if (connstr.data)
            termPQExpBuffer(&connstr);
        return false;
    }
    if (connstr.data)
        termPQExpBuffer(&connstr);

    /*
     * Replace the old connection with the new one, and update
     * connection-dependent variables.
     */
    PQsetNoticeProcessor(n_conn, NoticeProcessor, NULL);
    pset.db = n_conn;
    SyncVariablesbteq();
    connection_warningsbteq(false); /* Must be after SyncVariables */

    /* Tell the user about the new connection */
    if (!pset.quiet)
    {
        if (!o_conn ||
            param_is_newly_set(PQhost(o_conn), PQhost(pset.db)) ||
            param_is_newly_set(PQport(o_conn), PQport(pset.db)))
        {
            char       *host = PQhost(pset.db);

            /* If the host is an absolute path, the connection is via socket */
            if (is_absolute_path(host))
                printf(_("You are now connected to database \"%s\" as user \"%s\" via socket in \"%s\" at port \"%s\".\n"),
                       PQdb(pset.db), PQuser(pset.db), host, PQport(pset.db));
            else
                printf(_("You are now connected to database \"%s\" as user \"%s\" on host \"%s\" at port \"%s\".\n"),
                       PQdb(pset.db), PQuser(pset.db), host, PQport(pset.db));
        }
        else
            printf(_("You are now connected to database \"%s\" as user \"%s\".\n"),
                   PQdb(pset.db), PQuser(pset.db));
    }

    if (o_conn)
        PQfinish(o_conn);
    return true;
}


void
connection_warningsbteq(bool in_startup)
{
    if (!pset.quiet && !pset.notty)
    {
        int            client_ver = PG_VERSION_NUM;
        char        cverbuf[32];
        char        sverbuf[32];

        if (pset.sversion != client_ver)
        {
            const char *server_version;

            /* Try to get full text form, might include "devel" etc */
            server_version = PQparameterStatus(pset.db, "server_version");
            /* Otherwise fall back on pset.sversion */
            if (!server_version)
            {
                formatPGVersionNumber(pset.sversion, true,
                                      sverbuf, sizeof(sverbuf));
                server_version = sverbuf;
            }

            printf(_("%s (%s, server %s)\n"),
                   pset.progname, PG_VERSION, server_version);
        }
        /* For version match, only print bteq banner on startup. */
        else if (in_startup)
            printf("%s (%s)\n", pset.progname, PG_VERSION);

        if (pset.sversion / 100 > client_ver / 100)
            printf(_("WARNING: %s major version %s, server major version %s.\n"
                     "         Some bteq features might not work.\n"),
                   pset.progname,
                   formatPGVersionNumber(client_ver, false,
                                         cverbuf, sizeof(cverbuf)),
                   formatPGVersionNumber(pset.sversion, false,
                                         sverbuf, sizeof(sverbuf)));

#ifdef WIN32
        checkWin32Codepage();
#endif
        printSSLInfo();
    }
}


/*
 * printSSLInfo
 *
 * Prints information about the current SSL connection, if SSL is in use
 */
static void
printSSLInfo(void)
{
    const char *protocol;
    const char *cipher;
    const char *bits;
    const char *compression;

    if (!PQsslInUse(pset.db))
        return;                    /* no SSL */

    protocol = PQsslAttribute(pset.db, "protocol");
    cipher = PQsslAttribute(pset.db, "cipher");
    bits = PQsslAttribute(pset.db, "key_bits");
    compression = PQsslAttribute(pset.db, "compression");

    printf(_("SSL connection (protocol: %s, cipher: %s, bits: %s, compression: %s)\n"),
           protocol ? protocol : _("unknown"),
           cipher ? cipher : _("unknown"),
           bits ? bits : _("unknown"),
           (compression && strcmp(compression, "off") != 0) ? _("on") : _("off"));
}


/*
 * checkWin32Codepage
 *
 * Prints a warning when win32 console codepage differs from Windows codepage
 */
#ifdef WIN32
static void
checkWin32Codepage(void)
{
    unsigned int wincp,
                concp;

    wincp = GetACP();
    concp = GetConsoleCP();
    if (wincp != concp)
    {
        printf(_("WARNING: Console code page (%u) differs from Windows code page (%u)\n"
                 "         8-bit characters might not work correctly. See bteq reference\n"
                 "         page \"Notes for Windows users\" for details.\n"),
               concp, wincp);
    }
}
#endif


/*
 * SyncVariables
 *
 * Make bteq's internal variables agree with connection state upon
 * establishing a new connection.
 */
void
SyncVariablesbteq(void)
{
    char        vbuf[32];
    const char *server_version;

    /* get stuff from connection */
    pset.encoding = PQclientEncoding(pset.db);
    pset.popt.topt.encoding = pset.encoding;
    pset.sversion = PQserverVersion(pset.db);

    SetVariable(pset.vars, "DBNAME", PQdb(pset.db));
    SetVariable(pset.vars, "USER", PQuser(pset.db));
    SetVariable(pset.vars, "HOST", PQhost(pset.db));
    SetVariable(pset.vars, "PORT", PQport(pset.db));
    SetVariable(pset.vars, "ENCODING", pg_encoding_to_char(pset.encoding));

    /* this bit should match connection_warnings(): */
    /* Try to get full text form of version, might include "devel" etc */
    server_version = PQparameterStatus(pset.db, "server_version");
    /* Otherwise fall back on pset.sversion */
    if (!server_version)
    {
        formatPGVersionNumber(pset.sversion, true, vbuf, sizeof(vbuf));
        server_version = vbuf;
    }
    SetVariable(pset.vars, "SERVER_VERSION_NAME", server_version);

    snprintf(vbuf, sizeof(vbuf), "%d", pset.sversion);
    SetVariable(pset.vars, "SERVER_VERSION_NUM", vbuf);

    /* send stuff to it, too */
    PQsetErrorVerbosity(pset.db, pset.verbosity);
    PQsetErrorContextVisibility(pset.db, pset.show_context);
}
