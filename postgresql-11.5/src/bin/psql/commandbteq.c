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

#define MAX_WIDTH 1048575
#define MIN_WIDTH 20
#define LOGON_ERROR " *** Error:  Invalid logon!\n"
#define WIDTH_VALUE_ERROR " *** Error: WIDTH command keyword must be followed by a number.\n"
#define WIDTH_VALUE_RANGE_ERROR " *** Error: Width value must be in the 20..1048575 range.\n"
#define EXTRA_TEXT_ERROR " *** Error: Invalid command syntax.\n            Extra text found starting at '%s'.\n"
#define EXTRA_TEXT_WARNING " *** Warning: Ignoring extra text found starting at '%s'.\n              The current instruction's remaining text has been discarded.\n              Future BTEQ versions may not be able to be lenient\n              about this invalid syntax. Correct the script to\n              ensure it can continue to work.\n"
#define UNRECOGNIZED_SET_COMMAND_ERROR " *** Error: Unrecognized SET command '%s'.\n"
#define UNRECOGNIZED_COMMAND_ERROR " *** Error: Unrecognized command '%s'.\n"
#define UNRECOGNIZED_COMMAND " *** Error: Unrecognized command.\n"

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
static char *read_arg(BteqScanState scan_state);
static dotResult exec_command_quit(BteqScanState scan_state, bool active_branch);
static dotResult exec_command_set(BteqScanState scan_state, bool active_branch);
static void ignore_dot_options(BteqScanState scan_state);
static bool is_branching_command(const char *cmd);
static char *cat_space(char *str);
static void copy_previous_query(PQExpBuffer query_buf, PQExpBuffer previous_buf);
static bool do_connect(enum trivalue reuse_previous_specification,
                       char *dbname, char *user, char *host, char *port,
                       char *password);
static void printSSLInfo(void);
char *to_uppper(char *str);
void cat_symbols(char *str, char *symbols);

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
    Assert(scan_state != NULL);
    Assert(cstack != NULL);

    /* Parse off the command name */
    cmd = bteq_scan_dot_command(scan_state);
    cat_symbols(cmd, "; ");
    if (PQstatus(pset.db) == CONNECTION_BAD && !PSCAN_BTEQ_DOT) {
        printf("Enter your logon or BTEQ command\n");
        return BTEQ_CMD_NEWEDIT;
    }

    /* And try to execute it */
    status = exec_command(cmd, scan_state, cstack, query_buf, previous_buf);

    if (status == BTEQ_CMD_UNKNOWN)
    {
        if (cmd == NULL || strcasecmp(cmd, "") == 0) {
            printf(UNRECOGNIZED_COMMAND);
        } else {
            printf(UNRECOGNIZED_COMMAND_ERROR, to_uppper(cmd));
        }
        
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
                                             OT_BTEQ_NORMAL, NULL, true)))
        {
            if (active_branch)
                printf(EXTRA_TEXT_ERROR, arg);
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
        psql_error(".%s command ignored; use \\endif or Ctrl-C to exit current \\if block\n",
                   cmd);
    }

    if (strcasecmp(cmd, "logon") == 0) {
        status = exec_command_logon(scan_state, active_branch);
    } else if (strcasecmp(cmd, "set") == 0) {
        status = exec_command_set(scan_state, active_branch);
    } else if (strcasecmp(cmd, "quit") == 0 || strcasecmp(cmd, "q") == 0) {
        status = exec_command_quit(scan_state, active_branch);
    } else {
        status = BTEQ_CMD_UNKNOWN;
    }
    /*
     * All the commands that return BTEQ_CMD_SEND want to execute previous_buf
     * if query_buf is empty.  For convenience we implement that here, not in
     * the individual command subroutines.
     */
    if (status == BTEQ_CMD_SEND)
        copy_previous_query(query_buf, previous_buf);

    return status;
}


void
extract_token(char *command, char *delimiter, char **left, char **right) {

    if (command == NULL || strcasecmp(command, "") == 0 ) {
        return;
    }
    char *command_dup = strdup(command);

    char *tmp;
    tmp = strtok(command_dup, delimiter);

    if (tmp != NULL) {
       *left = strdup(tmp);
    }
    if (left != NULL) {
        tmp = strtok(NULL,delimiter);
        if (tmp != NULL) {
            *right = strdup(tmp);
        }
    }
    free(command_dup);
}


/*
 * .logon -- toggle field alignment
 *
 * This makes little sense but we keep it around.
 */
static dotResult
exec_command_logon(BteqScanState scan_state, bool active_branch)
{
    char *host_port = NULL;
    char *user_pass = NULL;
    char *host = NULL;
    char *port = NULL;
    char *user = NULL;
    char *pass = NULL;

    char *logon = bteq_scan_dot_option(scan_state, OT_BTEQ_WHOLE_LINE,
                                       NULL, false);
    if (logon != NULL) {
        logon = cat_space(logon);
        extract_token(logon, "/", &host_port, &user_pass);
    }

    if (host_port != NULL) {
        extract_token(host_port, ":", &host, &port);
    }

    if (user_pass != NULL) {
        extract_token(user_pass, ",", &user, &pass);
    }

    bool success = true;

    if (host == NULL || user == NULL) {
        printf("All connection parameters must be supplied because no "
                   "database connection exists\n");
        success = false;
        goto cleanup;
    }

    if (pset.cur_cmd_interactive) {
        if (user) {
            user = cat_space(user);
            cat_symbols(user,"; \t");
        }
        if (pass != NULL && strlen(pass) > 0) {

            printf(LOGON_ERROR);
            success = false;
            goto cleanup;
        }
        pass = (char *)malloc(50*sizeof(char));
        simple_prompt("Password ", pass, 50, false);
    } else {
        if (pass) {
            pass = cat_space(pass);
        }
    }

    success = do_connect(TRI_NO, NULL, user, host, port, pass);
cleanup:
    free(logon);
    free(host_port);
    free(user_pass);
    free(host);
    free(port);
    free(user);
    free(pass);
    return success ? BTEQ_CMD_SKIP_LINE : BTEQ_CMD_ERROR;
}


/*
 * .q or .quit -- exit BTEQ
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
 * .set -- set variable
 */
static dotResult
exec_command_set(BteqScanState scan_state, bool active_branch)
{
    bool        success = true;
    if (active_branch)
    {
        char *width_keyword = read_arg(scan_state);
        if (width_keyword == NULL ) {
            return BTEQ_CMD_UNKNOWN;
        }
        char       *width_arg;
        char       *ptr;
        if (strcasecmp(width_keyword, "width") == 0) {
            width_arg = read_arg(scan_state);
            if (width_arg == NULL) {
                printf(WIDTH_VALUE_ERROR);
                return BTEQ_CMD_ERROR;
            }
            int width_value = strtol(width_arg, &ptr, 10);
            char *arg = bteq_scan_dot_option(scan_state, OT_BTEQ_WHOLE_LINE, NULL, true);
            cat_symbols(arg, "; \t");
            if (*ptr) {
                printf(WIDTH_VALUE_ERROR);
                success = false;
            } else if (width_value < MIN_WIDTH || width_value > MAX_WIDTH) {
                printf(WIDTH_VALUE_RANGE_ERROR);
                success = false;
            } else {
                if (arg != NULL && arg[0] != '\0') {
                    if (pset.cur_cmd_interactive) {
                        printf(EXTRA_TEXT_ERROR, arg);
                    } else {
                        printf(EXTRA_TEXT_WARNING, arg);
                    }
                    free(arg);
                }
                pset.popt_bteq.topt.table_width = width_value;
            }
            free(width_arg);
        } else {
            printf(UNRECOGNIZED_SET_COMMAND_ERROR, to_uppper(width_keyword));
            success = false;
        }
        free(width_keyword);
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
 * do_connect -- handler for .logon
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
           char *dbname, char *user, char *host, char *port,char *password)
{
    bool have_password = false;
    bool new_pass = false;
    do
    {
#define PARAMS_ARRAY_SIZE    8
        const char **keywords = pg_malloc(PARAMS_ARRAY_SIZE * sizeof(*keywords));
        const char **values = pg_malloc(PARAMS_ARRAY_SIZE * sizeof(*values));

        keywords[0] = "host";
        values[0] = host;
        keywords[1] = "port";
        values[1] = port;
        keywords[2] = "user";
        values[2] = user;
        keywords[3] = "password";
        values[3] = have_password ? password : NULL;
        keywords[4] = "dbname"; /* see do_connect() */
        values[4] = (dbname == NULL) ?
            "postgres" : dbname;
        keywords[5] = "fallback_application_name";
        values[5] = pset.progname;
        keywords[6] = "client_encoding";
        values[6] = (pset.notty || getenv("PGCLIENTENCODING")) ? NULL : "auto";
        keywords[7] = NULL;
        values[7] = NULL;

        new_pass = false;
        pset.db = PQconnectdbParams(keywords, values, true);
        free(keywords);
        free(values);

        if (PQstatus(pset.db) == CONNECTION_BAD &&
            PQconnectionNeedsPassword(pset.db) &&
            !have_password &&
            pset.getPassword != TRI_NO )
        {
            /*
             * Before closing the old PGconn, extract the user name that was
             * actually connected with --- it might've come out of a URI or
             * connstring "database name" rather than options.username.
             */
            const char *realusername = PQuser(pset.db);
            char       *password_prompt;

            if (realusername && realusername[0])
                password_prompt = psprintf(_("Password %s: "),
                                           realusername);
            else
                password_prompt = pg_strdup(_("Password: "));
            PQfinish(pset.db);
            free(password_prompt);
            have_password = true;
            new_pass = true;
        }
    } while (new_pass);

    if (PQstatus(pset.db) == CONNECTION_BAD) {
        fprintf(stderr, "%s: %s", pset.progname, PQerrorMessage(pset.db));
        PQfinish(pset.db);
        exit(EXIT_FAILURE);
    }
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
 * SyncVariablesbteq
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

    /* this bit should match connection_warningsbteq(): */
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

/*
 * Read and interpret an argument to the dot command.
 *
 * Returns a malloc'd string, or NULL if no/empty argument.
 */


static char *
read_arg(BteqScanState scan_state)
{
    char       *result;
    char        quote;

    /*
     * Ideally we should treat the arguments as SQL identifiers.  But for
     * backwards compatibility with 7.2 and older pg_dump files, we have to
     * take unquoted arguments verbatim (don't downcase them). For now,
     * double-quoted arguments may be stripped of double quotes (as if SQL
     * identifiers).  By 7.4 or so, pg_dump files can be expected to
     * double-quote all mixed-case dot command arguments, and then we can get rid
     * of OT_BTEQ_NORMAL.
     */
    result = bteq_scan_dot_option(scan_state, OT_BTEQ_NORMAL, &quote, true);

    if (!result)
        return NULL;

    if (quote)
        return result;

    if (*result == '\0' || strcmp(result, "-") == 0)
    {
        free(result);
        return NULL;
    }

    return result;
}


/*
* cat spaces
*/
static char *
cat_space(char *str) {
    size_t len = 0;
    if (str == NULL || strcasecmp(str,"") == 0) {
        return "";
    }

    len = strlen(str)-1;
    while (str[len] == ' ' || str[len] == '\t' || str[len] == '\r') {
        str[len--] = '\0';
    }

    while ((*str == ' '|| *str == '\t' || *str == '\r') && *str != '\0') {
        str++;
    }

    if (str[len] == ';') {
        str[len] = '\0';
    }
    return str;
}


/*
 * process_file_bteq
 *
 * Reads commands from filename and passes them to the main processing loop.
 * Handler for \i and \ir, but can be used for other things as well.  Returns
 * MainLoopBteq() error code.
 *
 * If use_relative_path is true and filename is not an absolute path, then open
 * the file from where the currently processed file (if any) is located.
 */


int
process_file_bteq(char *filename, bool use_relative_path)
{
    FILE       *fd;
    int            result;
    char       *oldfilename;
    char        relpath[MAXPGPATH];
    if (!filename)
    {
        fd = stdin;
        filename = NULL;
    }
    else if (strcmp(filename, "-") != 0)
    {
        canonicalize_path(filename);

        /*
         * If we were asked to resolve the pathname relative to the location
         * of the currently executing script, and there is one, and this is a
         * relative pathname, then prepend all but the last pathname component
         * of the current script to this pathname.
         */
        if (use_relative_path && pset.inputfile &&
            !is_absolute_path(filename) && !has_drive_prefix(filename))
        {
            strlcpy(relpath, pset.inputfile, sizeof(relpath));
            get_parent_directory(relpath);
            join_path_components(relpath, relpath, filename);
            canonicalize_path(relpath);

            filename = relpath;
        }

        fd = fopen(filename, PG_BINARY_R);
        if (!fd)
        {
            psql_error("%s: %s\n", filename, strerror(errno));
            return EXIT_FAILURE;
        }
    }
    else
    {
        fd = stdin;
        filename = "<stdin>";    /* for future error messages */
    }

    oldfilename = pset.inputfile;
    pset.inputfile = filename;
    result = MainLoopBteq(fd);

    if (fd != stdin)
        fclose(fd);

    pset.inputfile = oldfilename;
    return result;
}


/*
* String to uppercase
*/
char *
to_uppper(char *str) {
    if (str == NULL) {
        return NULL;
    }
    int i = 0;
    while (*(str + i) != '\0') {
        *(str + i) = toupper(*(str + i));
        i++;
    }
    return str;
}


/*
* Delete the selected symbols at the end of the string
*/
void
cat_symbols(char *str, char *symbols) {
    if (str == NULL || symbols == NULL) {
        return;
    }
    int len = strlen(str) - 1;
    for (int i = 0; symbols[i] != '\0'; i++) {
        while (*(str + len) == symbols[i] && *str != '\0') {
            *(str + len--) = '\0';
            i = 0;
        }
    }
}