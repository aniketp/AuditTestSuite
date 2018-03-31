#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>

#include<poll.h>
#include<time.h>
#include<errno.h>
#include<fcntl.h>
#include<sys/stat.h>
#include<sys/ioctl.h>

#include<atf-c.h>
#include<bsm/audit.h>
#include<bsm/libbsm.h>
#include<security/audit/audit_ioctl.h>

#define ERROR (-1)
#define BUFFLEN 1024

struct pollfd fds[1];
mode_t mode = 0777;
char *path = "fileforaudit";
char *successreg = "fileforaudit.*return,success";
char *failurereg = "fileforaudit.*return,failure";

static bool
get_records(char *path, FILE *pipestream)
{
    u_char *buff;
    tokenstr_t token;
    ssize_t size = BUFFLEN;
    char *del = ",", membuff[size];
    int reclen, bytesread = 0;

    /*
     * Open a stream on 'membuff' (address to memory buffer) for storing
     * the audit records in the default mode.'reclen' is the length of the
     * available records from auditpipe which is passed to the functions
     * au_fetch_tok(3) and au_print_flags_tok(3) for further use.
     */
    FILE *memstream = fmemopen(membuff, size, "w");
    reclen = au_read_rec(pipestream, &buff);

    /*
     * Iterate through each BSM token, extracting the bits that are
     * required to starting processing sequences.
     */
    while (bytesread < reclen) {
        if (au_fetch_tok(&token, buff + bytesread, \
             reclen - bytesread) == ERROR) {
            atf_tc_fail("Incomplete audit record");
        };

    /* Print the tokens as they are obtained, in their default form */
        au_print_flags_tok(memstream, &token, del, AU_OFLAG_NONE);
        bytesread += token.len;
    }

    free(buff); fclose(memstream);
    return atf_utils_grep_string("%s", membuff, path);
}

/*
 * Ensure that the auditpipe(4) does not depend on the universal
 * audit configuration at /etc/security/audit_control by setting
 * the flag mask as the corresponding audit_class of the event
 */
static void
set_preselect_mode(int filedesc, au_mask_t *fmask) {
    int fmode = AUDITPIPE_PRESELECT_MODE_LOCAL;

    /* Set local preselection mode for auditing */
    if (ioctl(filedesc, AUDITPIPE_SET_PRESELECT_MODE, &fmode) < 0) {
        atf_tc_fail("Preselection mode: %s", strerror(errno));
    }

    /* Set local preselection flag corresponding to the audit_event*/
    if (ioctl(filedesc, AUDITPIPE_SET_PRESELECT_FLAGS, fmask) < 0) {
        atf_tc_fail("Preselection flag: %s", strerror(errno));
    }

    /* This removes any outstanding record on the auditpipe */
    if (ioctl(filedesc, AUDITPIPE_FLUSH) < 0) {
        atf_tc_fail("Auditpipe flush: %s", strerror(errno));
    }
}

/*
 * Check if the auditd(8) startup was properly received at the auditpipe
 */
static void
check_audit_startup(struct pollfd fds[], FILE *pipestream) {
    int timeout = 2000;
    char *auditpath = "audit startup";

    if (poll(fds, 1, timeout) < 0) {
        atf_tc_fail("Poll: %s", strerror(errno));
    } else {
        if (fds[0].revents & POLLIN) {
            /* We now have a proof that auditd(8) started smoothly */
            ATF_REQUIRE(get_records(auditpath, pipestream));
        } else {
            /* revents is not POLLIN */
            atf_tc_fail("Auditpipe returned an unknown event "
                        "%#x", fds[0].revents);
        }
    }
}

/*
 * Loop until the auditpipe returns something, check if it is what
 * we want else repeat the procedure until ppoll(2) times out.
 */
static void
check_audit(struct pollfd fds[], char *path, FILE *pipestream) {
    struct timespec curptr, endptr;

    /* Set the expire time for poll(2) while waiting for mkdir(2) */
    ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &endptr));
    endptr.tv_sec += 5;

    while(true) {
        /* Update the current time left for auditpipe to return any event */
        ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &curptr));
        curptr.tv_sec = endptr.tv_sec - curptr.tv_sec;

        switch(ppoll(fds, 1, &curptr, NULL)) {
            /* ppoll(2) returns an event, check if it's the event we want */
            case 1:
                if (fds[0].revents & POLLIN) {
                    if (get_records(path, pipestream)) {
                    /* We have confirmed mkdir(2)' audit */
                        atf_tc_pass();
                    }
                } else {
                    atf_tc_fail("Auditpipe returned an unknown event "
                                "%#x", fds[0].revents);
                } break;

            /* poll(2) timed out */
            case 0:
                atf_tc_fail("Auditpipe did not return anything within "
                            "the time limit"); break;
            /* poll(2) standard error */
            case ERROR:
                atf_tc_fail("Poll: %s", strerror(errno)); break;

            default:
                atf_tc_fail("Poll returned an unknown event");
        }
    }
}

/*
 * Get the corresponding audit_class for class-name "name" then set the
 * success and failure bits for fmask to be used as the ioctl argument
 */
static au_mask_t
get_audit_class(const char *name) {
    au_mask_t fmask;
    au_class_ent_t *class;

    ATF_REQUIRE((class = getauclassnam(name)) != NULL);
    fmask.am_success = class->ac_class;
    fmask.am_failure = class->ac_class;
    return fmask;
}

static FILE
*setup(struct pollfd fds[], const char *name)
{
    au_mask_t fmask;
    fmask = get_audit_class(name);

    fds[0].fd = open("/dev/auditpipe", O_RDONLY);
    fds[0].events = POLLIN;
    FILE *pipestream = fdopen(fds[0].fd, "r");

    ATF_REQUIRE_EQ(0, system("service auditd onestatus || \
     { service auditd onestart && touch started_auditd ; }"));

    /* If 'started_auditd' exists, that means we started auditd */
    if (atf_utils_file_exists("started_auditd")) {
        check_audit_startup(fds, pipestream);
    }
    set_preselect_mode(fds[0].fd, &fmask);
    return pipestream;
}

static void
cleanup(struct pollfd fds[], FILE *pipestream) {
    fclose(pipestream);
    close(fds[0].fd);
}


/*
 * Test1: mkdir(2) success
 */
ATF_TC_WITH_CLEANUP(mkdir_success);
ATF_TC_HEAD(mkdir_success, tc)
{
    atf_tc_set_md_var(tc, "descr", "Checks for the successful audit of "
                                    "mkdir(2) in success mode");
}

ATF_TC_BODY(mkdir_success, tc)
{
    FILE *pipefd = setup(fds, "fc");
    /* Success condition: mkdir(2) */
    ATF_REQUIRE_EQ(0, mkdir(path, mode));
    check_audit(fds, successreg, pipefd);
    cleanup(fds, pipefd);
}

ATF_TC_CLEANUP(mkdir_success, tc)
{
    system("[ -f started_auditd ] && service auditd onestop > /dev/null 2>&1");
}


/*
 * Test2: mkdir(2) failure
 */
ATF_TC_WITH_CLEANUP(mkdir_failure);
ATF_TC_HEAD(mkdir_failure, tc)
{
    atf_tc_set_md_var(tc, "descr", "Checks for the successful audit of "
                                    "mkdir(2) in failure mode");
}

ATF_TC_BODY(mkdir_failure, tc)
{
    ATF_REQUIRE_EQ(0, mkdir(path, mode));
    FILE *pipefd = setup(fds, "fc");
    /* Failure condition: mkdir(2) */
    ATF_REQUIRE_EQ(ERROR, mkdir(path, mode));
    check_audit(fds, failurereg, pipefd);
    cleanup(fds, pipefd);
}

ATF_TC_CLEANUP(mkdir_failure, tc)
{
    system("[ -f started_auditd ] && service auditd onestop > /dev/null 2>&1");
}


/*
 * Test3: mkdirat(2) success
 */
ATF_TC_WITH_CLEANUP(mkdirat_success);
ATF_TC_HEAD(mkdirat_success, tc)
{
    atf_tc_set_md_var(tc, "descr", "Checks for the successful audit of "
                                    "mkdirat(2) in success mode");
}

ATF_TC_BODY(mkdirat_success, tc)
{
    FILE *pipefd = setup(fds, "fc");
    /* Success condition: mkdirat(2) */
    ATF_REQUIRE_EQ(0, mkdirat(AT_FDCWD, path, mode));
    check_audit(fds, successreg, pipefd);
    cleanup(fds, pipefd);
}

ATF_TC_CLEANUP(mkdirat_success, tc)
{
    system("[ -f started_auditd ] && service auditd onestop > /dev/null 2>&1");
}


/*
 * Test4: mkdir(2) failure
 */
ATF_TC_WITH_CLEANUP(mkdirat_failure);
ATF_TC_HEAD(mkdirat_failure, tc)
{
    atf_tc_set_md_var(tc, "descr", "Checks for the successful audit of "
                                    "mkdirat(2) in failure mode");
}

ATF_TC_BODY(mkdirat_failure, tc)
{
    ATF_REQUIRE_EQ(0, mkdirat(AT_FDCWD, path, mode));
    FILE *pipefd = setup(fds, "fc");
    /* Failure condition: mkdirat(2) */
    ATF_REQUIRE_EQ(ERROR, mkdirat(AT_FDCWD, path, mode));
    check_audit(fds, failurereg, pipefd);
    cleanup(fds, pipefd);
}

ATF_TC_CLEANUP(mkdirat_failure, tc)
{
    system("[ -f started_auditd ] && service auditd onestop > /dev/null 2>&1");
}


ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, mkdir_success);
    ATF_TP_ADD_TC(tp, mkdir_failure);
    ATF_TP_ADD_TC(tp, mkdirat_success);
    ATF_TP_ADD_TC(tp, mkdirat_failure);
    return atf_no_error();
}
