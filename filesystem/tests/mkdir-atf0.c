#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<errno.h>
#include<fcntl.h>
#include<poll.h>
#include<time.h>

#include<sys/stat.h>
#include<sys/ioctl.h>

#include<atf-c.h>
#include<bsm/audit.h>
#include<bsm/libbsm.h>
#include<security/audit/audit_ioctl.h>

#define ERROR (-1)
#define BUFFLEN 1024

static void
setup(void)
{
    ATF_REQUIRE_EQ(0, system("service auditd onestatus || \
     { service auditd onestart && touch started_auditd ; }"));
}

static bool
getrecords(char *path, FILE *pipestream)
{
    u_char *buff;
    tokenstr_t token;
    ssize_t size = BUFFLEN;
    char *del = ",", membuff[size];
    int reclen, bytesread = 0;

    /*
     * Open a stream on 'membuff' (address to memory buffer) for storing
     * the audit records in the default mode.'reclen' is the length of the
     * available records from auditpipe and the let's the functions
     * au_fetch_tok(3) and au_print_flags_tok(3) do their respective jobs.
     */
    FILE *memstream = fmemopen(membuff, size, "w");
    ATF_REQUIRE(reclen = au_read_rec(pipestream, &buff) != ERROR);

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
 * Test1: mkdir(2) success
 */
ATF_TC_WITH_CLEANUP(mkdir_success);
ATF_TC_HEAD(mkdir_success, tc)
{
    atf_tc_set_md_var(tc, "descr", "Checks for the successful audit of "
                                    "mkdir(2)");
}

ATF_TC_BODY(mkdir_success, tc)
{
    struct pollfd fds[1];
    struct timespec endptr, curptr;
    mode_t mode = 0777;
    ssize_t size = BUFFLEN;

    char buff[size], buff2[size], membuff[size];
    int timeout = 2000, ret = 0;
    char *path = "fileforaudit", *auditpath="audit startup";


    /* Define arguments to configure local audit ioctls */
    int fmode = AUDITPIPE_PRESELECT_MODE_LOCAL;
    au_mask_t fmask;
    au_class_ent_t *class;

    ATF_REQUIRE((class = getauclassnam("fc")) != NULL);
    fmask.am_success = class->ac_class;
    fmask.am_failure = class->ac_class;

    /* Open /dev/auditpipe for auditing */
    fds[0].fd = open("/dev/auditpipe", O_RDONLY);
    fds[0].events = POLLIN;
    FILE *pipefd = fdopen(fds[0].fd, "r");
    setup();

    /*
     * Check if the audit startup was properly logged in the trail
     * If 'started_auditd' exists, that means we started auditd
     */
    if (atf_utils_file_exists("started_auditd")) {
        if (poll(fds, 1, timeout) < 0) {
            atf_tc_fail("Poll: %s", strerror(errno));
        } else {
            if (fds[0].revents & POLLIN) {
                /* We now have a proof that auditd(8) started smoothly */
                ATF_REQUIRE(getrecords(auditpath, pipefd));
            } else {
                /* revents is not POLLIN */
                atf_tc_fail("Auditpipe returned an unknown event "
                            "%#x", fds[0].revents);
            }
        }
    }

    /*
     * The next three steps ensure that the auditpipe(4) does not depend
     * on the universal audit configuration at /etc/security/audit_control
     * by setting the flag mask as the corresponding class of the event
     * to be audited, mkdir(2) in this case.
     */

    /* Set local preselection mode for auditing */
    if (ioctl(fds[0].fd, AUDITPIPE_SET_PRESELECT_MODE, &fmode) < 0) {
        atf_tc_fail("Preselection mode: %s", strerror(errno));
    }

    /* Set local preselection flag as (fc) for mkdir(2) */
    if (ioctl(fds[0].fd, AUDITPIPE_SET_PRESELECT_FLAGS, &fmask) < 0) {
        atf_tc_fail("Preselection flag: %s", strerror(errno));
    }

    /* This removes any outstanding record on audit pipe */
    if (ioctl(fds[0].fd, AUDITPIPE_FLUSH) < 0) {
        atf_tc_fail("Auditpipe flush: %s", strerror(errno));
    }

    /* Set the expire time for poll(2) while waiting for mkdir(2) */
    ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &endptr));
    endptr.tv_sec += 5;

    /* Success condition: mkdir(2) */
    ATF_REQUIRE_EQ(0, mkdir(path, mode));

    /*
     * Loop until the auditpipe returns something, check if it is what
     * we want else repeat the procedure until poll(2) times out.
     */
    while(true) {
        /* Update the current time left for auditpipe to return any event */
        ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &curptr));
        curptr.tv_sec = endptr.tv_sec - curptr.tv_sec;

        switch(ppoll(fds, 1, &curptr, NULL)) {
            /* ppoll(2) returns an event, check if it's the event we want */
            case 1:
                if (fds[0].revents & POLLIN) {
                    if (getrecords(path, pipefd)) {
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

    fclose(pipefd);
    close(fds[0].fd);

}

ATF_TC_CLEANUP(mkdir_success, tc)
{
    system("[ -f started_auditd ] && service auditd onestop > /dev/null 2>&1");
}

ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, mkdir_success);
    return atf_no_error();
}
