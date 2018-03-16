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
#include<security/audit/audit_ioctl.h>

#define ERROR (-1)

static void
setup() {
    ATF_REQUIRE_EQ(0, system("service auditd onestatus || \
     { service auditd onestart && touch started_auditd ; }"));
}

/*
 * Test1: mkdir(2) success
 */
ATF_TC_WITH_CLEANUP(mkdir_success);
ATF_TC_HEAD(mkdir_success, tc)
{
    atf_tc_set_md_var(tc, "descr", "Checks for the successful audit of"
                                    "mkdir(2)");
}

ATF_TC_BODY(mkdir_success, tc)
{
    char buff[512], cmd[64], buff2[512];
    struct pollfd fds[1];
    int timeout = 2000, ret = 0;
    char *file1 = "temp1", *file2 = "temp2";
    char *path = "fileforaudit";
    mode_t mode = 0777;

    /* Define arguments to configure local audit ioctls */
    int fmode = AUDITPIPE_PRESELECT_MODE_LOCAL;
    au_mask_t fmask;
    fmask.am_success = 0x00000010;
    fmask.am_failure = 0x00000010;

    /* Convert binary trail to human readable form (Temporary fix) */
    snprintf(cmd, sizeof(cmd), "praudit -l %s > %s", file1, file2);

    /* Open /dev/auditpipe for auditing */
    fds[0].fd = open("/dev/auditpipe", O_RDONLY);
    fds[0].events = POLLIN;
    setup();

    /* Check if the audit startup was properly logged */
    /* If 'started_auditd' exists, that means we started auditd */
    if (atf_utils_file_exists("started_auditd")) {
        if (poll(fds, 1, timeout) < 0) {
            atf_tc_fail("Poll: %s", strerror(errno));
        } else {
            if (fds[0].revents & POLLIN) {
                ATF_REQUIRE((ret = read(fds[0].fd, buff2, \
                     sizeof(buff2))) != ERROR);
                /* Store the buffer in a file */
                FILE *fd = fopen(file1, "w");
                fwrite(buff2, 1, ret, fd);
                fclose(fd);

                /* We now have a proof that auditd(8) started smoothly */
                ATF_REQUIRE(system(cmd) != ERROR);
            } else {
                /* revents is not POLLIN */
                atf_tc_fail("Auditpipe returned an unknown event"
                            "%#x", fds[0].revents);
            }
        }

        ATF_REQUIRE(atf_utils_grep_file("audit startup", file2));
    }

    /*
     * The next three steps ensure that the auditpipe(4) does not depend
     * on the universal audit configuration at /etc/security/audit_control
     * by setting the flag mask as the corresponding class of the event
     * to be audited, mkdir(2) in this case.
     */

    /* Set local preselection mode for auditing */
    if(ioctl(fds[0].fd, AUDITPIPE_SET_PRESELECT_MODE, &fmode) < 0){
        atf_tc_fail("Preselection mode: %s", strerror(errno));
    }

    /* Set local preselection flag as (fc) for mkdir(2) */
    if(ioctl(fds[0].fd, AUDITPIPE_SET_PRESELECT_FLAGS, &fmask) < 0){
        atf_tc_fail("Preselection flag: %s", strerror(errno));
    }

    /* This removes any outstanding record on audit pipe */
    if(ioctl(fds[0].fd, AUDITPIPE_FLUSH) < 0){
        atf_tc_fail("Auditpipe flush: %s", strerror(errno));
    }


    /* Success condition: mkdir(2) */
    ATF_REQUIRE_EQ(0, mkdir(path, mode));

    time_t end;
    end = time(NULL) + 5;

    /*
     * Loop until the auditpipe returns something, check if it is what
     * we want else repeat the procedure until poll(2) times out.
     */
    while(true){
        switch(poll(fds, 1, (end - time(NULL))*1000)){
            /* poll(2) returns an event, check if it's the event we want */
            case 1: {
                if (fds[0].revents & POLLIN) {
                    ATF_REQUIRE((ret = read(fds[0].fd, buff, \
                        sizeof(buff))) != ERROR);
                    FILE *fd = fopen(file1, "w");
                    fwrite(buff, 1, ret, fd);
                    fclose(fd);

                    ATF_REQUIRE(system(cmd) != ERROR);
                    if(atf_utils_grep_file("%s", file2, path)){
                        /* We have confirmed mkdir(2)'s audit */
                        atf_tc_pass();
                    }
                } else {
                    atf_tc_fail("Auditpipe returned an unknown event"
                                "%#x", fds[0].revents);
                }
            } break;

            /* poll(2) timed out */
            case 0:
                atf_tc_fail("Auditpipe did not return anything within"
                            "the time limit"); break;
            /* poll(2) standard error */
            case ERROR:
                atf_tc_fail("Poll: %s", strerror(errno)); break;

            default:
                atf_tc_fail("Poll returned an unknown value");
        }
    }

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
