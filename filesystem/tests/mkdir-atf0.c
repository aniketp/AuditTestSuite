#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<errno.h>
#include<fcntl.h>
#include<sys/stat.h>
#include<poll.h>
#include<atf-c.h>

#define ERROR (-1)

static void
setup(void) {
    ATF_REQUIRE_EQ(0, system("{ service auditd onestatus || \
    { service auditd onestart && touch started_auditd ; } ; } && audit -n \
    > /dev/null 2>&1 "));
}

/*
 * Test1: mkdir(2) success
 */
ATF_TC_WITH_CLEANUP(mkdir_success);
ATF_TC_HEAD(mkdir_success, tc)
{
    atf_tc_set_md_var(tc, "descr", "Checks the success condition of mkdir(2)");
}

ATF_TC_BODY(mkdir_success, tc)
{
    char buff[512], cmd[64], buff2[512];
    struct pollfd fds[1];
    int timeout = 5000, ret = 0;
    char *file1 = "temp1", *file2 = "temp2";
    char *path = "fileforaudit";
    mode_t mode = 0777;

    /* Convert binary trail to human readable form (Temporary fix) */
    snprintf(cmd, sizeof(cmd), "praudit -l %s > %s", file1, file2);

    fds[0].fd = open("/dev/auditpipe", O_RDONLY);
    fds[0].events = POLLIN;
    setup();

    if (poll(fds, 1, timeout) < 0) {
        atf_tc_fail("Poll: %s", strerror(errno));
    } else {
        if (fds[0].revents & POLLIN) {
            ATF_REQUIRE((ret = read(fds[0].fd, buff2, sizeof(buff2))) != ERROR);
            /* Store the buffer in a file */
            FILE *fd = fopen(file1, "w");
            fwrite(buff2, 1, ret, fd);
            fclose(fd);

            /* We now have a proof that auditd(8) started smoothly */
            ATF_REQUIRE(system(cmd) != ERRO
        } else {
            /* revents is not POLLIN */
            atf_tc_fail("auditpipe returned an unknown event %#x", fds[0].revents);
        }
    }

    /* Check if the audit startup was properly logged */
    if(atf_utils_grep_file("audit startup", file2)){
        /* Success condition: mkdir(2) */
        ATF_REQUIRE_EQ(0, mkdir(path, mode));

        if (poll(fds, 1, timeout) < 0) {
            atf_tc_fail("Poll: %s", strerror(errno));
        } else {
            if (fds[0].revents & POLLIN) {
                ATF_REQUIRE((ret = read(fds[0].fd, buff, sizeof(buff))) != ERROR);
                /*
                 * Overwrite the previous logfile with the buffer containing
                 * mkdir(2) tokens along with some other utility system calls
                 */
                FILE *fd = fopen(file1, "w");
                fwrite(buff, 1, ret, fd);
                fclose(fd);
            } else {
                /* revents is not POLLIN */
                atf_tc_fail("auditpipe returned an unknown event %#x", \
                 fds[0].revents);
            }
        }
    }

    close(fds[0].fd);

    ATF_REQUIRE(system(cmd) != ERROR);
    ATF_REQUIRE(atf_utils_grep_file("%s", file2, path));

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
