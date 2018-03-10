#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<fcntl.h>
#include<poll.h>
#include<atf-c.h>

#define BUFFLEN 512
#define ERROR (-1)

char *filedesc = "grepfile.txt";
char *filepath = "fileforaudit";
mode_t mode = 0777;

static void
setup(void) {
    ATF_REQUIRE_EQ(0, system("{ service auditd onestatus || \
    { service auditd onestart && touch started_auditd ; } ; } && audit -n \
    > /dev/null 2>&1 "));
}

static void
get_trail(char* path) {
    char buff[BUFFLEN];
    struct pollfd fds[1];
    int timeout = 5000;

    fds[0].fd = open(filedesc, O_RDWR);
    fds[0].events = POLLIN;

    FILE *fp1 = fopen(filedesc, "w");
    FILE *praudit = popen("praudit -l /dev/auditpipe", "r");

    if (poll(fds, 1, timeout) < 0) {
        perror("poll");
        exit(ERROR);
    } else {
        while(fgets(buff, BUFFLEN, praudit) != 0){
            if(strstr(buff, path) != 0) {
                // Writing to the grepfile.txt if file path found
                fprintf(fp1, "%s", buff);

                // If the write was successful, this condition must be true
                if (fds[0].revents & POLLIN) {
                    break;  // Success
                }
                if (fds[0].revents & POLLHUP) {
                    printf("Hangup\n"); break;
                }
            }
        }
    }

    close(fds[0].fd);
    pclose(praudit);
    fclose(fp1);


}

/*
 * Test2: mkdir(2) failure
 */
ATF_TC_WITH_CLEANUP(mkdir_failure);
ATF_TC_HEAD(mkdir_failure, tc)
{
    atf_tc_set_md_var(tc, "descr", "Checks the failure condition of mkdir(2)");
}

ATF_TC_BODY(mkdir_failure, tc)
{

    setup();
    sleep(1);
    mkdir(filepath, mode);
    get_trail(filepath);
    ATF_REQUIRE(atf_utils_grep_file("%s", filedesc, filepath));

}

ATF_TC_CLEANUP(mkdir_failure, tc)
{
    system("service auditd onestop");
}

ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, mkdir_failure);

    return atf_no_error();
}
