#define _BSD_SOURCE
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/stat.h>

#include<atf-c.h>

#define BUFFLEN 512
#define ERROR (-1)

char *filedesc = "/tmp/tmplog.txt";
char *dir1 = "/tmp/dir1";
mode_t mode = 0777;

static void
setup(void) {
    ATF_REQUIRE_EQ(0, system("{ service auditd onestatus || \
    { service auditd onestart && touch started_auditd ; } ; } && audit -n"));
}

static void
get_trail(char* syscall) {
    char buff1[BUFFLEN], buff2[BUFFLEN];
    char trail[BUFFLEN];

    FILE *fp = popen("ls /var/audit", "r");
    while(fgets(buff1, BUFFLEN, fp) != 0){
        if(strstr(buff1, ".not_terminated") != 0) {
            strtok(buff1, "\n");
            snprintf(trail, sizeof(trail), "%s | grep %s\n", buff1, syscall);
            break;
        }
        //fprintf(fp2, "%s", buff)
    }

    pclose(fp);

    char command[50]; strcpy(command, "praudit -l /var/audit/");
    strcat(command, trail);
    FILE *fp3 = fopen(filedesc, "w");

    FILE *fp2 = popen(command, "r");
    while(fgets(buff2, BUFFLEN, fp2)){
        fprintf(fp3, "%s", buff2);
    }

    pclose(fp2);
    fclose(fp3);

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
    char *syscall = "mkdir";

    setup();
    ATF_REQUIRE(mkdir(dir1, mode) != ERROR);
    get_trail(syscall);
    ATF_REQUIRE(atf_utils_grep_file(syscall, filedesc));

}

ATF_TC_CLEANUP(mkdir_failure, tc)
{
    system("service auditd onestop");
    unlink(filedesc);
}

ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, mkdir_failure);

    return atf_no_error();
}
