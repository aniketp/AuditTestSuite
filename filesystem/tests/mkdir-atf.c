#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/stat.h>

#include<atf-c.h>

#define ERROR (-1)

mode_t mode = 0777;
int filedesc = 0;
const char *dir1 = "/tmp/temp1", *dir2 = "/tmp/temp2";
char *fd = '/var/audit/203.2323';  // Example file

/*
 * Test1: mkdir(2) success
 */
ATF_TC(mkdir_success);
ATF_TC_HEAD(mkdir_success, tc)
{
    atf_tc_set_md_var(tc, "descr", "Checks the success condition of mkdir(2)");
}

ATF_TC_BODY(mkdir_success, tc)
{
    int filedesc1;
    if ((filedesc1 = mkdir(dir1, mode)) == ERROR){
        atf_tc_fail("mkdir error");
    }

    ATF_REQUIRE(atf_utils_grep_file("mkdir.2.*temp1.*return,success", fd));
}

/*
 * Test2: mkdir(2) failure
 */
ATF_TC(mkdir_failure);
ATF_TC_HEAD(mkdir_failure, tc)
{
    atf_tc_set_md_var(tc, "descr", "Checks the failure condition of mkdir(2)");
}

ATF_TC_BODY(mkdir_failure, tc)
{
    mkdir(dir1, mode);
    ATF_REQUIRE(atf_utils_grep_file("mkdir.2.*temp1.*return,failure", fd));
}

/*
 * Test3: mkdirat(2) success
 */
ATF_TC(mkdirat_success);
ATF_TC_HEAD(mkdirat_success, tc)
{
    atf_tc_set_md_var(tc, "descr", "Checks the success condition of mkdirat(2)");
}

ATF_TC_BODY(mkdirat_success, tc)
{
    int filedesc2;
    if ((filedesc2 = mkdirat(filedesc, dir2, mode)) == ERROR){
        atf_tc_fail("mkdirat error");
    }

    ATF_REQUIRE(atf_utils_grep_file("mkdirat.2.*temp2.*return,success", fd));
}

/*
 * Test4: mkdirat(2) failure
 */
 ATF_TC(mkdirat_failure);
 ATF_TC_HEAD(mkdirat_failure, tc)
 {
     atf_tc_set_md_var(tc, "descr", "Checks the failure condition of mkdirat(2)");
 }

 ATF_TC_BODY(mkdirat_failure, tc)
 {
     mkdirat(filedesc, dir2, mode);
     ATF_REQUIRE(atf_utils_grep_file("mkdirat.2.*temp2.*return,failure", fd));
 }


ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, mkdir_success);
    ATF_TP_ADD_TC(tp, mkdir_failure);
    ATF_TP_ADD_TC(tp, mkdirat_success);
    ATF_TP_ADD_TC(tp, mkdirat_failure);

    return atf_no_error();
}
