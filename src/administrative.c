/*-
 * Copyright (c) 2018 Aniket Pandey
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <ufs/ufs/quota.h>

#include <atf-c.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <bsm/audit.h>

#include "utils.h"

static pid_t pid;
static mode_t mode = 0777;
static struct pollfd fds[1];
static char adregex[60];
static const char *path = "fileforaudit";


ATF_TC_WITH_CLEANUP(settimeofday_success);
ATF_TC_HEAD(settimeofday_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"settimeofday(2) call");
}

ATF_TC_BODY(settimeofday_success, tc)
{
	pid = getpid();
	snprintf(adregex, 60, "settimeofday.*%d.*return,success", pid);

	struct timeval tp;
	struct timezone tzp;
	ATF_REQUIRE_EQ(0, gettimeofday(&tp, &tzp));

	FILE *pipefd = setup(fds, "ad");
	/* Setting the same time as obtained by gettimeofday(2) */
	ATF_REQUIRE_EQ(0, settimeofday(&tp, &tzp));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(settimeofday_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(settimeofday_failure);
ATF_TC_HEAD(settimeofday_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"settimeofday(2) call");
}

ATF_TC_BODY(settimeofday_failure, tc)
{
	pid = getpid();
	snprintf(adregex, 60, "settimeofday.*%d.*return,failure", pid);

	struct timeval tp;
	struct timezone tzp;
	ATF_REQUIRE_EQ(0, gettimeofday(&tp, &tzp));

	FILE *pipefd = setup(fds, "ad");
	/* Invalid value for tp.tv_sec; */
	tp.tv_sec = -1;
	ATF_REQUIRE_EQ(-1, settimeofday(&tp, &tzp));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(settimeofday_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(adjtime_success);
ATF_TC_HEAD(adjtime_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"adjtime(2) call");
}

ATF_TC_BODY(adjtime_success, tc)
{
	pid = getpid();
	snprintf(adregex, 60, "adjtime.*%d.*return,success", pid);

	FILE *pipefd = setup(fds, "ad");
	/* We don't want to change the system time, hence NULL */
	ATF_REQUIRE_EQ(0, adjtime(NULL,NULL));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(adjtime_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(adjtime_failure);
ATF_TC_HEAD(adjtime_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"adjtime(2) call");
}

ATF_TC_BODY(adjtime_failure, tc)
{
	pid = getpid();
	snprintf(adregex, 60, "adjtime.*%d.*return,failure", pid);

	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(-1, adjtime((struct timeval *)(-1), NULL));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(adjtime_failure, tc)
{
	cleanup();
}



ATF_TC_WITH_CLEANUP(nfs_getfh_success);
ATF_TC_HEAD(nfs_getfh_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"getfh(2) call");
}

ATF_TC_BODY(nfs_getfh_success, tc)
{
	fhandle_t fhp;
	pid = getpid();
	snprintf(adregex, 60, "nfs_getfh.*%d.*return,success", pid);

	/* File needs to exist to call getfh(2) */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(0, getfh(path, &fhp));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(nfs_getfh_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(nfs_getfh_failure);
ATF_TC_HEAD(nfs_getfh_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"getfh(2) call");
}

ATF_TC_BODY(nfs_getfh_failure, tc)
{
	pid = getpid();
	snprintf(adregex, 60, "nfs_getfh.*%d.*return,failure", pid);

	FILE *pipefd = setup(fds, "ad");
	/* Failure reason: file does not exist */
	ATF_REQUIRE_EQ(-1, getfh(path, NULL));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(nfs_getfh_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(getauid_success);
ATF_TC_HEAD(getauid_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"getauid(2) call");
}

ATF_TC_BODY(getauid_success, tc)
{
	au_id_t auid;
	pid = getpid();
	snprintf(adregex, 60, "getauid.*%d.*return,success", pid);

	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(0, getauid(&auid));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(getauid_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(getauid_failure);
ATF_TC_HEAD(getauid_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"getauid(2) call");
}

ATF_TC_BODY(getauid_failure, tc)
{
	pid = getpid();
	snprintf(adregex, 60, "getauid.*%d.*return,failure", pid);

	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(-1, getauid(NULL));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(getauid_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(setauid_success);
ATF_TC_HEAD(setauid_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"setauid(2) call");
}

ATF_TC_BODY(setauid_success, tc)
{
	au_id_t auid;
	pid = getpid();
	snprintf(adregex, 60, "setauid.*%d.*return,success", pid);
	ATF_REQUIRE_EQ(0, getauid(&auid));

	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(0, setauid(&auid));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(setauid_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(setauid_failure);
ATF_TC_HEAD(setauid_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"setauid(2) call");
}

ATF_TC_BODY(setauid_failure, tc)
{
	pid = getpid();
	snprintf(adregex, 60, "setauid.*%d.*return,failure", pid);

	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(-1, setauid(NULL));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(setauid_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(getaudit_success);
ATF_TC_HEAD(getaudit_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"getaudit(2) call");
}

ATF_TC_BODY(getaudit_success, tc)
{
	auditinfo_t auditinfo;
	pid = getpid();
	snprintf(adregex, 60, "getaudit.*%d.*return,success", pid);

	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(0, getaudit(&auditinfo));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(getaudit_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(getaudit_failure);
ATF_TC_HEAD(getaudit_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"getaudit(2) call");
}

ATF_TC_BODY(getaudit_failure, tc)
{
	pid = getpid();
	snprintf(adregex, 60, "getaudit.*%d.*return,failure", pid);

	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(-1, getaudit(NULL));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(getaudit_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(setaudit_success);
ATF_TC_HEAD(setaudit_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"setaudit(2) call");
}

ATF_TC_BODY(setaudit_success, tc)
{
	auditinfo_t auditinfo;
	pid = getpid();
	snprintf(adregex, 60, "setaudit.*%d.*return,success", pid);
	ATF_REQUIRE_EQ(0, getaudit(&auditinfo));

	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(0, setaudit(&auditinfo));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(setaudit_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(setaudit_failure);
ATF_TC_HEAD(setaudit_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"setaudit(2) call");
}

ATF_TC_BODY(setaudit_failure, tc)
{
	pid = getpid();
	snprintf(adregex, 60, "setaudit.*%d.*return,failure", pid);

	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(-1, setaudit(NULL));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(setaudit_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(getaudit_addr_success);
ATF_TC_HEAD(getaudit_addr_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"getaudit_addr(2) call");
}

ATF_TC_BODY(getaudit_addr_success, tc)
{
	auditinfo_addr_t auditinfo;
	u_int *length = (u_int *)malloc(sizeof(u_int));
	pid = getpid();
	snprintf(adregex, 60, "getaudit_addr.*%d.*return,success", pid);

	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(0, getaudit_addr(&auditinfo, *length));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(getaudit_addr_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(getaudit_addr_failure);
ATF_TC_HEAD(getaudit_addr_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"getaudit_addr(2) call");
}

ATF_TC_BODY(getaudit_addr_failure, tc)
{
	pid = getpid();
	snprintf(adregex, 60, "getaudit_addr.*%d.*return,failure", pid);

	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(-1, getaudit_addr(NULL, 0));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(getaudit_addr_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(setaudit_addr_success);
ATF_TC_HEAD(setaudit_addr_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"setaudit_addr(2) call");
}

ATF_TC_BODY(setaudit_addr_success, tc)
{
	auditinfo_addr_t auditinfo;
	u_int *length = (u_int *)malloc(sizeof(u_int));
	pid = getpid();
	snprintf(adregex, 60, "setaudit_addr.*%d.*return,success", pid);
	ATF_REQUIRE_EQ(0, getaudit_addr(&auditinfo, *length));

	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(0, setaudit_addr(&auditinfo, *length));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(setaudit_addr_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(setaudit_addr_failure);
ATF_TC_HEAD(setaudit_addr_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"setaudit_addr(2) call");
}

ATF_TC_BODY(setaudit_addr_failure, tc)
{
	pid = getpid();
	snprintf(adregex, 60, "setaudit_addr.*%d.*return,failure", pid);

	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(-1, setaudit_addr(NULL, 0));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(setaudit_addr_failure, tc)
{
	cleanup();
}


/*
 * Audit of reboot(2) cannot be tested in normal conditions as we don't want
 * to reboot the system while running the tests
 */


ATF_TC_WITH_CLEANUP(reboot_failure);
ATF_TC_HEAD(reboot_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"reboot(2) call");
}

ATF_TC_BODY(reboot_failure, tc)
{
	pid = getpid();
	snprintf(adregex, 60, "reboot.*%d.*return,failure", pid);

	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(-1, reboot(-1));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(reboot_failure, tc)
{
	cleanup();
}


/*
 * Audit of acct(2) cannot be tested in normal conditions as we don't want
 * to enable/disable the collection of system accounting records
 */


ATF_TC_WITH_CLEANUP(acct_failure);
ATF_TC_HEAD(acct_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"acct(2) call");
}

ATF_TC_BODY(acct_failure, tc)
{
	pid = getpid();
	snprintf(adregex, 60, "acct.*%d.*return,failure", pid);

	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(-1, acct(path));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(acct_failure, tc)
{
	cleanup();
}


/*
 * Audit of quotactl(2) cannot be tested in normal conditions as we don't want
 * to tamper with filesystem quotas
 */


ATF_TC_WITH_CLEANUP(quotactl_failure);
ATF_TC_HEAD(quotactl_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"quotactl(2) call");
}

ATF_TC_BODY(quotactl_failure, tc)
{
	pid = getpid();
	snprintf(adregex, 60, "quotactl.*%d.*return,failure", pid);

	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(-1, quotactl(NULL, 0, 0, NULL));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(quotactl_failure, tc)
{
	cleanup();
}


/*
 * Audit of mount(2) and nmount(2) cannot be tested in normal
 * conditions as we are not allowed to mount a filesystem.
 */


ATF_TC_WITH_CLEANUP(mount_failure);
ATF_TC_HEAD(mount_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"mount(2) call");
}

ATF_TC_BODY(mount_failure, tc)
{
	pid = getpid();
	snprintf(adregex, 60, "mount.*%d.*return,failure", pid);

	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(-1, mount(NULL, NULL, 0, NULL));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(mount_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(nmount_failure);
ATF_TC_HEAD(nmount_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"nmount(2) call");
}

ATF_TC_BODY(nmount_failure, tc)
{
	pid = getpid();
	snprintf(adregex, 60, "nmount.*%d.*return,failure", pid);

	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(-1, nmount(NULL, 0, 0));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(nmount_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(ntp_adjtime_failure);
ATF_TC_HEAD(ntp_adjtime_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"ntp_adjtime(2) call");
}

ATF_TC_BODY(ntp_adjtime_failure, tc)
{
	pid = getpid();
	snprintf(adregex, 60, "ntp_adjtime.*%d.*return,failure", pid);

	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(-1, ntp_adjtime(NULL));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(ntp_adjtime_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(auditctl_failure);
ATF_TC_HEAD(auditctl_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"auditctl(2) call");
}

ATF_TC_BODY(auditctl_failure, tc)
{
	pid = getpid();
	snprintf(adregex, 60, "auditctl.*%d.*return,failure", pid);

	FILE *pipefd = setup(fds, "ad");
	ATF_REQUIRE_EQ(-1, auditctl(NULL));
	check_audit(fds, adregex, pipefd);
}

ATF_TC_CLEANUP(auditctl_failure, tc)
{
	cleanup();
}



ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, settimeofday_success);
	ATF_TP_ADD_TC(tp, settimeofday_failure);
	ATF_TP_ADD_TC(tp, adjtime_success);
	ATF_TP_ADD_TC(tp, adjtime_failure);

	ATF_TP_ADD_TC(tp, nfs_getfh_success);
	ATF_TP_ADD_TC(tp, nfs_getfh_failure);

	ATF_TP_ADD_TC(tp, getauid_success);
	ATF_TP_ADD_TC(tp, getauid_failure);
	ATF_TP_ADD_TC(tp, setauid_success);
	ATF_TP_ADD_TC(tp, setauid_failure);

	ATF_TP_ADD_TC(tp, getaudit_success);
	ATF_TP_ADD_TC(tp, getaudit_failure);
	ATF_TP_ADD_TC(tp, setaudit_success);
	ATF_TP_ADD_TC(tp, setaudit_failure);

	ATF_TP_ADD_TC(tp, getaudit_addr_success);
	ATF_TP_ADD_TC(tp, getaudit_addr_failure);
	ATF_TP_ADD_TC(tp, setaudit_addr_success);
	ATF_TP_ADD_TC(tp, setaudit_addr_failure);

	ATF_TP_ADD_TC(tp, reboot_failure);
	ATF_TP_ADD_TC(tp, acct_failure);
	ATF_TP_ADD_TC(tp, quotactl_failure);
	ATF_TP_ADD_TC(tp, mount_failure);
	ATF_TP_ADD_TC(tp, nmount_failure);
	ATF_TP_ADD_TC(tp, ntp_adjtime_failure);
	ATF_TP_ADD_TC(tp, auditctl_failure);

	return (atf_no_error());
}
