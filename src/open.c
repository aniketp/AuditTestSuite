/*-
 * Copyright 2018 Aniket Pandey
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

/*
 * Note: open(2) and openat(2) have 12 events each for various values of 'flag'
 * Please see: contrib/openbsm/etc/audit_event#L261
 *
 * 270:AUE_OPENAT_R:openat(2) - read:fr
 * 271:AUE_OPENAT_RC:openat(2) - read,creat:fc,fr,fa,fm
 * 272:AUE_OPENAT_RT:openat(2) - read,trunc:fd,fr,fa,fm
 * 273:AUE_OPENAT_RTC:openat(2) - read,creat,trunc:fc,fd,fr,fa,fm
 * 274:AUE_OPENAT_W:openat(2) - write:fw
 * 275:AUE_OPENAT_WC:openat(2) - write,creat:fc,fw,fa,fm
 * 276:AUE_OPENAT_WT:openat(2) - write,trunc:fd,fw,fa,fm
 * 277:AUE_OPENAT_WTC:openat(2) - write,creat,trunc:fc,fd,fw,fa,fm
 * 278:AUE_OPENAT_RW:openat(2) - read,write:fr,fw
 * 279:AUE_OPENAT_RWC:openat(2) - read,write,create:fc,fw,fr,fa,fm
 * 280:AUE_OPENAT_RWT:openat(2) - read,write,trunc:fd,fw,fr,fa,fm
 * 281:AUE_OPENAT_RWTC:openat(2) - read,write,creat,trunc:fc,fd,fw,fr,fa,fm
 */

#include <sys/syscall.h>

#include <atf-c.h>
#include <fcntl.h>

#include "utils.h"

static struct pollfd fds[1];
static mode_t mode = 0777;
static const char *path = "fileforaudit";
static const char *errpath = "adirhasnoname/fileforaudit";


ATF_TC_WITH_CLEANUP(open_read_success);
ATF_TC_HEAD(open_read_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful open(2)"
					" call for O_RDONLY flag");
}

ATF_TC_BODY(open_read_success, tc)
{
	const char *regex = "read.*fileforaudit.*return,success";
	/* File needs to exist to open(2) as O_RDONLY */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE(syscall(SYS_open, path, O_RDONLY) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_read_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_read_failure);
ATF_TC_HEAD(open_read_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"open(2) call for O_RDONLY flag");
}

ATF_TC_BODY(open_read_failure, tc)
{
	const char *regex = "read.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE_EQ(-1, syscall(SYS_open, errpath, O_RDONLY));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_read_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_read_success);
ATF_TC_HEAD(openat_read_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of successful openat(2)"
					" call for O_RDONLY flag");
}

ATF_TC_BODY(openat_read_success, tc)
{
	const char *regex = "read.*fileforaudit.*return,success";
	/* File needs to exist to openat(2) as O_RDONLY */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE(openat(AT_FDCWD, path, O_RDONLY) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_read_failure);
ATF_TC_HEAD(openat_read_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"openat(2) call for O_RDONLY flag");
}

ATF_TC_BODY(openat_read_failure, tc)
{
	const char *regex = "read.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE_EQ(-1, openat(AT_FDCWD, errpath, O_RDONLY));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_read_creat_success);
ATF_TC_HEAD(open_read_creat_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful open(2)"
					" call for O_RDONLY, O_CREAT flags");
}

ATF_TC_BODY(open_read_creat_success, tc)
{
	const char *regex = "read,creat.*fileforaudit.*return,success";
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE(syscall(SYS_open, path, O_RDONLY | O_CREAT) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_read_creat_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_read_creat_failure);
ATF_TC_HEAD(open_read_creat_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful open(2)"
					" call for O_RDONLY, O_CREAT flags");
}

ATF_TC_BODY(open_read_creat_failure, tc)
{
	const char *regex = "read,creat.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE_EQ(-1, syscall(SYS_open, errpath, O_RDONLY | O_CREAT));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_read_creat_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_read_creat_success);
ATF_TC_HEAD(openat_read_creat_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of successful openat(2)"
					" call for O_RDONLY, O_CREAT flags");
}

ATF_TC_BODY(openat_read_creat_success, tc)
{
	const char *regex = "read,creat.*fileforaudit.*return,success";
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE(openat(AT_FDCWD, path, O_RDONLY | O_CREAT) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_creat_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_read_creat_failure);
ATF_TC_HEAD(openat_read_creat_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful openat"
					" call for O_RDONLY, O_CREAT flags");
}

ATF_TC_BODY(openat_read_creat_failure, tc)
{
	const char *regex = "read,creat.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE_EQ(-1, openat(AT_FDCWD, errpath, O_RDONLY | O_CREAT));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_creat_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_read_trunc_success);
ATF_TC_HEAD(open_read_trunc_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful open(2)"
					" call for O_RDONLY, O_TRUNC flags");
}

ATF_TC_BODY(open_read_trunc_success, tc)
{
	const char *regex = "read,trunc.*fileforaudit.*return,success";
	/* File needs to exist to open(2) as O_RDONLY | O_TRUNC */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE(syscall(SYS_open, path, O_RDONLY | O_TRUNC) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_read_trunc_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_read_trunc_failure);
ATF_TC_HEAD(open_read_trunc_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful open(2)"
					" call for O_RDONLY, O_TRUNC flags");
}

ATF_TC_BODY(open_read_trunc_failure, tc)
{
	const char *regex = "read,trunc.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE_EQ(-1, syscall(SYS_open, errpath, O_RDONLY | O_TRUNC));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_read_trunc_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_read_trunc_success);
ATF_TC_HEAD(openat_read_trunc_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of successful openat(2)"
					" call for O_RDONLY, O_TRUNC flags");
}

ATF_TC_BODY(openat_read_trunc_success, tc)
{
	const char *regex = "read,trunc.*fileforaudit.*return,success";
	/* File needs to exist to openat(2) as O_RDONLY | O_TRUNC */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE(openat(AT_FDCWD, path, O_RDONLY | O_TRUNC) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_trunc_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_read_trunc_failure);
ATF_TC_HEAD(openat_read_trunc_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful openat"
					" call for O_RDONLY, O_TRUNC flags");
}

ATF_TC_BODY(openat_read_trunc_failure, tc)
{
	const char *regex = "read,trunc.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE_EQ(-1, openat(AT_FDCWD, errpath, O_RDONLY | O_TRUNC));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_trunc_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_read_creat_trunc_success);
ATF_TC_HEAD(open_read_creat_trunc_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful open(2)"
				" call for O_RDONLY, O_CREAT, O_TRUNC flags");
}

ATF_TC_BODY(open_read_creat_trunc_success, tc)
{
	const char *regex = "read,creat,trunc.*fileforaudit.*return,success";
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE(syscall(SYS_open, path,
		O_RDONLY | O_CREAT | O_TRUNC) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_read_creat_trunc_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_read_creat_trunc_failure);
ATF_TC_HEAD(open_read_creat_trunc_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful open(2)"
				" call for O_RDONLY, O_CREAT, O_TRUNC flags");
}

ATF_TC_BODY(open_read_creat_trunc_failure, tc)
{
	const char *regex = "read,creat,trunc.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE_EQ(-1,
		syscall(SYS_open, errpath, O_RDONLY | O_CREAT | O_TRUNC));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_read_creat_trunc_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_read_creat_trunc_success);
ATF_TC_HEAD(openat_read_creat_trunc_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of successful openat(2)"
				" call for O_RDONLY, O_CREAT, O_TRUNC flags");
}

ATF_TC_BODY(openat_read_creat_trunc_success, tc)
{
	const char *regex = "read,creat,trunc.*fileforaudit.*return,success";
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE(openat(AT_FDCWD, path, O_RDONLY | O_CREAT | O_TRUNC) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_creat_trunc_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_read_creat_trunc_failure);
ATF_TC_HEAD(openat_read_creat_trunc_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful openat"
				" call for O_RDONLY, O_CREAT, O_TRUNC flags");
}

ATF_TC_BODY(openat_read_creat_trunc_failure, tc)
{
	const char *regex = "read,creat,trunc.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE_EQ(-1,
		openat(AT_FDCWD, errpath, O_RDONLY | O_CREAT | O_TRUNC));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_creat_trunc_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_write_success);
ATF_TC_HEAD(open_write_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful open(2)"
					" call for O_WRONLY flag");
}

ATF_TC_BODY(open_write_success, tc)
{
	const char *regex = "write.*fileforaudit.*return,success";
	/* File needs to exist to open(2) as O_WRONLY */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE(syscall(SYS_open, path, O_WRONLY) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_write_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_write_failure);
ATF_TC_HEAD(open_write_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"open(2) call for O_WRONLY flag");
}

ATF_TC_BODY(open_write_failure, tc)
{
	const char *regex = "write.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE_EQ(-1, syscall(SYS_open, errpath, O_WRONLY));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_write_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_write_success);
ATF_TC_HEAD(openat_write_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of successful openat(2)"
					" call for O_WRONLY flag");
}

ATF_TC_BODY(openat_write_success, tc)
{
	const char *regex = "write.*fileforaudit.*return,success";
	/* File needs to exist to openat(2) as O_WRONLY */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE(openat(AT_FDCWD, path, O_WRONLY) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_write_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_write_failure);
ATF_TC_HEAD(openat_write_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"openat(2) call for O_WRONLY flag");
}

ATF_TC_BODY(openat_write_failure, tc)
{
	const char *regex = "write.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE_EQ(-1, openat(AT_FDCWD, errpath, O_WRONLY));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_write_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_write_creat_success);
ATF_TC_HEAD(open_write_creat_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful open(2)"
					" call for O_WRONLY, O_CREAT flags");
}

ATF_TC_BODY(open_write_creat_success, tc)
{
	const char *regex = "write,creat.*fileforaudit.*return,success";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE(syscall(SYS_open, path, O_WRONLY | O_CREAT) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_write_creat_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_write_creat_failure);
ATF_TC_HEAD(open_write_creat_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful open(2)"
					" call for O_WRONLY, O_CREAT flags");
}

ATF_TC_BODY(open_write_creat_failure, tc)
{
	const char *regex = "write,creat.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE_EQ(-1, syscall(SYS_open, errpath, O_WRONLY | O_CREAT));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_write_creat_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_write_creat_success);
ATF_TC_HEAD(openat_write_creat_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of successful openat(2)"
					" call for O_WRONLY, O_CREAT flags");
}

ATF_TC_BODY(openat_write_creat_success, tc)
{
	const char *regex = "write,creat.*fileforaudit.*return,success";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE(openat(AT_FDCWD, path, O_WRONLY | O_CREAT) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_write_creat_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_write_creat_failure);
ATF_TC_HEAD(openat_write_creat_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful openat"
					" call for O_WRONLY, O_CREAT flags");
}

ATF_TC_BODY(openat_write_creat_failure, tc)
{
	const char *regex = "write,creat.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE_EQ(-1, openat(AT_FDCWD, errpath, O_WRONLY | O_CREAT));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_write_creat_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_write_trunc_success);
ATF_TC_HEAD(open_write_trunc_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful open(2)"
					" call for O_WRONLY, O_TRUNC flags");
}

ATF_TC_BODY(open_write_trunc_success, tc)
{
	const char *regex = "write,trunc.*fileforaudit.*return,success";
	/* File needs to exist to open(2) as O_WRONLY | O_TRUNC */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE(syscall(SYS_open, path, O_WRONLY | O_TRUNC) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_write_trunc_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_write_trunc_failure);
ATF_TC_HEAD(open_write_trunc_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful open(2)"
					" call for O_WRONLY, O_TRUNC flags");
}

ATF_TC_BODY(open_write_trunc_failure, tc)
{
	const char *regex = "write,trunc.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE_EQ(-1, syscall(SYS_open, errpath, O_WRONLY | O_TRUNC));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_write_trunc_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_write_trunc_success);
ATF_TC_HEAD(openat_write_trunc_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of successful openat(2)"
					" call for O_WRONLY, O_TRUNC flags");
}

ATF_TC_BODY(openat_write_trunc_success, tc)
{
	const char *regex = "write,trunc.*fileforaudit.*return,success";
	/* File needs to exist to openat(2) as O_WRONLY | O_TRUNC */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE(openat(AT_FDCWD, path, O_WRONLY | O_TRUNC) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_write_trunc_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_write_trunc_failure);
ATF_TC_HEAD(openat_write_trunc_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful openat"
					" call for O_WRONLY, O_TRUNC flags");
}

ATF_TC_BODY(openat_write_trunc_failure, tc)
{
	const char *regex = "write,trunc.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE_EQ(-1, openat(AT_FDCWD, errpath, O_WRONLY | O_TRUNC));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_write_trunc_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_write_creat_trunc_success);
ATF_TC_HEAD(open_write_creat_trunc_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful open(2)"
				" call for O_WRONLY, O_CREAT, O_TRUNC flags");
}

ATF_TC_BODY(open_write_creat_trunc_success, tc)
{
	const char *regex = "write,creat,trunc.*fileforaudit.*return,success";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE(syscall(SYS_open, path,
		O_WRONLY | O_CREAT | O_TRUNC) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_write_creat_trunc_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_write_creat_trunc_failure);
ATF_TC_HEAD(open_write_creat_trunc_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful open(2)"
				" call for O_WRONLY, O_CREAT, O_TRUNC flags");
}

ATF_TC_BODY(open_write_creat_trunc_failure, tc)
{
	const char *regex = "write,creat,trunc.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE_EQ(-1,
		syscall(SYS_open, errpath, O_WRONLY | O_CREAT | O_TRUNC));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_write_creat_trunc_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_write_creat_trunc_success);
ATF_TC_HEAD(openat_write_creat_trunc_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of successful openat(2)"
				" call for O_WRONLY, O_CREAT, O_TRUNC flags");
}

ATF_TC_BODY(openat_write_creat_trunc_success, tc)
{
	const char *regex = "write,creat,trunc.*fileforaudit.*return,success";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE(openat(AT_FDCWD, path, O_WRONLY | O_CREAT | O_TRUNC) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_write_creat_trunc_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_write_creat_trunc_failure);
ATF_TC_HEAD(openat_write_creat_trunc_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful openat"
				" call for O_WRONLY, O_CREAT, O_TRUNC flags");
}

ATF_TC_BODY(openat_write_creat_trunc_failure, tc)
{
	const char *regex = "write,creat,trunc.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE_EQ(-1, openat(AT_FDCWD, errpath,
		O_WRONLY | O_CREAT | O_TRUNC));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_write_creat_trunc_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_read_write_success);
ATF_TC_HEAD(open_read_write_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful open(2)"
					" call for O_RDWR flag");
}

ATF_TC_BODY(open_read_write_success, tc)
{
	const char *regex = "read,write.*fileforaudit.*return,success";
	/* File needs to exist to open(2) as O_RDWR */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE(syscall(SYS_open, path, O_RDWR) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_read_write_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_read_write_failure);
ATF_TC_HEAD(open_read_write_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"open(2) call for O_RDWR flag");
}

ATF_TC_BODY(open_read_write_failure, tc)
{
	const char *regex = "read,write.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE_EQ(-1, syscall(SYS_open, errpath, O_RDWR));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_read_write_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_read_write_success);
ATF_TC_HEAD(openat_read_write_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"openat(2) call for O_RDWR flag");
}

ATF_TC_BODY(openat_read_write_success, tc)
{
	const char *regex = "read,write.*fileforaudit.*return,success";
	/* File needs to exist to openat(2) as O_RDWR */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE(openat(AT_FDCWD, path, O_RDWR) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_write_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_read_write_failure);
ATF_TC_HEAD(openat_read_write_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"openat(2) call for O_RDWR flag");
}

ATF_TC_BODY(openat_read_write_failure, tc)
{
	const char *regex = "read,write.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE_EQ(-1, openat(AT_FDCWD, errpath, O_RDWR));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_write_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_read_write_creat_success);
ATF_TC_HEAD(open_read_write_creat_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful open(2)"
					" call for O_RDWR, O_CREAT flags");
}

ATF_TC_BODY(open_read_write_creat_success, tc)
{
	const char *regex = "read,write,creat.*fileforaudit.*return,success";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE(syscall(SYS_open, path, O_RDWR | O_CREAT) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_read_write_creat_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_read_write_creat_failure);
ATF_TC_HEAD(open_read_write_creat_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful open(2)"
					" call for O_RDWR, O_CREAT flags");
}

ATF_TC_BODY(open_read_write_creat_failure, tc)
{
	const char *regex = "read,write,creat.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE_EQ(-1, syscall(SYS_open, errpath, O_RDWR | O_CREAT));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_read_write_creat_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_read_write_creat_success);
ATF_TC_HEAD(openat_read_write_creat_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of successful openat(2)"
					" call for O_RDWR, O_CREAT flags");
}

ATF_TC_BODY(openat_read_write_creat_success, tc)
{
	const char *regex = "read,write,creat.*fileforaudit.*return,success";
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE(openat(AT_FDCWD, path, O_RDWR | O_CREAT) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_write_creat_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_read_write_creat_failure);
ATF_TC_HEAD(openat_read_write_creat_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful openat"
					" call for O_RDWR, O_CREAT flags");
}

ATF_TC_BODY(openat_read_write_creat_failure, tc)
{
	const char *regex = "read,write,creat.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE_EQ(-1, openat(AT_FDCWD, errpath, O_RDWR | O_CREAT));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_write_creat_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_read_write_trunc_success);
ATF_TC_HEAD(open_read_write_trunc_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful open(2)"
					" call for O_RDWR, O_TRUNC flags");
}

ATF_TC_BODY(open_read_write_trunc_success, tc)
{
	const char *regex = "read,write,trunc.*fileforaudit.*return,success";
	/* File needs to exist to open(2) as O_RDWR | O_TRUNC */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE(syscall(SYS_open, path, O_RDWR | O_TRUNC) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_read_write_trunc_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_read_write_trunc_failure);
ATF_TC_HEAD(open_read_write_trunc_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful open(2)"
					" call for O_RDWR, O_TRUNC flags");
}

ATF_TC_BODY(open_read_write_trunc_failure, tc)
{
	const char *regex = "read,write,trunc.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE_EQ(-1, syscall(SYS_open, errpath, O_RDWR | O_TRUNC));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_read_write_trunc_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_read_write_trunc_success);
ATF_TC_HEAD(openat_read_write_trunc_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of successful openat(2)"
					" call for O_RDWR, O_TRUNC flags");
}

ATF_TC_BODY(openat_read_write_trunc_success, tc)
{
	const char *regex = "read,write,trunc.*fileforaudit.*return,success";
	/* File needs to exist to openat(2) as O_RDWR | O_TRUNC */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE(openat(AT_FDCWD, path, O_RDWR | O_TRUNC) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_write_trunc_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_read_write_trunc_failure);
ATF_TC_HEAD(openat_read_write_trunc_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful openat"
					" call for O_RDWR, O_TRUNC flags");
}

ATF_TC_BODY(openat_read_write_trunc_failure, tc)
{
	const char *regex = "read,write,trunc.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE_EQ(-1, openat(AT_FDCWD, errpath, O_RDWR | O_TRUNC));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_write_trunc_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_read_write_creat_trunc_success);
ATF_TC_HEAD(open_read_write_creat_trunc_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful open(2)"
				" call for O_RDWR, O_CREAT, O_TRUNC flags");
}

ATF_TC_BODY(open_read_write_creat_trunc_success, tc)
{
	const char *regex = "read,write,creat,trunc.*fileforaudit.*,success";
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE(syscall(SYS_open, path, O_RDWR | O_CREAT | O_TRUNC) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_read_write_creat_trunc_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(open_read_write_creat_trunc_failure);
ATF_TC_HEAD(open_read_write_creat_trunc_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful open(2)"
				" call for O_RDWR, O_CREAT, O_TRUNC flags");
}

ATF_TC_BODY(open_read_write_creat_trunc_failure, tc)
{
	const char *regex = "read,write,creat,trunc.*fileforaudit.*,failure";
	FILE *pipefd = setup(fds, "fr");
	ATF_REQUIRE_EQ(-1,
		syscall(SYS_open, errpath, O_RDWR | O_CREAT | O_TRUNC));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(open_read_write_creat_trunc_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_read_write_creat_trunc_success);
ATF_TC_HEAD(openat_read_write_creat_trunc_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of successful openat(2)"
				" call for O_RDWR, O_CREAT, O_TRUNC flags");
}

ATF_TC_BODY(openat_read_write_creat_trunc_success, tc)
{
	const char *regex = "read,write,creat,trunc.*fileforaudit.*,success";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE(openat(AT_FDCWD, path, O_RDWR | O_CREAT | O_TRUNC) != -1);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_write_creat_trunc_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(openat_read_write_creat_trunc_failure);
ATF_TC_HEAD(openat_read_write_creat_trunc_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful openat"
				" call for O_RDWR, O_CREAT, O_TRUNC flags");
}

ATF_TC_BODY(openat_read_write_creat_trunc_failure, tc)
{
	const char *regex = "read,write,creat,trunc.*fileforaudit.*,failure";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE_EQ(-1,
		openat(AT_FDCWD, errpath, O_RDWR | O_CREAT | O_TRUNC));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_write_creat_trunc_failure, tc)
{
	cleanup();
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, open_read_success);
	ATF_TP_ADD_TC(tp, open_read_failure);
	ATF_TP_ADD_TC(tp, openat_read_success);
	ATF_TP_ADD_TC(tp, openat_read_failure);

	ATF_TP_ADD_TC(tp, open_read_creat_success);
	ATF_TP_ADD_TC(tp, open_read_creat_failure);
	ATF_TP_ADD_TC(tp, openat_read_creat_success);
	ATF_TP_ADD_TC(tp, openat_read_creat_failure);

	ATF_TP_ADD_TC(tp, open_read_trunc_success);
	ATF_TP_ADD_TC(tp, open_read_trunc_failure);
	ATF_TP_ADD_TC(tp, openat_read_trunc_success);
	ATF_TP_ADD_TC(tp, openat_read_trunc_failure);

	ATF_TP_ADD_TC(tp, open_read_creat_trunc_success);
	ATF_TP_ADD_TC(tp, open_read_creat_trunc_failure);
	ATF_TP_ADD_TC(tp, openat_read_creat_trunc_success);
	ATF_TP_ADD_TC(tp, openat_read_creat_trunc_failure);

	ATF_TP_ADD_TC(tp, open_write_success);
	ATF_TP_ADD_TC(tp, open_write_failure);
	ATF_TP_ADD_TC(tp, openat_write_success);
	ATF_TP_ADD_TC(tp, openat_write_failure);

	ATF_TP_ADD_TC(tp, open_write_creat_success);
	ATF_TP_ADD_TC(tp, open_write_creat_failure);
	ATF_TP_ADD_TC(tp, openat_write_creat_success);
	ATF_TP_ADD_TC(tp, openat_write_creat_failure);

	ATF_TP_ADD_TC(tp, open_write_trunc_success);
	ATF_TP_ADD_TC(tp, open_write_trunc_failure);
	ATF_TP_ADD_TC(tp, openat_write_trunc_success);
	ATF_TP_ADD_TC(tp, openat_write_trunc_failure);

	ATF_TP_ADD_TC(tp, open_write_creat_trunc_success);
	ATF_TP_ADD_TC(tp, open_write_creat_trunc_failure);
	ATF_TP_ADD_TC(tp, openat_write_creat_trunc_success);
	ATF_TP_ADD_TC(tp, openat_write_creat_trunc_failure);

	ATF_TP_ADD_TC(tp, open_read_write_success);
	ATF_TP_ADD_TC(tp, open_read_write_failure);
	ATF_TP_ADD_TC(tp, openat_read_write_success);
	ATF_TP_ADD_TC(tp, openat_read_write_failure);

	ATF_TP_ADD_TC(tp, open_read_write_creat_success);
	ATF_TP_ADD_TC(tp, open_read_write_creat_failure);
	ATF_TP_ADD_TC(tp, openat_read_write_creat_success);
	ATF_TP_ADD_TC(tp, openat_read_write_creat_failure);

	ATF_TP_ADD_TC(tp, open_read_write_trunc_success);
	ATF_TP_ADD_TC(tp, open_read_write_trunc_failure);
	ATF_TP_ADD_TC(tp, openat_read_write_trunc_success);
	ATF_TP_ADD_TC(tp, openat_read_write_trunc_failure);

	ATF_TP_ADD_TC(tp, open_read_write_creat_trunc_success);
	ATF_TP_ADD_TC(tp, open_read_write_creat_trunc_failure);
	ATF_TP_ADD_TC(tp, openat_read_write_creat_trunc_success);
	ATF_TP_ADD_TC(tp, openat_read_write_creat_trunc_failure);

	return (atf_no_error());
}
