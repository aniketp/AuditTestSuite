/*-
 * Copyright 2018 Aniket Pandey
 * All rights reserved.
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

#include <sys/syscall.h>

#include <atf-c.h>
#include <fcntl.h>
#include <unistd.h>

#include "utils.h"

static struct pollfd fds[1];
static mode_t mode = 0777;
static off_t offlen = 0;
static const char *path = "fileforaudit";
static const char *errpath = "dirdoesnotexist/fileforaudit";
static const char *successreg = "fileforaudit.*return,success";
static const char *failurereg = "fileforaudit.*return,failure";


ATF_TC_WITH_CLEANUP(truncate_success);
ATF_TC_HEAD(truncate_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"truncate(2) call");
}

ATF_TC_BODY(truncate_success, tc)
{
	/* File needs to exist to call truncate(2) */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE_EQ(0, truncate(path, offlen));
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(truncate_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(truncate_failure);
ATF_TC_HEAD(truncate_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"truncate(2) call");
}

ATF_TC_BODY(truncate_failure, tc)
{
	FILE *pipefd = setup(fds, "fw");
	/* Failure reason: file does not exist */
	ATF_REQUIRE_EQ(-1, truncate(errpath, offlen));
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(truncate_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(ftruncate_success);
ATF_TC_HEAD(ftruncate_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"ftruncate(2) call");
}

ATF_TC_BODY(ftruncate_success, tc)
{
	int filedesc;
	const char *regex = "ftruncate.*return,success";
	/* Valid file descriptor needs to exist to call ftruncate(2) */
	ATF_REQUIRE((filedesc = open(path, O_CREAT | O_RDWR)) != -1);
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE_EQ(0, ftruncate(filedesc, offlen));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(ftruncate_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(ftruncate_failure);
ATF_TC_HEAD(ftruncate_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"ftruncate(2) call");
}

ATF_TC_BODY(ftruncate_failure, tc)
{
	const char *regex = "ftruncate.*return,failure";
	FILE *pipefd = setup(fds, "fw");
	/* Failure reason: bad file descriptor */
	ATF_REQUIRE_EQ(-1, ftruncate(-1, offlen));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(ftruncate_failure, tc)
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
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful openat(2)"
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
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful openat(2)"
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
	ATF_REQUIRE(syscall(SYS_open, path, O_WRONLY | O_CREAT | O_TRUNC) != -1);
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
	ATF_REQUIRE_EQ(-1, syscall(SYS_open, errpath, O_WRONLY | O_CREAT | O_TRUNC));
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
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful openat(2)"
				" call for O_WRONLY, O_CREAT, O_TRUNC flags");
}

ATF_TC_BODY(openat_write_creat_trunc_failure, tc)
{
	const char *regex = "write,creat,trunc.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE_EQ(-1, openat(AT_FDCWD, errpath, O_WRONLY | O_CREAT | O_TRUNC));
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
	FILE *pipefd = setup(fds, "fw");
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
	FILE *pipefd = setup(fds, "fw");
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
	FILE *pipefd = setup(fds, "fw");
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
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful openat(2)"
					" call for O_RDWR, O_CREAT flags");
}

ATF_TC_BODY(openat_read_write_creat_failure, tc)
{
	const char *regex = "read,write,creat.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fw");
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
	FILE *pipefd = setup(fds, "fw");
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
	FILE *pipefd = setup(fds, "fw");
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
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful openat(2)"
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
	const char *regex = "read,write,creat,trunc.*fileforaudit.*return,success";
	FILE *pipefd = setup(fds, "fw");
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
	const char *regex = "read,write,creat,trunc.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE_EQ(-1, syscall(SYS_open, errpath, O_RDWR | O_CREAT | O_TRUNC));
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
	const char *regex = "read,write,creat,trunc.*fileforaudit.*return,success";
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
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful openat(2)"
				" call for O_RDWR, O_CREAT, O_TRUNC flags");
}

ATF_TC_BODY(openat_read_write_creat_trunc_failure, tc)
{
	const char *regex = "read,write,creat,trunc.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fw");
	ATF_REQUIRE_EQ(-1, openat(AT_FDCWD, errpath, O_RDWR | O_CREAT | O_TRUNC));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_write_creat_trunc_failure, tc)
{
	cleanup();
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, truncate_success);
	ATF_TP_ADD_TC(tp, truncate_failure);
	ATF_TP_ADD_TC(tp, ftruncate_success);
	ATF_TP_ADD_TC(tp, ftruncate_failure);

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