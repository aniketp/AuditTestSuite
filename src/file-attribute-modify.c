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

#include <sys/stat.h>
#include <sys/syscall.h>

#include <atf-c.h>
#include <fcntl.h>
#include <unistd.h>

#include "utils.h"

static struct pollfd fds[1];
static mode_t mode = 0777;
static struct stat statbuff;
static const char *path = "fileforaudit";
static const char *errpath = "dirdoesnotexist/fileforaudit";
static const char *successreg = "fileforaudit.*return,success";
static const char *failurereg = "fileforaudit.*return,failure";


ATF_TC_WITH_CLEANUP(chmod_success);
ATF_TC_HEAD(chmod_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"chmod(2) call");
}

ATF_TC_BODY(chmod_success, tc)
{
	/* File needs to exist to call chmod(2) */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(0, chmod(path, mode));
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(chmod_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(chmod_failure);
ATF_TC_HEAD(chmod_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"chmod(2) call");
}

ATF_TC_BODY(chmod_failure, tc)
{
	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: file does not exist */
	ATF_REQUIRE_EQ(-1, chmod(errpath, mode));
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(chmod_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(fchmod_success);
ATF_TC_HEAD(fchmod_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"fchmod(2) call");
}

ATF_TC_BODY(fchmod_success, tc)
{
	int filedesc;
	char regex[30];

	/* File needs to exist to call fchmod(2) */
	ATF_REQUIRE((filedesc = open(path, O_CREAT, mode)) != -1);
	ATF_REQUIRE_EQ(0, fstat(filedesc, &statbuff));
	/* Prepare the regex to be checked in the audit record */
	snprintf(regex, 30, "fchmod.*%lu.*return,success", statbuff.st_ino);

	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(0, fchmod(filedesc, mode));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(fchmod_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(fchmod_failure);
ATF_TC_HEAD(fchmod_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"fchmod(2) call");
}

ATF_TC_BODY(fchmod_failure, tc)
{
	const char *regex = "fchmod.*return,failure : Bad file descriptor";
	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: Invalid file descriptor */
	ATF_REQUIRE_EQ(-1, fchmod(-1, mode));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(fchmod_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(lchmod_success);
ATF_TC_HEAD(lchmod_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"lchmod(2) call");
}

ATF_TC_BODY(lchmod_success, tc)
{
	/* Symbolic link needs to exist to call lchmod(2) */
	ATF_REQUIRE_EQ(0, symlink("symlink", path));
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(0, lchmod(path, mode));
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(lchmod_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(lchmod_failure);
ATF_TC_HEAD(lchmod_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"lchmod(2) call");
}

ATF_TC_BODY(lchmod_failure, tc)
{
	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: file does not exist */
	ATF_REQUIRE_EQ(-1, lchmod(errpath, mode));
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(lchmod_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(fchmodat_success);
ATF_TC_HEAD(fchmodat_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"fchmodat(2) call");
}

ATF_TC_BODY(fchmodat_success, tc)
{
	/* File needs to exist to call fchmodat(2) */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(0, fchmodat(AT_FDCWD, path, mode, 0));
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(fchmodat_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(fchmodat_failure);
ATF_TC_HEAD(fchmodat_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"fchmodat(2) call");
}

ATF_TC_BODY(fchmodat_failure, tc)
{
	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: file does not exist */
	ATF_REQUIRE_EQ(-1, fchmodat(AT_FDCWD, errpath, mode, 0));
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(fchmodat_failure, tc)
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful openat(2)"
					" call for O_RDONLY, O_CREAT flags");
}

ATF_TC_BODY(openat_read_creat_failure, tc)
{
	const char *regex = "read,creat.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful openat(2)"
					" call for O_RDONLY, O_TRUNC flags");
}

ATF_TC_BODY(openat_read_trunc_failure, tc)
{
	const char *regex = "read,trunc.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE(syscall(SYS_open, path, O_RDONLY | O_CREAT | O_TRUNC) != -1);
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
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(-1, syscall(SYS_open, errpath, O_RDONLY | O_CREAT | O_TRUNC));
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
	FILE *pipefd = setup(fds, "fm");
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
	atf_tc_set_md_var(tc, "descr", "Tests the audit of unsuccessful openat(2)"
				" call for O_RDONLY, O_CREAT, O_TRUNC flags");
}

ATF_TC_BODY(openat_read_creat_trunc_failure, tc)
{
	const char *regex = "read,creat,trunc.*fileforaudit.*return,failure";
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(-1, openat(AT_FDCWD, errpath, O_RDONLY | O_CREAT | O_TRUNC));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_creat_trunc_failure, tc)
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(-1, openat(AT_FDCWD, errpath, O_WRONLY | O_CREAT | O_TRUNC));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_write_creat_trunc_failure, tc)
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
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
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(-1, openat(AT_FDCWD, errpath, O_RDWR | O_CREAT | O_TRUNC));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_write_creat_trunc_failure, tc)
{
	cleanup();
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, chmod_success);
	ATF_TP_ADD_TC(tp, chmod_failure);
	ATF_TP_ADD_TC(tp, fchmod_success);
	ATF_TP_ADD_TC(tp, fchmod_failure);
	ATF_TP_ADD_TC(tp, lchmod_success);
	ATF_TP_ADD_TC(tp, lchmod_failure);
	ATF_TP_ADD_TC(tp, fchmodat_success);
	ATF_TP_ADD_TC(tp, fchmodat_failure);

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
