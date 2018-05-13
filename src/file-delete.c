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
static const char *path = "fileforaudit";
static const char *errpath = "dirdoesnotexist/fileforaudit";
static const char *successreg = "fileforaudit.*return,success";
static const char *failurereg = "fileforaudit.*return,failure";


ATF_TC_WITH_CLEANUP(rmdir_success);
ATF_TC_HEAD(rmdir_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"rmdir(2) call");
}

ATF_TC_BODY(rmdir_success, tc)
{
	ATF_REQUIRE_EQ(0, mkdir(path, mode));
	FILE *pipefd = setup(fds, "fd");
	ATF_REQUIRE_EQ(0, rmdir(path));
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(rmdir_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(rmdir_failure);
ATF_TC_HEAD(rmdir_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"rmdir(2) call");
}

ATF_TC_BODY(rmdir_failure, tc)
{
	FILE *pipefd = setup(fds, "fd");
	/* Failure reason: directory does not exist */
	ATF_REQUIRE_EQ(-1, rmdir(errpath));
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(rmdir_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(rename_success);
ATF_TC_HEAD(rename_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"rename(2) call");
}

ATF_TC_BODY(rename_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fd");
	ATF_REQUIRE_EQ(0, rename(path, "renamed"));
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(rename_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(rename_failure);
ATF_TC_HEAD(rename_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"rename(2) call");
}

ATF_TC_BODY(rename_failure, tc)
{
	FILE *pipefd = setup(fds, "fd");
	/* Failure reason: file does not exist */
	ATF_REQUIRE_EQ(-1, rename(path, "renamed"));
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(rename_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(renameat_success);
ATF_TC_HEAD(renameat_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"renameat(2) call");
}

ATF_TC_BODY(renameat_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fd");
	ATF_REQUIRE_EQ(0, renameat(AT_FDCWD, path, AT_FDCWD, "renamed"));
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(renameat_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(renameat_failure);
ATF_TC_HEAD(renameat_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"renameat(2) call");
}

ATF_TC_BODY(renameat_failure, tc)
{
	FILE *pipefd = setup(fds, "fd");
	/* Failure reason: file does not exist */
	ATF_REQUIRE_EQ(-1, renameat(AT_FDCWD, path, AT_FDCWD, "renamed"));
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(renameat_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(unlink_success);
ATF_TC_HEAD(unlink_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"unlink(2) call");
}

ATF_TC_BODY(unlink_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fd");
	ATF_REQUIRE_EQ(0, unlink(path));
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(unlink_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(unlink_failure);
ATF_TC_HEAD(unlink_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"unlink(2) call");
}

ATF_TC_BODY(unlink_failure, tc)
{
	FILE *pipefd = setup(fds, "fd");
	/* Failure reason: file does not exist */
	ATF_REQUIRE_EQ(-1, unlink(errpath));
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(unlink_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(unlinkat_success);
ATF_TC_HEAD(unlinkat_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"unlinkat(2) call");
}

ATF_TC_BODY(unlinkat_success, tc)
{
	ATF_REQUIRE_EQ(0, mkdir(path, mode));
	FILE *pipefd = setup(fds, "fd");
	ATF_REQUIRE_EQ(0, unlinkat(AT_FDCWD, path, AT_REMOVEDIR));
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(unlinkat_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(unlinkat_failure);
ATF_TC_HEAD(unlinkat_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"unlinkat(2) call");
}

ATF_TC_BODY(unlinkat_failure, tc)
{
	FILE *pipefd = setup(fds, "fd");
	/* Failure reason: directory does not exist */
	ATF_REQUIRE_EQ(-1, unlinkat(AT_FDCWD, errpath, AT_REMOVEDIR));
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(unlinkat_failure, tc)
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
	ATF_REQUIRE_EQ(-1, openat(AT_FDCWD, errpath, O_RDONLY | O_CREAT | O_TRUNC));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_creat_trunc_failure, tc)
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
	ATF_REQUIRE_EQ(-1, openat(AT_FDCWD, errpath, O_WRONLY | O_CREAT | O_TRUNC));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_write_creat_trunc_failure, tc)
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
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
	FILE *pipefd = setup(fds, "fd");
	ATF_REQUIRE_EQ(-1, openat(AT_FDCWD, errpath, O_RDWR | O_CREAT | O_TRUNC));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(openat_read_write_creat_trunc_failure, tc)
{
	cleanup();
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, rmdir_success);
	ATF_TP_ADD_TC(tp, rmdir_failure);

	ATF_TP_ADD_TC(tp, rename_success);
	ATF_TP_ADD_TC(tp, rename_failure);
	ATF_TP_ADD_TC(tp, renameat_success);
	ATF_TP_ADD_TC(tp, renameat_failure);

	ATF_TP_ADD_TC(tp, unlink_success);
	ATF_TP_ADD_TC(tp, unlink_failure);
	ATF_TP_ADD_TC(tp, unlinkat_success);
	ATF_TP_ADD_TC(tp, unlinkat_failure);

	ATF_TP_ADD_TC(tp, open_read_trunc_success);
	ATF_TP_ADD_TC(tp, open_read_trunc_failure);
	ATF_TP_ADD_TC(tp, openat_read_trunc_success);
	ATF_TP_ADD_TC(tp, openat_read_trunc_failure);

	ATF_TP_ADD_TC(tp, open_read_creat_trunc_success);
	ATF_TP_ADD_TC(tp, open_read_creat_trunc_failure);
	ATF_TP_ADD_TC(tp, openat_read_creat_trunc_success);
	ATF_TP_ADD_TC(tp, openat_read_creat_trunc_failure);

	ATF_TP_ADD_TC(tp, open_write_trunc_success);
	ATF_TP_ADD_TC(tp, open_write_trunc_failure);
	ATF_TP_ADD_TC(tp, openat_write_trunc_success);
	ATF_TP_ADD_TC(tp, openat_write_trunc_failure);

	ATF_TP_ADD_TC(tp, open_write_creat_trunc_success);
	ATF_TP_ADD_TC(tp, open_write_creat_trunc_failure);
	ATF_TP_ADD_TC(tp, openat_write_creat_trunc_success);
	ATF_TP_ADD_TC(tp, openat_write_creat_trunc_failure);

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
