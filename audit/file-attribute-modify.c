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

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/extattr.h>

#include <atf-c.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "utils.h"

static struct pollfd fds[1];
static mode_t mode = 0777;
static uid_t uid = -1;
static gid_t gid = -1;
static char extregex[80];
static struct stat statbuff;
static const char *name = "authorname";
static const char *path = "fileforaudit";
static const char *errpath = "dirdoesnotexist/fileforaudit";
static const char *successreg = "fileforaudit.*return,success";
static const char *failurereg = "fileforaudit.*return,failure";


ATF_TC_WITH_CLEANUP(flock_success);
ATF_TC_HEAD(flock_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"flock(2) call");
}

ATF_TC_BODY(flock_success, tc)
{
	int filedesc;
	const char *regex = "flock.*return,success";
	/* File needs to exist to call flock(2) */
	ATF_REQUIRE((filedesc = open(path, O_CREAT, mode)) != -1);
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(0, flock(filedesc, LOCK_SH));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(flock_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(flock_failure);
ATF_TC_HEAD(flock_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"flock(2) call");
}

ATF_TC_BODY(flock_failure, tc)
{
	const char *regex = "flock.*return,failure : Bad file descriptor";
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(-1, flock(-1, LOCK_SH));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(flock_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(fcntl_success);
ATF_TC_HEAD(fcntl_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"fcntl(2) call");
}

ATF_TC_BODY(fcntl_success, tc)
{
	int filedesc;
	const char *regex = "fcntl.*return,success,13";
	/* File needs to exist to call fcntl(2) */
	ATF_REQUIRE((filedesc = open(path, O_CREAT, mode)) != -1);
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(13, fcntl(filedesc, F_DUPFD, 13));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(fcntl_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(fcntl_failure);
ATF_TC_HEAD(fcntl_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"fcntl(2) call");
}

ATF_TC_BODY(fcntl_failure, tc)
{
	const char *regex = "fcntl.*return,failure : Bad file descriptor";
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(-1, fcntl(-1, F_DUPFD, 1));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(fcntl_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(fsync_success);
ATF_TC_HEAD(fsync_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"fsync(2) call");
}

ATF_TC_BODY(fsync_success, tc)
{
	int filedesc;
	char regex[30];

	/* File needs to exist to call fsync(2) */
	ATF_REQUIRE((filedesc = open(path, O_CREAT, mode)) != -1);
	ATF_REQUIRE_EQ(0, fstat(filedesc, &statbuff));
	/* Prepare the regex to be checked in the audit record */
	snprintf(regex, 30, "fsync.*%lu.*return,success", statbuff.st_ino);

	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(0, fsync(filedesc));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(fsync_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(fsync_failure);
ATF_TC_HEAD(fsync_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"fsync(2) call");
}

ATF_TC_BODY(fsync_failure, tc)
{
	const char *regex = "fsync.*return,failure : Bad file descriptor";
	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: Invalid file descriptor */
	ATF_REQUIRE_EQ(-1, fsync(-1));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(fsync_failure, tc)
{
	cleanup();
}


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


ATF_TC_WITH_CLEANUP(chown_success);
ATF_TC_HEAD(chown_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"chown(2) call");
}

ATF_TC_BODY(chown_success, tc)
{
	/* File needs to exist to call chown(2) */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(0, chown(path, uid, gid));
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(chown_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(chown_failure);
ATF_TC_HEAD(chown_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"chown(2) call");
}

ATF_TC_BODY(chown_failure, tc)
{
	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: file does not exist */
	ATF_REQUIRE_EQ(-1, chown(errpath, uid, gid));
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(chown_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(fchown_success);
ATF_TC_HEAD(fchown_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"fchown(2) call");
}

ATF_TC_BODY(fchown_success, tc)
{
	int filedesc;
	char regex[30];

	/* File needs to exist to call fchown(2) */
	ATF_REQUIRE((filedesc = open(path, O_CREAT, mode)) != -1);
	ATF_REQUIRE_EQ(0, fstat(filedesc, &statbuff));
	/* Prepare the regex to be checked in the audit record */
	snprintf(regex, 30, "fchown.*%lu.*return,success", statbuff.st_ino);

	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(0, fchown(filedesc, uid, gid));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(fchown_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(fchown_failure);
ATF_TC_HEAD(fchown_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"fchown(2) call");
}

ATF_TC_BODY(fchown_failure, tc)
{
	const char *regex = "fchown.*return,failure : Bad file descriptor";
	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: Invalid file descriptor */
	ATF_REQUIRE_EQ(-1, fchown(-1, uid, gid));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(fchown_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(lchown_success);
ATF_TC_HEAD(lchown_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"lchown(2) call");
}

ATF_TC_BODY(lchown_success, tc)
{
	/* Symbolic link needs to exist to call lchown(2) */
	ATF_REQUIRE_EQ(0, symlink("symlink", path));
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(0, lchown(path, uid, gid));
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(lchown_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(lchown_failure);
ATF_TC_HEAD(lchown_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"lchown(2) call");
}

ATF_TC_BODY(lchown_failure, tc)
{
	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: Symbolic link does not exist */
	ATF_REQUIRE_EQ(-1, lchown(errpath, uid, gid));
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(lchown_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(fchownat_success);
ATF_TC_HEAD(fchownat_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"fchownat(2) call");
}

ATF_TC_BODY(fchownat_success, tc)
{
	/* File needs to exist to call fchownat(2) */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(0, fchownat(AT_FDCWD, path, uid, gid, 0));
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(fchownat_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(fchownat_failure);
ATF_TC_HEAD(fchownat_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"fchownat(2) call");
}

ATF_TC_BODY(fchownat_failure, tc)
{
	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: file does not exist */
	ATF_REQUIRE_EQ(-1, fchownat(AT_FDCWD, errpath, uid, gid, 0));
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(fchownat_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(chflags_success);
ATF_TC_HEAD(chflags_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"chflags(2) call");
}

ATF_TC_BODY(chflags_success, tc)
{
	/* File needs to exist to call chflags(2) */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(0, chflags(path, SF_IMMUTABLE));
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(chflags_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(chflags_failure);
ATF_TC_HEAD(chflags_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"chflags(2) call");
}

ATF_TC_BODY(chflags_failure, tc)
{
	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: file does not exist */
	ATF_REQUIRE_EQ(-1, chflags(errpath, SF_IMMUTABLE));
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(chflags_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(fchflags_success);
ATF_TC_HEAD(fchflags_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"fchflags(2) call");
}

ATF_TC_BODY(fchflags_success, tc)
{
	int filedesc;
	char regex[30];

	/* File needs to exist to call fchflags(2) */
	ATF_REQUIRE((filedesc = open(path, O_CREAT, mode)) != -1);
	ATF_REQUIRE_EQ(0, fstat(filedesc, &statbuff));
	/* Prepare the regex to be checked in the audit record */
	snprintf(regex, 30, "fchflags.*%lu.*return,success", statbuff.st_ino);

	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(0, fchflags(filedesc, SF_IMMUTABLE));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(fchflags_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(fchflags_failure);
ATF_TC_HEAD(fchflags_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"fchflags(2) call");
}

ATF_TC_BODY(fchflags_failure, tc)
{
	const char *regex = "fchflags.*return,failure : Bad file descriptor";
	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: Invalid file descriptor */
	ATF_REQUIRE_EQ(-1, fchflags(-1, SF_IMMUTABLE));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(fchflags_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(lchflags_success);
ATF_TC_HEAD(lchflags_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"lchflags(2) call");
}

ATF_TC_BODY(lchflags_success, tc)
{
	/* Symbolic link needs to exist to call lchflags(2) */
	ATF_REQUIRE_EQ(0, symlink("symlink", path));
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(0, lchflags(path, SF_IMMUTABLE));
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(lchflags_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(lchflags_failure);
ATF_TC_HEAD(lchflags_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"lchflags(2) call");
}

ATF_TC_BODY(lchflags_failure, tc)
{
	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: Symbolic link does not exist */
	ATF_REQUIRE_EQ(-1, lchflags(errpath, SF_IMMUTABLE));
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(lchflags_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(utimes_success);
ATF_TC_HEAD(utimes_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"utimes(2) call");
}

ATF_TC_BODY(utimes_success, tc)
{
	/* File needs to exist to call utimes(2) */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(0, utimes(path, NULL));
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(utimes_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(utimes_failure);
ATF_TC_HEAD(utimes_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"utimes(2) call");
}

ATF_TC_BODY(utimes_failure, tc)
{
	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: file does not exist */
	ATF_REQUIRE_EQ(-1, utimes(errpath, NULL));
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(utimes_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(futimes_success);
ATF_TC_HEAD(futimes_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"futimes(2) call");
}

ATF_TC_BODY(futimes_success, tc)
{
	int filedesc;
	char regex[30];

	/* File needs to exist to call futimes(2) */
	ATF_REQUIRE((filedesc = open(path, O_CREAT, mode)) != -1);
	ATF_REQUIRE_EQ(0, fstat(filedesc, &statbuff));
	/* Prepare the regex to be checked in the audit record */
	snprintf(regex, 30, "futimes.*%lu.*return,success", statbuff.st_ino);

	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(0, futimes(filedesc, NULL));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(futimes_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(futimes_failure);
ATF_TC_HEAD(futimes_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"futimes(2) call");
}

ATF_TC_BODY(futimes_failure, tc)
{
	const char *regex = "futimes.*return,failure : Bad file descriptor";
	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: Invalid file descriptor */
	ATF_REQUIRE_EQ(-1, futimes(-1, NULL));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(futimes_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(lutimes_success);
ATF_TC_HEAD(lutimes_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"lutimes(2) call");
}

ATF_TC_BODY(lutimes_success, tc)
{
	/* Symbolic link needs to exist to call lutimes(2) */
	ATF_REQUIRE_EQ(0, symlink("symlink", path));
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(0, lutimes(path, NULL));
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(lutimes_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(lutimes_failure);
ATF_TC_HEAD(lutimes_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"lutimes(2) call");
}

ATF_TC_BODY(lutimes_failure, tc)
{
	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: symbolic link does not exist */
	ATF_REQUIRE_EQ(-1, lutimes(errpath, NULL));
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(lutimes_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(futimesat_success);
ATF_TC_HEAD(futimesat_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"futimesat(2) call");
}

ATF_TC_BODY(futimesat_success, tc)
{
	/* File needs to exist to call futimesat(2) */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(0, futimesat(AT_FDCWD, path, NULL));
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(futimesat_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(futimesat_failure);
ATF_TC_HEAD(futimesat_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"futimesat(2) call");
}

ATF_TC_BODY(futimesat_failure, tc)
{
	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: file does not exist */
	ATF_REQUIRE_EQ(-1, futimesat(AT_FDCWD, errpath, NULL));
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(futimesat_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(mprotect_success);
ATF_TC_HEAD(mprotect_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"mprotect(2) call");
}

ATF_TC_BODY(mprotect_success, tc)
{
	const char *regex = "mprotect.*return,success";
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(0, mprotect(NULL, 0, 0));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(mprotect_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(mprotect_failure);
ATF_TC_HEAD(mprotect_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"mprotect(2) call");
}

ATF_TC_BODY(mprotect_failure, tc)
{
	const char *regex = "mprotect.*return,failure : Invalid argument";
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(-1, mprotect((void *)SIZE_MAX, -1, PROT_NONE));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(mprotect_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(undelete_failure);
ATF_TC_HEAD(undelete_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"undelete(2) call");
}

ATF_TC_BODY(undelete_failure, tc)
{
	const char *regex = "undelete.*return,failure";
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(-1, undelete(errpath));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(undelete_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(extattr_set_file_success);
ATF_TC_HEAD(extattr_set_file_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"extattr_set_file(2) call");
}

ATF_TC_BODY(extattr_set_file_success, tc)
{
	const char *buff = "ezio";
	/* File needs to exist to call extattr_set_file(2) */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	/* Prepare the regex to be checked in the audit record */
	snprintf(extregex, 80, "extattr_set_file.*%s.*%s.*return,success,%lu", \
		path, name, sizeof(buff));

	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(sizeof(buff), extattr_set_file(path, \
		EXTATTR_NAMESPACE_USER, name, buff, sizeof(buff)));
	check_audit(fds, extregex, pipefd);
}

ATF_TC_CLEANUP(extattr_set_file_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(extattr_set_file_failure);
ATF_TC_HEAD(extattr_set_file_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"extattr_set_file(2) call");
}

ATF_TC_BODY(extattr_set_file_failure, tc)
{
	/* Prepare the regex to be checked in the audit record */
	snprintf(extregex, 80, "extattr_set_file.*%s.*%s.*failure", path, name);

	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: file does not exist */
	ATF_REQUIRE_EQ(-1, extattr_set_file(path, \
		EXTATTR_NAMESPACE_USER, name, NULL, 0));
	check_audit(fds, extregex, pipefd);
}

ATF_TC_CLEANUP(extattr_set_file_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(extattr_set_fd_success);
ATF_TC_HEAD(extattr_set_fd_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"extattr_set_fd(2) call");
}

ATF_TC_BODY(extattr_set_fd_success, tc)
{
	int filedesc;
	const char *buff = "ezio";
	/* File needs to exist to call extattr_set_fd(2) */
	ATF_REQUIRE((filedesc = open(path, O_CREAT, mode)) != -1);

	/* Prepare the regex to be checked in the audit record */
	snprintf(extregex, 80, "extattr_set_fd.*%s.*return,success", name);
	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(sizeof(buff), extattr_set_fd(filedesc, \
		EXTATTR_NAMESPACE_USER, name, buff, sizeof(buff)));

	check_audit(fds, extregex, pipefd);
}

ATF_TC_CLEANUP(extattr_set_fd_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(extattr_set_fd_failure);
ATF_TC_HEAD(extattr_set_fd_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"extattr_set_fd(2) call");
}

ATF_TC_BODY(extattr_set_fd_failure, tc)
{
	/* Prepare the regex to be checked in the audit record */
	snprintf(extregex, 80, "extattr_set_fd.*%s.*return,failure : "
	"Bad file descriptor", name);

	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: Invalid file descriptor */
	ATF_REQUIRE_EQ(-1, extattr_set_fd(-1, \
		EXTATTR_NAMESPACE_USER, name, NULL, 0));
	check_audit(fds, extregex, pipefd);
}

ATF_TC_CLEANUP(extattr_set_fd_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(extattr_set_link_success);
ATF_TC_HEAD(extattr_set_link_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"extattr_set_link(2) call");
}

ATF_TC_BODY(extattr_set_link_success, tc)
{
	const char *buff = "ezio";
	/* Symbolic link needs to exist to call extattr_set_link(2) */
	ATF_REQUIRE_EQ(0, symlink("symlink", path));
	/* Prepare the regex to be checked in the audit record */
	snprintf(extregex, 80, "extattr_set_link.*%s.*%s.*return,success,%lu", \
		path, name, sizeof(buff));

	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE_EQ(sizeof(buff), extattr_set_link(path, \
		EXTATTR_NAMESPACE_USER, name, buff, sizeof(buff)));

	check_audit(fds, extregex, pipefd);
}

ATF_TC_CLEANUP(extattr_set_link_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(extattr_set_link_failure);
ATF_TC_HEAD(extattr_set_link_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"extattr_set_link(2) call");
}

ATF_TC_BODY(extattr_set_link_failure, tc)
{
	/* Prepare the regex to be checked in the audit record */
	snprintf(extregex, 80, "extattr_set_link.*%s.*%s.*failure", path, name);
	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: symbolic link does not exist */
	ATF_REQUIRE_EQ(-1, extattr_set_link(path, \
		EXTATTR_NAMESPACE_USER, name, NULL, 0));
	check_audit(fds, extregex, pipefd);
}

ATF_TC_CLEANUP(extattr_set_link_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(extattr_delete_file_success);
ATF_TC_HEAD(extattr_delete_file_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"extattr_delete_file(2) call");
}

ATF_TC_BODY(extattr_delete_file_success, tc)
{
	int readbuff;
	const char *buff = "ezio";
	/* File needs to exist to call extattr_delete_file(2) */
	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);
	ATF_REQUIRE_EQ(sizeof(buff), extattr_set_file(path, \
		EXTATTR_NAMESPACE_USER, name, buff, sizeof(buff)));

	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE((readbuff = extattr_delete_file(path, \
		EXTATTR_NAMESPACE_USER, name)) != -1);
	/* Prepare the regex to be checked in the audit record */
	snprintf(extregex, 80, "extattr_delete_file.*%s.*return,success,%d", \
		path, readbuff);
	check_audit(fds, extregex, pipefd);
}

ATF_TC_CLEANUP(extattr_delete_file_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(extattr_delete_file_failure);
ATF_TC_HEAD(extattr_delete_file_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"extattr_delete_file(2) call");
}

ATF_TC_BODY(extattr_delete_file_failure, tc)
{
	/* Prepare the regex to be checked in the audit record */
	snprintf(extregex, 80, "extattr_delete_file.*%s.*return,failure", path);

	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: file does not exist */
	ATF_REQUIRE_EQ(-1, extattr_delete_file(path, \
		EXTATTR_NAMESPACE_USER, name));
	check_audit(fds, extregex, pipefd);
}

ATF_TC_CLEANUP(extattr_delete_file_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(extattr_delete_fd_success);
ATF_TC_HEAD(extattr_delete_fd_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"extattr_delete_fd(2) call");
}

ATF_TC_BODY(extattr_delete_fd_success, tc)
{
	int filedesc, readbuff;
	const char *buff = "ezio";

	/* File needs to exist to call extattr_delete_fd(2) */
	ATF_REQUIRE((filedesc = open(path, O_CREAT, mode)) != -1);
	ATF_REQUIRE_EQ(sizeof(buff), extattr_set_file(path, \
		EXTATTR_NAMESPACE_USER, name, buff, sizeof(buff)));

	FILE *pipefd = setup(fds, "fm");
	ATF_REQUIRE((readbuff = extattr_delete_fd(filedesc, \
		EXTATTR_NAMESPACE_USER, name)) != -1);
	/* Prepare the regex to be checked in the audit record */
	snprintf(extregex, 80, "extattr_delete_fd.*return,success,%d", readbuff);
	check_audit(fds, extregex, pipefd);
}

ATF_TC_CLEANUP(extattr_delete_fd_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(extattr_delete_fd_failure);
ATF_TC_HEAD(extattr_delete_fd_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"extattr_delete_fd(2) call");
}

ATF_TC_BODY(extattr_delete_fd_failure, tc)
{
	/* Prepare the regex to be checked in the audit record */
	snprintf(extregex, 80, "extattr_delete_fd.*return,failure : "
				"Bad file descriptor");

	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: Invalid file descriptor */
	ATF_REQUIRE_EQ(-1, extattr_delete_fd(-1, EXTATTR_NAMESPACE_USER, name));
	check_audit(fds, extregex, pipefd);
}

ATF_TC_CLEANUP(extattr_delete_fd_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(extattr_delete_link_success);
ATF_TC_HEAD(extattr_delete_link_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"extattr_delete_link(2) call");
}

ATF_TC_BODY(extattr_delete_link_success, tc)
{
	int readbuff;
	const char *buff = "ezio";

	/* Symbolic link needs to exist to call extattr_delete_link(2) */
	ATF_REQUIRE_EQ(0, symlink("symlink", path));
	ATF_REQUIRE_EQ(sizeof(buff), extattr_set_link(path, \
		EXTATTR_NAMESPACE_USER, name, buff, sizeof(buff)));
	FILE *pipefd = setup(fds, "fm");

	ATF_REQUIRE((readbuff = extattr_delete_link(path, \
		EXTATTR_NAMESPACE_USER, name)) != -1);
	/* Prepare the regex to be checked in the audit record */
	snprintf(extregex, 80, "extattr_delete_link.*%s.*return,success,%d", \
		path, readbuff);
	check_audit(fds, extregex, pipefd);
}

ATF_TC_CLEANUP(extattr_delete_link_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(extattr_delete_link_failure);
ATF_TC_HEAD(extattr_delete_link_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"extattr_delete_link(2) call");
}

ATF_TC_BODY(extattr_delete_link_failure, tc)
{
	/* Prepare the regex to be checked in the audit record */
	snprintf(extregex, 80, "extattr_delete_link.*%s.*failure", path);
	FILE *pipefd = setup(fds, "fm");
	/* Failure reason: symbolic link does not exist */
	ATF_REQUIRE_EQ(-1, extattr_delete_link(path, \
		EXTATTR_NAMESPACE_USER, name));
	check_audit(fds, extregex, pipefd);
}

ATF_TC_CLEANUP(extattr_delete_link_failure, tc)
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
	ATF_TP_ADD_TC(tp, flock_success);
	ATF_TP_ADD_TC(tp, flock_failure);

	ATF_TP_ADD_TC(tp, fcntl_success);
	ATF_TP_ADD_TC(tp, fcntl_failure);

	ATF_TP_ADD_TC(tp, fsync_success);
	ATF_TP_ADD_TC(tp, fsync_failure);

	ATF_TP_ADD_TC(tp, chmod_success);
	ATF_TP_ADD_TC(tp, chmod_failure);
	ATF_TP_ADD_TC(tp, fchmod_success);
	ATF_TP_ADD_TC(tp, fchmod_failure);
	ATF_TP_ADD_TC(tp, lchmod_success);
	ATF_TP_ADD_TC(tp, lchmod_failure);
	ATF_TP_ADD_TC(tp, fchmodat_success);
	ATF_TP_ADD_TC(tp, fchmodat_failure);

	ATF_TP_ADD_TC(tp, chown_success);
	ATF_TP_ADD_TC(tp, chown_failure);
	ATF_TP_ADD_TC(tp, fchown_success);
	ATF_TP_ADD_TC(tp, fchown_failure);
	ATF_TP_ADD_TC(tp, lchown_success);
	ATF_TP_ADD_TC(tp, lchown_failure);
	ATF_TP_ADD_TC(tp, fchownat_success);
	ATF_TP_ADD_TC(tp, fchownat_failure);

	ATF_TP_ADD_TC(tp, chflags_success);
	ATF_TP_ADD_TC(tp, chflags_failure);
	ATF_TP_ADD_TC(tp, fchflags_success);
	ATF_TP_ADD_TC(tp, fchflags_failure);
	ATF_TP_ADD_TC(tp, lchflags_success);
	ATF_TP_ADD_TC(tp, lchflags_failure);
	//ATF_TP_ADD_TC(tp, chflagsat_success);
	//ATF_TP_ADD_TC(tp, chflagsat_failure);

	ATF_TP_ADD_TC(tp, utimes_success);
	ATF_TP_ADD_TC(tp, utimes_failure);
	ATF_TP_ADD_TC(tp, futimes_success);
	ATF_TP_ADD_TC(tp, futimes_failure);
	ATF_TP_ADD_TC(tp, lutimes_success);
	ATF_TP_ADD_TC(tp, lutimes_failure);
	ATF_TP_ADD_TC(tp, futimesat_success);
	ATF_TP_ADD_TC(tp, futimesat_failure);

	ATF_TP_ADD_TC(tp, mprotect_success);
	ATF_TP_ADD_TC(tp, mprotect_failure);
	ATF_TP_ADD_TC(tp, undelete_failure);

	ATF_TP_ADD_TC(tp, extattr_set_file_success);
	ATF_TP_ADD_TC(tp, extattr_set_file_failure);
	ATF_TP_ADD_TC(tp, extattr_set_fd_success);
	ATF_TP_ADD_TC(tp, extattr_set_fd_failure);
	ATF_TP_ADD_TC(tp, extattr_set_link_success);
	ATF_TP_ADD_TC(tp, extattr_set_link_failure);

	ATF_TP_ADD_TC(tp, extattr_delete_file_success);
	ATF_TP_ADD_TC(tp, extattr_delete_file_failure);
	ATF_TP_ADD_TC(tp, extattr_delete_fd_success);
	ATF_TP_ADD_TC(tp, extattr_delete_fd_failure);
	ATF_TP_ADD_TC(tp, extattr_delete_link_success);
	ATF_TP_ADD_TC(tp, extattr_delete_link_failure);

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
