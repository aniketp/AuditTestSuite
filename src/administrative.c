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

#include <sys/time.h>

#include <atf-c.h>

#include "utils.h"

static struct pollfd fds[1];


ATF_TC_WITH_CLEANUP(settimeofday_success);
ATF_TC_HEAD(settimeofday_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"settimeofday(2) call");
}

ATF_TC_BODY(settimeofday_success, tc)
{
	struct timeval tp;
	struct timezone *tzp;
	ATF_REQUIRE_EQ(0, gettimeofday(&tp, &tzp));

	FILE *pipefd = setup(fds, "ad");
	/* Setting the same time as obtained by gettimeofday(2) */
	ATF_REQUIRE_EQ(0, settimeofday(tp, tzp));
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(settimeofday_success, tc)
{
	cleanup();
}
