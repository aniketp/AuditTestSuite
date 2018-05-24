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

#include <sys/socket.h>

#include <atf-c.h>
#include <unistd.h>

#include "utils.h"
#define ERROR (-1)

static int sockfd;
static int tr = 1;
static struct pollfd fds[1];
static char regex[40];

ATF_TC_WITH_CLEANUP(socket_success);
ATF_TC_HEAD(socket_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"socket(2) call");
}

ATF_TC_BODY(socket_success, tc)
{
	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE((sockfd = socket(PF_INET, SOCK_STREAM, 0)) != -1);
	/* Check the presence of sockfd in audit record */
	snprintf(regex, 30, "socket.*return,success,%d", sockfd);
	check_audit(fds, regex, pipefd);
	close(sockfd);
}

ATF_TC_CLEANUP(socket_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(socket_failure);
ATF_TC_HEAD(socket_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"socket(2) call");
}

ATF_TC_BODY(socket_failure, tc)
{
	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(-1, socket(ERROR, SOCK_STREAM, 0));
	/* Check the presence of hex(-1) in audit record */
	snprintf(regex, 40, "socket.*0x%x.*return,failure", ERROR);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(socket_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(setsockopt_success);
ATF_TC_HEAD(setsockopt_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"setsockopt(2) call");
}

ATF_TC_BODY(setsockopt_success, tc)
{
	ATF_REQUIRE((sockfd = socket(PF_INET, SOCK_STREAM, 0)) != -1);
	/* Check the presence of sockfd in audit record */
	snprintf(regex, 30, "setsockopt.*0x%x.*return,success", sockfd);

	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(0, setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &tr, \
		sizeof(int)))
	check_audit(fds, regex, pipefd);
	close(sockfd);
}

ATF_TC_CLEANUP(setsockopt_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(setsockopt_failure);
ATF_TC_HEAD(setsockopt_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"setsockopt(2) call");
}

ATF_TC_BODY(setsockopt_failure, tc)
{
	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(-1, setsockopt(ERROR, SOL_SOCKET, SO_REUSEADDR, &tr, \
		sizeof(int)));
	/* Check the presence of hex(-1) in audit record */
	snprintf(regex, 40, "setsockopt.*0x%x.*return,failure", ERROR);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(setsockopt_failure, tc)
{
	cleanup();
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, socket_success);
	ATF_TP_ADD_TC(tp, socket_failure);
	ATF_TP_ADD_TC(tp, setsockopt_success);
	ATF_TP_ADD_TC(tp, setsockopt_failure);

	return (atf_no_error());
}
