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

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/stat.h>

#include <atf-c.h>

#include "utils.h"

struct msgstr {
	long int	mtype;
	char		mtext[128];
};
typedef struct msgstr msgstr_t;

static struct pollfd fds[1];
static struct msqid_ds msgbuff;
static int msqid;
static char ipcregex[60];
static ssize_t msgsize;


ATF_TC_WITH_CLEANUP(msgget_success);
ATF_TC_HEAD(msgget_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"msgget(2) call");
}

ATF_TC_BODY(msgget_success, tc)
{
	FILE *pipefd = setup(fds, "ip");
	ATF_REQUIRE((msqid = msgget(IPC_PRIVATE, IPC_CREAT | S_IRUSR)) != -1);
	/* Check the presence of message queue ID in audit record */
	snprintf(ipcregex, 60, "msgget.*return,success,%d", msqid);
	check_audit(fds, ipcregex, pipefd);

	/* Destroy the message queue with ID = msqid */
	ATF_REQUIRE_EQ(0, msgctl(msqid, IPC_RMID, NULL));
}

ATF_TC_CLEANUP(msgget_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(msgget_failure);
ATF_TC_HEAD(msgget_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"msgget(2) call");
}

ATF_TC_BODY(msgget_failure, tc)
{
	const char *regex = "msgget.*return,failure : No such file or directory";
	FILE *pipefd = setup(fds, "ip");
	ATF_REQUIRE_EQ(-1, msgget((key_t)(-1), 0));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(msgget_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(msgsnd_success);
ATF_TC_HEAD(msgsnd_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"msgsnd(2) call");
}

ATF_TC_BODY(msgsnd_success, tc)
{
	msqid = msgget(IPC_PRIVATE, IPC_CREAT | S_IRUSR);
	msgsize = sizeof(msgstr_t) - sizeof(long int);

	/* Initialize a msgstr_t structure to store message */
	msgstr_t msg1 = {1, "sample message"};
	/* Check the presence of message queue ID in audit record */
	snprintf(ipcregex, 60, "msgsnd.*Message IPC.*%d.*return,success", msqid);

	FILE *pipefd = setup(fds, "ip");
	ATF_REQUIRE_EQ(0, msgsnd(msqid, &msg1, msgsize, IPC_NOWAIT));
	check_audit(fds, ipcregex, pipefd);

	/* Destroy the message queue with ID = msqid */
	ATF_REQUIRE_EQ(0, msgctl(msqid, IPC_RMID, NULL));
}

ATF_TC_CLEANUP(msgsnd_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(msgsnd_failure);
ATF_TC_HEAD(msgsnd_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"msgsnd(2) call");
}

ATF_TC_BODY(msgsnd_failure, tc)
{
	const char *regex = "msgsnd.*Message IPC.*return,failure : Bad address";
	FILE *pipefd = setup(fds, "ip");
	ATF_REQUIRE_EQ(-1, msgsnd(-1, NULL, 0, IPC_NOWAIT));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(msgsnd_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(msgrcv_success);
ATF_TC_HEAD(msgrcv_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"msgrcv(2) call");
}

ATF_TC_BODY(msgrcv_success, tc)
{
	ssize_t recv_bytes;
	msqid = msgget(IPC_PRIVATE, IPC_CREAT | S_IRUSR);
	msgsize = sizeof(msgstr_t) - sizeof(long int);

	/* Initialize two msgstr_t structures to store respective messages */
	msgstr_t msg1 = {1, "sample message"};
	msgstr_t msg2;

	/* Send a message to the queue with ID = msqid */
	ATF_REQUIRE_EQ(0, msgsnd(msqid, &msg1, msgsize, IPC_NOWAIT));

	FILE *pipefd = setup(fds, "ip");
	ATF_REQUIRE((recv_bytes = msgrcv(msqid, &msg2, \
		msgsize, 0, MSG_NOERROR | IPC_NOWAIT)) != -1);
	/* Check the presence of queue ID and returned bytes in audit record */
	snprintf(ipcregex, 60, \
		"msgrcv.*Message IPC,*%d.*return,success,%zd", msqid, recv_bytes);
	check_audit(fds, ipcregex, pipefd);

	/* Destroy the message queue with ID = msqid */
	ATF_REQUIRE_EQ(0, msgctl(msqid, IPC_RMID, NULL));
}

ATF_TC_CLEANUP(msgrcv_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(msgrcv_failure);
ATF_TC_HEAD(msgrcv_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"msgrcv(2) call");
}

ATF_TC_BODY(msgrcv_failure, tc)
{
	const char *regex = "msgrcv.*return,failure : Invalid argument";
	FILE *pipefd = setup(fds, "ip");
	ATF_REQUIRE_EQ(-1, msgrcv(-1, NULL, 0, 0, MSG_NOERROR | IPC_NOWAIT));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(msgrcv_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(msgctl_rmid_success);
ATF_TC_HEAD(msgctl_rmid_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"msgctl(2) call for IPC_RMID command");
}

ATF_TC_BODY(msgctl_rmid_success, tc)
{
	msqid = msgget(IPC_PRIVATE, IPC_CREAT | S_IRUSR);

	FILE *pipefd = setup(fds, "ip");
	ATF_REQUIRE_EQ(0, msgctl(msqid, IPC_RMID, NULL));
	/* Check the presence of queue ID and IPC_RMID in audit record */
	snprintf(ipcregex, 60, "msgctl.*IPC_RMID.*%d.*return,success", msqid);
	check_audit(fds, ipcregex, pipefd);
}

ATF_TC_CLEANUP(msgctl_rmid_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(msgctl_rmid_failure);
ATF_TC_HEAD(msgctl_rmid_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"msgctl(2) call for IPC_RMID command");
}

ATF_TC_BODY(msgctl_rmid_failure, tc)
{
	const char *regex = "msgctl.*IPC_RMID.*return,failure : Invalid argument";
	FILE *pipefd = setup(fds, "ip");
	ATF_REQUIRE_EQ(-1, msgctl(-1, IPC_RMID, NULL));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(msgctl_rmid_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(msgctl_stat_success);
ATF_TC_HEAD(msgctl_stat_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"msgctl(2) call for IPC_STAT command");
}

ATF_TC_BODY(msgctl_stat_success, tc)
{
	msqid = msgget(IPC_PRIVATE, IPC_CREAT | S_IRUSR);

	FILE *pipefd = setup(fds, "ip");
	ATF_REQUIRE_EQ(0, msgctl(msqid, IPC_STAT, &msgbuff));
	/* Check the presence of queue ID and IPC_STAT in audit record */
	snprintf(ipcregex, 60, "msgctl.*IPC_STAT.*%d.*return,success", msqid);
	check_audit(fds, ipcregex, pipefd);

	/* Destroy the message queue with ID = msqid */
	ATF_REQUIRE_EQ(0, msgctl(msqid, IPC_RMID, NULL));
}

ATF_TC_CLEANUP(msgctl_stat_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(msgctl_stat_failure);
ATF_TC_HEAD(msgctl_stat_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"msgctl(2) call for IPC_STAT command");
}

ATF_TC_BODY(msgctl_stat_failure, tc)
{
	const char *regex = "msgctl.*IPC_STAT.*return,failure : Invalid argument";
	FILE *pipefd = setup(fds, "ip");
	ATF_REQUIRE_EQ(-1, msgctl(-1, IPC_STAT, &msgbuff));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(msgctl_stat_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(msgctl_set_success);
ATF_TC_HEAD(msgctl_set_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"msgctl(2) call for IPC_SET command");
}

ATF_TC_BODY(msgctl_set_success, tc)
{
	msqid = msgget(IPC_PRIVATE, IPC_CREAT | S_IRUSR);
	/* Fill up the msgbuff structure to be used with IPC_SET */
	ATF_REQUIRE_EQ(0, msgctl(msqid, IPC_STAT, &msgbuff));

	FILE *pipefd = setup(fds, "ip");
	ATF_REQUIRE_EQ(0, msgctl(msqid, IPC_SET, &msgbuff));
	/* Check the presence of message queue ID in audit record */
	snprintf(ipcregex, 60, "msgctl.*IPC_SET.*%d.*return,success", msqid);
	check_audit(fds, ipcregex, pipefd);

	/* Destroy the message queue with ID = msqid */
	ATF_REQUIRE_EQ(0, msgctl(msqid, IPC_RMID, NULL));
}

ATF_TC_CLEANUP(msgctl_set_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(msgctl_set_failure);
ATF_TC_HEAD(msgctl_set_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"msgctl(2) call for IPC_SET command");
}

ATF_TC_BODY(msgctl_set_failure, tc)
{
	const char *regex = "msgctl.*IPC_SET.*return,failure : Invalid argument";
	FILE *pipefd = setup(fds, "ip");
	ATF_REQUIRE_EQ(-1, msgctl(-1, IPC_SET, &msgbuff));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(msgctl_set_failure, tc)
{
	cleanup();
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, msgget_success);
	ATF_TP_ADD_TC(tp, msgget_failure);
	ATF_TP_ADD_TC(tp, msgsnd_success);
	ATF_TP_ADD_TC(tp, msgsnd_failure);
	ATF_TP_ADD_TC(tp, msgrcv_success);
	ATF_TP_ADD_TC(tp, msgrcv_failure);

	ATF_TP_ADD_TC(tp, msgctl_rmid_success);
	ATF_TP_ADD_TC(tp, msgctl_rmid_failure);
	ATF_TP_ADD_TC(tp, msgctl_stat_success);
	ATF_TP_ADD_TC(tp, msgctl_stat_failure);
	ATF_TP_ADD_TC(tp, msgctl_set_success);
	ATF_TP_ADD_TC(tp, msgctl_set_failure);

	return (atf_no_error());
}
