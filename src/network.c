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
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <atf-c.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>

#include "utils.h"

#define ERROR (-1)
#define SERVER_PATH "server"
#define MAX_DATA 1024

static int sockfd, sockfd2;
static int tr = 1;
static socklen_t len;
static struct pollfd fds[1];
static char regex[60];
static char data[MAX_DATA];
static char msgbuff[] = "Sample Message\n";

/*
 * Assign local address to a server's socket
 */
static void
assign_address(struct sockaddr_un *server)
{
	memset(server, 0, sizeof(*server));
	server->sun_family = AF_UNIX;
	strcpy(server->sun_path, SERVER_PATH);
}

/*
 * Check the read status of client socket descriptor
 */
static int
check_readfs(int clientfd)
{
	struct timeval timeout;
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;

	/* Initialize fd_set using the provided MACROS for select() */
	fd_set readfs;
	FD_ZERO(&readfs);
 	FD_SET(clientfd, &readfs);

	/* Check if clientfd is ready for receiving data and return */
	ATF_REQUIRE(select(clientfd+1, &readfs, NULL, NULL, &timeout) > 0);
	return (FD_ISSET(clientfd, &readfs));
}

/*
 * Initialize iovec structure to be used as a field of struct msghdr 
 */
static void
init_iov(struct iovec *io, char msgbuf[], int DATALEN)
{
	io->iov_base = msgbuf;
	io->iov_len = DATALEN;
}

/*
 * Initialize msghdr structure for communication via datagram sockets
 */
static void
init_msghdr(struct msghdr *hdrbuf, struct iovec *io, struct sockaddr_un *address)
{
	ssize_t length;
	length = sizeof(struct sockaddr_un);
	hdrbuf->msg_name = address;
	hdrbuf->msg_namelen = length;
	hdrbuf->msg_iov = io;
	hdrbuf->msg_iovlen = 1;
}

/*
 * Variadic function to close socket descriptors
 */
static void
close_sockets(int count, ...)
{
	int sockd;
	va_list socklist;
	va_start(socklist, count);
	for (sockd = 0; sockd < count; sockd++) {
		close(va_arg(socklist, int));
	}
	va_end(socklist);
}


ATF_TC_WITH_CLEANUP(socket_success);
ATF_TC_HEAD(socket_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"socket(2) call");
}

ATF_TC_BODY(socket_success, tc)
{
	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE((sockfd = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);
	/* Check the presence of sockfd in audit record */
	snprintf(regex, 60, "socket.*return,success,%d", sockfd);
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
	snprintf(regex, 60, "socket.*0x%x.*return,failure", ERROR);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(socket_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(socketpair_success);
ATF_TC_HEAD(socketpair_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"socketpair(2) call");
}

ATF_TC_BODY(socketpair_success, tc)
{
	int sv[2];
	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(0, socketpair(PF_UNIX, SOCK_STREAM, 0, sv));
	/* Check the presence of 0x0 in audit record */
	snprintf(regex, 60, "socketpair.*0x0.*return,success");
	check_audit(fds, regex, pipefd);
	/* Close all socket descriptors */
	close_sockets(2, sv[0], sv[1]);
}

ATF_TC_CLEANUP(socketpair_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(socketpair_failure);
ATF_TC_HEAD(socketpair_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"socketpair(2) call");
}

ATF_TC_BODY(socketpair_failure, tc)
{
	int sv;
	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(-1, socketpair(ERROR, SOCK_STREAM, 0, &sv));
	/* Check the presence of hex(-1) in audit record */
	snprintf(regex, 60, "socketpair.*0x%x.*return,failure", ERROR);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(socketpair_failure, tc)
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
	ATF_REQUIRE((sockfd = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);
	/* Check the presence of sockfd in audit record */
	snprintf(regex, 60, "setsockopt.*0x%x.*return,success", sockfd);

	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(0, setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &tr, \
		sizeof(int)));
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
	snprintf(regex, 60, "setsockopt.*0x%x.*return,failure", ERROR);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(setsockopt_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(bind_success);
ATF_TC_HEAD(bind_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"bind(2) call");
}

ATF_TC_BODY(bind_success, tc)
{
	struct sockaddr_un server;
	assign_address(&server);
	len = sizeof(struct sockaddr_un);

	/* Preliminary socket setup */
	ATF_REQUIRE((sockfd = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);
	/* Check the presence of AF_UNIX address path in audit record */
	snprintf(regex, 60, "bind.*unix.*%s.*return,success", SERVER_PATH);

	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(0, bind(sockfd, (struct sockaddr *)&server, len));
	check_audit(fds, regex, pipefd);
	close(sockfd);
}

ATF_TC_CLEANUP(bind_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(bind_failure);
ATF_TC_HEAD(bind_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"bind(2) call");
}

ATF_TC_BODY(bind_failure, tc)
{
	/* Preliminary socket setup */
	struct sockaddr_un server;
	assign_address(&server);
	len = sizeof(struct sockaddr_un);

	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(-1, bind(-1, (struct sockaddr *)&server, len));
	/* Check the presence of hex(-1) and AF_UNIX path in audit record */
	snprintf(regex, 60, "bind.*0x%x.*%s.*return,failure", ERROR, SERVER_PATH);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(bind_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(bindat_success);
ATF_TC_HEAD(bindat_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"bindat(2) call");
}

ATF_TC_BODY(bindat_success, tc)
{
	struct sockaddr_un server;
	assign_address(&server);
	len = sizeof(struct sockaddr_un);

	/* Preliminary socket setup */
	ATF_REQUIRE((sockfd = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);
	/* Check the presence of socket descriptor in audit record */
	snprintf(regex, 60, "bindat.*0x%x.*return,success", sockfd);

	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(0, bindat(AT_FDCWD, sockfd, \
		(struct sockaddr *)&server, len));
	check_audit(fds, regex, pipefd);
	close(sockfd);
}

ATF_TC_CLEANUP(bindat_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(bindat_failure);
ATF_TC_HEAD(bindat_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"bindat(2) call");
}

ATF_TC_BODY(bindat_failure, tc)
{
	/* Preliminary socket setup */
	struct sockaddr_un server;
	assign_address(&server);
	len = sizeof(struct sockaddr_un);

	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(-1, bindat(AT_FDCWD, -1, (struct sockaddr *)&server, len));
	/* Check the presence of hex(-1) in audit record */
	snprintf(regex, 60, "bindat.*0x%x.*return,failure", ERROR);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(bindat_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(listen_success);
ATF_TC_HEAD(listen_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"listen(2) call");
}

ATF_TC_BODY(listen_success, tc)
{
	struct sockaddr_un server;
	assign_address(&server);
	len = sizeof(struct sockaddr_un);

	/* Preliminary socket setup */
	ATF_REQUIRE((sockfd = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);
	ATF_REQUIRE_EQ(0, bind(sockfd, (struct sockaddr *)&server, len));
	/* Check the presence of socket descriptor in the audit record */
	snprintf(regex, 60, "listen.*0x%x.*return,success", sockfd);

	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(0, listen(sockfd, 1));
	check_audit(fds, regex, pipefd);
	close(sockfd);
}

ATF_TC_CLEANUP(listen_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(listen_failure);
ATF_TC_HEAD(listen_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"listen(2) call");
}

ATF_TC_BODY(listen_failure, tc)
{
	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(-1, listen(ERROR, 1));
	/* Check the presence of hex(-1) in audit record */
	snprintf(regex, 60, "listen.*0x%x.*return,failure", ERROR);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(listen_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(connect_success);
ATF_TC_HEAD(connect_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"connect(2) call");
}

ATF_TC_BODY(connect_success, tc)
{
	struct sockaddr_un server;
	assign_address(&server);
	len = sizeof(struct sockaddr_un);

	/* Server Socket: Assign address and listen for connection */
	ATF_REQUIRE((sockfd = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);
	/* Non-blocking server socket */
	ATF_REQUIRE(fcntl(sockfd, F_SETFL, O_NONBLOCK) != -1);
	/* Bind to the specified address and wait for connection */
	ATF_REQUIRE_EQ(0, bind(sockfd, (struct sockaddr *)&server, len));
	ATF_REQUIRE_EQ(0, listen(sockfd, 1));

	/* Set up "blocking" client socket */
	ATF_REQUIRE((sockfd2 = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);

	/* Audit record must contain AF_UNIX address path & sockfd2 */
	snprintf(regex, 60, "connect.*0x%x.*%s.*success", sockfd2, SERVER_PATH);

	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(0, connect(sockfd2, (struct sockaddr *)&server, len));
	check_audit(fds, regex, pipefd);

	/* Close all socket descriptors */
	close_sockets(2, sockfd, sockfd2);
}

ATF_TC_CLEANUP(connect_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(connect_failure);
ATF_TC_HEAD(connect_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"connect(2) call");
}

ATF_TC_BODY(connect_failure, tc)
{
	/* Preliminary socket setup */
	struct sockaddr_un server;
	assign_address(&server);
	len = sizeof(struct sockaddr_un);

	/* Audit record must contain AF_UNIX address path & Hex(-1) */
	snprintf(regex, 60, "connect.*0x%x.*%s.*failure", ERROR, SERVER_PATH);

	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(-1, connect(ERROR, (struct sockaddr *)&server, len));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(connect_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(connectat_success);
ATF_TC_HEAD(connectat_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"connectat(2) call");
}

ATF_TC_BODY(connectat_success, tc)
{
	struct sockaddr_un server;
	assign_address(&server);
	len = sizeof(struct sockaddr_un);

	/* Server Socket: Assign address and listen for connection */
	ATF_REQUIRE((sockfd = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);
	/* Non-blocking server socket */
	ATF_REQUIRE(fcntl(sockfd, F_SETFL, O_NONBLOCK) != -1);
	/* Bind to the specified address and wait for connection */
	ATF_REQUIRE_EQ(0, bind(sockfd, (struct sockaddr *)&server, len));
	ATF_REQUIRE_EQ(0, listen(sockfd, 1));

	/* Set up "blocking" client socket */
	ATF_REQUIRE((sockfd2 = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);

	/* Audit record must contain sockfd2 */
	snprintf(regex, 60, "connectat.*0x%x.*return,success", sockfd2);

	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(0, connectat(AT_FDCWD, sockfd2, \
		(struct sockaddr *)&server, len));
	check_audit(fds, regex, pipefd);

	/* Close all socket descriptors */
	close_sockets(2, sockfd, sockfd2);
}

ATF_TC_CLEANUP(connectat_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(connectat_failure);
ATF_TC_HEAD(connectat_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"connectat(2) call");
}

ATF_TC_BODY(connectat_failure, tc)
{
	/* Preliminary socket setup */
	struct sockaddr_un server;
	assign_address(&server);
	len = sizeof(struct sockaddr_un);

	/* Audit record must contain Hex(-1) */
	snprintf(regex, 60, "connectat.*0x%x.*return,failure", ERROR);

	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(-1, connectat(AT_FDCWD, ERROR, \
		(struct sockaddr *)&server, len));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(connectat_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(accept_success);
ATF_TC_HEAD(accept_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"accept(2) call");
}

ATF_TC_BODY(accept_success, tc)
{
	int clientfd;
	struct sockaddr_un server, client;
	assign_address(&server);
	len = sizeof(struct sockaddr_un);

	/* Server Socket: Assign address and listen for connection */
	ATF_REQUIRE((sockfd = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);
	/* Non-blocking server socket */
	ATF_REQUIRE(fcntl(sockfd, F_SETFL, O_NONBLOCK) != -1);
	/* Bind to the specified address and wait for connection */
	ATF_REQUIRE_EQ(0, bind(sockfd, (struct sockaddr *)&server, len));
	ATF_REQUIRE_EQ(0, listen(sockfd, 1));

	/* Set up "blocking" client socket */
	ATF_REQUIRE((sockfd2 = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);
	ATF_REQUIRE_EQ(0, connect(sockfd2, (struct sockaddr *)&server, len));

	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE((clientfd = accept(sockfd, \
		(struct sockaddr *)&client, &len)) != -1);

	/* Audit record must contain clientfd & sockfd */
	snprintf(regex, 60, \
		"accept.*0x%x.*return,success,%d", sockfd, clientfd);
	check_audit(fds, regex, pipefd);

	/* Close all socket descriptors */
	close_sockets(3, sockfd, sockfd2, clientfd);
}

ATF_TC_CLEANUP(accept_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(accept_failure);
ATF_TC_HEAD(accept_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"accept(2) call");
}

ATF_TC_BODY(accept_failure, tc)
{
	/* Preliminary socket setup */
	struct sockaddr_un client;
	len = sizeof(struct sockaddr_un);

	/* Audit record must contain Hex(-1) */
	snprintf(regex, 60, "accept.*0x%x.*return,failure", ERROR);

	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(-1, accept(ERROR, (struct sockaddr *)&client, &len));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(accept_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(send_success);
ATF_TC_HEAD(send_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"send(2) call");
}

ATF_TC_BODY(send_success, tc)
{
	/* Preliminary socket setup */
	int clientfd;
	ssize_t bytes_sent;
	struct sockaddr_un server, client;
	assign_address(&server);
	len = sizeof(struct sockaddr_un);

	/* Server Socket: Assign address and listen for connection */
	ATF_REQUIRE((sockfd = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);
	/* Non-blocking server socket */
	ATF_REQUIRE(fcntl(sockfd, F_SETFL, O_NONBLOCK) != -1);
	/* Bind to the specified address and wait for connection */
	ATF_REQUIRE_EQ(0, bind(sockfd, (struct sockaddr *)&server, len));
	ATF_REQUIRE_EQ(0, listen(sockfd, 1));

	/* Set up "blocking" client and connect with non-blocking server */
	ATF_REQUIRE((sockfd2 = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);
	ATF_REQUIRE_EQ(0, connect(sockfd2, (struct sockaddr *)&server, len));
	ATF_REQUIRE((clientfd = accept(sockfd, \
		(struct sockaddr *)&client, &len)) != -1);

	/* Send a sample message to the connected socket */
	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE((bytes_sent = \
		send(sockfd2, msgbuff, strlen(msgbuff), 0)) != -1);

	/* Audit record must contain sockfd2 and bytes_sent */
	snprintf(regex, 60, \
		"send.*0x%x.*return,success,%zd", sockfd2, bytes_sent);
	check_audit(fds, regex, pipefd);

	/* Close all socket descriptors */
	close_sockets(3, sockfd, sockfd2, clientfd);
}

ATF_TC_CLEANUP(send_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(send_failure);
ATF_TC_HEAD(send_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"send(2) call");
}

ATF_TC_BODY(send_failure, tc)
{
	/* Audit record must contain Hex(-1) */
	snprintf(regex, 60, "send.*0x%x.*return,failure", ERROR);
	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(-1, send(ERROR, msgbuff, strlen(msgbuff), 0));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(send_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(recv_success);
ATF_TC_HEAD(recv_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"recv(2) call");
}

ATF_TC_BODY(recv_success, tc)
{
	/* Preliminary socket setup */
	int clientfd;
	ssize_t bytes_recv;
	struct sockaddr_un server, client;
	assign_address(&server);
	len = sizeof(struct sockaddr_un);

	/* Server Socket: Assign address and listen for connection */
	ATF_REQUIRE((sockfd = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);
	/* Non-blocking server socket */
	ATF_REQUIRE(fcntl(sockfd, F_SETFL, O_NONBLOCK) != -1);
	/* Bind to the specified address and wait for connection */
	ATF_REQUIRE_EQ(0, bind(sockfd, (struct sockaddr *)&server, len));
	ATF_REQUIRE_EQ(0, listen(sockfd, 1));

	/* Set up "blocking" client and connect with non-blocking server */
	ATF_REQUIRE((sockfd2 = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);
	ATF_REQUIRE_EQ(0, connect(sockfd2, (struct sockaddr *)&server, len));
	ATF_REQUIRE((clientfd = accept(sockfd, \
		(struct sockaddr *)&client, &len)) != -1);
	/* Send a sample message to the connected socket */
	ATF_REQUIRE(send(sockfd2, msgbuff, strlen(msgbuff), 0) != -1);

	/* Receive data once clientfd is ready for reading */
	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE(check_readfs(clientfd) != 0);
	ATF_REQUIRE((bytes_recv = recv(clientfd, data, MAX_DATA, 0)) != 0);

	/* Audit record must contain clientfd and bytes_recv */
	snprintf(regex, 60, \
		"recv.*0x%x.*return,success,%zd", clientfd, bytes_recv);
	check_audit(fds, regex, pipefd);

	/* Close all socket descriptors */
	close_sockets(3, sockfd, sockfd2, clientfd);
}

ATF_TC_CLEANUP(recv_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(recv_failure);
ATF_TC_HEAD(recv_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"recv(2) call");
}

ATF_TC_BODY(recv_failure, tc)
{
	/* Audit record must contain Hex(-1) */
	snprintf(regex, 60, "recv.*0x%x.*return,failure", ERROR);
	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(-1, recv(ERROR, data, MAX_DATA, 0));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(recv_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(sendto_success);
ATF_TC_HEAD(sendto_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"sendto(2) call");
}

ATF_TC_BODY(sendto_success, tc)
{
	/* Preliminary socket setup */
	int clientfd;
	ssize_t bytes_sent;
	struct sockaddr_un server, client;
	assign_address(&server);
	len = sizeof(struct sockaddr_un);

	/* Server Socket: Assign address and listen for connection */
	ATF_REQUIRE((sockfd = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);
	/* Non-blocking server socket */
	ATF_REQUIRE(fcntl(sockfd, F_SETFL, O_NONBLOCK) != -1);
	/* Bind to the specified address and wait for connection */
	ATF_REQUIRE_EQ(0, bind(sockfd, (struct sockaddr *)&server, len));
	ATF_REQUIRE_EQ(0, listen(sockfd, 1));

	/* Set up "blocking" client and connect with non-blocking server */
	ATF_REQUIRE((sockfd2 = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);
	ATF_REQUIRE_EQ(0, connect(sockfd2, (struct sockaddr *)&server, len));
	ATF_REQUIRE((clientfd = accept(sockfd, \
		(struct sockaddr *)&client, &len)) != -1);

	/* Send a sample message to client's address */
	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE((bytes_sent = sendto(sockfd2, msgbuff, \
		strlen(msgbuff), 0, (struct sockaddr *)&client, len)) != -1);

	/* Audit record must contain  sockfd2 and bytes_sent */
	snprintf(regex, 60, \
		"sendto.*0x%x.*return,success,%zd", sockfd2, bytes_sent);
	check_audit(fds, regex, pipefd);

	/* Close all socket descriptors */
	close_sockets(3, sockfd, sockfd2, clientfd);
}

ATF_TC_CLEANUP(sendto_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(sendto_failure);
ATF_TC_HEAD(sendto_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"sendto(2) call");
}

ATF_TC_BODY(sendto_failure, tc)
{
	/* Preliminary client address setup */
	struct sockaddr_un client;
	len  = sizeof(struct sockaddr_un);

	/* Audit record must contain Hex(-1) */
	snprintf(regex, 60, "sendto.*0x%x.*return,failure", ERROR);
	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(-1, sendto(ERROR, msgbuff, \
		strlen(msgbuff), 0, (struct sockaddr *)&client, len));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(sendto_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(recvfrom_success);
ATF_TC_HEAD(recvfrom_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"recvfrom(2) call");
}

ATF_TC_BODY(recvfrom_success, tc)
{
	/* Preliminary socket setup */
	int clientfd;
	ssize_t bytes_recv;
	struct sockaddr_un server, client;
	assign_address(&server);
	len = sizeof(struct sockaddr_un);

	/* Server Socket: Assign address and listen for connection */
	ATF_REQUIRE((sockfd = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);
	/* Non-blocking server socket */
	ATF_REQUIRE(fcntl(sockfd, F_SETFL, O_NONBLOCK) != -1);
	/* Bind to the specified address and wait for connection */
	ATF_REQUIRE_EQ(0, bind(sockfd, (struct sockaddr *)&server, len));
	ATF_REQUIRE_EQ(0, listen(sockfd, 1));

	/* Set up "blocking" client and connect with non-blocking server */
	ATF_REQUIRE((sockfd2 = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);
	ATF_REQUIRE_EQ(0, connect(sockfd2, (struct sockaddr *)&server, len));
	ATF_REQUIRE((clientfd = accept(sockfd, \
		(struct sockaddr *)&client, &len)) != -1);
	/* Send a sample message to the connected socket */
	ATF_REQUIRE(send(sockfd2, msgbuff, strlen(msgbuff), 0) != -1);

	/* Receive data once clientfd is ready for reading */
	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE(check_readfs(clientfd) != 0);
	ATF_REQUIRE((bytes_recv = recvfrom(clientfd, data, \
		MAX_DATA, 0, (struct sockaddr *)&client, &len)) != 0);

	/* Audit record must contain clientfd and bytes_sent */
	snprintf(regex, 60, \
		"recvfrom.*0x%x.*return,success,%zd", clientfd, bytes_recv);
	check_audit(fds, regex, pipefd);

	/* Close all socket descriptors */
	close_sockets(3, sockfd, sockfd2, clientfd);
}

ATF_TC_CLEANUP(recvfrom_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(recvfrom_failure);
ATF_TC_HEAD(recvfrom_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"recvfrom(2) call");
}

ATF_TC_BODY(recvfrom_failure, tc)
{
	/* Preliminary client address setup */
	struct sockaddr_un client;
	len = sizeof(struct sockaddr_un);

	/* Audit record must contain Hex(-1) */
	snprintf(regex, 60, "recvfrom.*0x%x.*return,failure", ERROR);
	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(-1, recvfrom(ERROR, data, \
		MAX_DATA, 0, (struct sockaddr *)&client, &len));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(recvfrom_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(sendmsg_success);
ATF_TC_HEAD(sendmsg_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"recvmsg(2) call");
}

ATF_TC_BODY(sendmsg_success, tc)
{
	/* Preliminary socket setup */
	ssize_t bytes_sent;
	struct msghdr sendbuf = {}, recvbuf = {};
	struct iovec io1, io2;
	struct sockaddr_un server, client;
	assign_address(&server);
	len = sizeof(struct sockaddr_un);

	/* Create a datagram server socket & bind to UNIX address family */
	ATF_REQUIRE((sockfd = socket(PF_UNIX, SOCK_DGRAM, 0)) != -1);
	/* Non-blocking server socket */
	ATF_REQUIRE(fcntl(sockfd, F_SETFL, O_NONBLOCK) != -1);
	ATF_REQUIRE_EQ(0, bind(sockfd, (struct sockaddr *)&server, len));

	/* Message buffer to be sent to the server */
	init_iov(&io1, msgbuff, sizeof(msgbuff));
	init_msghdr(&sendbuf, &io1, &server);

	/* Prepare buffer to store the received data in */
	init_iov(&io2, data, MAX_DATA);
	init_msghdr(&recvbuf, &io2, &client);

	/* Set up "blocking" UDP client to communicate with the server */
	ATF_REQUIRE((sockfd2 = socket(PF_UNIX, SOCK_DGRAM, 0)) != -1);

	/* Send a sample message to the specified client address */
	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE((bytes_sent = sendmsg(sockfd2, &sendbuf, 0)) != -1);

	/* Audit record must contain sockfd2 and bytes_sent */
	snprintf(regex, 60, \
		"sendmsg.*0x%x.*return,success,%zd", sockfd2, bytes_sent);
	check_audit(fds, regex, pipefd);

	/* Close all socket descriptors */
	close_sockets(2, sockfd, sockfd2);
}

ATF_TC_CLEANUP(sendmsg_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(sendmsg_failure);
ATF_TC_HEAD(sendmsg_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"sendmsg(2) call");
}

ATF_TC_BODY(sendmsg_failure, tc)
{
	struct msghdr msgbuf;
	/* Audit record must contain Hex(-1) */
	snprintf(regex, 60, "sendmsg.*return,failure : Message too long");
	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(-1, sendmsg(ERROR, &msgbuf, 0));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(sendmsg_failure, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(recvmsg_success);
ATF_TC_HEAD(recvmsg_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"recvmsg(2) call");
}

ATF_TC_BODY(recvmsg_success, tc)
{
	/* Preliminary socket setup */
	ssize_t bytes_recv;
	struct msghdr sendbuf = {}, recvbuf = {};
	struct iovec io1, io2;
	struct sockaddr_un server, client;
	assign_address(&server);
	len = sizeof(struct sockaddr_un);

	/* Create a datagram server socket & bind to UNIX address family */
	ATF_REQUIRE((sockfd = socket(PF_UNIX, SOCK_DGRAM, 0)) != -1);
	/* Non-blocking server socket */
	ATF_REQUIRE(fcntl(sockfd, F_SETFL, O_NONBLOCK) != -1);
	ATF_REQUIRE_EQ(0, bind(sockfd, (struct sockaddr *)&server, len));

	/* Message buffer to be sent to the server */
	init_iov(&io1, msgbuff, sizeof(msgbuff));
	init_msghdr(&sendbuf, &io1, &server);

	/* Prepare buffer to store the received data in */
	init_iov(&io2, data, MAX_DATA);
	init_msghdr(&recvbuf, &io2, &client);

	/* Set up "blocking" UDP client to communicate with the server */
	ATF_REQUIRE((sockfd2 = socket(PF_UNIX, SOCK_DGRAM, 0)) != -1);
	/* Send a sample message to the connected socket */
	ATF_REQUIRE(sendmsg(sockfd2, &sendbuf, 0) != -1);

	/* Receive data once clientfd is ready for reading */
	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE(check_readfs(sockfd) != 0);
	ATF_REQUIRE((bytes_recv = recvmsg(sockfd, &recvbuf, 0)) != -1);

	/* Audit record must contain sockfd and bytes_recv */
	snprintf(regex, 60, \
		"recvmsg.*0x%x.*return,success,%zd", sockfd, bytes_recv);
	check_audit(fds, regex, pipefd);

	/* Close all socket descriptors */
	close_sockets(2, sockfd, sockfd2);
}

ATF_TC_CLEANUP(recvmsg_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(recvmsg_failure);
ATF_TC_HEAD(recvmsg_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"recvmsg(2) call");
}

ATF_TC_BODY(recvmsg_failure, tc)
{
	struct msghdr msgbuf;
	/* Audit record must contain Hex(-1) */
	snprintf(regex, 60, "recvmsg.*return,failure : Message too long");
	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(-1, recvmsg(ERROR, &msgbuf, 0));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(recvmsg_failure, tc)
{
	cleanup();
}



ATF_TC_WITH_CLEANUP(shutdown_success);
ATF_TC_HEAD(shutdown_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"shutdown(2) call");
}

ATF_TC_BODY(shutdown_success, tc)
{
	int clientfd;
	struct sockaddr_un server, client;
	assign_address(&server);
	len = sizeof(struct sockaddr_un);

	/* Server Socket: Assign address and listen for connection */
	ATF_REQUIRE((sockfd = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);
	/* Non-blocking server socket */
	ATF_REQUIRE(fcntl(sockfd, F_SETFL, O_NONBLOCK) != -1);
	/* Bind to the specified address and wait for connection */
	ATF_REQUIRE_EQ(0, bind(sockfd, (struct sockaddr *)&server, len));
	ATF_REQUIRE_EQ(0, listen(sockfd, 1));

	/* Set up "blocking" client and connect with non-blocking server */
	ATF_REQUIRE((sockfd2 = socket(PF_UNIX, SOCK_STREAM, 0)) != -1);
	ATF_REQUIRE_EQ(0, connect(sockfd2, (struct sockaddr *)&server, len));
	ATF_REQUIRE((clientfd = accept(sockfd, \
		(struct sockaddr *)&client, &len)) != -1);

	/* Audit record must contain clientfd */
	snprintf(regex, 60, "shutdown.*0x%x.*return,success", clientfd);

	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(0, shutdown(clientfd, SHUT_RDWR));
	check_audit(fds, regex, pipefd);

	/* Close all socket descriptors */
	close_sockets(3, sockfd, sockfd2, clientfd);
}

ATF_TC_CLEANUP(shutdown_success, tc)
{
	cleanup();
}


ATF_TC_WITH_CLEANUP(shutdown_failure);
ATF_TC_HEAD(shutdown_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"shutdown(2) call");
}

ATF_TC_BODY(shutdown_failure, tc)
{
	/* Audit record must contain Hex(-1) */
	snprintf(regex, 60, "shutdown.*0x%x.*return,failure", ERROR);
	FILE *pipefd = setup(fds, "nt");
	ATF_REQUIRE_EQ(-1, shutdown(ERROR, SHUT_RDWR));
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(shutdown_failure, tc)
{
	cleanup();
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, socket_success);
	ATF_TP_ADD_TC(tp, socket_failure);
	ATF_TP_ADD_TC(tp, socketpair_success);
	ATF_TP_ADD_TC(tp, socketpair_failure);
	ATF_TP_ADD_TC(tp, setsockopt_success);
	ATF_TP_ADD_TC(tp, setsockopt_failure);

	ATF_TP_ADD_TC(tp, bind_success);
	ATF_TP_ADD_TC(tp, bind_failure);
	ATF_TP_ADD_TC(tp, bindat_success);
	ATF_TP_ADD_TC(tp, bindat_failure);
	ATF_TP_ADD_TC(tp, listen_success);
	ATF_TP_ADD_TC(tp, listen_failure);

	ATF_TP_ADD_TC(tp, connect_success);
	ATF_TP_ADD_TC(tp, connect_failure);
	ATF_TP_ADD_TC(tp, connectat_success);
	ATF_TP_ADD_TC(tp, connectat_failure);
	ATF_TP_ADD_TC(tp, accept_success);
	ATF_TP_ADD_TC(tp, accept_failure);

	ATF_TP_ADD_TC(tp, send_success);
	ATF_TP_ADD_TC(tp, send_failure);
	ATF_TP_ADD_TC(tp, recv_success);
	ATF_TP_ADD_TC(tp, recv_failure);

	ATF_TP_ADD_TC(tp, sendto_success);
	ATF_TP_ADD_TC(tp, sendto_failure);
	ATF_TP_ADD_TC(tp, recvfrom_success);
	ATF_TP_ADD_TC(tp, recvfrom_failure);

	ATF_TP_ADD_TC(tp, sendmsg_success);
	ATF_TP_ADD_TC(tp, sendmsg_failure);
	ATF_TP_ADD_TC(tp, recvmsg_success);
	ATF_TP_ADD_TC(tp, recvmsg_failure);

	ATF_TP_ADD_TC(tp, shutdown_success);
	ATF_TP_ADD_TC(tp, shutdown_failure);

	return (atf_no_error());
}
