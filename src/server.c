/* Copyright (C) 2009-2012, Martin Johansson <martin@fatbob.nu>
   Copyright (C) 2005-2012, Thorvald Natvig <thorvald@natvig.com>

   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

   - Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.
   - Redistributions in binary form must reproduce the above copyright notice,
     this list of conditions and the following disclaimer in the documentation
     and/or other materials provided with the distribution.
   - Neither the name of the Developers nor the names of its contributors may
     be used to endorse or promote products derived from this software without
     specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <stdio.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

#include "client.h"
#include "conf.h"
#include "log.h"
#include "timer.h"
#include "version.h"

#define LISTEN_SOCK 0
#define TCP_SOCK 0
#define UDP_SOCK 1

/* globals */
int udpsock; 
bool_t shutdown_server;
extern char *bindaddr;
extern int bindport;

void Server_run()
{
	int timeout = 1000, rc;
	struct pollfd *pollfds;
	int tcpsock, sockopt6 = 1;
	struct sockaddr_in6 sin;
	int val, clientcount;
	etimer_t janitorTimer;
	unsigned short port;
	in_addr_t inet_address;
	struct in6_addr inet6_address[sizeof(struct in6_addr)];
	
	/* max clients + listen sock + udp sock + client connecting that will be disconnected */
	pollfds = malloc((getIntConf(MAX_CLIENTS) + 3) * sizeof(struct pollfd));
	if (pollfds == NULL)
		Log_fatal("out of memory");

	/* Figure out bind address and port */
	if (bindport != 0)
		port = htons(bindport);
	else
		port = htons(getIntConf(BINDPORT));
	
	if (bindaddr != NULL && inet_pton(AF_INET6, bindaddr, inet6_address) != -1)
		inet_pton(AF_INET6, bindaddr, inet6_address);
	else if (inet_addr(getStrConf(BINDADDR)) !=  -1)
		inet_pton(AF_INET6, getStrConf(BINDADDR), inet6_address);
	else
		*inet6_address = in6addr_any;
	char boundaddr6[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, inet6_address, boundaddr6, INET6_ADDRSTRLEN);
	Log_info("Bind to [%s]:%hu", inet6_address == 0 ? "*" : boundaddr6, ntohs(port));
	
	/* Prepare TCP6 socket */
	memset(&sin, 0, sizeof(sin));
	tcpsock = socket(PF_INET6, SOCK_STREAM, 0);
	if (tcpsock < 0)
		Log_fatal("socket");
	int on = 1;
	if (setsockopt(tcpsock, SOL_SOCKET, SO_REUSEADDR, &sockopt6, sizeof(int)) != 0)
		Log_fatal("setsockopt: %s", strerror(errno));
	sin.sin6_family = AF_INET6;
	sin.sin6_port = port;
	sin.sin6_scope_id = 0;
	sin.sin6_addr = *inet6_address;
	rc = bind(tcpsock, (struct sockaddr6 *) &sin, sizeof (struct sockaddr_in6));
	if (rc < 0) Log_fatal("bind6: %s", strerror(errno));
	rc = listen(tcpsock, 3);
	if (rc < 0) Log_fatal("listen");
	fcntl(tcpsock, F_SETFL, O_NONBLOCK);

	pollfds[LISTEN_SOCK].fd = tcpsock;
	pollfds[LISTEN_SOCK].events = POLLIN;

	/* Prepare UDP socket */
	memset(&sin, 0, sizeof(sin));
	udpsock = socket(PF_INET6, SOCK_DGRAM, 0);
	sin.sin6_family = AF_INET6;
	sin.sin6_port = port;
	sin.sin6_addr = *inet6_address;
	
	rc = bind(udpsock, (struct sockaddr *) &sin, sizeof (struct sockaddr_in6));
	if (rc < 0)
		Log_fatal("bind %d %s: %s", getIntConf(BINDPORT), getStrConf(BINDADDR), strerror(errno));
	val = 0xe0;
	rc = setsockopt(udpsock, IPPROTO_IP, IP_TOS, &val, sizeof(val));
	if (rc < 0)
		Log_warn("Server: Failed to set TOS for UDP Socket");
	val = 0x80;
	rc = setsockopt(udpsock, IPPROTO_IP, IP_TOS, &val, sizeof(val));
	if (rc < 0)
		Log_warn("Server: Failed to set TOS for UDP Socket");
	
	fcntl(udpsock, F_SETFL, O_NONBLOCK);
	pollfds[UDP_SOCK].fd = udpsock;
	pollfds[UDP_SOCK].events = POLLIN | POLLHUP | POLLERR;
	
	Timer_init(&janitorTimer);
	
	Log_info("uMurmur version %s ('%s') protocol version %d.%d.%d",
	         UMURMUR_VERSION, UMURMUR_CODENAME, PROTVER_MAJOR, PROTVER_MINOR, PROTVER_PATCH);
	Log_info("Visit http://code.google.com/p/umurmur/");
	
	/* Main server loop */
	while (!shutdown_server) {
		struct sockaddr_in6 remote;
		int i;
		
		pollfds[UDP_SOCK].revents = 0;
		pollfds[TCP_SOCK].revents = 0;
		clientcount = Client_getfds(&pollfds[2]);
		
		timeout = (int)(1000000LL - (int64_t)Timer_elapsed(&janitorTimer)) / 1000LL;
		if (timeout <= 0) {
			Client_janitor();
			Timer_restart(&janitorTimer);
			timeout = (int)(1000000LL - (int64_t)Timer_elapsed(&janitorTimer)) / 1000LL;
		}
		rc = poll(pollfds, clientcount + 2, timeout);
		if (rc == 0) { /* Timeout */
			/* Do maintenance */
			Timer_restart(&janitorTimer);
			Client_janitor();
			continue;
		}
		if (rc < 0) {
			if (errno == EINTR) /* signal */
				continue;
			else
				Log_fatal("poll: error %d", errno);
		}
		if (pollfds[LISTEN_SOCK].revents) { /* New tcp connection */
			int tcpfd, flag = 1;
			uint32_t addrlen;
			addrlen = sizeof(struct sockaddr_in6);
			tcpfd = accept(pollfds[LISTEN_SOCK].fd, (struct sockaddr*)&remote, &addrlen);
			fcntl(tcpfd, F_SETFL, O_NONBLOCK);
			setsockopt(tcpfd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
			Log_debug("Connection from %s port %d\n", inet_ntoa(remote.sin_addr),
					  ntohs(remote.sin_port));
			if (Client_add(tcpfd, &remote) < 0)
				close(tcpfd);
		}

		if (pollfds[UDP_SOCK].revents) {
			Client_read_udp();
		}
		for (i = 0; i < clientcount; i++) {
			if (pollfds[i + 2].revents & POLLIN) {
				Client_read_fd(pollfds[i + 2].fd);
			}
			if (pollfds[i + 2].revents & POLLOUT) {
				Client_write_fd(pollfds[i + 2].fd);
			}
		}
	}	

	/* Disconnect clients */
	Client_disconnect_all();
	free(pollfds);
}

void Server_shutdown()
{
	shutdown_server = true;
}
