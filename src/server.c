/* Copyright (C) 2010, Martin Johansson <martin@fatbob.nu>
   Copyright (C) 2005-2010, Thorvald Natvig <thorvald@natvig.com>

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

#include "client.h"
#include "conf.h"
#include "log.h"
#include "timer.h"

#define LISTEN_SOCK 0
#define TCP_SOCK 0
#define UDP_SOCK 1

int udpsock; /* XXX restructure! */
bool_t shutdown_server;

void Server_run()
{
	int timeout = 1000, rc;
	struct pollfd *pollfds;
	int tcpsock, sockopt = 1;
	struct sockaddr_in sin;
	int val, clientcount;
	etimer_t janitorTimer;

	/* max clients + listen sock + udp sock + client connecting that will be disconnected */
	pollfds = malloc((getIntConf(MAX_CLIENTS) + 3) * sizeof(struct pollfd));
	if (pollfds == NULL)
		Log_fatal("out of memory");
	
	/* Prepare TCP socket */
	memset(&sin, 0, sizeof(sin));
	tcpsock = socket(PF_INET, SOCK_STREAM, 0);
	if (tcpsock < 0)
		Log_fatal("socket");
	if (setsockopt(tcpsock, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(int)) != 0)
		Log_fatal("setsockopt: %s", strerror(errno));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(getIntConf(BINDPORT));
	sin.sin_addr.s_addr = inet_addr(getStrConf(BINDADDR)) ==  -1 ? inet_addr("0.0.0.0") : inet_addr(getStrConf(BINDADDR));
	rc = bind(tcpsock, (struct sockaddr *) &sin, sizeof (struct sockaddr_in));
	if (rc < 0) Log_fatal("bind: %s", strerror(errno));
	rc = listen(tcpsock, 3);
	if (rc < 0) Log_fatal("listen");
	fcntl(tcpsock, F_SETFL, O_NONBLOCK);
	
	pollfds[LISTEN_SOCK].fd = tcpsock;
	pollfds[LISTEN_SOCK].events = POLLIN;

	/* Prepare UDP socket */
	memset(&sin, 0, sizeof(sin));
	udpsock = socket(PF_INET, SOCK_DGRAM, 0);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(getIntConf(BINDPORT));
	sin.sin_addr.s_addr = inet_addr(getStrConf(BINDADDR)) ==  -1 ? inet_addr("0.0.0.0") : inet_addr(getStrConf(BINDADDR));
	rc = bind(udpsock, (struct sockaddr *) &sin, sizeof (struct sockaddr_in));
	if (rc < 0)
		Log_fatal("bind %d %s: %s", getIntConf(BINDPORT), getStrConf(BINDADDR), strerror(errno));
	val = 0xe0;
	rc = setsockopt(udpsock, IPPROTO_IP, IP_TOS, &val, sizeof(val));
	if (rc < 0)
		Log_fatal("Server: Failed to set TOS for UDP Socket");
	val = 0x80;
	rc = setsockopt(udpsock, IPPROTO_IP, IP_TOS, &val, sizeof(val));
	if (rc < 0)
		Log_fatal("Server: Failed to set TOS for UDP Socket");
	
	fcntl(udpsock, F_SETFL, O_NONBLOCK);
	pollfds[UDP_SOCK].fd = udpsock;
	pollfds[UDP_SOCK].events = POLLIN | POLLHUP | POLLERR;
	
	Timer_init(&janitorTimer);
	
	Log_info("uMurmur voicechat server started -- http://code.google.com/p/umurmur/");

	/* Main server loop */
	while (!shutdown_server) {
		struct sockaddr_in remote;
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
			addrlen = sizeof(struct sockaddr_in);
			tcpfd = accept(pollfds[LISTEN_SOCK].fd, (struct sockaddr*)&remote, &addrlen);
			fcntl(tcpfd, F_SETFL, O_NONBLOCK);
			setsockopt(tcpfd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
			Log_info("Connection from %s port %d\n", inet_ntoa(remote.sin_addr),
					 ntohs(remote.sin_port));
			Client_add(tcpfd, &remote);
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
