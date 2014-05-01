/* Copyright (C) 2009-2014, Martin Johansson <martin@fatbob.nu>
   Copyright (C) 2005-2014, Thorvald Natvig <thorvald@natvig.com>

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

#define TCP_SOCK  0
#define TCP_SOCK6 1

#define UDP_SOCK  2
#define UDP_SOCK6 3

/* globals */
bool_t shutdown_server;
extern char *bindaddr;
extern char *bindaddr6;
extern int bindport;
extern int bindport6;

int* udpsocks;

/* Initialize the address structures for IPv4 and IPv6 */
struct sockaddr_storage** Server_setupAddressesAndPorts()
{
	struct sockaddr_storage** addresses = malloc(2 * sizeof(void*));

	struct sockaddr_storage* v4address = calloc(1, sizeof(struct sockaddr_storage));
	v4address->ss_family = AF_INET;
	struct sockaddr_storage* v6address = calloc(1, sizeof(struct sockaddr_storage));
	v6address->ss_family = AF_INET6;

#if defined(NETBSD) || defined(FREEBSD) || defined(OPENBSD) || defined(__APPLE__)
	v4address->ss_len = sizeof(struct sockaddr_storage);
	v6address->ss_len = sizeof(struct sockaddr_storage);
#endif

	int error = 0;

	const char* confadd = getStrConf(BINDADDR);
	error = inet_pton(AF_INET, (!bindaddr) ? ((getStrConf(BINDADDR)) ? getStrConf(BINDADDR) : "0.0.0.0")
		: bindaddr, &(((struct sockaddr_in*)v4address)->sin_addr));
	if (error == 0) Log_fatal("Invalid IPv4 address supplied!");

	error = inet_pton(AF_INET6, (!bindaddr6) ? ((getStrConf(BINDADDR6)) ? getStrConf(BINDADDR6) : "::")
		: bindaddr6, &(((struct sockaddr_in6*)v6address)->sin6_addr));
	if (error == 0) Log_fatal("Invalid IPv6 address supplied!");

	((struct sockaddr_in*)v4address)->sin_port = htons((bindport) ? bindport : getIntConf(BINDPORT));
	((struct sockaddr_in6*)v6address)->sin6_port = htons((bindport6) ? bindport6 : getIntConf(BINDPORT6));

	addresses[0] = v4address;
	addresses[1] = v6address;

	return addresses;
}

void Server_runLoop(struct pollfd* pollfds)
{
	int timeout = 1000, rc, clientcount;

	etimer_t janitorTimer;
	Timer_init(&janitorTimer);

	while (!shutdown_server) {
		struct sockaddr_storage remote;
		int i;

		pollfds[UDP_SOCK].revents = 0;
		pollfds[UDP_SOCK6].revents = 0;
		pollfds[TCP_SOCK].revents = 0;
		pollfds[TCP_SOCK6].revents = 0;
		clientcount = Client_getfds(&pollfds[4]);

		timeout = (int)(1000000LL - (int64_t)Timer_elapsed(&janitorTimer)) / 1000LL;
		if (timeout <= 0) {
			Client_janitor();
			Timer_restart(&janitorTimer);
			timeout = (int)(1000000LL - (int64_t)Timer_elapsed(&janitorTimer)) / 1000LL;
		}
		rc = poll(pollfds, clientcount + 4, timeout);
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
		if (pollfds[TCP_SOCK].revents) { /* New tcp connection */
			int tcpfd, flag = 1;
			uint32_t addrlen;
			addrlen = sizeof(struct sockaddr_in);
			tcpfd = accept(pollfds[TCP_SOCK].fd, (struct sockaddr*)&remote, &addrlen);
			fcntl(tcpfd, F_SETFL, O_NONBLOCK);
			setsockopt(tcpfd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
			Log_debug("Connection from %s port %d\n", inet_ntoa(((struct sockaddr_in*)&remote)->sin_addr),
				ntohs(((struct sockaddr_in*)&remote)->sin_port));
			if (Client_add(tcpfd, &remote) < 0)
				close(tcpfd);
		}

		if (pollfds[TCP_SOCK6].revents) { /* New tcp connection */
			int tcpfd, flag = 1;
			uint32_t addrlen;
			addrlen = sizeof(struct sockaddr_in6);
			tcpfd = accept(pollfds[TCP_SOCK6].fd, (struct sockaddr*)&remote, &addrlen);
			fcntl(tcpfd, F_SETFL, O_NONBLOCK);
			setsockopt(tcpfd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
			if (Client_add(tcpfd, &remote) < 0)
				close(tcpfd);
		}

		if (pollfds[UDP_SOCK].revents) {
			Client_read_udp(udpsocks[0]);
		}
		if (pollfds[UDP_SOCK6].revents) {
			Client_read_udp(udpsocks[1]);
		}
		for (i = 0; i < clientcount; i++) {
			if (pollfds[i + 4].revents & POLLIN) {
				Client_read_fd(pollfds[i + 4].fd);
			}
			if (pollfds[i + 4].revents & POLLOUT) {
				Client_write_fd(pollfds[i + 4].fd);
			}
		}
	}
}

void Server_setupTCPSockets(struct sockaddr_storage* addresses[2], struct pollfd* pollfds)
{
	uint8_t yes = 1;
	int error = 0;
	int sockets[2];

	/* IPv4 socket setup */
	sockets[0] = socket(PF_INET, SOCK_STREAM, 0);
	if (sockets[0] < 0)
		Log_fatal("socket IPv4");
	if (setsockopt(sockets[0], SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) != 0)
		Log_fatal("setsockopt IPv4: %s", strerror(errno));
	if (bind(sockets[0], (struct sockaddr *)addresses[0], sizeof (struct sockaddr_in)) < 0)
		Log_fatal("bind IPv4: %s", strerror(errno));
	if (listen(sockets[0], 3) < 0)
		Log_fatal("listen IPv4");
	fcntl(sockets[0], F_SETFL, O_NONBLOCK);

	pollfds[TCP_SOCK].fd = sockets[0];
	pollfds[TCP_SOCK].events = POLLIN;

	/* IPv6 socket setup */
	sockets[1] = socket(PF_INET6, SOCK_STREAM, 0);
	if (sockets[1] < 0)
		Log_fatal("socket IPv6");
	if (setsockopt(sockets[1], SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) != 0)
		Log_fatal("setsockopt IPv6: %s", strerror(errno));
	if (setsockopt(sockets[1], IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(int)) != 0)
		Log_fatal("setsockopt IPv6: %s", strerror(errno));
	if (bind(sockets[1], (struct sockaddr *)addresses[1], sizeof (struct sockaddr_in6)) < 0)
		Log_fatal("bind IPv6: %s", strerror(errno));
	if (listen(sockets[1], 3) < 0)
		Log_fatal("listen IPv6");
	fcntl(sockets[1], F_SETFL, O_NONBLOCK);

	pollfds[TCP_SOCK6].fd = sockets[1];
	pollfds[TCP_SOCK6].events = POLLIN;
}

void Server_setupUDPSockets(struct sockaddr_storage* addresses[2], struct pollfd* pollfds)
{
	uint8_t yes = 1;
	int val = 0;
	int error = 0;
	int sockets[2];
	char ipv6Representation[INET6_ADDRSTRLEN];

	if((udpsocks = malloc(2 * sizeof(int))) == NULL)
		Log_fatal("Out of memory (%s:%s)", __FILE__, __LINE__);

	inet_ntop(AF_INET6, &((struct sockaddr_in6*)addresses[1])->sin6_addr, ipv6Representation, sizeof(INET6_ADDRSTRLEN));

	sockets[0] = socket(PF_INET, SOCK_DGRAM, 0);
	if (bind(sockets[0], (struct sockaddr *) addresses[0], sizeof (struct sockaddr_in)) < 0)
		Log_fatal("bind %d %s: %s", ((struct sockaddr_in*)addresses[0])->sin_port,
			inet_ntoa(((struct sockaddr_in*)addresses[0])->sin_addr), strerror(errno));
	val = 0xe0;
	if (setsockopt(sockets[0], IPPROTO_IP, IP_TOS, &val, sizeof(val)) < 0)
		Log_warn("Server: Failed to set TOS for UDP Socket");
	val = 0x80;
	if (setsockopt(sockets[0], IPPROTO_IP, IP_TOS, &val, sizeof(val)) < 0)
		Log_warn("Server: Failed to set TOS for UDP Socket");

	fcntl(sockets[0], F_SETFL, O_NONBLOCK);
	pollfds[UDP_SOCK].fd = sockets[0];
	pollfds[UDP_SOCK].events = POLLIN | POLLHUP | POLLERR;

	sockets[1] = socket(PF_INET6, SOCK_DGRAM, 0);
	if (setsockopt(sockets[1], IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(int)) != 0)
		Log_fatal("setsockopt IPv6: %s", strerror(errno));
	if (bind(sockets[1], (struct sockaddr *) addresses[1], sizeof (struct sockaddr_in6)) < 0)
		Log_fatal("bind %d %s: %s", ((struct sockaddr_in*)addresses[1])->sin_port, ipv6Representation, strerror(errno));
	val = 0xe0;
	if (setsockopt(sockets[1], IPPROTO_IPV6, IPV6_TCLASS, &val, sizeof(val)) < 0)
		Log_warn("Server: Failed to set TOS for UDP Socket");
	val = 0x80;
	if (setsockopt(sockets[1], IPPROTO_IPV6, IPV6_TCLASS, &val, sizeof(val)) < 0)
		Log_warn("Server: Failed to set TOS for UDP Socket");

	fcntl(sockets[1], F_SETFL, O_NONBLOCK);
	pollfds[UDP_SOCK6].fd = sockets[1];
	pollfds[UDP_SOCK6].events = POLLIN | POLLHUP | POLLERR;
	udpsocks[0] = sockets[0];
	udpsocks[1] = sockets[1];
}

void Server_run()
{
	struct pollfd *pollfds;

	/* max clients + listen sock + udp sock + client connecting that will be disconnected */
	if ((pollfds = calloc((getIntConf(MAX_CLIENTS) + 5) , sizeof(struct pollfd))) == NULL)
		Log_fatal("out of memory");

	/* Figure out bind address and port */
	struct sockaddr_storage** addresses = Server_setupAddressesAndPorts();

	/* Prepare TCP sockets */
	Server_setupTCPSockets(addresses, pollfds);

	/* Prepare UDP sockets */
	Server_setupUDPSockets(addresses, pollfds);

	Log_info("uMurmur version %s ('%s') protocol version %d.%d.%d",
		UMURMUR_VERSION, UMURMUR_CODENAME, PROTVER_MAJOR, PROTVER_MINOR, PROTVER_PATCH);
	Log_info("Visit http://code.google.com/p/umurmur/");

	/* Main server loop */
	Server_runLoop(pollfds);

	/* Disconnect clients and cleanup memory */
	Client_disconnect_all();
	free(pollfds);
	free(addresses[0]);
	free(addresses[1]);
	free(addresses);
	free(udpsocks);
}

void Server_shutdown()
{
	shutdown_server = true;
}
