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

#define LISTEN_SOCK  0
#define LISTEN_SOCK6 1

#define TCP_SOCK  0
#define TCP_SOCK6 1

#define UDP_SOCK  2
#define UDP_SOCK6 3

/* globals */
int udpsock, udpsock6;
bool_t shutdown_server;
extern char *bindaddr;
extern char *bindaddr6;
extern int bindport;
extern int bindport6;

/* Initialize the address structures for IPv4 and IPv6 */
struct sockaddr_storage** Server_setupAddressesAndPorts()
{
  struct sockaddr_storage** addresses = malloc(2 * sizeof(void*));

  struct sockaddr_storage* v4address = calloc(1, sizeof(struct sockaddr_storage));
  v4address->ss_family = AF_INET;
  v4address->ss_len = sizeof(struct sockaddr_storage);
  struct sockaddr_storage* v6address = calloc(1, sizeof(struct sockaddr_storage));
  v6address->ss_family = AF_INET6;
  v6address->ss_len = sizeof(struct sockaddr_storage);

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
  }

void Server_run()
{
	int rc;
	struct pollfd *pollfds;
	int tcpsock, tcpsock6, sockopt = 1;
	int val;
	unsigned short port;
	in_addr_t inet_address;

	/* max clients + listen sock + udp sock + client connecting that will be disconnected */
	pollfds = malloc((getIntConf(MAX_CLIENTS) + 3) * sizeof(struct pollfd));
	if (pollfds == NULL)
		Log_fatal("out of memory");

	/* Figure out bind address and port */
  struct sockaddr_storage** addresses = Server_setupAddressesAndPorts();

	/* Prepare TCP sockets */
	tcpsock = socket(PF_INET, SOCK_STREAM, 0);
	if (tcpsock < 0)
		Log_fatal("socket IPv4");
	if (setsockopt(tcpsock, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(int)) != 0)
		Log_fatal("setsockopt IPv4: %s", strerror(errno));

	tcpsock6 = socket(PF_INET6, SOCK_STREAM, 0);
	if (tcpsock6 < 0)
		Log_fatal("socket IPv6");
	if (setsockopt(tcpsock6, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(int)) != 0)
		Log_fatal("setsockopt IPv6: %s", strerror(errno));
	if (setsockopt(tcpsock6, IPPROTO_IPV6, IPV6_V6ONLY, &sockopt, sizeof(int)) != 0)
		Log_fatal("setsockopt IPv6: %s", strerror(errno));

	rc = bind(tcpsock, (struct sockaddr *)addresses[0], sizeof (struct sockaddr_in));
	if (rc < 0) Log_fatal("bind IPv4: %s", strerror(errno));
	rc = listen(tcpsock, 3);
	if (rc < 0) Log_fatal("listen IPv4");
	fcntl(tcpsock, F_SETFL, O_NONBLOCK);

	rc = bind(tcpsock6, (struct sockaddr *)addresses[1], sizeof (struct sockaddr_in6));
	if (rc < 0) Log_fatal("bind IPv6: %s", strerror(errno));
	rc = listen(tcpsock6, 3);
	if (rc < 0) Log_fatal("listen IPv6");
	fcntl(tcpsock6, F_SETFL, O_NONBLOCK);

	pollfds[LISTEN_SOCK].fd = tcpsock;
	pollfds[LISTEN_SOCK].events = POLLIN;

	pollfds[LISTEN_SOCK6].fd = tcpsock;
	pollfds[LISTEN_SOCK6].events = POLLIN;

	/* Prepare UDP sockets */
	udpsock = socket(PF_INET, SOCK_DGRAM, 0);
	udpsock6 = socket(PF_INET6, SOCK_DGRAM, 0);

	rc = bind(udpsock, (struct sockaddr *) addresses[0], sizeof (struct sockaddr_in));
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


	if (setsockopt(udpsock6, IPPROTO_IPV6, IPV6_V6ONLY, &sockopt, sizeof(int)) != 0)
		Log_fatal("setsockopt IPv6: %s", strerror(errno));

	rc = bind(udpsock6, (struct sockaddr *) addresses[1], sizeof (struct sockaddr_in6));
	if (rc < 0)
		Log_fatal("bind %d %s: %s", getIntConf(BINDPORT), getStrConf(BINDADDR), strerror(errno));
	val = 0xe0;
	rc = setsockopt(udpsock6, IPPROTO_IP, IP_TOS, &val, sizeof(val));
	if (rc < 0)
		Log_warn("Server: Failed to set TOS for UDP Socket");
	val = 0x80;
	rc = setsockopt(udpsock6, IPPROTO_IP, IP_TOS, &val, sizeof(val));
	if (rc < 0)
		Log_warn("Server: Failed to set TOS for UDP Socket");

	fcntl(udpsock6, F_SETFL, O_NONBLOCK);
	pollfds[UDP_SOCK6].fd = udpsock6;
	pollfds[UDP_SOCK6].events = POLLIN | POLLHUP | POLLERR;

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
}

void Server_shutdown()
{
	shutdown_server = true;
}
