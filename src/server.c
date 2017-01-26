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
#include "memory.h"
#include "timer.h"
#include "version.h"
#include "util.h"
#include "sharedmemory.h"

/* globals */
bool_t shutdown_server;
extern char *bindaddr;
extern char *bindaddr6;
extern int bindport;
extern int bindport6;
int* udpsocks;
bool_t hasv4 = true, hasv6 = true;

const int on = 1;
int nofServerSocks = 4;

/* Check which IP versions are supported by the system. */
static void checkIPversions(void)
{
	int testsocket = -1;

	testsocket = socket(PF_INET, SOCK_STREAM, 0);
	hasv4 = (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT) ? false : true;
	if (!(testsocket < 0)) close(testsocket);

	testsocket = socket(PF_INET6, SOCK_STREAM, 0);
	hasv6 = (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT) ? false : true;
	if (!(testsocket < 0)) close(testsocket);

	if(!hasv4)
	{
		Log_info("IPv4 is not supported by this system");
		nofServerSocks -= 2;
	}

	if(!hasv6)
	{
		Log_info("IPv6 is not supported by this system");
		nofServerSocks -= 2;
	}
	if(nofServerSocks == 0)
	{
		Log_fatal("Neither IPv4 nor IPv6 are supported by this system");
	}
}

/* Initialize the address structures for IPv4 and IPv6 */
struct sockaddr_storage** Server_setupAddressesAndPorts(void)
{
	struct sockaddr_storage** addresses = Memory_safeCalloc(2, sizeof(void*));

	struct sockaddr_storage* v4address = Memory_safeCalloc(1, sizeof(struct sockaddr_storage));
	v4address->ss_family = AF_INET;
	struct sockaddr_storage* v6address = Memory_safeCalloc(1, sizeof(struct sockaddr_storage));
	v6address->ss_family = AF_INET6;

#if defined(__NetBSD__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
	v4address->ss_len = sizeof(struct sockaddr_storage);
	v6address->ss_len = sizeof(struct sockaddr_storage);
#endif

	int error = 0;

	error = inet_pton(AF_INET, (!bindaddr) ? ((getStrConf(BINDADDR)) ? getStrConf(BINDADDR) : "0.0.0.0")
		: bindaddr, &(((struct sockaddr_in*)v4address)->sin_addr));
	if (error == 0)
		Log_fatal("Invalid IPv4 address supplied!");
	else if (error == -1)
		Log_warn("Could not allocate IPv4 address");

	error = inet_pton(AF_INET6, (!bindaddr6) ? ((getStrConf(BINDADDR6)) ? getStrConf(BINDADDR6) : "::")
		: bindaddr6, &(((struct sockaddr_in6*)v6address)->sin6_addr));
	if (error == 0)
		Log_fatal("Invalid IPv6 address supplied!");
	else if (error == -1)
		Log_warn("Could not allocate IPv6 address");

	((struct sockaddr_in*)v4address)->sin_port = htons((bindport) ? bindport : getIntConf(BINDPORT));
	((struct sockaddr_in6*)v6address)->sin6_port = htons((bindport6) ? bindport6 : getIntConf(BINDPORT6));

	addresses[0] = v4address;
	addresses[1] = v6address;

	return addresses;
}

void Server_runLoop(struct pollfd* pollfds)
{
	int timeout, rc, clientcount;

	etimer_t janitorTimer;
	Timer_init(&janitorTimer);

	while (!shutdown_server) {
		struct sockaddr_storage remote;
		int i;

#ifdef USE_SHAREDMEMORY_API
    Sharedmemory_alivetick();
#endif

		for(i = 0; i < nofServerSocks; i++) {
			pollfds[i].revents = 0;
		}

		clientcount = Client_getfds(&pollfds[nofServerSocks]);

		timeout = (int)(1000000LL - (int64_t)Timer_elapsed(&janitorTimer)) / 1000LL;
		if (timeout <= 0) {
			Client_janitor();
			Timer_restart(&janitorTimer);
			timeout = (int)(1000000LL - (int64_t)Timer_elapsed(&janitorTimer)) / 1000LL;
		}
		rc = poll(pollfds, clientcount + nofServerSocks, timeout);
		if (rc == 0) {
			/* Poll timed out, do maintenance */
			Timer_restart(&janitorTimer);
			Client_janitor();
			continue;
		}
		if (rc < 0) {
			if (errno == EINTR) /* signal */
				continue;
			else
				Log_fatal("poll: error %d (%s)", errno, strerror(errno));
		}

		/* Check for new connection */
		for (i = 0; i < nofServerSocks / 2; i++) {
			if (pollfds[i].revents) {
				int tcpfd;
				uint32_t addrlen = sizeof(struct sockaddr_storage);
				tcpfd = accept(pollfds[i].fd, (struct sockaddr *)&remote, &addrlen);
				fcntl(tcpfd, F_SETFL, O_NONBLOCK);
				setsockopt(tcpfd, IPPROTO_TCP, TCP_NODELAY, (char *) &on, sizeof(int));
				char *addressString = Util_addressToString(&remote);
				Log_debug("Connection from %s port %d\n", addressString, Util_addressToPort(&remote));
				free(addressString);
				if (Client_add(tcpfd, &remote) < 0)
					close(tcpfd);
			}
		}

		for (i = nofServerSocks / 2; i < nofServerSocks; i++) {
			if (pollfds[i].revents)
				Client_read_udp(udpsocks[i - nofServerSocks / 2]);
		}

		for (i = 0; i < clientcount; i++) {
			if (pollfds[nofServerSocks + i].revents & POLLIN)
				Client_read_fd(pollfds[nofServerSocks + i].fd);

			if (pollfds[nofServerSocks + i].revents & POLLOUT)
				Client_write_fd(pollfds[nofServerSocks + i].fd);
		}
#ifdef USE_SHAREDMEMORY_API
    Sharedmemory_update();
#endif
	}
}

void Server_setupTCPSockets(struct sockaddr_storage* addresses[2], struct pollfd* pollfds)
{
	int yes = 1;
	int sockets[2];

	if (hasv4) {
		/* IPv4 socket setup */
		sockets[0] = socket(PF_INET, SOCK_STREAM, 0);
		if (sockets[0] < 0)
			Log_fatal("socket IPv4");
		if (setsockopt(sockets[0], SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) != 0)
			Log_fatal("setsockopt IPv4: %s", strerror(errno));
		if (bind(sockets[0], (struct sockaddr *)addresses[0], sizeof (struct sockaddr_in)) < 0) {
			char *addressString = Util_addressToString(addresses[0]);
			Log_fatal("bind %s %d: %s", addressString, Util_addressToPort(addresses[0]), strerror(errno));
			free(addressString);
		}
		if (listen(sockets[0], 3) < 0)
			Log_fatal("listen IPv4");
		fcntl(sockets[0], F_SETFL, O_NONBLOCK);

		pollfds[0].fd = sockets[0];
		pollfds[0].events = POLLIN;
	}

	if (hasv6) {
		/* IPv6 socket setup */
		sockets[1] = socket(PF_INET6, SOCK_STREAM, 0);
		if (sockets[1] < 0)
			Log_fatal("socket IPv6: %s", strerror(errno));
		if (setsockopt(sockets[1], SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) != 0)
			Log_fatal("setsockopt IPv6: %s", strerror(errno));
		if (setsockopt(sockets[1], IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(int)) != 0)
			Log_fatal("setsockopt IPv6: %s", strerror(errno));
		if (bind(sockets[1], (struct sockaddr *)addresses[1], sizeof (struct sockaddr_in6)) < 0) {
			char *addressString = Util_addressToString(addresses[1]);
			Log_fatal("bind %s %d: %s", addressString, Util_addressToPort(addresses[1]), strerror(errno));
			free(addressString);
		}
		if (listen(sockets[1], 3) < 0)
			Log_fatal("listen IPv6");
		fcntl(sockets[1], F_SETFL, O_NONBLOCK);


		/* If  there is an IPv4 address, then IPv6 will use the second socket, otherwise it uses the first */
		pollfds[(hasv4) ? 1 : 0].fd = sockets[1];
		pollfds[(hasv4) ? 1 : 0].events = POLLIN;
	}
}

void Server_setupUDPSockets(struct sockaddr_storage* addresses[2], struct pollfd* pollfds)
{
	int val = 0;
	int sockets[2] = {-1, -1};

	udpsocks = Memory_safeCalloc(nofServerSocks / 2, sizeof(int));

	if (hasv4) {
		sockets[0] = socket(PF_INET, SOCK_DGRAM, 0);
		if (bind(sockets[0], (struct sockaddr *) addresses[0], sizeof (struct sockaddr_in)) < 0) {
			char *addressString = Util_addressToString(addresses[0]);
			Log_fatal("bind %s %d: %s", addressString, Util_addressToPort(addresses[0]), strerror(errno));
			free(addressString);
		}
		val = 0xe0;
		if (setsockopt(sockets[0], IPPROTO_IP, IP_TOS, &val, sizeof(val)) < 0)
			Log_warn("Server: Failed to set TOS for UDP Socket");
		val = 0x80;
		if (setsockopt(sockets[0], IPPROTO_IP, IP_TOS, &val, sizeof(val)) < 0)
			Log_warn("Server: Failed to set TOS for UDP Socket");

		fcntl(sockets[0], F_SETFL, O_NONBLOCK);
		pollfds[(hasv6) ? 2 : 1].fd = sockets[0];
		pollfds[(hasv6) ? 2 : 1].events = POLLIN | POLLHUP | POLLERR;
		udpsocks[0] = sockets[0];
	}

	if (hasv6) {
		sockets[1] = socket(PF_INET6, SOCK_DGRAM, 0);
		if (setsockopt(sockets[1], IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(int)) != 0)
			Log_fatal("setsockopt IPv6: %s", strerror(errno));
		if (bind(sockets[1], (struct sockaddr *) addresses[1], sizeof (struct sockaddr_in6)) < 0) {
			char *addressString = Util_addressToString(addresses[1]);
			Log_fatal("bind %s %d: %s", addressString, Util_addressToPort(addresses[1]), strerror(errno));
			free(addressString);
		}
		val = 0xe0;
		if (setsockopt(sockets[1], IPPROTO_IPV6, IPV6_TCLASS, &val, sizeof(val)) < 0)
			Log_warn("Server: Failed to set TOS for UDP Socket");
		val = 0x80;
		if (setsockopt(sockets[1], IPPROTO_IPV6, IPV6_TCLASS, &val, sizeof(val)) < 0)
			Log_warn("Server: Failed to set TOS for UDP Socket");

		fcntl(sockets[1], F_SETFL, O_NONBLOCK);
		pollfds[(hasv4) ? 3 : 1].fd = sockets[1];
		pollfds[(hasv4) ? 3 : 1].events = POLLIN | POLLHUP | POLLERR;
		udpsocks[(hasv4) ? 1 : 0] = sockets[1];
	}

}

void Server_run(void)
{
	struct pollfd *pollfds;

	checkIPversions();

	/* max clients + server sokets + client connecting that will be disconnected */
	pollfds = Memory_safeCalloc((getIntConf(MAX_CLIENTS) + nofServerSocks + 1) , sizeof(struct pollfd));

	/* Figure out bind address and port */
	struct sockaddr_storage** addresses = Server_setupAddressesAndPorts();

	/* Prepare TCP sockets */
	Server_setupTCPSockets(addresses, pollfds);

	/* Prepare UDP sockets */
	Server_setupUDPSockets(addresses, pollfds);

	Log_info("uMurmur version %s ('%s') protocol version %d.%d.%d",
		UMURMUR_VERSION, UMURMUR_CODENAME, PROTVER_MAJOR, PROTVER_MINOR, PROTVER_PATCH);
	Log_info("Visit https://github.com/umurmur/umurmur");

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

void Server_shutdown(void)
{
	shutdown_server = true;
}
