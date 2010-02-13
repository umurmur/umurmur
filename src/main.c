/* Copyright (C) 2009-2010, Martin Johansson <martin@fatbob.nu>
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "server.h"
#include "ssl.h"
#include "channel.h"
#include "log.h"
#include "client.h"
#include "conf.h"
#include "version.h"

char system_string[64], version_string[64];

void lockfile(const char *pidfile)
{
	int lfp;
	char str[16];
	
	lfp = open(pidfile, O_RDWR|O_CREAT, 0640);
	
	if (lfp < 0)
		Log_fatal("Cannot open PID-file %s for writing", pidfile);
	sprintf(str,"%d\n", getpid());
	write(lfp, str, strlen(str)); /* record pid to lockfile */
	Log_info("PID-file: %s", pidfile);
}


void signal_handler(int sig)
{
	switch(sig) {
	case SIGHUP:
		/* XXX - do stuff? */
		Log_info("HUP signal");
		break;
	case SIGTERM:
		Log_info("TERM signal. Shutting down.");
		Server_shutdown();
		break;
	}
}

void daemonize()
{
	int i;
	
	if (getppid() == 1)
		return; /* already a daemon */
	i = fork();
	if ( i < 0) {
		fprintf(stderr, "Fork error. Exiting\n");
		exit(1); /* fork error */
	}
	if ( i > 0)
		exit(0); /* parent exits */
	
	/* child (daemon) continues */
	setsid(); /* obtain a new process group */
	for (i = getdtablesize(); i >= 0; --i)
		close(i); /* close all descriptors */
	
	i = open("/dev/null",O_RDWR);
	dup(i);
	dup(i);
	
	umask(027); /* set newly created file permissions */
	chdir("/");
		
}

void setscheduler()
{
	int rc;
	struct sched_param sp;

	sp.sched_priority = sched_get_priority_min(SCHED_RR); /* Should suffice */
	Log_info("Setting SCHED_RR prio %d", sp.sched_priority);
	rc = sched_setscheduler(0, SCHED_RR, &sp);
	if (rc < 0)
		Log_warn("Failed to set scheduler: %s", strerror(errno));
}

void printhelp()
{
	printf("uMurmur version %s. Mumble protocol %d.%d.%d\n", UMURMUR_VERSION, PROTVER_MAJOR, PROTVER_MINOR, PROTVER_PATCH);
	printf("Usage: umurmurd [-d] [-p <pidfile>] [-c <conf file>] [-h]\n");
	printf("       -d             - Do not deamonize\n");
	printf("       -p <pidfile>   - Write PID to this file\n");
	printf("       -c <conf file> - Specify configuration file\n");
	printf("       -r             - Run with realtime priority\n");
	printf("       -h             - Print this help\n");
	exit(0);
}

int main(int argc, char **argv)
{
	bool_t nodaemon = false;
	bool_t realtime = false;
	char *conffile = NULL, *pidfile = NULL;
	int c;
	struct utsname utsbuf;
	
	/* Arguments */
	while ((c = getopt(argc, argv, "drp:c:h")) != EOF) {
		switch(c) {
		case 'c':
			conffile = optarg;
			break;
		case 'p':
			pidfile = optarg;
			break;
		case 'd':
			nodaemon = true;
			break;
		case 'h':
			printhelp();
			break;
		case 'r':
			realtime = true;
			break;
		default:
			fprintf(stderr, "Unrecognized option\n");
			printhelp();
			break;
		}
	}
	
	if (Conf_init(conffile) != 0) {
		fprintf(stderr, "Configuration error\n");
		exit(1);
	}
		
	if (!nodaemon) {
		Log_init(false);
		daemonize();
		if (pidfile != NULL)
			lockfile(pidfile);
	}
	else
		Log_init(true);
	
	signal(SIGCHLD, SIG_IGN); /* ignore child */
	signal(SIGTSTP, SIG_IGN); /* ignore tty signals */
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, signal_handler); /* catch hangup signal */
	signal(SIGTERM, signal_handler); /* catch kill signal */
	
	/* Build system string */
	if (uname(&utsbuf) == 0) {
		snprintf(system_string, 64, "%s %s", utsbuf.sysname, utsbuf.machine);
		snprintf(version_string, 64, "%s", utsbuf.release);
	}
	else {
		snprintf(system_string, 64, "unknown unknown");
		snprintf(version_string, 64, "unknown");
	}
	
	/* Initializing */
	SSLi_init();
	Chan_init();
	Client_init();

	if (realtime)
		setscheduler();
	
	Server_run();
	
	SSLi_deinit();
	Chan_free();
	Log_free();
	Conf_deinit();
	
	if (pidfile != NULL)
		unlink(pidfile);
	
	return 0;
}
