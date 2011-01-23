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
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#ifdef _POSIX_PRIORITY_SCHEDULING
#include <sched.h>
#endif
#include "server.h"
#include "ssl.h"
#include "channel.h"
#include "log.h"
#include "client.h"
#include "conf.h"
#include "version.h"

char system_string[64], version_string[64];
int bindport;
char *bindaddr;

void lockfile(const char *pidfile)
{
	int lfp, flags;
	char str[16];

	/* Don't use O_TRUNC here -- we want to leave the PID file
	 * unmodified if we cannot lock it.
	 */
	lfp = open(pidfile, O_WRONLY|O_CREAT, 0640);
	
	if (lfp < 0)
		Log_fatal("Cannot open PID-file %s for writing", pidfile);

	/* Try to lock the file. */
	if (lockf(lfp, F_TLOCK, 0) < 0) {
		close(lfp);

		if (errno == EACCES || errno == EAGAIN)
			Log_fatal("PID file is locked -- uMurmur already running?");

		Log_fatal("Cannot lock PID file: %s", strerror(errno));
	}

	/* Now that we locked the file, erase its contents. */
	if (ftruncate(lfp, 0) < 0) {
		close(lfp);
		Log_fatal("Cannot truncate PID file: %s", strerror(errno));
	}

	snprintf(str,16,"%d\n", getpid());
	write(lfp, str, strlen(str)); /* record pid to lockfile */
	Log_info("PID-file: %s", pidfile);

	/* If uMurmur ever starts to fork()+exec(), we don't want it to
	 * leak the fd to the forked process though. Set the close-on-exec
	 * flag to prevent leakage.
	 */
	flags = fcntl(lfp, F_GETFD, 0);
	flags |= FD_CLOEXEC;
	fcntl(lfp, F_SETFD, (long) flags);

	/* Don't close(lfp) here!
	 * We want the fd to remain opened so the lock is held until the
	 * process exits.
	 */
	lfp = -1;
}

/* Drops privileges (if configured to do so). */
static void switch_user(void)
{
	struct passwd *pwd;
	struct group *grp = NULL;
	const char *username, *groupname;
	gid_t gid;

	username = getStrConf(USERNAME);
	groupname = getStrConf(GROUPNAME);

	if (!*username) {
		/* It's an error to specify groupname
		 * but leave username empty.
		 */
		if (*groupname)
			Log_fatal("username missing");

		/* Nothing to do. */
		return;
	}

	pwd = getpwnam(username);
	if (!pwd)
		Log_fatal("Unknown user '%s'", username);

	if (!*groupname)
		gid = pwd->pw_gid;
	else {
		grp = getgrnam(groupname);

		if (!grp)
			Log_fatal("Unknown group '%s'", groupname);

		gid = grp->gr_gid;
	}

	if (initgroups(pwd->pw_name, gid))
		Log_fatal("initgroups() failed: %s", strerror(errno));

	if (setgid(gid))
		Log_fatal("setgid() failed: %s", strerror(errno));

	if (setuid(pwd->pw_uid))
		Log_fatal("setuid() failed: %s", strerror(errno));
	
	if (!grp)
		grp = getgrgid(gid);
	if (!grp)
		Log_fatal("getgrgid() failed: %s", strerror(errno));
	
	Log_info("Switch to user '%s' group '%s'", pwd->pw_name, grp->gr_name);
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

#ifdef _POSIX_PRIORITY_SCHEDULING
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
#endif

void printhelp()
{
	printf("uMurmur version %s. Mumble protocol %d.%d.%d\n", UMURMUR_VERSION, PROTVER_MAJOR, PROTVER_MINOR, PROTVER_PATCH);
	printf("Usage: umurmurd [-d] [-p <pidfile>] [-c <conf file>] [-h]\n");
	printf("       -d             - Do not daemonize\n");
	printf("       -p <pidfile>   - Write PID to this file\n");
	printf("       -c <conf file> - Specify configuration file\n");
#ifdef _POSIX_PRIORITY_SCHEDULING
	printf("       -r             - Run with realtime priority\n");
#endif
	printf("       -a <address>   - Bind to IP address\n");
	printf("       -b <port>      - Bind to port\n");
	printf("       -h             - Print this help\n");
	exit(0);
}

int main(int argc, char **argv)
{
	bool_t nodaemon = false;
#ifdef _POSIX_PRIORITY_SCHEDULING
	bool_t realtime = false;
#endif
	char *conffile = NULL, *pidfile = NULL;
	int c;
	struct utsname utsbuf;
	
	/* Arguments */
#ifdef _POSIX_PRIORITY_SCHEDULING
	while ((c = getopt(argc, argv, "drp:c:a:b:h")) != EOF) {
#else
	while ((c = getopt(argc, argv, "dp:c:a:b:h")) != EOF) {
#endif
		switch(c) {
		case 'c':
			conffile = optarg;
			break;
		case 'p':
			pidfile = optarg;
			break;
		case 'a':
			bindaddr = optarg;
			break;
		case 'b':
			bindport = atoi(optarg);
			break;
		case 'd':
			nodaemon = true;
			break;
		case 'h':
			printhelp();
			break;
#ifdef _POSIX_PRIORITY_SCHEDULING
		case 'r':
			realtime = true;
			break;
#endif
		default:
			fprintf(stderr, "Unrecognized option\n");
			printhelp();
			break;
		}
	}

	/* Logging to terminal if not daemonizing, otherwise to syslog.
	 * Need to initialize logging before calling Conf_init()
	 */
	if (!nodaemon)
		Log_init(false);
	else
		Log_init(true);
	
	/* Initialize the config subsystem early;
	 * switch_user() will need to read some config variables.
	 */
	Conf_init(conffile);

	if (!nodaemon) {
		daemonize();
		if (pidfile != NULL)
			lockfile(pidfile);

		switch_user();
	}

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

#ifdef _POSIX_PRIORITY_SCHEDULING
	if (realtime)
		setscheduler();
#endif
	
	Server_run();
	
	SSLi_deinit();
	Chan_free();
	Log_free();
	Conf_deinit();
	
	if (pidfile != NULL)
		unlink(pidfile);
	
	return 0;
}
