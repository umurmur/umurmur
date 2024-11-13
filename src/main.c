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
#if (_POSIX_PRIORITY_SCHEDULING > 0)
#define POSIX_PRIORITY_SCHEDULING
#include <sched.h>
#endif
#endif
#include "server.h"
#include "ssl.h"
#include "channel.h"
#include "log.h"
#include "client.h"
#include "conf.h"
#include "version.h"
#include "config.h"
#include "sharedmemory.h"
#include "ban.h"

char system_string[256], version_string[64];
int bindport;
int bindport6;
char *bindaddr;
char *bindaddr6;

void lockfile(const char *pidfile)
{
	int lfp, flags, ret;
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
	ret = write(lfp, str, strlen(str)); /* record pid to lockfile */
	if (ret < 0)
		Log_fatal("Failed to write PID to file %s: %s", pidfile, strerror(errno));
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
			Log_info("HUP signal received.");
			Log_reset();
			break;
		case SIGTERM:
			Log_info("TERM signal. Shutting down.");
			Server_shutdown();
			break;
	}
}

void daemonize(void)
{
	int i;

	if (getppid() == 1)
		return; /* already a daemon */
	i = fork();
	if ( i < 0) {
		Log_fatal("fork: %s", strerror(errno));
	}
	if ( i > 0)
		exit(0); /* parent exits */

	/* child (daemon) continues */
	setsid(); /* obtain a new process group */
	for (i = getdtablesize(); i >= 0; --i)
		close(i); /* close all descriptors */

#ifdef USE_GNUTLS
	 gnutls_global_init();
#endif

	i = open("/dev/null",O_RDWR);
	if (i < 0)
		Log_fatal("Failed to open /dev/null: %s", strerror(errno));
	if (dup(i) < 0)
		Log_fatal("dup: %s", strerror(errno));
	if (dup(i) < 0)
		Log_fatal("dup: %s", strerror(errno));

	umask(027); /* set newly created file permissions */
	if (chdir("/") < 0)
		Log_fatal("chdir: %s", strerror(errno));
}

#ifdef POSIX_PRIORITY_SCHEDULING
void setscheduler(void)
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

void printhelp(void)
{
	printf("uMurmur version %s ('%s'). Mumble protocol %d.%d.%d\n", UMURMUR_VERSION,
		UMURMUR_CODENAME, PROTVER_MAJOR, PROTVER_MINOR, PROTVER_PATCH);
	printf("Usage: umurmurd [-d] [-r] [-s] [-h] [-p <pidfile>] [-t] [-c <conf file>] [-a <addr>] [-b <port>]\n");
	printf("       -d             - Do not daemonize - run in foreground.\n");
#ifdef POSIX_PRIORITY_SCHEDULING
	printf("       -r             - Run with realtime priority\n");
#endif
	printf("       -s             - Force user switching\n");
	printf("       -p <pidfile>   - Write PID to this file\n");
	printf("       -c <conf file> - Specify configuration file (default %s)\n", DEFAULT_CONFIG);
	printf("       -t             - Test config. Error message to stderr + non-zero exit code on error\n");
	printf("       -a <address>   - Bind to IP address\n");
	printf("       -A <address>   - Bind to IPv6 address\n");
	printf("       -b <port>      - Bind to port\n");
	printf("       -B <port>      - Bind to port (IPv6)\n");
	printf("       -h             - Print this help\n");
	exit(0);
}

int main(int argc, char **argv)
{
	bool_t nodaemon = false;
	bool_t forceswitch = false;
#ifdef POSIX_PRIORITY_SCHEDULING
	bool_t realtime = false;
#endif
	bool_t testconfig = false;
	char *conffile = NULL, *pidfile = NULL;
	int c;
	struct utsname utsbuf;

	/* Arguments */
#ifdef POSIX_PRIORITY_SCHEDULING
	while ((c = getopt(argc, argv, "drsp:c:a:A:b:B:ht")) != EOF) {
#else
		while ((c = getopt(argc, argv, "dsp:c:a:A:b:B:ht")) != EOF) {
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
				case 'A':
					bindaddr6 = optarg;
					break;
				case 'b':
					bindport = atoi(optarg);
					break;
				case 'B':
					bindport6 = atoi(optarg);
					break;
				case 'd':
					nodaemon = true;
					break;
				case 'h':
					printhelp();
					break;
				case 't':
					testconfig = true;
					break;
#ifdef POSIX_PRIORITY_SCHEDULING
				case 'r':
					realtime = true;
					break;
#endif
				case 's':
					forceswitch = true;
					break;
				default:
					fprintf(stderr, "Unrecognized option\n");
					printhelp();
					break;
			}
		}

		if (testconfig) {
			if (!Conf_ok(conffile))
				exit(1);
			else
				exit(0);
		}

		/* Initialize the config subsystem early;
		 * switch_user() will need to read some config variables as well as logging.
		 */
		Conf_init(conffile);

		/* Logging to terminal if not daemonizing, otherwise to syslog or log file.
		*/
		if (!nodaemon) {
			daemonize();
			Log_init(false);
			if (pidfile != NULL)
				lockfile(pidfile);
		}
		else Log_init(true);

#ifdef POSIX_PRIORITY_SCHEDULING
		/* Set the scheduling policy, has to be called after daemonizing
		 * but before we drop privileges */
		if (realtime)
			setscheduler();
#endif

		signal(SIGCHLD, SIG_IGN); /* ignore child */
		signal(SIGTSTP, SIG_IGN); /* ignore tty signals */
		signal(SIGTTOU, SIG_IGN);
		signal(SIGTTIN, SIG_IGN);
		signal(SIGPIPE, SIG_IGN);
		signal(SIGHUP, signal_handler); /* catch hangup signal */
		signal(SIGTERM, signal_handler); /* catch kill signal */

		/* Build system string */
		if (uname(&utsbuf) == 0) {
			snprintf(system_string, 256, "%s %s", utsbuf.sysname, utsbuf.machine);
			strncpy(version_string, utsbuf.release, sizeof(version_string) - 1);
		}
		else {
			strncpy(system_string, "unknown unknown", sizeof(system_string) - 1);
			strncpy(version_string, "unknown", sizeof(version_string) - 1);
		}

		/* Initializing */
		SSLi_init();
		Chan_init();
		Client_init();
		Ban_init();

#ifdef USE_SHAREDMEMORY_API
    Sharedmemory_init( bindport, bindport6 );
#endif

		if(!nodaemon || forceswitch) {
			/* SSL and scheduling is setup, we can drop privileges now */
			switch_user();

			/* Reopen log file. If user switch results in access denied, we catch
			 * it early.
			 */
			Log_reset();
		}

		Server_run();

#ifdef USE_SHAREDMEMORY_API
    Sharedmemory_deinit();
#endif

		Ban_deinit();
		SSLi_deinit();
		Chan_free();
		Log_free();
		Conf_deinit();

		if (pidfile != NULL)
			unlink(pidfile);

		return 0;
	}
