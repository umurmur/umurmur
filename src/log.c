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

#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>

#include "conf.h"
#include "util.h"

#define STRSIZE 254

static bool_t termprint, init;
static FILE *logfile;

static bool_t preparelogfdforprivdrop(int fd, const char *logfilename)
{
	const char *username, *groupname;
	struct passwd *pwd;
	struct group *grp;
	uid_t uid;
	gid_t gid;
	struct stat st;
	mode_t mode;

	/* Nothing to do unless we're root and privilege dropping is configured. */
	if (geteuid() != 0)
		return true;

	username = getStrConf(USERNAME);
	groupname = getStrConf(GROUPNAME);
	if (username == NULL || !*username)
		return true;

	pwd = getpwnam(username);
	if (!pwd) {
		fprintf(stderr, "Unknown user '%s' while preparing log file '%s'\n", username, logfilename);
		return false;
	}

	uid = pwd->pw_uid;
	gid = pwd->pw_gid;
	if (groupname != NULL && *groupname) {
		grp = getgrnam(groupname);
		if (!grp) {
			fprintf(stderr, "Unknown group '%s' while preparing log file '%s'\n", groupname, logfilename);
			return false;
		}
		gid = grp->gr_gid;
	}

	if (fchown(fd, uid, gid) < 0) {
		fprintf(stderr, "Failed to set ownership on log file '%s': %s\n", logfilename, strerror(errno));
		return false;
	}

	if (fstat(fd, &st) < 0) {
		fprintf(stderr, "Failed to stat log file '%s': %s\n", logfilename, strerror(errno));
		return false;
	}

	mode = st.st_mode & 0777;
	if ((mode & S_IWUSR) == 0 || (mode & S_IRUSR) == 0) {
		mode |= S_IWUSR | S_IRUSR;
		if (fchmod(fd, mode) < 0) {
			fprintf(stderr, "Failed to set permissions on log file '%s': %s\n", logfilename, strerror(errno));
			return false;
		}
	}

	return true;
}

static int openlogfd(const char *logfilename)
{
	int fd = open(logfilename, O_WRONLY | O_APPEND | O_CREAT, 0640);
	if (fd < 0 && (errno == EACCES || errno == EPERM))
		fd = open(logfilename, O_WRONLY | O_APPEND);
	return fd;
}

bool_t Log_preflight(void)
{
	const char *logfilename;
	int fd;

	logfilename = getStrConf(LOGFILE);
	if (logfilename == NULL)
		return true;

	fd = openlogfd(logfilename);
	if (fd < 0) {
		fprintf(stderr, "Cannot open log file '%s' for writing: %s\n", logfilename, strerror(errno));
		return false;
	}
	if (!preparelogfdforprivdrop(fd, logfilename)) {
		close(fd);
		return false;
	}

	close(fd);
	return true;
}

static void openlogfile(const char *logfilename)
{
	int fd, flags;

	fd = openlogfd(logfilename);
	if (fd < 0) {
		Log_fatal("Failed to open log file '%s' for writing: %s\n", logfilename, strerror(errno));
	}

	logfile = fdopen(fd, "a");
	if (logfile == NULL) {
		close(fd);
		Log_fatal("fdopen() failed for log file '%s': %s\n", logfilename, strerror(errno));
	}

	/* Set the stream as line buffered */
	if (setvbuf(logfile, NULL, _IOLBF, 0) < 0)
		Log_fatal("setvbuf() failed: %s\n", strerror(errno));

	/* XXX - Is it neccessary/appropriate that logging to file is non-blocking?
	 * If not, there's a risk that execution blocks, meaning that voice blocks
	 * as well since uMurmur is single threaded by design. OTOH, what could
	 * cause a block? If the disk causes blocking, it is probably br0ken, but
	 * the log could be on a nfs or smb share, so let's set it up as
	 * non-blocking and we'll see what happens.
	 */
	fd = fileno(logfile);
	flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static char *timestring(void)
{
	static char timebuf[32];
	time_t t;
	struct tm *timespec;

	t= time(NULL);
	timespec = localtime(&t);
	strftime(timebuf, 32, "%b %e %T", timespec);
	return timebuf;
}

void Log_init(bool_t terminal)
{
	const char *logfilename;

	termprint = terminal;
	if (termprint)
		return;

	logfilename = getStrConf(LOGFILE);
	if (logfilename != NULL) {
		openlogfile(logfilename);
	}
	else openlog("uMurmurd", LOG_PID, LOG_DAEMON);
	init = true;
}

void Log_free(void)
{
	if (termprint)
		return;
	else if (logfile)
		fclose(logfile);
	else
		closelog();
}

void Log_reset(void)
{
	const char *logfilename;

	if (logfile) {
		logfilename = getStrConf(LOGFILE);
		fclose(logfile);
		openlogfile(logfilename);
	}
}

void logthis(const char *logstring, ...)
{
	va_list argp;
	char buf[STRSIZE + 1];

	va_start(argp, logstring);
	vsnprintf(&buf[0], STRSIZE, logstring, argp);
	va_end(argp);

	if (termprint)
		fprintf(stderr, "%s\n", buf);
	else if (logfile)
		fprintf(logfile, "%s %s\n", timestring(), buf);
	else
		syslog(LOG_INFO, "%s", buf);
}

void Log_warn(const char *logstring, ...)
{
	va_list argp;
	char buf[STRSIZE + 1];
	int offset = 0;

	if (termprint || logfile)
		offset = snprintf(buf, sizeof(buf), "WARN: ");

	va_start(argp, logstring);
	vsnprintf(&buf[offset], STRSIZE - offset, logstring, argp);
	va_end(argp);

	if (termprint)
		fprintf(stderr, "%s\n", buf);
	else if (logfile)
		fprintf(logfile, "%s %s\n", timestring(), buf);
	else
		syslog(LOG_WARNING, "%s", buf);
}

void Log_info(const char *logstring, ...)
{
	va_list argp;
	char buf[STRSIZE + 1];
	int offset = 0;

	if (termprint || logfile)
		offset = snprintf(buf, sizeof(buf), "INFO: ");

	va_start(argp, logstring);
	vsnprintf(&buf[offset], STRSIZE - offset, logstring, argp);
	va_end(argp);

	if (termprint)
		fprintf(stderr, "%s\n", buf);
	else if (logfile)
		fprintf(logfile, "%s %s\n", timestring(), buf);
	else
		syslog(LOG_INFO, "%s", buf);
}

void Log_info_client(client_t *client, const char *logstring, ...)
{
	va_list argp;
	char buf[STRSIZE + 1];
	int offset = 0;

	if (termprint || logfile)
		offset = snprintf(buf, sizeof(buf), "INFO: ");

	va_start(argp, logstring);
	offset += vsnprintf(&buf[offset], STRSIZE - offset, logstring, argp);
	va_end(argp);

	char *clientAddressString = Util_clientAddressToString(client);
	offset += snprintf(&buf[offset], STRSIZE - offset, " - [%d] %s@%s:%d",
		client->sessionId,
		client->username == NULL ? "" : client->username,
		clientAddressString,
		Util_clientAddressToPortTCP(client));
	free(clientAddressString);

	if (termprint)
		fprintf(stderr, "%s\n", buf);
	else if (logfile)
		fprintf(logfile, "%s %s\n", timestring(), buf);
	else
		syslog(LOG_INFO, "%s", buf);
}

#ifdef DEBUG
void Log_debug(const char *logstring, ...)
{
	va_list argp;
	char buf[STRSIZE + 1];
	int offset = 0;

	if (termprint || logfile)
		offset = snprintf(buf, sizeof(buf), "DEBUG: ");

	va_start(argp, logstring);
	vsnprintf(&buf[offset], STRSIZE - offset, logstring, argp);
	va_end(argp);
	if (termprint)
		fprintf(stderr, "%s\n", buf);
	else if (logfile)
		fprintf(logfile, "%s %s\n", timestring(), buf);
	else
		syslog(LOG_DEBUG, "%s", buf);
}
#endif

void Log_fatal(const char *logstring, ...)
{
	va_list argp;
	char buf[STRSIZE + 1];
	int offset = 0;

	if (termprint || logfile)
		offset = snprintf(buf, sizeof(buf), "FATAL: ");

	va_start(argp, logstring);
	vsnprintf(&buf[offset], STRSIZE - offset, logstring, argp);
	va_end(argp);

	if (termprint)
		fprintf(stderr, "%s\n", buf);
	else if (logfile)
		fprintf(logfile, "%s %s\n", timestring(), buf);
	else { /* If logging subsystem is not initialized, fall back to stderr +
			* syslog logging for fatal errors.
			*/
		if (!init) {
			openlog("uMurmurd", LOG_PID, LOG_DAEMON);
			fprintf(stderr, "%s\n", buf);
		}
		syslog(LOG_CRIT, "%s", buf);
	}

	exit(1);
}
