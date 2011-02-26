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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "log.h"
#include "conf.h"

#define STRSIZE 254

static bool_t termprint, init;
static FILE *logfile;

static void openlogfile(const char *logfilename)
{
	int fd, flags;
	logfile = fopen(logfilename, "a");
	if (logfile == NULL) {
		Log_fatal("Failed to open log file '%s' for writing: %s\n", logfilename, strerror(errno));
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

void Log_free()
{
	if (termprint)
		return;
	else if (logfile)
		fclose(logfile);
	else 
		closelog();
}
		
void Log_reset()
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
		fprintf(logfile, "%s\n", buf);
	else
		syslog(LOG_INFO, "%s", buf);
}

void Log_warn(const char *logstring, ...)
{
	va_list argp;
	char buf[STRSIZE + 1];
	int offset = 0;
	
	va_start(argp, logstring);
	offset = sprintf(buf, "WARN: ");
	vsnprintf(&buf[offset], STRSIZE - offset, logstring, argp);
	va_end(argp);
	if (termprint)
		fprintf(stderr, "%s\n", buf);
	else if (logfile)
		fprintf(logfile, "%s\n", buf);
	else
		syslog(LOG_WARNING, "%s", buf);
}

void Log_info(const char *logstring, ...)
{
	va_list argp;
	char buf[STRSIZE + 1];
	int offset = 0;
	
	va_start(argp, logstring);
	offset = sprintf(buf, "INFO: ");
	vsnprintf(&buf[offset], STRSIZE - offset, logstring, argp);
	va_end(argp);
	if (termprint)
		fprintf(stderr, "%s\n", buf);
	else if (logfile)
		fprintf(logfile, "%s\n", buf);
	else
		syslog(LOG_INFO, "%s", buf);
}

void Log_info_client(client_t *client, const char *logstring, ...)
{
	va_list argp;
	char buf[STRSIZE + 1];
	int offset = 0;
	
	va_start(argp, logstring);
	offset = sprintf(buf, "INFO: ");
	offset += vsnprintf(&buf[offset], STRSIZE - offset, logstring, argp);
	va_end(argp);
	offset += snprintf(&buf[offset], STRSIZE - offset, " - [%d] %s@%s:%d",
					   client->sessionId,
					   client->username == NULL ? "" : client->username,
					   inet_ntoa(client->remote_tcp.sin_addr),
					   ntohs(client->remote_tcp.sin_port));
	if (termprint)
		fprintf(stderr, "%s\n", buf);
	else if (logfile)
		fprintf(logfile, "%s\n", buf);
	else
		syslog(LOG_INFO, "%s", buf);
}

#ifdef DEBUG
void Log_debug(const char *logstring, ...)
{
	va_list argp;
	char buf[STRSIZE + 1];
	int offset = 0;
	
	va_start(argp, logstring);
	offset = sprintf(buf, "DEBUG: ");
	vsnprintf(&buf[offset], STRSIZE - offset, logstring, argp);
	va_end(argp);
	if (termprint)
		fprintf(stderr, "%s\n", buf);
	else if (logfile)
		fprintf(logfile, "%s\n", buf);
	else
		syslog(LOG_DEBUG, "%s", buf);
}
#endif

void Log_fatal(const char *logstring, ...)
{
	va_list argp;
	char buf[STRSIZE + 1];
	int offset = 0;
	va_start(argp, logstring);
	offset = sprintf(buf, "FATAL: ");
	vsnprintf(&buf[offset], STRSIZE - offset, logstring, argp);
	va_end(argp);
	if (termprint)
		fprintf(stderr, "%s\n", buf);
	else if (logfile)
		fprintf(logfile, "%s\n", buf);
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
