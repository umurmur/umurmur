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

#include "log.h"

#define STRSIZE 254

static bool_t termprint;

void Log_init(bool_t terminal)
{
	termprint = terminal;
	if (!termprint)
		openlog("uMurmurd", LOG_PID, LOG_DAEMON);
}

void Log_free()
{
	if (!termprint)
		closelog();
}
		

void logthis(const char *logstring, ...)
{
	va_list argp;
	char buf[STRSIZE + 2];
	
	va_start(argp, logstring);
	vsnprintf(&buf[0], STRSIZE, logstring, argp);
	va_end(argp);
	strcat(buf, "\n");
	if (termprint)
		fprintf(stderr, "%s", buf);
	else
		syslog(LOG_INFO, buf);
}

void Log_warn(const char *logstring, ...)
{
	va_list argp;
	char buf[STRSIZE + 2];
	int offset = 0;
	
	va_start(argp, logstring);
	offset = sprintf(buf, "WARN: ");
	vsnprintf(&buf[offset], STRSIZE - offset, logstring, argp);
	va_end(argp);
	strcat(buf, "\n");
	if (termprint)
		fprintf(stderr, "%s", buf);
	else
		syslog(LOG_WARNING, buf);
}

void Log_info(const char *logstring, ...)
{
	va_list argp;
	char buf[STRSIZE + 2];
	int offset = 0;
	
	va_start(argp, logstring);
	offset = sprintf(buf, "INFO: ");
	vsnprintf(&buf[offset], STRSIZE - offset, logstring, argp);
	va_end(argp);
	strcat(buf, "\n");
	if (termprint)
		fprintf(stderr, "%s", buf);
	else
		syslog(LOG_INFO, buf);
}
void Log_info_client(client_t *client, const char *logstring, ...)
{
	va_list argp;
	char buf[STRSIZE + 2];
	int offset = 0;
	
	va_start(argp, logstring);
	offset = sprintf(buf, "INFO: ");
	offset += vsnprintf(&buf[offset], STRSIZE - offset, logstring, argp);
	va_end(argp);
	offset += snprintf(&buf[offset], STRSIZE - offset, " - [%d] %s@%s:%d",
					   client->sessionId,
					   client->playerName,
					   inet_ntoa(client->remote_tcp.sin_addr),
					   ntohs(client->remote_tcp.sin_port));
	strcat(buf, "\n");
	if (termprint)
		fprintf(stderr, "%s", buf);
	else
		syslog(LOG_INFO, buf);
	
}

#ifdef DEBUG
void Log_debug(const char *logstring, ...)
{
	va_list argp;
	char buf[STRSIZE + 2];
	int offset = 0;
	
	va_start(argp, logstring);
	offset = sprintf(buf, "DEBUG: ");
	vsnprintf(&buf[offset], STRSIZE - offset, logstring, argp);
	va_end(argp);
	strcat(buf, "\n");
	if (termprint)
		fprintf(stderr, "%s", buf);
	else
		syslog(LOG_DEBUG, buf);
}
#endif

void Log_fatal(const char *logstring, ...)
{
	va_list argp;
	char buf[STRSIZE + 2];
	int offset = 0;
	va_start(argp, logstring);
	offset = sprintf(buf, "FATAL: ");
	vsnprintf(&buf[offset], STRSIZE - offset, logstring, argp);
	va_end(argp);
	strcat(buf, "\n");
	if (termprint)
		fprintf(stderr, "%s", buf);
	else
		syslog(LOG_CRIT, buf);
	exit(1);
}
