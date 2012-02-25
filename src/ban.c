/* Copyright (C) 2009-2011, Martin Johansson <martin@fatbob.nu>
   Copyright (C) 2005-2011, Thorvald Natvig <thorvald@natvig.com>

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

#include <stdlib.h>
#include "log.h"
#include "list.h"
#include "ban.h"
#include "conf.h"
#include "ssl.h"

declare_list(banlist);
static int bancount; /* = 0 */

void Ban_UserBan(client_t *client, char *reason)
{
	ban_t *ban;
	char hexhash[41];

	ban = malloc(sizeof(ban_t));
	memcpy(ban->hash, client->hash, 20);
	memcpy(&ban->address, &client->remote_tcp.sin_addr, sizeof(in_addr_t));
	ban->reason = strdup(reason);
	ban->name = strdup(client->username);
	Timer_init(&ban->startTime);
	list_add_tail(&ban->node, &banlist);
	
	SSLi_hash2hex(ban->hash, hexhash);
	Log_info("User %s kickbanned. Reason: '%s' Hash: %s IP: %s Banned for: %d seconds",
	         ban->name, ban->reason, hexhash, inet_ntoa(*((struct in_addr *)&ban->address)),
	         getIntConf(BAN_LENGTH));
}


void Ban_pruneBanned()
{
	struct dlist *itr;
	static int64_t bantime = 0;
	ban_t *ban;
	char hexhash[41];
	
	if (bantime == 0) {
		bantime = getIntConf(BAN_LENGTH) * 1000000LL;
	}
	
	list_iterate(itr, &banlist) {
		ban = list_get_entry(itr, ban_t, node);
#ifdef DEBUG
		SSLi_hash2hex(ban->hash, hexhash);
		Log_debug("BL: User %s Reason: '%s' Hash: %s IP: %s Time left: %d",
		          ban->name, ban->reason, hexhash, inet_ntoa(*((struct in_addr *)&ban->address)),
		          bantime / 1000000LL - Timer_elapsed(&ban->startTime) / 1000000LL);
#endif
		if (Timer_isElapsed(&ban->startTime, bantime)) {
			free(ban->name);
			free(ban->reason);
			list_del(&ban->node);
			free(ban);
		}
	}
}

bool_t Ban_isBanned(client_t *client)
{
	struct dlist *itr;
	ban_t *ban;
	list_iterate(itr, &banlist) {
		ban = list_get_entry(itr, ban_t, node);
		if (memcmp(ban->hash, client->hash, 20) == 0) 
			return true;
	}
	return false;
	
}

bool_t Ban_isBannedAddr(in_addr_t *addr)
{
	struct dlist *itr;
	ban_t *ban;
	list_iterate(itr, &banlist) {
		ban = list_get_entry(itr, ban_t, node);
		if (memcmp(&ban->address, addr, sizeof(in_addr_t)) == 0) 
			return true;
	}
	return false;
}

