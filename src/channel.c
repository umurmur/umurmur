/* Copyright (C) 2009, Martin Johansson <martin@fatbob.nu>
   Copyright (C) 2005-2009, Thorvald Natvig <thorvald@natvig.com>

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
#include "list.h"
#include "client.h"
#include "channel.h"
#include "conf.h"


static int nextchanId;
static channel_t *rootChan;
channel_t *defaultChan;
declare_list(channels); /* A flat list of the channels */

static channel_t *createChannel(int id, const char *name, const char *desc)
{
	channel_t *ch;

	ch = malloc(sizeof(channel_t));
	if (ch == NULL)
		Log_fatal("out of memory");
	memset(ch, 0, sizeof(channel_t));
	ch->id = id;
	strncpy(ch->name, name, MAX_TEXT);
	strncpy(ch->desc, desc, MAX_TEXT);
	init_list_entry(&ch->subs);
	init_list_entry(&ch->node);
	init_list_entry(&ch->clients);
	init_list_entry(&ch->flatlist_node);
	return ch;
}

#if 0
/* Might be used when tree travesal becomes neccessary */
static channel_t *first_subchannel(channel_t *ch)
{
	if (list_empty(&ch->subs))
		return NULL;
	else
		return list_get_entry(list_get_first(&ch->subs), channel_t, node);
}

static channel_t *next_channel(channel_t *ch)
{
	if (list_get_next(&ch->node) == &list_get_entry(&ch->node, channel_t, node)->parent->subs)
		return NULL;
	else
		return list_get_entry(list_get_next(&ch->node), channel_t, node);	
}
#endif

void Chan_iterate(channel_t **channelpptr)
{
	channel_t *ch = *channelpptr;

	if (!list_empty(&channels)) {
		if (ch == NULL)
			ch = list_get_entry(list_get_first(&channels), channel_t, flatlist_node);
		else {
			if (list_get_next(&ch->flatlist_node) == &channels)
				ch = NULL;
			else
				ch = list_get_entry(list_get_next(&ch->flatlist_node), channel_t, flatlist_node);
		}
		if (ch)
			Log_debug("Channel %d", ch->id);
	}

	*channelpptr = ch;
}
			
void Chan_init()
{
	int i;
	conf_channel_t chdesc;
	const char *defaultChannelName;

	defaultChannelName = getStrConf(DEAFULT_CHANNEL);
	
	for (i = 0; ; i++) {
		if (Conf_getNextChannel(&chdesc, i) < 0) {
			if (i == 0)
				Log_fatal("No valid channels found in configuration file. Exiting.");
			break;
		}
		if (i == 0) {
			rootChan = createChannel(0, chdesc.name, chdesc.description);
			list_add_tail(&rootChan->flatlist_node, &channels);
			if (strcmp(defaultChannelName, chdesc.name) == 0)
				defaultChan = rootChan;
		}
		else {
			channel_t *ch, *ch_itr = NULL;
			ch = Chan_createChannel(chdesc.name, chdesc.description);
			
			if (strcmp(defaultChannelName, chdesc.name) == 0) {
				Log_info("Setting default channel %s", ch->name); 
				defaultChan = ch;
			}
			
			do {
				Chan_iterate(&ch_itr);
			} while (ch_itr != NULL && strcmp(ch_itr->name, chdesc.parent) != 0);
			
			if (ch_itr == NULL)
				Log_fatal("Error in channel configuration: parent not found");
			else {
				Chan_addChannel(ch_itr, ch);
				Log_info("Adding channel %s parent %s", ch->name, chdesc.parent);
			}
		}
	}
	if (defaultChan == NULL)
		defaultChan = rootChan;
}

void Chan_free()
{
	struct dlist *itr, *save;
	
	list_iterate_safe(itr, save, &channels) {
		Log_debug("Free channel %s", list_get_entry(itr, channel_t, flatlist_node)->name);
		free(list_get_entry(itr, channel_t, flatlist_node));
	}
}

channel_t *Chan_createChannel(const char *name, const char *desc)
{
	/* Get an ID */
	nextchanId += 1; 
	return createChannel(nextchanId, name, desc);
}

void Chan_freeChannel(channel_t *ch)
{
	list_del(&ch->node);
	list_del(&ch->flatlist_node);
	free(ch);
}

void Chan_addChannel(channel_t *parent, channel_t *ch)
{
	list_add_tail(&ch->node, &parent->subs);
	ch->parent = parent;
	list_add_tail(&ch->flatlist_node, &channels);
}


void Chan_playerJoin(channel_t *ch, client_t *client)
{
	/* Only allowed in one channel at a time */
	Log_debug("Add player %s to channel %s", client->playerName, ch->name); 

	if (client->channel)
		list_del(&client->chan_node);
	list_add_tail(&client->chan_node, &ch->clients);
	client->channel = (void *)ch;
	
}

void Chan_playerJoin_id(int channelid, client_t *client)
{
	channel_t *ch_itr = NULL;
	do {
		Chan_iterate(&ch_itr);
	} while (ch_itr != NULL && ch_itr->id != channelid);
	if (ch_itr == NULL)
		Log_warn("Channel id %d not found - ignoring.", channelid);
	else
		Chan_playerJoin(ch_itr, client);
	
}

void Chan_addChannel_id(int parentId, channel_t *ch)
{
	channel_t *ch_itr = NULL;
	do {
		Chan_iterate(&ch_itr);
	} while (ch_itr != NULL && ch_itr->id != parentId);
	if (ch_itr == NULL)
		Log_warn("Channel id %d not found - ignoring.", parentId);
	else
		list_add_tail(&ch->node, &ch_itr->subs);
}

void Chan_removeChannel(channel_t *ch)
{
	list_del(&ch->node);
}
