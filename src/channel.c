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
#include <limits.h>
#include "log.h"
#include "list.h"
#include "client.h"
#include "channel.h"
#include "conf.h"


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
	init_list_entry(&ch->channel_links);
	return ch;
}

static int findFreeId()
{
	int id = 0;
	channel_t *ch_itr = NULL;
	for (id = 0; id < INT_MAX; id++) {
		ch_itr = NULL;
		while ((ch_itr = Chan_iterate(&ch_itr)) != NULL) {
			if (ch_itr->id == id)
				break;
		}
		if (ch_itr == NULL) /* Found free id */
			return id;
	}
	return -1;
}

#if 0
/* Might be used when tree traversal becomes neccessary */
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

channel_t *Chan_iterate(channel_t **channelpptr)
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
	}

	*channelpptr = ch;
	return ch;
}

channel_t *Chan_iterate_siblings(channel_t *parent, channel_t **channelpptr)
{
	channel_t *ch = *channelpptr;

	if (!list_empty(&parent->subs)) {
		if (ch == NULL)
			ch = list_get_entry(list_get_first(&parent->subs), channel_t, node);
		else {
			if (list_get_next(&ch->node) == &parent->subs)
				ch = NULL;
			else
				ch = list_get_entry(list_get_next(&ch->node), channel_t, node);
		}
	}

	*channelpptr = ch;
	return ch;
}
			
void Chan_init()
{
	int i;
	conf_channel_t chdesc;
	conf_channel_link_t chlink;
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
				Log_info("Adding channel '%s' parent '%s'", ch->name, chdesc.parent);
			}
		}
	}
	if (defaultChan == NULL)
		defaultChan = rootChan;

	/* Channel links */
	for (i = 0; ; i++) {
		channel_t *ch_src, *ch_dst, *ch_itr = NULL;
		if (Conf_getNextChannelLink(&chlink, i) < 0) {
			if (i == 0)
				Log_info("No channel links found in configuration file.");
			break;
		}
		ch_itr = NULL;
		do {
			Chan_iterate(&ch_itr);
		} while (ch_itr != NULL && strcmp(ch_itr->name, chlink.source) != 0);
		if (ch_itr == NULL)
			Log_fatal("Error in channel link configuration: source channel '%s' not found.", chlink.source);
		else
			ch_src = ch_itr;
		
		ch_itr = NULL;		
		do {
			Chan_iterate(&ch_itr);
		} while (ch_itr != NULL && strcmp(ch_itr->name, chlink.destination) != 0);
		if (ch_itr == NULL)
			Log_fatal("Error in channel link configuration: destination channel '%s' not found", chlink.destination);
		else
			ch_dst = ch_itr;
		
		list_add_tail(&ch_dst->link_node, &ch_src->channel_links);
		Log_info("Adding channel link %s -> %s", ch_src->name, ch_dst->name);
	}
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
	int id = findFreeId();
	if (id < 0)
		Log_fatal("No free channel ID found");
	return createChannel(id, name, desc);
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


int Chan_playerJoin(channel_t *ch, client_t *client)
{
	channel_t *leaving = NULL;
	int leaving_id = -1;
	
	/* Only allowed in one channel at a time */
	Log_debug("Add player %s to channel %s", client->playerName, ch->name); 

	if (client->channel) {
		list_del(&client->chan_node);
		leaving = (channel_t *)client->channel;
		if (leaving->temporary && list_empty(&leaving->clients)) {
			leaving_id = leaving->id;
			Chan_freeChannel(leaving);
		}
	}
	list_add_tail(&client->chan_node, &ch->clients);
	client->channel = (void *)ch;
	return leaving_id;
}

int Chan_playerJoin_id(int channelid, client_t *client)
{
	channel_t *ch_itr = NULL;
	do {
		Chan_iterate(&ch_itr);
	} while (ch_itr != NULL && ch_itr->id != channelid);
	if (ch_itr == NULL) {
		Log_warn("Channel id %d not found - ignoring.", channelid);
		return -1;
	}
	else
		return Chan_playerJoin(ch_itr, client);	
}

#if 0
void Chan_addChannel_id(int parentId, channel_t *ch)
{
	channel_t *ch_itr = NULL;
	do {
		Chan_iterate(&ch_itr);
	} while (ch_itr != NULL && ch_itr->id != parentId);
	if (ch_itr == NULL)
		Log_warn("Chan_addChannel_id: Channel id %d not found - ignoring.", parentId);
	else
		list_add_tail(&ch->node, &ch_itr->subs);
}
#endif

channel_t *Chan_fromId(int channelid)
{
	channel_t *ch_itr = NULL;
	do {
		Chan_iterate(&ch_itr);
	} while (ch_itr != NULL && ch_itr->id != channelid);
	if (ch_itr == NULL)
		Log_warn("Chan_fromId: Channel id %d not found.", channelid);
	return ch_itr;
}

void Chan_removeChannel(channel_t *ch)
{
	list_del(&ch->node);
}
