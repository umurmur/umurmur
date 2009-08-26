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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "messages.h"
#include "pds.h"
#include "log.h"


void dumpmsg(uint8_t *data, int size);

int Msg_messageToNetwork(message_t *msg, uint8_t *buffer, int bufsize)
{
	pds_t *pds = Pds_create(buffer, bufsize);
	int len;
	
	Pds_add_numval(pds, msg->messageType);
	Pds_add_numval(pds, msg->sessionId);
	
	switch (msg->messageType) {
		case Speex:
			Pds_add_numval(pds, msg->payload.speex.seq);
			Pds_append_data_nosize(pds, msg->payload.speex.data, msg->payload.speex.size);
			break;
		case ServerReject:
			Pds_add_string(pds, msg->payload.serverReject.reason);
			Pds_add_numval(pds, msg->payload.serverReject.type);
			break;
		case ServerSync:
			Pds_add_numval(pds, msg->payload.serverSync.maxBandwidth);
			Pds_add_string(pds, msg->payload.serverSync.welcomeText);
			break;
		case ServerJoin:
			Pds_add_string(pds, msg->payload.serverJoin.playerName);			
			Pds_add_numval(pds, msg->payload.serverJoin.id);
			break;
		case ChannelDescUpdate:
			Pds_add_numval(pds, msg->payload.channelDescUpdate.id);
			Pds_add_string(pds, msg->payload.channelDescUpdate.desc);			
			break;
		case ChannelAdd:
			Pds_add_numval(pds, msg->payload.channelAdd.id);
			Pds_add_numval(pds, msg->payload.channelAdd.parentId);
			Pds_add_string(pds, msg->payload.channelAdd.name);
			break;
		case PlayerMove:
			Pds_add_numval(pds, msg->payload.playerMove.victim);
			Pds_add_numval(pds, msg->payload.playerMove.channel);
			break;
		case QueryUsers:
			break;
		case Ping:
			Pds_add_numval(pds, msg->payload.ping.timestamp);
			break;
		case PingStats:
			Pds_add_numval(pds, msg->payload.pingStats.timestamp);
			Pds_add_numval(pds, msg->payload.pingStats.good);
			Pds_add_numval(pds, msg->payload.pingStats.late);
			Pds_add_numval(pds, msg->payload.pingStats.lost);
			Pds_add_numval(pds, msg->payload.pingStats.resync);
			Pds_add_double(pds, msg->payload.pingStats.dUDPPingAvg);
			Pds_add_double(pds, msg->payload.pingStats.dUDPPingVar);
			Pds_add_numval(pds, msg->payload.pingStats.UDPPackets);
			Pds_add_double(pds, msg->payload.pingStats.dTCPPingAvg);
			Pds_add_double(pds, msg->payload.pingStats.dTCPPingVar);
			Pds_add_numval(pds, msg->payload.pingStats.TCPPackets);			
			break;
		case PlayerMute:
			break;
		case PlayerDeaf:
			break;
		case PlayerSelfMuteDeaf:
			break;
		case TextMessage:
			Pds_add_numval(pds, msg->payload.textMessage.victim);			
			Pds_add_numval(pds, msg->payload.textMessage.channel);			
			Pds_add_numval(pds, msg->payload.textMessage.bTree);			
			Pds_add_string(pds, msg->payload.textMessage.message);
			break;
		case PermissionDenied:
			Pds_add_string(pds, msg->payload.permissionDenied.reason);
			break;
		case CryptSetup:
			Pds_append_data(pds, msg->payload.cryptSetup.key, AES_BLOCK_SIZE);
			Pds_append_data(pds, msg->payload.cryptSetup.serverNonce, AES_BLOCK_SIZE);
			Pds_append_data(pds, msg->payload.cryptSetup.clientNonce, AES_BLOCK_SIZE);
			break;
		case CryptSync:
			if (!msg->payload.cryptSync.empty)
				Pds_append_data(pds, msg->payload.cryptSync.nonce, AES_BLOCK_SIZE);			
			break;
		case ServerLeave:
			/* No info to add */
			break;

	default:
		Log_warn("Unsupported message %d", msg->messageType);
		break;
	}
	len = pds->offset;
	Pds_free(pds);
	return len;
}

message_t *Msg_create(messageType_t messageType)
{
	message_t *msg = malloc(sizeof(message_t));

	if (msg == NULL)
		Log_fatal("Out of memory");
	memset(msg, 0, sizeof(message_t));
	msg->refcount = 1;
	msg->messageType = messageType;
	init_list_entry(&msg->node);
	
	if (msg->messageType == Speex) {
		msg->payload.speex.data = malloc(SPEEX_DATA_SIZE);
		if (msg->payload.speex.data == NULL)
			Log_fatal("Out of memory");
	}
	return msg;
}

void Msg_inc_ref(message_t *msg)
{
	msg->refcount++;
}

void Msg_free(message_t *msg)
{
	if (msg->refcount) msg->refcount--;
	if (msg->refcount > 0)
		return;
	if (msg->messageType == Speex)
		free(msg->payload.speex.data);
	free(msg);
}

void dumpmsg(uint8_t *data, int size)
{
	int i, r = 0, offset = 0;
	char buf[512];
	
	while (r * 8 + i < size) {
		for (i = 0; i < 8 && r * 8 + i < size; i++) {
			offset += sprintf(buf + offset, "%x ", data[r * 8 + i]);
		}
		sprintf(buf + offset, "\n");
		printf(buf);
		offset = 0;
		r++;
		i = 0;
	} 
}

message_t *Msg_networkToMessage(uint8_t *data, int size)
{
	message_t *msg = NULL;
	int messageType;
	int sessionId;
	pds_t *pds;

	pds = Pds_create(data, size);
	messageType = Pds_get_numval(pds);
	sessionId = Pds_get_numval(pds);
	
	switch (messageType) {
		case Speex:
			msg = Msg_create(Speex);
			msg->payload.speex.seq = Pds_get_numval(pds);
			msg->payload.speex.size = pds->maxsize - pds->offset;
			memcpy(msg->payload.speex.data, &pds->data[pds->offset], pds->maxsize - pds->offset);
			break;
		case ServerAuthenticate:
			msg = Msg_create(ServerAuthenticate);
			msg->payload.serverAuthenticate.version = Pds_get_numval(pds);
			Pds_get_string(pds, msg->payload.serverAuthenticate.userName, MAX_TEXT);
			Pds_get_string(pds, msg->payload.serverAuthenticate.password, MAX_TEXT);
			break;
		case ServerReject:
			msg = Msg_create(ServerReject);
			break;
		case ServerSync:
			msg = Msg_create(ServerSync);
			break;
		case ServerJoin:
			msg = Msg_create(ServerJoin);
			break;
		case ServerLeave:
			msg = Msg_create(ServerLeave);
			break;
		case QueryUsers:
			msg = Msg_create(QueryUsers);
			break;
		case Ping:
			msg = Msg_create(Ping);
			msg->payload.ping.timestamp = Pds_get_numval(pds);
			break;
		case PingStats:
			msg = Msg_create(PingStats);
			msg->payload.pingStats.timestamp = Pds_get_numval(pds);
			msg->payload.pingStats.good = Pds_get_numval(pds);
			msg->payload.pingStats.late = Pds_get_numval(pds);
			msg->payload.pingStats.lost = Pds_get_numval(pds);
			msg->payload.pingStats.resync = Pds_get_numval(pds);
			msg->payload.pingStats.dUDPPingAvg = Pds_get_double(pds);
			msg->payload.pingStats.dUDPPingVar = Pds_get_double(pds);
			msg->payload.pingStats.UDPPackets = Pds_get_numval(pds);
			msg->payload.pingStats.dTCPPingAvg = Pds_get_double(pds);
			msg->payload.pingStats.dTCPPingVar = Pds_get_double(pds);
			msg->payload.pingStats.TCPPackets = Pds_get_numval(pds);
			break;
		case PlayerMute:
			msg = Msg_create(PlayerMute);
			msg->payload.playerMute.victim = Pds_get_numval(pds);
			msg->payload.playerMute.bMute = Pds_get_numval(pds);
			break;
		case PlayerDeaf:
			msg = Msg_create(PlayerDeaf);
			msg->payload.playerDeaf.victim = Pds_get_numval(pds);
			msg->payload.playerDeaf.bDeaf = Pds_get_numval(pds);
			break;
		case PlayerSelfMuteDeaf:
			msg = Msg_create(PlayerSelfMuteDeaf);
			msg->payload.playerSelfMuteDeaf.bMute = Pds_get_numval(pds);
			msg->payload.playerSelfMuteDeaf.bDeaf = Pds_get_numval(pds);
			break;
		case TextMessage:
			msg = Msg_create(TextMessage);
			msg->payload.textMessage.victim = Pds_get_numval(pds);
			msg->payload.textMessage.channel = Pds_get_numval(pds);
			msg->payload.textMessage.bTree = Pds_get_numval(pds);
			Pds_get_string(pds, msg->payload.textMessage.message, MAX_TEXT);
			break;
		case PermissionDenied:
			Log_warn("Ignoring message PermissionDenied - not supported");
			break;
		case CryptSetup:
			Log_warn("Ignoring message CryptSetup - not supported");
			break;
		case CryptSync:
			msg = Msg_create(CryptSync);
			if (Pds_get_data(pds, msg->payload.cryptSync.nonce, AES_BLOCK_SIZE) == 0)
				msg->payload.cryptSync.empty = true;
			else
				msg->payload.cryptSync.empty = false;				
			break;
		case PlayerMove:
			msg = Msg_create(PlayerMove);
			msg->payload.playerMove.victim = Pds_get_numval(pds);
			msg->payload.playerMove.channel = Pds_get_numval(pds);
			break;
			
			/* The commands below are not supported -> no need to read the parameters */
		case PlayerRename:
			msg = Msg_create(PlayerRename);
			break;			
		case ChannelAdd:
			msg = Msg_create(ChannelAdd);
			break;
		case ChannelDescUpdate:
			msg = Msg_create(ChannelDescUpdate);
			break;
		case ContextAction:
			msg = Msg_create(ContextAction);
			break;
		case ContextAddAction:
			msg = Msg_create(ContextAddAction);
			break;
		case ServerBanList:
			msg = Msg_create(ServerBanList);
			break;
		case PlayerKick:
			msg = Msg_create(PlayerKick);
			break;
		case PlayerBan:
			msg = Msg_create(PlayerBan);
			break;
		case ChannelRemove:
			msg = Msg_create(ChannelRemove);
			break;
		case ChannelMove:
			msg = Msg_create(ChannelMove);
			break;
		case ChannelLink:
			msg = Msg_create(ChannelLink);
			break;
		case ChannelRename:
			msg = Msg_create(ChannelRename);
			break;
		case EditACL:
			msg = Msg_create(EditACL);
			break;
		case PlayerTexture:
			msg = Msg_create(PlayerTexture);
			break;
		default:
			Log_warn("Message: Type %d (session %d) is unknown type", messageType, sessionId);
	}
	if (msg) {
		msg->sessionId = sessionId;
#if 0
		if (!pds->bOk) {
			Msg_free(msg);
			msg = NULL;
			Log_warn("Message: Type %d (session %d, size %d) corrupt or short packet",
					 messageType, sessionId, pds->offset);
		} else if (pds->maxsize - pds->offset != 0) {
			Msg_free(msg);
			msg = NULL;
			Log_warn("Message: Type %d (session %d) Long packet: %d/%d leftover bytes",
					 messageType, sessionId, pds->overshoot, pds->offset);
		} else if (!pds->bOk) {
			Msg_free(msg);
			msg = NULL;
			Log_warn("Message: Type %d (session %d, size %d) failed to validate", messageType, sessionId, pds->maxsize);
		}
#endif
	}
	Pds_free(pds);
	return msg;
}
