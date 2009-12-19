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
#include <arpa/inet.h>

#include "messages.h"
#include "client.h"
#include "pds.h"
#include "log.h"


void dumpmsg(uint8_t *data, int size);

void Msg_addPreamble(uint8_t *buffer, uint16_t type, uint32_t len)
{
	uint16_t *msgType = (uint16_t *) &buffer[0];
	uint32_t *msgLen = (uint32_t *) &buffer[2];
	
	*msgType = htons(type);
	*msgLen = htonl(len);
}

static void Msg_getPreamble(uint8_t *buffer, int *type, int *len)
{
	uint16_t *msgType = (uint16_t *) &buffer[0];
	uint32_t *msgLen = (uint32_t *) &buffer[2];
	
	*type = (int)ntohs(*msgType);
	*len = (int)ntohl(*msgLen);
}

#define MAX_MSGSIZE (BUFSIZE - 6)
int Msg_messageToNetwork(message_t *msg, uint8_t *buffer)
{
	int len;
	uint8_t *bufptr = buffer + 6;
		
	Log_debug("To net: msg type %d", msg->messageType);
	switch (msg->messageType) {
	case Version:
		len = mumble_proto__version__get_packed_size(msg->payload.version);
		if (len > MAX_MSGSIZE) {
			Log_warn("Too big tx message. Discarding");
			break;
		}
		Msg_addPreamble(buffer, msg->messageType, len);
		mumble_proto__version__pack(msg->payload.version, bufptr);
		break;
	case UDPTunnel:
		len = mumble_proto__udptunnel__get_packed_size(msg->payload.UDPTunnel);
		if (len > MAX_MSGSIZE) {
			Log_warn("Too big tx message. Discarding");
			break;
		}
		Msg_addPreamble(buffer, msg->messageType, len);
		mumble_proto__udptunnel__pack(msg->payload.UDPTunnel, bufptr);		
		break;
	case Authenticate:
		len = mumble_proto__authenticate__get_packed_size(msg->payload.authenticate);
		if (len > MAX_MSGSIZE) {
			Log_warn("Too big tx message. Discarding");
			break;
			}
		Msg_addPreamble(buffer, msg->messageType, len);
		mumble_proto__authenticate__pack(msg->payload.authenticate, bufptr);
		break;
	case Ping:
		len = mumble_proto__ping__get_packed_size(msg->payload.ping);
		if (len > MAX_MSGSIZE) {
			Log_warn("Too big tx message. Discarding");
			break;
			}
		Msg_addPreamble(buffer, msg->messageType, len);
		mumble_proto__ping__pack(msg->payload.ping, bufptr);
		break;
	case Reject:
		len = mumble_proto__reject__get_packed_size(msg->payload.reject);
		if (len > MAX_MSGSIZE) {
			Log_warn("Too big tx message. Discarding");
			break;
			}
		Msg_addPreamble(buffer, msg->messageType, len);
		mumble_proto__reject__pack(msg->payload.reject, bufptr);
		break;
	case ServerSync:
		len = mumble_proto__server_sync__get_packed_size(msg->payload.serverSync);
		if (len > MAX_MSGSIZE) {
			Log_warn("Too big tx message. Discarding");
			break;
			}
		Msg_addPreamble(buffer, msg->messageType, len);
		mumble_proto__server_sync__pack(msg->payload.serverSync, bufptr);
		break;
	case TextMessage:
		len = mumble_proto__text_message__get_packed_size(msg->payload.textMessage);
		if (len > MAX_MSGSIZE) {
			Log_warn("Too big tx message. Discarding");
			break;
			}
		Msg_addPreamble(buffer, msg->messageType, len);
		mumble_proto__text_message__pack(msg->payload.textMessage, bufptr);
		break;
	case PermissionDenied:
		len = mumble_proto__permission_denied__get_packed_size(msg->payload.permissionDenied);
		if (len > MAX_MSGSIZE) {
			Log_warn("Too big tx message. Discarding");
			break;
			}
		Msg_addPreamble(buffer, msg->messageType, len);
		mumble_proto__permission_denied__pack(msg->payload.permissionDenied, bufptr);
		break;
	case CryptSetup:
		len = mumble_proto__crypt_setup__get_packed_size(msg->payload.cryptSetup);
		if (len > MAX_MSGSIZE) {
			Log_warn("Too big tx message. Discarding");
			break;
			}
		Msg_addPreamble(buffer, msg->messageType, len);
		mumble_proto__crypt_setup__pack(msg->payload.cryptSetup, bufptr);
		break;
	case UserList:
		len = mumble_proto__user_list__get_packed_size(msg->payload.userList);
		if (len > MAX_MSGSIZE) {
			Log_warn("Too big tx message. Discarding");
			break;
			}
		Msg_addPreamble(buffer, msg->messageType, len);
		mumble_proto__user_list__pack(msg->payload.userList, bufptr);
		break;
	case UserState:
		len = mumble_proto__user_state__get_packed_size(msg->payload.userState);
		if (len > MAX_MSGSIZE) {
			Log_warn("Too big tx message. Discarding");
			break;
			}
		Msg_addPreamble(buffer, msg->messageType, len);
		mumble_proto__user_state__pack(msg->payload.userState, bufptr);
		break;
	case ChannelState:
		len = mumble_proto__channel_state__get_packed_size(msg->payload.channelState);
		if (len > MAX_MSGSIZE) {
			Log_warn("Too big tx message. Discarding");
			break;
			}
		Msg_addPreamble(buffer, msg->messageType, len);
		mumble_proto__channel_state__pack(msg->payload.channelState, bufptr);
		break;
	case VoiceTarget:
		len = mumble_proto__voice_target__get_packed_size(msg->payload.voiceTarget);
		if (len > MAX_MSGSIZE) {
			Log_warn("Too big tx message. Discarding");
			break;
			}
		Msg_addPreamble(buffer, msg->messageType, len);
		mumble_proto__voice_target__pack(msg->payload.voiceTarget, bufptr);
		break;
	case CodecVersion:
		len = mumble_proto__codec_version__get_packed_size(msg->payload.codecVersion);
		if (len > MAX_MSGSIZE) {
			Log_warn("Too big tx message. Discarding");
			break;
			}
		Msg_addPreamble(buffer, msg->messageType, len);
		mumble_proto__codec_version__pack(msg->payload.codecVersion, bufptr);
		break;

	default:
		Log_warn("Unsupported message %d", msg->messageType);
		return 0;
	}
	return len + 6;
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
	
	switch (messageType) {
	case Version:
		msg->payload.version = malloc(sizeof(MumbleProto__Version));
		mumble_proto__version__init(msg->payload.version);
		break;
	case UDPTunnel:
		msg->payload.UDPTunnel = malloc(sizeof(MumbleProto__UDPTunnel));
		mumble_proto__udptunnel__init(msg->payload.UDPTunnel);
		break;
	case Authenticate:
		msg->payload.authenticate = malloc(sizeof(MumbleProto__Authenticate));
		mumble_proto__authenticate__init(msg->payload.authenticate);
		break;
	case Ping:
		msg->payload.ping = malloc(sizeof(MumbleProto__Ping));
		mumble_proto__ping__init(msg->payload.ping);
		break;
	case Reject:
		msg->payload.reject = malloc(sizeof(MumbleProto__Reject));
		mumble_proto__reject__init(msg->payload.reject);
		break;
	case ServerSync:
		msg->payload.serverSync = malloc(sizeof(MumbleProto__ServerSync));
		mumble_proto__server_sync__init(msg->payload.serverSync);
		break;
	case TextMessage:
		msg->payload.textMessage = malloc(sizeof(MumbleProto__TextMessage));
		mumble_proto__text_message__init(msg->payload.textMessage);
		break;
	case PermissionDenied:
		msg->payload.permissionDenied = malloc(sizeof(MumbleProto__PermissionDenied));
		mumble_proto__permission_denied__init(msg->payload.permissionDenied);
		break;
	case CryptSetup:
		msg->payload.cryptSetup = malloc(sizeof(MumbleProto__CryptSetup));
		mumble_proto__crypt_setup__init(msg->payload.cryptSetup);
		break;
	case UserList:
		msg->payload.userList = malloc(sizeof(MumbleProto__UserList));
		mumble_proto__user_list__init(msg->payload.userList);
		break;
	case UserState:
		msg->payload.userState = malloc(sizeof(MumbleProto__UserState));
		mumble_proto__user_state__init(msg->payload.userState);
		break;
	case UserRemove:
		msg->payload.userRemove = malloc(sizeof(MumbleProto__UserRemove));
		mumble_proto__user_remove__init(msg->payload.userRemove);
		break;
	case VoiceTarget:
		msg->payload.voiceTarget = malloc(sizeof(MumbleProto__VoiceTarget));
		mumble_proto__voice_target__init(msg->payload.voiceTarget);
		break;
	case CodecVersion:
		msg->payload.codecVersion = malloc(sizeof(MumbleProto__CodecVersion));
		mumble_proto__codec_version__init(msg->payload.codecVersion);
		break;
	case ChannelState:
		msg->payload.channelState = malloc(sizeof(MumbleProto__ChannelState));
		mumble_proto__channel_state__init(msg->payload.channelState);
		break;

	default:
		Log_warn("Msg_create: Unsupported message %d", msg->messageType);
		break;
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

	/* XXX - add free for locally generated messages too */
	switch (msg->messageType) {
	case Version:
		if (msg->unpacked)
			mumble_proto__version__free_unpacked(msg->payload.version, NULL);
		else {
			free(msg->payload.version);
		}
		break;
	case UDPTunnel:
		if (msg->unpacked)
			mumble_proto__udptunnel__free_unpacked(msg->payload.UDPTunnel, NULL);
		else {
			free(msg->payload.UDPTunnel->packet.data);
			free(msg->payload.UDPTunnel);
		}
		break;
	case Authenticate:
		if (msg->unpacked)
			mumble_proto__authenticate__free_unpacked(msg->payload.authenticate, NULL);
		break;
	case Ping:
		if (msg->unpacked)
			mumble_proto__ping__free_unpacked(msg->payload.ping, NULL);
		else {
			free(msg->payload.ping);
		}
		break;
	case Reject:
		if (msg->unpacked)
			mumble_proto__reject__free_unpacked(msg->payload.reject, NULL);
		else {
			free(msg->payload.reject->reason);
			free(msg->payload.reject);
		}
		break;
	case ServerSync:
		if (msg->unpacked)
			mumble_proto__server_sync__free_unpacked(msg->payload.serverSync, NULL);
		else {
			free(msg->payload.serverSync->welcome_text);
			free(msg->payload.serverSync);
		}
		break;
	case TextMessage:
		if (msg->unpacked)
			mumble_proto__text_message__free_unpacked(msg->payload.textMessage, NULL);
		else {
			free(msg->payload.textMessage);
		}
		break;
	case PermissionDenied:
		if (msg->unpacked)
			mumble_proto__permission_denied__free_unpacked(msg->payload.permissionDenied, NULL);
		else {
			free(msg->payload.permissionDenied->reason);
			free(msg->payload.permissionDenied);
		}
		break;
	case CryptSetup:
		if (msg->unpacked)
			mumble_proto__crypt_setup__free_unpacked(msg->payload.cryptSetup, NULL);
		else {
			free(msg->payload.cryptSetup);
		}
		break;
	case UserList:
		if (msg->unpacked)
			mumble_proto__user_list__free_unpacked(msg->payload.userList, NULL);
		else {
			free(msg->payload.userList);
		}
		break;
	case UserState:
		if (msg->unpacked)
			mumble_proto__user_state__free_unpacked(msg->payload.userState, NULL);
		else {
			free(msg->payload.userState->name);
			free(msg->payload.userState);
		}
		break;
	case UserRemove:
		if (msg->unpacked)
			mumble_proto__user_remove__free_unpacked(msg->payload.userRemove, NULL);
		else {
			free(msg->payload.userRemove);
		}
		break;
	case VoiceTarget:
		if (msg->unpacked)
			mumble_proto__voice_target__free_unpacked(msg->payload.voiceTarget, NULL);
		else {
			free(msg->payload.voiceTarget);
		}
		break;
	case CodecVersion:
		if (msg->unpacked)
			mumble_proto__codec_version__free_unpacked(msg->payload.codecVersion, NULL);
		else {
			free(msg->payload.codecVersion);
		}
		break;
	case ChannelState:
		if (msg->unpacked)
			mumble_proto__channel_state__free_unpacked(msg->payload.channelState, NULL);
		else {
			if (msg->payload.channelState->description)
				free(msg->payload.channelState->description);
			free(msg->payload.channelState->name);
			free(msg->payload.channelState);
		}
		break;

	default:
		Log_warn("Msg_free: Unsupported message %d", msg->messageType);
		break;
	}
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
	uint8_t *msgData = &data[6];
	int messageType, msgLen;

	Msg_getPreamble(data, &messageType, &msgLen);

	Log_debug("Message type %d size %d", messageType, msgLen);
	dumpmsg(data, size);
	
	switch (messageType) {
	case Version:
	{
		msg = Msg_create(Version);
		msg->unpacked = true;
		msg->payload.version = mumble_proto__version__unpack(NULL, msgLen, msgData);
		break;
	}
	case UDPTunnel:
	{
		msg = Msg_create(UDPTunnel);
		msg->unpacked = true;
		msg->payload.UDPTunnel = mumble_proto__udptunnel__unpack(NULL, msgLen, msgData);
		break;
	}
	case Authenticate:
	{
		msg = Msg_create(Authenticate);
		msg->unpacked = true;
		msg->payload.authenticate = mumble_proto__authenticate__unpack(NULL, msgLen, msgData);
		break;
	}
	case Ping:
	{
		msg = Msg_create(Ping);
		msg->unpacked = true;
		msg->payload.ping = mumble_proto__ping__unpack(NULL, msgLen, msgData);
		break;
	}
	case Reject:
	{
		msg = Msg_create(Reject);
		msg->unpacked = true;
		msg->payload.reject = mumble_proto__reject__unpack(NULL, msgLen, msgData);
		break;
	}
	case ServerSync:
	{
		msg = Msg_create(ServerSync);
		msg->unpacked = true;
		msg->payload.serverSync = mumble_proto__server_sync__unpack(NULL, msgLen, msgData);
		break;
	}
	case TextMessage:
	{
		msg = Msg_create(TextMessage);
		msg->unpacked = true;
		msg->payload.textMessage = mumble_proto__text_message__unpack(NULL, msgLen, msgData);
		break;
	}
	case PermissionDenied:
	{
		msg = Msg_create(PermissionDenied);
		msg->unpacked = true;
		msg->payload.permissionDenied = mumble_proto__permission_denied__unpack(NULL, msgLen, msgData);
		break;
	}
	case CryptSetup:
	{
		msg = Msg_create(CryptSetup);
		msg->unpacked = true;
		msg->payload.cryptSetup = mumble_proto__crypt_setup__unpack(NULL, msgLen, msgData);
		break;
	}
	case UserList:
	{
		msg = Msg_create(UserList);
		msg->unpacked = true;
		msg->payload.userList = mumble_proto__user_list__unpack(NULL, msgLen, msgData);
		break;
	}
	case UserState:
	{
		msg = Msg_create(UserState);
		msg->unpacked = true;
		msg->payload.userState = mumble_proto__user_state__unpack(NULL, msgLen, msgData);
		break;
	}
	case VoiceTarget:
	{
		msg = Msg_create(VoiceTarget);
		msg->unpacked = true;
		msg->payload.voiceTarget = mumble_proto__voice_target__unpack(NULL, msgLen, msgData);
		break;
	}
	case CodecVersion:
	{
		msg = Msg_create(CodecVersion);
		msg->unpacked = true;
		msg->payload.codecVersion = mumble_proto__codec_version__unpack(NULL, msgLen, msgData);
		break;
	}

	default:
		Log_warn("Unsupported message %d", messageType);
		break;
	}
	return msg;
}
