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
#ifndef MESSAGES_H_89768
#define MESSAGES_H_89768

#include <stdint.h>
#include "Mumble.pb-c.h"
#include "list.h"
#include "types.h"

#define MAX_TEXT 256
#define MESSAGE_STREAM_VERSION 4

typedef enum {
	Version,
	UDPTunnel,
	Authenticate,
	Ping,
	Reject,
	ServerSync,
	ChannelRemove,
	ChannelState,
	UserRemove,
	UserState,
	BanList,
	TextMessage,
	PermissionDenied,
	ACL,
	QueryUsers,
	CryptSetup,
	ContextActionAdd,
	ContextAction,
	UserList,
	VoiceTarget,
	PermissionQuery,
	CodecVersion,
} messageType_t;

typedef enum {
	UDPVoiceCELTAlpha,
	UDPPing,
	UDPVoiceSpeex,
	UDPVoiceCELTBeta,
} UDPMessageType_t;


typedef union payload {
	struct  _MumbleProto__Version *version;
	struct  _MumbleProto__UDPTunnel *UDPTunnel;
	struct  _MumbleProto__Authenticate *authenticate;
	struct  _MumbleProto__Ping *ping;
	struct  _MumbleProto__Reject *reject;
	struct  _MumbleProto__ServerSync *serverSync;
	struct  _MumbleProto__ChannelRemove *channelRemove;
	struct  _MumbleProto__ChannelState *channelState;
	struct  _MumbleProto__UserRemove *userRemove;
	struct  _MumbleProto__UserState *userState;
	/* BanEntry not supported */
	/* BanList not supported */
	struct  _MumbleProto__TextMessage *textMessage;
	struct  _MumbleProto__PermissionDenied *permissionDenied;
	/* ChanACL not supported */
	/* ACL not supported */
	struct  _MumbleProto__QueryUsers *queryUsers;
	struct  _MumbleProto__CryptSetup *cryptSetup;
	/* ContextActionAdd not supported */
	/* ContextAction not supported */
	struct  _MumbleProto__UserList__User *userList_user;
	struct  _MumbleProto__UserList *userList;
	struct  _MumbleProto__VoiceTarget__Target *voiceTarget_target;
	struct  _MumbleProto__VoiceTarget *voiceTarget;
	struct  _MumbleProto__PermissionQuery *permissionQuery;
	struct  _MumbleProto__CodecVersion *codecVersion;
} payload_t;

typedef struct message {
	messageType_t messageType;
	int refcount;
	struct dlist node;
	bool_t unpacked;
	payload_t payload;
} message_t;



int Msg_messageToNetwork(message_t *msg, uint8_t *buffer);
message_t *Msg_networkToMessage(uint8_t *data, int size);
void Msg_free(message_t *msg);
void Msg_inc_ref(message_t *msg);

message_t *Msg_create(messageType_t messageType);

#endif
