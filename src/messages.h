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
#include <openssl/aes.h>
#include "list.h"
#include "types.h"

#define MAX_TEXT 256
#define SPEEX_DATA_SIZE 1024
#define MESSAGE_STREAM_VERSION 4

typedef enum {
	ServerReject,
	ServerAuthenticate,
	Speex,
	ServerSync,
	ServerJoin,
	ServerLeave,
	ServerBanList,
	PlayerMute,
	PlayerDeaf,
	PlayerKick,
	PlayerRename, /*10 */
	PlayerBan,
	PlayerMove,
	PlayerSelfMuteDeaf,
	ChannelAdd,
	ChannelRemove,
	ChannelMove,
	ChannelLink,
	ChannelRename,
	PermissionDenied,
	EditACL, /* 20 */
	QueryUsers,
	Ping,
	TextMessage,
	PlayerTexture,
	CryptSetup,
	CryptSync,
	PingStats,
	ContextAction,
	ContextAddAction,
	ChannelDescUpdate,
} messageType_t;


typedef enum {
	AltSpeak = 0x01,
	LoopBack = 0x02,
	EndSpeech = 0x04,
	FrameCountMask = 0x30
} speexflag_t;

typedef struct {
	int speexflag;
	int seq;
	uint8_t *data;
	int size;
} speex_t;

typedef struct {
	int maxBandwidth;
	char welcomeText[MAX_TEXT];
} serverSync_t;

typedef struct {
	char playerName[MAX_TEXT];
	int id;
} serverLeave_t;

typedef enum {
	None,
	WrongVersion,
	InvalidUsername,
	WrongUserPW,
	WrongServerPW,
	UsernameInUse,
	ServerFull
} rejectType_t;

typedef struct {
	char reason[MAX_TEXT];
	rejectType_t type;
} serverReject_t;

typedef struct {
	int version;
	char userName[MAX_TEXT];
	char password[MAX_TEXT];
} serverAuthenticate_t;

typedef struct {
	int id;
	int parentId;
	char name[MAX_TEXT];
} channelAdd_t;

typedef struct {
	int id;
	char desc[MAX_TEXT];
} channelDescUpdate_t;

typedef struct {
	char playerName[MAX_TEXT];
	int id;
} serverJoin_t;

typedef struct {
	int victim;
	int channel;
} playerMove_t;

typedef struct {
	uint8_t key[AES_BLOCK_SIZE];
	uint8_t clientNonce[AES_BLOCK_SIZE];
	uint8_t serverNonce[AES_BLOCK_SIZE];
} cryptSetup_t;

typedef struct {
	bool_t empty;
	uint8_t nonce[AES_BLOCK_SIZE];
} cryptSync_t;

typedef struct {
	uint64_t timestamp;
} ping_t;

typedef struct {
	uint64_t timestamp;
	uint32_t good;
	uint32_t late;
	uint32_t lost;
	uint32_t resync;
	double dUDPPingAvg;
	double dUDPPingVar;
	uint32_t UDPPackets;
	double dTCPPingAvg;
	double dTCPPingVar;
	uint32_t TCPPackets;
} pingStats_t;

typedef struct {
	char reason[MAX_TEXT];
} permissionDenied_t;

typedef struct {
	uint32_t victim;
	bool_t bMute;
} playerMute_t;

typedef struct {
	uint32_t victim;
	bool_t bDeaf;
} playerDeaf_t;

typedef struct {
	bool_t bMute;
	bool_t bDeaf;
} playerSelfMuteDeaf_t;

typedef struct {
	int32_t victim;
	int32_t channel;
	bool_t bTree;
	char message[MAX_TEXT];
} textMessage_t;

typedef union payload {
	speex_t speex;
	serverSync_t serverSync;
	serverJoin_t serverJoin;
	serverLeave_t serverLeave;
	serverReject_t serverReject;
	serverAuthenticate_t serverAuthenticate;
	cryptSetup_t cryptSetup;
	cryptSync_t cryptSync;
	pingStats_t pingStats;
	ping_t ping;
	channelAdd_t channelAdd;
	channelDescUpdate_t channelDescUpdate;
	playerMove_t playerMove;
	permissionDenied_t permissinDenied;
	playerMute_t playerMute;
	playerDeaf_t playerDeaf;
	playerSelfMuteDeaf_t playerSelfMuteDeaf;
	permissionDenied_t permissionDenied;
	textMessage_t textMessage;
} payload_t;

typedef struct message {
	messageType_t messageType;
	uint32_t sessionId;
	int refcount;
	struct dlist node;
	payload_t payload;
} message_t;



int Msg_messageToNetwork(message_t *msg, uint8_t *buffer, int bufsize);
message_t *Msg_networkToMessage(uint8_t *data, int size);
void Msg_free(message_t *msg);
void Msg_inc_ref(message_t *msg);

message_t *Msg_create(messageType_t messageType);

#endif
