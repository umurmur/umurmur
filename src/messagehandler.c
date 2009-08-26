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
#include <string.h>
#include <openssl/aes.h>

#include "log.h"
#include "list.h"
#include "client.h"
#include "messages.h"
#include "crypt.h"
#include "channel.h"
#include "conf.h"

extern channel_t *defaultChan;

static void sendServerReject(client_t *client, const char *reason, rejectType_t type)
{
	message_t *msg = Msg_create(ServerReject);
	msg->sessionId = client->sessionId;
	strcpy(msg->payload.serverReject.reason, reason);
	msg->payload.serverReject.type = type;
	Client_send_message(client, msg);
}

static void sendPermissionDenied(client_t *client, const char *reason)
{
	message_t *msg = Msg_create(PermissionDenied);
	msg->sessionId = client->sessionId;
	strncpy(msg->payload.permissionDenied.reason, reason, MAX_TEXT);
	Client_send_message(client, msg);
}

void Mh_handle_message(client_t *client, message_t *msg)
{
	message_t *sendmsg;
	channel_t *ch_itr = NULL;
	client_t *client_itr;
	
	switch (msg->messageType) {
	case ServerAuthenticate:
		/*
		 * 1. Check stuff, Serverreject if not ok
		 * 2. Setup UDP encryption -> MessageCryptSetup
		 * 3. (Enter channel)
		 * 4. MessageChannelAdd + MessageChannelDescUpdate for all channels
		 * 5. (MessageChannelLink)
		 * 6. MessageServerJoin
		 * 7. MessagePlayerMove
		 * 8. MessageServerJoin for all connected users
		 * 9. PlayerDeaf/PlayerMute/PlayerSelfMuteDeaf for all users it applies to
		 * 10. MessageServerSync
		 */
		if (msg->payload.serverAuthenticate.version != MESSAGE_STREAM_VERSION) {
			char buf[64];
			sprintf(buf, "Wrong version of mumble protocol (client: %d, server: %d)",
					msg->payload.serverAuthenticate.version, MESSAGE_STREAM_VERSION);
			sendServerReject(client, buf, WrongVersion);
			goto disconnect;
		}
				
		client_itr = NULL;
		while (Client_iterate(&client_itr) != NULL) {
			if (!IS_AUTH(client_itr))
				continue;
			if (strncmp(client_itr->playerName, msg->payload.serverAuthenticate.userName, MAX_TEXT) == 0) {
				char buf[64];
				sprintf(buf, "Username already in use");
				sendServerReject(client, buf, UsernameInUse);
				goto disconnect;
			}				
		}
		
		if (strncmp(getStrConf(PASSPHRASE), msg->payload.serverAuthenticate.password, MAX_TEXT) != 0) {
			char buf[64];
			sprintf(buf, "Wrong server password");
			sendServerReject(client, buf, WrongServerPW);
			goto disconnect;
		}				

		if (strlen(msg->payload.serverAuthenticate.userName) == 0) { /* XXX - other invalid names? */
			char buf[64];
			sprintf(buf, "Invalid username");
			sendServerReject(client, buf, InvalidUsername);
			goto disconnect;
		}				

		if (Client_count() >= getIntConf(MAX_CLIENTS)) {
			char buf[64];
			sprintf(buf, "Server is full (max %d users)", getIntConf(MAX_CLIENTS));
			sendServerReject(client, buf, ServerFull);
			goto disconnect;
		}
		
		/* Name & password */
		strncpy(client->playerName, msg->payload.serverAuthenticate.userName, MAX_TEXT);
		client->playerId = client->sessionId;

		client->authenticated = true;
		
		/* XXX - Kick ghost */
		
		/* Setup UDP encryption */
		CryptState_init(&client->cryptState);
		CryptState_genKey(&client->cryptState);
		sendmsg = Msg_create(CryptSetup);
		sendmsg->sessionId = client->sessionId;
		memcpy(sendmsg->payload.cryptSetup.key, client->cryptState.raw_key, AES_BLOCK_SIZE);
		memcpy(sendmsg->payload.cryptSetup.serverNonce, client->cryptState.encrypt_iv, AES_BLOCK_SIZE);
		memcpy(sendmsg->payload.cryptSetup.clientNonce, client->cryptState.decrypt_iv, AES_BLOCK_SIZE);
		Client_send_message(client, sendmsg);

		/* Channel stuff */
		Chan_playerJoin(defaultChan, client); /* Join default channel */

		/* Iterate channels and send channel info */
		ch_itr = NULL;
		Chan_iterate(&ch_itr);
		do {
			sendmsg = Msg_create(ChannelAdd);
			sendmsg->sessionId = 0;
			sendmsg->payload.channelAdd.id = ch_itr->id;
			if (ch_itr->id == 0)
				sendmsg->payload.channelAdd.parentId = -1;
			else
				sendmsg->payload.channelAdd.parentId = ch_itr->parent->id;
			strcpy(sendmsg->payload.channelAdd.name, ch_itr->name);
			Client_send_message(client, sendmsg);
			
			sendmsg = Msg_create(ChannelDescUpdate);
			sendmsg->sessionId = 0;
			sendmsg->payload.channelDescUpdate.id = ch_itr->id;
			strcpy(sendmsg->payload.channelDescUpdate.desc, ch_itr->desc);
			Client_send_message(client, sendmsg);
			
			Chan_iterate(&ch_itr);
		} while (ch_itr != NULL);

		/* Not supporting channel link for now */

		/* Server join for connecting user */
		sendmsg = Msg_create(ServerJoin);
		sendmsg->sessionId = client->sessionId;
		sendmsg->payload.serverJoin.id = client->playerId;
		strcpy(sendmsg->payload.serverJoin.playerName, client->playerName);
		Client_send_message_except(client, sendmsg);

		/* Player move for connecting user */
		if (((channel_t *)client->channel)->id != 0) {
			sendmsg = Msg_create(PlayerMove);
			sendmsg->sessionId = client->sessionId;
			sendmsg->payload.playerMove.victim = client->playerId;
			sendmsg->payload.playerMove.channel = ((channel_t *)client->channel)->id;
			Client_send_message_except(client, sendmsg);
		}
		client_itr = NULL;
		while (Client_iterate(&client_itr) != NULL) {
			if (!IS_AUTH(client_itr))
				continue;
			sendmsg = Msg_create(ServerJoin);
			sendmsg->sessionId = client_itr->sessionId;
			sendmsg->payload.serverJoin.id = client_itr->playerId;
			strncpy(sendmsg->payload.serverJoin.playerName, client_itr->playerName, MAX_TEXT);
			Client_send_message(client, sendmsg);
			
			sendmsg = Msg_create(PlayerMove);
			sendmsg->sessionId = client_itr->sessionId;
			sendmsg->payload.playerMove.victim = client_itr->playerId;
			sendmsg->payload.playerMove.channel = ((channel_t *)client_itr->channel)->id;
			Client_send_message(client, sendmsg);
		}
		
		sendmsg = Msg_create(ServerSync);
		sendmsg->sessionId = client->sessionId;
		strcpy(sendmsg->payload.serverSync.welcomeText, getStrConf(WELCOMETEXT));
		sendmsg->payload.serverSync.maxBandwidth = getIntConf(MAX_BANDWIDTH);
		Client_send_message(client, sendmsg);
		
		Log_info("Player %s authenticated", client->playerName);
		
		break;
		
	case PingStats:
		client->cryptState.uiRemoteGood = msg->payload.pingStats.good;
		client->cryptState.uiRemoteLate = msg->payload.pingStats.late;
		client->cryptState.uiRemoteLost = msg->payload.pingStats.lost;
		client->cryptState.uiRemoteResync = msg->payload.pingStats.resync;

		Log_debug("Pingstats <-: %d %d %d %d",
				  client->cryptState.uiRemoteGood, client->cryptState.uiRemoteLate,
				  client->cryptState.uiRemoteLost, client->cryptState.uiRemoteResync);
		
		/* Ignoring the double values since they don't seem to be used */
		sendmsg = Msg_create(PingStats);
		sendmsg->sessionId = client->sessionId;
		sendmsg->payload.pingStats.timestamp = msg->payload.pingStats.timestamp;
		
		sendmsg->payload.pingStats.good = client->cryptState.uiGood;
		sendmsg->payload.pingStats.late = client->cryptState.uiLate;
		sendmsg->payload.pingStats.lost = client->cryptState.uiLost;
		sendmsg->payload.pingStats.resync = client->cryptState.uiResync;
		
		Client_send_message(client, sendmsg);
		Log_debug("Pingstats ->: %d %d %d %d",
				  client->cryptState.uiGood, client->cryptState.uiLate,
				  client->cryptState.uiLost, client->cryptState.uiResync);

		break;
	case Ping:
		sendmsg = Msg_create(Ping);
		sendmsg->sessionId = client->sessionId;
		sendmsg->payload.ping.timestamp = msg->payload.ping.timestamp;
		Client_send_message(client, sendmsg);
		break;
	case CryptSync:
		Log_debug("Voice channel crypt resync requested");
		if (msg->payload.cryptSync.empty) {
			sendmsg = Msg_create(CryptSync);
			sendmsg->sessionId = msg->sessionId;
			sendmsg->payload.cryptSync.empty = false;
			memcpy(sendmsg->payload.cryptSync.nonce, client->cryptState.decrypt_iv, AES_BLOCK_SIZE);
			Client_send_message(client, sendmsg);
		} else {
			memcpy(client->cryptState.decrypt_iv, msg->payload.cryptSync.nonce, AES_BLOCK_SIZE);
			client->cryptState.uiResync++;
		}
		break;
	case PlayerMute:
		if (msg->payload.playerMute.victim != client->playerId) {
			sendPermissionDenied(client, "Permission denied");
		} else {
			Log_debug("Player ID %d muted", msg->payload.playerMute.victim);
			client->mute = msg->payload.playerMute.bMute;			
		}
		break;
	case PlayerDeaf:
		if (msg->payload.playerDeaf.victim != client->playerId) {
			sendPermissionDenied(client, "Permission denied");
		} else {
			Log_debug("Player ID %d deaf", msg->payload.playerDeaf.victim);
			client->deaf = msg->payload.playerDeaf.bDeaf;
		}
		break;
	case TextMessage:
		if (msg->payload.textMessage.bTree)
			sendPermissionDenied(client, "Tree message not supported");
		else if (msg->payload.textMessage.channel != -1) { /* To channel */
			channel_t *ch_itr = NULL;
			do {
				Chan_iterate(&ch_itr);
			} while (ch_itr != NULL && ch_itr->id != msg->payload.textMessage.channel);
			if (ch_itr == NULL)
				Log_warn("Channel id %d not found - ignoring.", msg->payload.textMessage.channel);
			else {
				struct dlist *itr;
				list_iterate(itr, &ch_itr->clients) {
					client_t *c;
					c = list_get_entry(itr, client_t, chan_node);
					if (c != client && !c->deaf) {
						Msg_inc_ref(msg);
						Client_send_message(c, msg);
						Log_debug("Text message to player ID %d", c->playerId);
					}
				}
			}
		} else { /* To player */
			client_t *itr = NULL;
			while (Client_iterate(&itr) != NULL) {
				if (!IS_AUTH(itr))
					continue;
				if (itr->playerId == msg->payload.textMessage.victim) {
					if (!itr->deaf) {
						Msg_inc_ref(msg);
						Client_send_message(itr, msg);
					}
					break;
				}
			}
			if (itr == NULL)
				Log_warn("TextMessage: Player ID %d not found", msg->payload.textMessage.victim);
		}
		break;
	case PlayerSelfMuteDeaf:
		client->deaf = msg->payload.playerSelfMuteDeaf.bDeaf;
		client->mute = msg->payload.playerSelfMuteDeaf.bMute;
		Log_debug("Player ID %d %s and %s", client->playerId, client->deaf ? "deaf": "not deaf",
				  client->mute ? "mute" : "not mute");
		break;
	case PlayerMove:
		Msg_inc_ref(msg); /* Re-use message */
		Client_send_message_except(NULL, msg);
		Chan_playerJoin_id(msg->payload.playerMove.channel, client);		
		break;

		/* Permission denied for all these messages. Not implemented. */
	case PlayerRename:
	case ChannelAdd:
	case ChannelDescUpdate:
	case ContextAction:
	case ContextAddAction:
	case ServerBanList:
	case PlayerKick:
	case PlayerBan:
	case ChannelRemove:
	case ChannelMove:
	case ChannelLink:
	case ChannelRename:
	case EditACL:
		sendPermissionDenied(client, "Not supported by uMurmur");
		break;
		
	case PlayerTexture: /* Ignore */
		break;
		
	default:
		Log_warn("Message %d not handled", msg->messageType);
		break;
	}
	Msg_free(msg);
	return;
disconnect:
	Msg_free(msg);
	Client_close(client);
}
