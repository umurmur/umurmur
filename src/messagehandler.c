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

static void sendServerReject(client_t *client, const char *reason, MumbleProto__Reject__RejectType type)
{
	message_t *msg = Msg_create(Reject);
	msg->payload.reject->reason = strdup(reason);
	msg->payload.reject->type = type;
	msg->payload.reject->has_type = true;
	Client_send_message(client, msg);
}

static void sendPermissionDenied(client_t *client, const char *reason)
{
	message_t *msg = Msg_create(PermissionDenied);
	msg->payload.permissionDenied->has_type = true;
	msg->payload.permissionDenied->type = MUMBLE_PROTO__PERMISSION_DENIED__DENY_TYPE__Text;
	msg->payload.permissionDenied->reason = strdup(reason);
	Client_send_message(client, msg);
}

void Mh_handle_message(client_t *client, message_t *msg)
{
	message_t *sendmsg;
	channel_t *ch_itr = NULL;
	client_t *client_itr;
	
	switch (msg->messageType) {
	case Authenticate:
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
				
		Log_debug("Authenticate message received");
		Log_debug("Username: %s", msg->payload.authenticate->username);
		
		client->authenticated = true;
		
		client_itr = NULL;
		while (Client_iterate(&client_itr) != NULL) {
			if (!IS_AUTH(client_itr))
				continue;
			if (strncmp(client_itr->playerName, msg->payload.authenticate->username, MAX_TEXT) == 0) {
				char buf[64];
				sprintf(buf, "Username already in use");
				Log_debug("Username already in use");
				sendServerReject(client, buf, MUMBLE_PROTO__REJECT__REJECT_TYPE__UsernameInUse);
				goto disconnect;
			}				
		}
		if (msg->payload.authenticate->password && strncmp(getStrConf(PASSPHRASE), msg->payload.authenticate->password, MAX_TEXT) != 0) {
			char buf[64];
			sprintf(buf, "Wrong server password");
			Log_debug("Wrong server password: %s", msg->payload.authenticate->password);
			sendServerReject(client, buf, MUMBLE_PROTO__REJECT__REJECT_TYPE__WrongServerPW);
			goto disconnect;
		}				
		if (strlen(msg->payload.authenticate->username) == 0 ||
			strlen(msg->payload.authenticate->username) >= MAX_TEXT) { /* XXX - other invalid names? */
			char buf[64];
			sprintf(buf, "Invalid username");
			Log_debug("Invalid username");
			sendServerReject(client, buf, MUMBLE_PROTO__REJECT__REJECT_TYPE__InvalidUsername);
			goto disconnect;
		}				

		if (Client_count() >= getIntConf(MAX_CLIENTS)) {
			char buf[64];
			sprintf(buf, "Server is full (max %d users)", getIntConf(MAX_CLIENTS));
			sendServerReject(client, buf, MUMBLE_PROTO__REJECT__REJECT_TYPE__ServerFull);
			goto disconnect;
		}
		
		/* Name & password */
		strncpy(client->playerName, msg->payload.authenticate->username, MAX_TEXT);
		client->playerId = client->sessionId;
				
		
		/* Setup UDP encryption */
		CryptState_init(&client->cryptState);
		CryptState_genKey(&client->cryptState);
		sendmsg = Msg_create(CryptSetup);
		sendmsg->payload.cryptSetup->has_key = true;
		sendmsg->payload.cryptSetup->key.data = client->cryptState.raw_key;
		sendmsg->payload.cryptSetup->key.len = AES_BLOCK_SIZE;
		sendmsg->payload.cryptSetup->has_server_nonce = true;
		sendmsg->payload.cryptSetup->server_nonce.data = client->cryptState.encrypt_iv;
		sendmsg->payload.cryptSetup->server_nonce.len = AES_BLOCK_SIZE;
		sendmsg->payload.cryptSetup->has_client_nonce = true;
		sendmsg->payload.cryptSetup->client_nonce.data = client->cryptState.decrypt_iv;
		sendmsg->payload.cryptSetup->client_nonce.len = AES_BLOCK_SIZE;
		Client_send_message(client, sendmsg);

		/* Channel stuff */
		Chan_playerJoin(defaultChan, client); /* Join default channel */

		/* Codec version */
		if (msg->payload.authenticate->n_celt_versions > MAX_CODECS)
			Log_warn("Client has more than %d CELT codecs. Ignoring %d codecs",
					 MAX_CODECS, msg->payload.authenticate->n_celt_versions - MAX_CODECS);
		if (msg->payload.authenticate->n_celt_versions > 0) {
			int i;
			client->codec_count = msg->payload.authenticate->n_celt_versions > MAX_CODECS ?
				MAX_CODECS : msg->payload.authenticate->n_celt_versions;
			for (i = 0; i < client->codec_count; i++)
				client->codecs[i] = msg->payload.authenticate->celt_versions[i];
		} else {
			client->codecs[0] = (int32_t)0x8000000a;
			client->codec_count = 1;
		}
		recheckCodecVersions();
			
		/* Iterate channels and send channel info */
		ch_itr = NULL;
		Chan_iterate(&ch_itr);
		do {
			sendmsg = Msg_create(ChannelState);
			sendmsg->payload.channelState->has_channel_id = true;
			sendmsg->payload.channelState->channel_id = ch_itr->id;
			if (ch_itr->id != 0) {
				sendmsg->payload.channelState->has_parent = true;
				sendmsg->payload.channelState->parent = ch_itr->parent->id;
			}
			sendmsg->payload.channelState->name = strdup(ch_itr->name);
			if (strlen(ch_itr->desc) > 0) {
				sendmsg->payload.channelState->description = strdup(ch_itr->desc);
			}
			Log_debug("Send channel info: %s", sendmsg->payload.channelState->name);
			Client_send_message(client, sendmsg);
			
			Chan_iterate(&ch_itr);
		} while (ch_itr != NULL);

		/* Not supporting channel links yet */
		
		/* Send user state for connecting user to other users */
		sendmsg = Msg_create(UserState);
		sendmsg->payload.userState->has_session = true;
		sendmsg->payload.userState->session = client->sessionId;
		sendmsg->payload.userState->has_user_id = true;
		sendmsg->payload.userState->user_id = client->playerId;
		sendmsg->payload.userState->name = strdup(client->playerName);
		sendmsg->payload.userState->has_channel_id = true;
		sendmsg->payload.userState->channel_id = ((channel_t *)client->channel)->id;
		
		Client_send_message_except(client, sendmsg);

		client_itr = NULL;
		while (Client_iterate(&client_itr) != NULL) {
			if (!IS_AUTH(client_itr))
				continue;
			sendmsg = Msg_create(UserState);
			sendmsg->payload.userState->has_session = true;
			sendmsg->payload.userState->session = client_itr->sessionId;
			sendmsg->payload.userState->name = strdup(client_itr->playerName);
			sendmsg->payload.userState->has_channel_id = true;
			sendmsg->payload.userState->channel_id = ((channel_t *)client_itr->channel)->id;

			/* XXX - check if self_* is correct */
			if (client_itr->deaf) {
				sendmsg->payload.userState->has_self_deaf = true;
				sendmsg->payload.userState->self_deaf = true;
			}
			if (client_itr->mute) {
				sendmsg->payload.userState->has_self_mute = true;
				sendmsg->payload.userState->self_mute = true;
			}
			Client_send_message(client, sendmsg);
		}

		/* Sync message */
		sendmsg = Msg_create(ServerSync);
		sendmsg->payload.serverSync->has_session = true;
		sendmsg->payload.serverSync->session = client->sessionId;
		sendmsg->payload.serverSync->welcome_text = strdup(getStrConf(WELCOMETEXT));
		sendmsg->payload.serverSync->has_max_bandwidth = true;
		sendmsg->payload.serverSync->max_bandwidth = getIntConf(MAX_BANDWIDTH);
		sendmsg->payload.serverSync->has_allow_html = true;
		sendmsg->payload.serverSync->allow_html = false; /* Support this? */
		Client_send_message(client, sendmsg);
		
		Log_info("User %s authenticated", client->playerName);
		break;
		
	case Ping:
	{
		uint64_t timestamp;
		if (msg->payload.ping->has_good)
			client->cryptState.uiRemoteGood = msg->payload.ping->good;
		if (msg->payload.ping->has_late)
			client->cryptState.uiRemoteLate = msg->payload.ping->late;
		if (msg->payload.ping->has_lost)
			client->cryptState.uiRemoteLost = msg->payload.ping->lost;
		if (msg->payload.ping->has_resync)
			client->cryptState.uiRemoteResync = msg->payload.ping->resync;

		Log_debug("Ping <-: %d %d %d %d",
				  client->cryptState.uiRemoteGood, client->cryptState.uiRemoteLate,
				  client->cryptState.uiRemoteLost, client->cryptState.uiRemoteResync
			);
		
		/* Ignoring the double values since they don't seem to be used */
		
		sendmsg = Msg_create(Ping);
		timestamp = msg->payload.ping->timestamp;

		sendmsg->payload.ping->timestamp = timestamp;
		
		sendmsg->payload.ping->good = client->cryptState.uiGood;
		sendmsg->payload.ping->has_good = true;
		sendmsg->payload.ping->late = client->cryptState.uiLate;
		sendmsg->payload.ping->has_late = true;
		sendmsg->payload.ping->lost = client->cryptState.uiLost;
		sendmsg->payload.ping->has_lost = true;
		sendmsg->payload.ping->resync = client->cryptState.uiResync;
		sendmsg->payload.ping->has_resync = true;

		Client_send_message(client, sendmsg);
		Log_debug("Ping ->: %d %d %d %d",
				  client->cryptState.uiGood, client->cryptState.uiLate,
				  client->cryptState.uiLost, client->cryptState.uiResync);

		break;
	}
	case CryptSetup:
		Log_debug("Voice channel crypt resync requested");
		if (!msg->payload.cryptSetup->has_client_nonce) {
			sendmsg = Msg_create(CryptSetup);
			sendmsg->payload.cryptSetup->has_server_nonce = true;
			sendmsg->payload.cryptSetup->server_nonce.data = client->cryptState.decrypt_iv;
			sendmsg->payload.cryptSetup->server_nonce.len = AES_BLOCK_SIZE;
			Client_send_message(client, sendmsg);
		} else {
			memcpy(client->cryptState.decrypt_iv, msg->payload.cryptSetup->client_nonce.data, AES_BLOCK_SIZE);
			client->cryptState.uiResync++;
		}
		break;
	case UserState:
		/* Only allow state changes for for the self user */
		if (msg->payload.userState->has_session &&
			msg->payload.userState->session != client->sessionId) {
			sendPermissionDenied(client, "Permission denied");
			break;
		}
		if (msg->payload.userState->has_user_id || msg->payload.userState->has_mute ||
			msg->payload.userState->has_deaf || msg->payload.userState->has_suppress ||
			msg->payload.userState->has_texture) {
			
			sendPermissionDenied(client, "Not supported by uMurmur");
			break;
		}
		if (msg->payload.userState->has_self_deaf) {
			client->deaf = msg->payload.userState->self_deaf;
		}
		if (msg->payload.userState->has_self_mute) {
			client->mute = msg->payload.userState->self_mute;			
		}
		if (msg->payload.userState->has_channel_id) {
			Chan_playerJoin_id(msg->payload.userState->channel_id, client);
		}
		/* Re-use message */
		Msg_inc_ref(msg);
		msg->payload.userState->has_actor = true;
		msg->payload.userState->actor = client->sessionId;
		Client_send_message_except(NULL, msg);
		break;
		
	case TextMessage:
		msg->payload.textMessage->has_actor = true;
		msg->payload.textMessage->actor = client->sessionId;

		/* XXX - Allow HTML stuff? */
		
		if (msg->payload.textMessage->n_tree_id > 0) {
			sendPermissionDenied(client, "Tree message not supported");
			break;
		}
			
		if (msg->payload.textMessage->n_channel_id > 0) { /* To channel */
			int i;
			channel_t *ch_itr;
			for (i = 0; i < msg->payload.textMessage->n_channel_id; i++) {
				ch_itr = NULL;
				do {
					Chan_iterate(&ch_itr);
				} while (ch_itr != NULL && ch_itr->id != msg->payload.textMessage->channel_id[i]);
				if (ch_itr == NULL)
					Log_warn("Channel id %d not found - ignoring.", msg->payload.textMessage->channel_id[i]);
				else {
					struct dlist *itr;
					list_iterate(itr, &ch_itr->clients) {
						client_t *c;
						c = list_get_entry(itr, client_t, chan_node);
						if (c != client && !c->deaf) {
							Msg_inc_ref(msg);
							Client_send_message(c, msg);
							Log_debug("Text message to session ID %d", c->sessionId);
						}
					}
				}
			} /* for */
		}
		if (msg->payload.textMessage->n_session > 0) { /* To user */
			int i;
			client_t *itr;
			for (i = 0; i < msg->payload.textMessage->n_session; i++) {
				itr = NULL;
				while (Client_iterate(&itr) != NULL) {
					if (!IS_AUTH(itr))
						continue;
					if (itr->playerId == msg->payload.textMessage->session[i]) {
						if (!itr->deaf) {
							Msg_inc_ref(msg);
							Client_send_message(itr, msg);
						}
						break;
					}
				}
				if (itr == NULL)
					Log_warn("TextMessage: Session ID %d not found", msg->payload.textMessage->session[i]);
			} /* for */
		}
		break;

	case VoiceTarget:
		/* XXX -TODO */
		break;

	case Version:
		Log_debug("Version message received");
		if (msg->payload.version->has_version) {
			client->version = msg->payload.version->version;
			Log_debug("Client version 0x%x", client->version);
		}
		if (msg->payload.version->release) {
			if (client->release) free(client->release);
			client->release = strdup(msg->payload.version->release);
			Log_debug("Client release %s", client->release);
		}
		if (msg->payload.version->os) {
			if (client->os) free(client->os);			
			client->os = strdup(msg->payload.version->os);
			Log_debug("Client OS %s", client->os);
		}
		break;
	case CodecVersion:
		Msg_inc_ref(msg); /* Re-use message */

		/* XXX - fill in version */
		
		Client_send_message(client, msg);
		break;
	case UDPTunnel:
		Client_voiceMsg(client, msg->payload.UDPTunnel->packet.data, msg->payload.UDPTunnel->packet.len);
	    break;
		/* Permission denied for all these messages. Not implemented. */
	case ChannelRemove:
	case ChannelState:
	case ContextAction:
	case ContextActionAdd:
	case ACL:
	case BanList:
		sendPermissionDenied(client, "Not supported by uMurmur");
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

