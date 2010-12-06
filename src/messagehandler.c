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
#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "list.h"
#include "client.h"
#include "messages.h"
#include "messagehandler.h"
#include "crypt.h"
#include "channel.h"
#include "conf.h"
#include "voicetarget.h"

#define MAX_TEXT 512

extern channel_t *defaultChan;
extern int iCodecAlpha, iCodecBeta;
extern bool_t bPreferAlpha;

static void sendServerReject(client_t *client, const char *reason, MumbleProto__Reject__RejectType type)
{
	message_t *msg = Msg_create(Reject);
	msg->payload.reject->reason = strdup(reason);
	msg->payload.reject->type = type;
	msg->payload.reject->has_type = true;
	Client_send_message(client, msg);
	
	Log_info_client(client, "Server reject reason: %s", reason);
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
	message_t *sendmsg = NULL;
	channel_t *ch_itr = NULL;
	client_t *client_itr;

	if (!client->authenticated && !(msg->messageType == Authenticate ||
									msg->messageType == Version)) {
		goto out;
	}
	
	switch (msg->messageType) {
	case UDPTunnel:
	case Ping:
	case CryptSetup:
	case VoiceTarget:
	case UserStats:
	case PermissionQuery:
		break;
	default:
		Timer_restart(&client->idleTime);
	}
	
	switch (msg->messageType) {
	case Authenticate:
		Log_debug("Authenticate message received");
		
		if (IS_AUTH(client) || !msg->payload.authenticate->username) {
			/* Authenticate message might be sent when a token is set by the user.*/
			if (msg->payload.authenticate->n_tokens > 0) {
				Log_debug("Tokens in auth message from %s", client->username);
			}
			break;
		}
		
		client->authenticated = true;
		
		client_itr = NULL;
		while (Client_iterate(&client_itr) != NULL) {
			if (!IS_AUTH(client_itr))
				continue;
			if (client_itr->username && strncmp(client_itr->username, msg->payload.authenticate->username, MAX_TEXT) == 0) {
				char buf[64];
				sprintf(buf, "Username already in use");
				Log_debug("Username already in use");
				sendServerReject(client, buf, MUMBLE_PROTO__REJECT__REJECT_TYPE__UsernameInUse);
				goto disconnect;
			}				
		}
		if (strlen(getStrConf(PASSPHRASE)) > 0) {
			if (!msg->payload.authenticate->password ||
				(msg->payload.authenticate->password &&
				 strncmp(getStrConf(PASSPHRASE), msg->payload.authenticate->password, MAX_TEXT) != 0)) {
				char buf[64];
				sprintf(buf, "Wrong server password");
				sendServerReject(client, buf, MUMBLE_PROTO__REJECT__REJECT_TYPE__WrongServerPW);
				Log_debug("Wrong server password: '%s'", msg->payload.authenticate->password != NULL ?
						  msg->payload.authenticate->password : "(null)");
				goto disconnect;
			}
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
		client->username = strdup(msg->payload.authenticate->username);				
		
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
		Chan_userJoin(defaultChan, client); /* Join default channel */

		/* Codec version */		
		Log_debug("Client %d has %d CELT codecs", client->sessionId,
				  msg->payload.authenticate->n_celt_versions);
		if (msg->payload.authenticate->n_celt_versions > 0) {
			int i;
			codec_t *codec_itr;
			client->codec_count = msg->payload.authenticate->n_celt_versions;
			
			for (i = 0; i < client->codec_count; i++)
			Client_codec_add(client, msg->payload.authenticate->celt_versions[i]);
			codec_itr = NULL;
			while (Client_codec_iterate(client, &codec_itr) != NULL)
				Log_debug("Client %d CELT codec ver 0x%x", client->sessionId, codec_itr->codec);
				
		} else {
			Client_codec_add(client, (int32_t)0x8000000a);
			client->codec_count = 1;
		}
		
		recheckCodecVersions();
		
		sendmsg = Msg_create(CodecVersion);
		sendmsg->payload.codecVersion->alpha = iCodecAlpha;
		sendmsg->payload.codecVersion->beta = iCodecBeta;
		sendmsg->payload.codecVersion->prefer_alpha = bPreferAlpha;
		Client_send_message(client, sendmsg);
		
		/* Iterate channels and send channel info */
		ch_itr = NULL;
		while (Chan_iterate(&ch_itr) != NULL) {
			sendmsg = Msg_create(ChannelState);
			sendmsg->payload.channelState->has_channel_id = true;
			sendmsg->payload.channelState->channel_id = ch_itr->id;
			if (ch_itr->id != 0) {
				sendmsg->payload.channelState->has_parent = true;
				sendmsg->payload.channelState->parent = ch_itr->parent->id;
			}
			sendmsg->payload.channelState->name = strdup(ch_itr->name);
			if (ch_itr->desc)
				sendmsg->payload.channelState->description = strdup(ch_itr->desc);
			Log_debug("Send channel info: %s", sendmsg->payload.channelState->name);
			Client_send_message(client, sendmsg);			
		}

		/* Iterate channels and send channel links info */
		ch_itr = NULL;
		while (Chan_iterate(&ch_itr) != NULL) {
			if (ch_itr->linkcount > 0) { /* Has links */
				uint32_t *links;
				int i = 0;
				struct dlist *itr;
				
				sendmsg = Msg_create(ChannelState);
				sendmsg->payload.channelState->has_channel_id = true;
				sendmsg->payload.channelState->channel_id = ch_itr->id;
				sendmsg->payload.channelState->n_links = ch_itr->linkcount;
				
				links = (uint32_t *)malloc(ch_itr->linkcount * sizeof(uint32_t));
				list_iterate(itr, &ch_itr->channel_links) { /* Iterate links */
					channel_t *ch;
					ch = list_get_entry(itr, channel_t, link_node);
					links[i++] = ch->id;
				}
				sendmsg->payload.channelState->links = links;
				Client_send_message(client, sendmsg);
			}
		}
		
		/* Send user state for connecting user to other users */
		sendmsg = Msg_create(UserState);
		sendmsg->payload.userState->has_session = true;
		sendmsg->payload.userState->session = client->sessionId;
		sendmsg->payload.userState->name = strdup(client->username);
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
			sendmsg->payload.userState->name = strdup(client_itr->username);
			sendmsg->payload.userState->has_channel_id = true;
			sendmsg->payload.userState->channel_id = ((channel_t *)client_itr->channel)->id;

			/* Only self_mute/deaf supported */
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
		Client_send_message(client, sendmsg);

		/* Server config message */
		sendmsg = Msg_create(ServerConfig);		
		sendmsg->payload.serverConfig->has_allow_html = true;
		sendmsg->payload.serverConfig->allow_html = true; /* Support this? */
		sendmsg->payload.serverConfig->has_message_length = true;
		sendmsg->payload.serverConfig->message_length = MAX_TEXT; /* Hardcoded */
		sendmsg->payload.serverConfig->has_image_message_length = true;
		sendmsg->payload.serverConfig->image_message_length = 0; /* XXX */
		Client_send_message(client, sendmsg);

		Log_info_client(client, "User %s authenticated", client->username);
		break;
		
	case Ping:
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
		
		client->UDPPingAvg = msg->payload.ping->udp_ping_avg;
		client->UDPPingVar = msg->payload.ping->udp_ping_var;
		client->TCPPingAvg = msg->payload.ping->tcp_ping_avg;
		client->TCPPingVar = msg->payload.ping->tcp_ping_var;
		client->UDPPackets = msg->payload.ping->udp_packets;
		client->TCPPackets = msg->payload.ping->tcp_packets;
		
		sendmsg = Msg_create(Ping);

		sendmsg->payload.ping->timestamp = msg->payload.ping->timestamp;
		sendmsg->payload.ping->has_timestamp = true;
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
		
		msg->payload.userState->has_session = true;
		msg->payload.userState->session = client->sessionId;
		msg->payload.userState->has_actor = true;
		msg->payload.userState->actor = client->sessionId;

		if (msg->payload.userState->has_self_deaf) {
			client->deaf = msg->payload.userState->self_deaf;
		}
		if (msg->payload.userState->has_self_mute) {
			client->mute = msg->payload.userState->self_mute;
			if (!client->mute) {
				msg->payload.userState->has_self_deaf = true;
				msg->payload.userState->self_deaf = false;
				client->deaf = false;
			}
		}
		if (msg->payload.userState->has_channel_id) {
			int leave_id;
			if (!Chan_userJoin_id_test(msg->payload.userState->channel_id))
				break;
			leave_id = Chan_userJoin_id(msg->payload.userState->channel_id, client);
			if (leave_id > 0) {
				Log_debug("Removing channel ID %d", leave_id);
				sendmsg = Msg_create(ChannelRemove);
				sendmsg->payload.channelRemove->channel_id = leave_id;
			}
		}
		if (msg->payload.userState->has_plugin_context) {
			if (client->context)
				free(client->context);
			client->context = malloc(msg->payload.userState->plugin_context.len);
			if (client->context == NULL)
				Log_fatal("Out of memory");
			memcpy(client->context, msg->payload.userState->plugin_context.data,
				   msg->payload.userState->plugin_context.len);
			
			break; /* Don't inform other users about this state */
		}
		
		/* Re-use message */
		Msg_inc_ref(msg);
				
		Client_send_message_except(NULL, msg);

		/* Need to send remove channel message _after_ UserState message */
		if (sendmsg != NULL)
			Client_send_message_except(NULL, sendmsg);
		break;
		
	case TextMessage:
		msg->payload.textMessage->has_actor = true;
		msg->payload.textMessage->actor = client->sessionId;

		/* XXX - HTML is allowed and can't be turned off */
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
				if (ch_itr != NULL) {
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
					if (itr->sessionId == msg->payload.textMessage->session[i]) {
						if (!itr->deaf) {
							Msg_inc_ref(msg);
							Client_send_message(itr, msg);
							Log_debug("Text message to session ID %d", itr->sessionId);
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
	{
		int i, j, count, targetId = msg->payload.voiceTarget->id;
		struct _MumbleProto__VoiceTarget__Target *target;

		if (!targetId || targetId >= 0x1f)
			break;
		Voicetarget_add_id(client, targetId);
		count = msg->payload.voiceTarget->n_targets;
		if (!count)
			break;
		for (i = 0; i < count; i++) {
			target = msg->payload.voiceTarget->targets[i];
			for (j = 0; j < target->n_session; j++)
				Voicetarget_add_session(client, targetId, target->session[j]);
			if (target->has_channel_id) {
				bool_t linked = false, children = false;
				if (target->has_links)
					linked = target->links;
				if (target->has_children)
					children = target->children;
				Voicetarget_add_channel(client, targetId, target->channel_id, linked, children);
			}
		}
		break;
	}
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
		if (msg->payload.version->os_version) {
			if (client->os_version) free(client->os_version);			
			client->os_version = strdup(msg->payload.version->os_version);
			Log_debug("Client OS version %s", client->os_version);
		}
		break;
	case PermissionQuery:
		Msg_inc_ref(msg); /* Re-use message */
		msg->payload.permissionQuery->has_permissions = true;
		msg->payload.permissionQuery->permissions = PERM_DEFAULT;
		
		Client_send_message(client, msg);
		break;
	case UDPTunnel:
		client->bUDP = false;
		Client_voiceMsg(client, msg->payload.UDPTunnel->packet.data, msg->payload.UDPTunnel->packet.len);
	    break;
	case ChannelState:
	{
		channel_t *ch_itr, *parent, *newchan;
		int leave_id;		
		/* Don't allow any changes to existing channels */
		if (msg->payload.channelState->has_channel_id) {
			sendPermissionDenied(client, "Not supported by uMurmur");
			break;
		}
		/* Must have parent */
		if (!msg->payload.channelState->has_parent) {
			sendPermissionDenied(client, "Not supported by uMurmur");
			break;
		}
		/* Must have name */
		if (msg->payload.channelState->name == NULL) {
			sendPermissionDenied(client, "Not supported by uMurmur");
			break;
		}
		/* Must be temporary channel */
		if (msg->payload.channelState->temporary != true) {
			sendPermissionDenied(client, "Only temporary channels are supported by uMurmur");
			break;
		}
		/* Check channel name is OK */
		if (strlen(msg->payload.channelState->name) > MAX_TEXT) {
			sendPermissionDenied(client, "Channel name too long");
			break;
		}
			
		parent = Chan_fromId(msg->payload.channelState->parent);
		if (parent == NULL)
			break;
		ch_itr = NULL;
		while (Chan_iterate_siblings(parent, &ch_itr) != NULL) {
			if (strcmp(ch_itr->name, msg->payload.channelState->name) == 0) {
				sendPermissionDenied(client, "Channel already exists");
				break;
			}
		}
		if (ch_itr != NULL)
			break;
		
		/* Disallow temporary channels as siblings to temporary channels */
		if (parent->temporary) {
			sendPermissionDenied(client, "Parent channel is temporary channel");
			break;
		}
			
		/* XXX - Murmur looks for "\\w" and sends perm denied if not found.
		 * I don't know why so I don't do that here...
		 */

		/* Create the channel */
		newchan = Chan_createChannel(msg->payload.channelState->name,
									 msg->payload.channelState->description);
		newchan->temporary = true;
		Chan_addChannel(parent, newchan);
		msg->payload.channelState->has_channel_id = true;
		msg->payload.channelState->channel_id = newchan->id;
		Msg_inc_ref(msg);
		Client_send_message_except(NULL, msg);

		/* Join the creating user */
		sendmsg = Msg_create(UserState);
		sendmsg->payload.userState->has_session = true;
		sendmsg->payload.userState->session = client->sessionId;
		sendmsg->payload.userState->has_channel_id = true;
		sendmsg->payload.userState->channel_id = newchan->id;
		Client_send_message_except(NULL, sendmsg);
		
		leave_id = Chan_userJoin(newchan, client);
		if (leave_id > 0) {
			Log_debug("Removing channel ID %d", leave_id);
			sendmsg = Msg_create(ChannelRemove);
			sendmsg->payload.channelRemove->channel_id = leave_id;
			Client_send_message_except(NULL, sendmsg);
		}
	}		
	break;

	case UserStats:
	{
		client_t *target = NULL;
		codec_t *codec_itr = NULL;
		int i;
		bool_t details = true;
		
		if (msg->payload.userStats->has_stats_only)
			details = !msg->payload.userStats->stats_only;
		
		if (!msg->payload.userStats->has_session)
			sendPermissionDenied(client, "Not supported by uMurmur");
		while (Client_iterate(&target) != NULL) {
			if (!IS_AUTH(target))
				continue;
			if (target->sessionId == msg->payload.userStats->session)
				break;
		}
		if (!target) /* Not found */
			break;
		
		/*
		 * Differences from Murmur:
		 * o Ignoring certificates intentionally
		 * o Ignoring channel local determining
		 */
		
		sendmsg = Msg_create(UserStats);
		sendmsg->payload.userStats->session = msg->payload.userStats->session;
		sendmsg->payload.userStats->from_client->has_good = true;
		sendmsg->payload.userStats->from_client->good = target->cryptState.uiGood;
		sendmsg->payload.userStats->from_client->has_late = true;
		sendmsg->payload.userStats->from_client->late = target->cryptState.uiLate;
		sendmsg->payload.userStats->from_client->has_lost = true;
		sendmsg->payload.userStats->from_client->lost = target->cryptState.uiLost;
		sendmsg->payload.userStats->from_client->has_resync = true;
		sendmsg->payload.userStats->from_client->resync = target->cryptState.uiResync;
		
		sendmsg->payload.userStats->from_server->has_good = true;
		sendmsg->payload.userStats->from_server->good = target->cryptState.uiRemoteGood;
		sendmsg->payload.userStats->from_server->has_late = true;
		sendmsg->payload.userStats->from_server->late = target->cryptState.uiRemoteLate;
		sendmsg->payload.userStats->from_server->has_lost = true;
		sendmsg->payload.userStats->from_server->lost = target->cryptState.uiRemoteLost;
		sendmsg->payload.userStats->from_server->has_resync = true;
		sendmsg->payload.userStats->from_server->resync = target->cryptState.uiRemoteResync;

		sendmsg->payload.userStats->has_udp_packets = true;
		sendmsg->payload.userStats->udp_packets = target->UDPPackets;
		sendmsg->payload.userStats->has_udp_ping_avg = true;
		sendmsg->payload.userStats->udp_ping_avg = target->UDPPingAvg;
		sendmsg->payload.userStats->has_udp_ping_var = true;
		sendmsg->payload.userStats->udp_ping_var = target->UDPPingVar;
		
		sendmsg->payload.userStats->has_tcp_ping_avg = true;
		sendmsg->payload.userStats->tcp_ping_avg = target->TCPPingAvg;
		sendmsg->payload.userStats->has_tcp_ping_var = true;
		sendmsg->payload.userStats->tcp_ping_var = target->TCPPingVar;
		sendmsg->payload.userStats->has_tcp_packets = true;
		sendmsg->payload.userStats->tcp_packets = target->TCPPackets;
		
		if (details) {

			sendmsg->payload.userStats->version->has_version = true;
			sendmsg->payload.userStats->version->version = target->version;
			sendmsg->payload.userStats->version->release = strdup(target->release);
			sendmsg->payload.userStats->version->os = strdup(target->os);
			sendmsg->payload.userStats->version->os_version = strdup(target->os_version);
			
			sendmsg->payload.userStats->n_celt_versions = target->codec_count;
			sendmsg->payload.userStats->celt_versions = malloc(sizeof(int32_t) * target->codec_count);
			if (!sendmsg->payload.userStats->celt_versions)
				Log_fatal("Out of memory");
			i = 0;
			while (Client_codec_iterate(target, &codec_itr) != NULL)
				sendmsg->payload.userStats->celt_versions[i++] = codec_itr->codec;

			/* Address */
			sendmsg->payload.userStats->has_address = true;
			sendmsg->payload.userStats->address.data = malloc(sizeof(uint8_t) * 16);
			if (!sendmsg->payload.userStats->address.data)
				Log_fatal("Out of memory");
			memset(sendmsg->payload.userStats->address.data, 0, 16);
			/* ipv4 representation as ipv6 address. Supposedly correct. */
			memcpy(&sendmsg->payload.userStats->address.data[12], &target->remote_tcp.sin_addr, 4);
			sendmsg->payload.userStats->address.len = 16;
		}
		/* BW */
		sendmsg->payload.userStats->has_bandwidth = true;
		sendmsg->payload.userStats->bandwidth = target->availableBandwidth;
		
		/* Onlinesecs */
		sendmsg->payload.userStats->has_onlinesecs = true;
		sendmsg->payload.userStats->onlinesecs = Timer_elapsed(&target->connectTime) / 1000000LL;		
		/* Idlesecs */
		sendmsg->payload.userStats->has_idlesecs = true;
		sendmsg->payload.userStats->idlesecs = Timer_elapsed(&target->idleTime) / 1000000LL;		
		Client_send_message(client, sendmsg);
	}
	break;
		/* Permission denied for all these messages. Not implemented. */
	case ChannelRemove:
	case ContextAction:
	case ContextActionAdd:
	case ACL:
	case BanList:
	case UserList:
	case QueryUsers:
		sendPermissionDenied(client, "Not supported by uMurmur");
		break;
				
	default:
		Log_warn("Message %d not handled", msg->messageType);
		break;
	}
out:
	Msg_free(msg);
	return;
	
disconnect:
	Msg_free(msg);
	Client_close(client);
}

