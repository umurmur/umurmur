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
#include <sys/poll.h>
#include <sys/socket.h>
#include <errno.h>
#include <limits.h>
#include "log.h"
#include "list.h"
#include "client.h"
#include "ssl.h"
#include "messages.h"
#include "messagehandler.h"
#include "conf.h"
#include "channel.h"
#include "version.h"
#include "voicetarget.h"

extern char system_string[], version_string[];

static int Client_read(client_t *client);
static int Client_write(client_t *client);
static int Client_send_udp(client_t *client, uint8_t *data, int len);
void Client_free(client_t *client);

declare_list(clients);
static int clientcount; /* = 0 */
static int maxBandwidth;

int iCodecAlpha, iCodecBeta;
bool_t bPreferAlpha;

extern int udpsock;

void Client_init()
{
	maxBandwidth = getIntConf(MAX_BANDWIDTH) / 8; /* From bits/s -> bytes/s */
}

int Client_count()
{
	return clientcount;
}

int Client_getfds(struct pollfd *pollfds)
{
	struct dlist *itr;
	int i = 0;
	list_iterate(itr, &clients) {
		client_t *c;
		c = list_get_entry(itr, client_t, node);
		pollfds[i].fd = c->tcpfd;
		pollfds[i].events = POLLIN | POLLHUP | POLLERR;
		if (c->txsize > 0 || c->readBlockedOnWrite) /* Data waiting to be sent? */
			pollfds[i].events |= POLLOUT;
		i++;
	}
	return i;
}

void Client_janitor()
{
	struct dlist *itr;
	int bwTop = maxBandwidth + maxBandwidth / 4;
	list_iterate(itr, &clients) {
		client_t *c;
		c = list_get_entry(itr, client_t, node);
		Log_debug("Client %s BW available %d", c->username, c->availableBandwidth);
		c->availableBandwidth += maxBandwidth;
		if (c->availableBandwidth > bwTop)
			c->availableBandwidth = bwTop;
		
		if (Timer_isElapsed(&c->lastActivity, 1000000LL * INACTICITY_TIMEOUT)) {
			/* No activity from client - assume it is lost and close. */
			Log_info_client(c, "Timeout, closing.");
			Client_free(c);
		}
	}
}

void Client_codec_add(client_t *client, int codec)
{
	codec_t *cd = malloc(sizeof(codec_t));
	if (cd == NULL)
		Log_fatal("Out of memory");
	init_list_entry(&cd->node);
	cd->codec = codec;
	list_add_tail(&cd->node, &client->codecs);
}

void Client_codec_free(client_t *client)
{
	struct dlist *itr, *save;
	list_iterate_safe(itr, save, &client->codecs) {
		list_del(&list_get_entry(itr, codec_t, node)->node);
		free(list_get_entry(itr, codec_t, node));
	}
}

codec_t *Client_codec_iterate(client_t *client, codec_t **codec_itr)
{
	codec_t *cd = *codec_itr;

	if (list_empty(&client->codecs))
		return NULL;
	
	if (cd == NULL) {
		cd = list_get_entry(list_get_first(&client->codecs), codec_t, node);
	} else {
		if (list_get_next(&cd->node) == &client->codecs)
			cd = NULL;
		else
			cd = list_get_entry(list_get_next(&cd->node), codec_t, node);
	}
	*codec_itr = cd;
	return cd;
}

void recheckCodecVersions()
{
	client_t *client_itr = NULL;
	int max = 0, version, current_version;
	message_t *sendmsg;
	struct dlist codec_list, *itr, *save;
	codec_t *codec_itr, *cd;
	bool_t found;
	
	init_list_entry(&codec_list);
	
	while (Client_iterate(&client_itr) != NULL) {
		codec_itr = NULL;
		while (Client_codec_iterate(client_itr, &codec_itr) != NULL) {
			found = false;
			list_iterate(itr, &codec_list) {
				cd = list_get_entry(itr, codec_t, node);
				if (cd->codec == codec_itr->codec) {
					cd->count++;
					found = true;
				}
			}
			if (!found) {
				cd = malloc(sizeof(codec_t));
				if (!cd)
					Log_fatal("Out of memory");
				memset(cd, 0, sizeof(codec_t));
				init_list_entry(&cd->node);
				cd->codec = codec_itr->codec;
				cd->count = 1;
				list_add_tail(&cd->node, &codec_list);
			}
		}
	}
	
	list_iterate(itr, &codec_list) {
		cd = list_get_entry(itr, codec_t, node);
		if (cd->count > max) {
			max = cd->count;
			version = cd->codec;
		}
	}
	list_iterate_safe(itr, save, &codec_list) {
		list_del(&list_get_entry(itr, codec_t, node)->node);
		free(list_get_entry(itr, codec_t, node));
	}
	
	current_version = bPreferAlpha ? iCodecAlpha : iCodecBeta;
	if (current_version == version)
		return;
	// If we don't already use the compat bitstream version set
	// it as alpha and announce it. If another codec now got the
	// majority set it as the opposite of the currently valid bPreferAlpha
	// and announce it.
	if (version == (uint32_t)0x8000000a)
		bPreferAlpha = true;
	else
		bPreferAlpha = ! bPreferAlpha;

	if (bPreferAlpha)
		iCodecAlpha = version;
	else
		iCodecBeta = version;
	
	sendmsg = Msg_create(CodecVersion);
	sendmsg->payload.codecVersion->alpha = version;
	sendmsg->payload.codecVersion->beta = version;
	sendmsg->payload.codecVersion->prefer_alpha = bPreferAlpha;
	Client_send_message_except(NULL, sendmsg);
	
	Log_info("CELT codec switch 0x%x 0x%x (prefer 0x%x)", iCodecAlpha, iCodecBeta,
			 bPreferAlpha ? iCodecAlpha : iCodecBeta);
	
}

static int findFreeSessionId()
{
	int id;
	client_t *itr = NULL;

	for (id = 1; id < INT_MAX; id++) {
		itr = NULL;
		while ((itr = Client_iterate(&itr)) != NULL) {
			if (itr->sessionId == id)
				break;
		}
		if (itr == NULL) /* Found free id */
			return id;
	}
	return -1;
}

int Client_add(int fd, struct sockaddr_in *remote)
{
	client_t *newclient;
	message_t *sendmsg;
	
	newclient = malloc(sizeof(client_t));
	if (newclient == NULL)
		Log_fatal("Out of memory");
	memset(newclient, 0, sizeof(client_t));

	newclient->tcpfd = fd;
	memcpy(&newclient->remote_tcp, remote, sizeof(struct sockaddr_in));
	newclient->ssl = SSL_newconnection(newclient->tcpfd, &newclient->SSLready);
	if (newclient->ssl == NULL) {
		Log_warn("SSL negotiation failed with %s:%d", inet_ntoa(remote->sin_addr),
				 ntohs(remote->sin_port));
		free(newclient);
		return -1;
	}
	newclient->availableBandwidth = maxBandwidth;
	Timer_init(&newclient->lastActivity);
	newclient->sessionId = findFreeSessionId();
	if (newclient->sessionId < 0)
		Log_fatal("Could not find a free session ID");
	
	init_list_entry(&newclient->txMsgQueue);
	init_list_entry(&newclient->chan_node);
	init_list_entry(&newclient->node);
	init_list_entry(&newclient->voicetargets);
	init_list_entry(&newclient->codecs);
	
	list_add_tail(&newclient->node, &clients);
	clientcount++;
	
	/* Send version message to client */
	sendmsg = Msg_create(Version);
	sendmsg->payload.version->has_version = true;
	sendmsg->payload.version->version = PROTOCOL_VERSION;
	sendmsg->payload.version->release = strdup(UMURMUR_VERSION);
	sendmsg->payload.version->os = strdup(system_string);
	sendmsg->payload.version->os_version = strdup(version_string);
	Client_send_message(newclient, sendmsg);

	return 0;
}

void Client_free(client_t *client)
{
	struct dlist *itr, *save;
	message_t *sendmsg;

	if (client->authenticated) {
		int leave_id;
		leave_id = Chan_userLeave(client);
		if (leave_id > 0) { /* Remove temp channel */
			sendmsg = Msg_create(ChannelRemove);
			sendmsg->payload.channelRemove->channel_id = leave_id;
			Client_send_message_except(client, sendmsg);
		}
		sendmsg = Msg_create(UserRemove);
		sendmsg->payload.userRemove->session = client->sessionId;
		Client_send_message_except(client, sendmsg);
	}
	list_iterate_safe(itr, save, &client->txMsgQueue) {
		list_del(&list_get_entry(itr, message_t, node)->node);
		Msg_free(list_get_entry(itr, message_t, node));
	}
	Client_codec_free(client);
	Voicetarget_free_all(client);
	
	list_del(&client->node);
	if (client->ssl)
		SSL_free(client->ssl);
	close(client->tcpfd);
	clientcount--;
	if (client->release)
		free(client->release);
	if (client->os)
		free(client->os);			
	if (client->username)
		free(client->username);
	if (client->context)
		free(client->context);
	free(client);
}

void Client_close(client_t *client)
{
	SSL_shutdown(client->ssl);
	client->shutdown_wait = true;
}

void Client_disconnect_all()
{
	struct dlist *itr, *save;
	
	list_iterate_safe(itr, save, &clients) {
		Client_free(list_get_entry(itr, client_t, node));
	}
}

int Client_read_fd(int fd)
{
	struct dlist *itr;
	client_t *client = NULL;
	
	list_iterate(itr, &clients) {
		if (fd == list_get_entry(itr, client_t, node)->tcpfd) {
			client = list_get_entry(itr, client_t, node);
			break;
		}
	}
	if (client == NULL)
		Log_fatal("No client found for fd %d", fd);
	
	return Client_read(client);
}

int Client_read(client_t *client)
{
	int rc;

	Timer_restart(&client->lastActivity);
	
	if (client->writeBlockedOnRead) {
		client->writeBlockedOnRead = false;
		Log_debug("Client_read: writeBlockedOnRead == true");
		return Client_write(client);
	}
	
	if (client->shutdown_wait) {
		Client_free(client);
		return 0;
	}
	if (!client->SSLready) {
		int rc;
		rc = SSL_nonblockaccept(client->ssl, &client->SSLready);
		if (rc < 0) {
			Client_free(client);
			return -1;
		}
	}

	do {
		errno = 0;
		if (!client->msgsize) 
			rc = SSL_read(client->ssl, &client->rxbuf[client->rxcount], 6 - client->rxcount);
		else
			rc = SSL_read(client->ssl, &client->rxbuf[client->rxcount], client->msgsize);
		if (rc > 0) {
			message_t *msg;
			client->rxcount += rc;
			if (!client->msgsize && client->rxcount >= 6) {
				uint32_t msgLen;
				memcpy(&msgLen, &client->rxbuf[2], sizeof(uint32_t));
				client->msgsize = ntohl(msgLen);
			}
			if (client->msgsize > BUFSIZE - 6) {
				/* XXX - figure out how to handle this. A large size here can represent two cases:
				 * 1. A valid size. The only message that is this big is UserState message with a big texture
				 * 2. An invalid size = protocol error, e.g. connecting with a 1.1.x client
				 */
				Log_warn("Too big message received (%d bytes). Playing safe and disconnecting client %s:%d",
						 client->msgsize, inet_ntoa(client->remote_tcp.sin_addr), ntohs(client->remote_tcp.sin_port));
				Client_free(client);
				return -1;
				/* client->rxcount = client->msgsize = 0; */
			}
			else if (client->rxcount == client->msgsize + 6) { /* Got all of the message */
				msg = Msg_networkToMessage(client->rxbuf, client->msgsize + 6);
				/* pass messsage to handler */
				if (msg)
					Mh_handle_message(client, msg);
				client->rxcount = client->msgsize = 0;
			}
		} else /* rc <= 0 */ {
			if (SSL_get_error(client->ssl, rc) == SSL_ERROR_WANT_READ) {
				return 0;
			}
			else if (SSL_get_error(client->ssl, rc) == SSL_ERROR_WANT_WRITE) {
				client->readBlockedOnWrite = true;
				return 0;
			}
			else if (SSL_get_error(client->ssl, rc) == SSL_ERROR_ZERO_RETURN) {
				Log_info_client(client, "Connection closed by peer");
				if (!client->shutdown_wait)
					Client_close(client);
			}
			else {
				if (SSL_get_error(client->ssl, rc) == SSL_ERROR_SYSCALL) {
					/* Hmm. This is where we end up when the client closes its connection.
					 * Kind of strange...
					 */
					Log_info_client(client, "Connection closed by peer");
				}
				else {
					Log_info_client(client, "SSL error: %d - Closing connection", SSL_get_error(client->ssl, rc));
				}
				Client_free(client);
				return -1;
			}
		}
	} while (SSL_pending(client->ssl));
	
	return 0;
}

int Client_write_fd(int fd)
{
	struct dlist *itr;
	client_t *client = NULL;
	
	list_iterate(itr, &clients) {
		if(fd == list_get_entry(itr, client_t, node)->tcpfd) {
			client = list_get_entry(itr, client_t, node);
			break;
		}
	}
	if (client == NULL)
		Log_fatal("No client found for fd %d", fd);
	Client_write(client);
	return 0;
}

int Client_write(client_t *client)
{
	int rc;
	
	if (client->readBlockedOnWrite) {
		client->readBlockedOnWrite = false;
		Log_debug("Client_write: readBlockedOnWrite == true");
		return Client_read(client);
	}
	rc = SSL_write(client->ssl, &client->txbuf[client->txcount], client->txsize - client->txcount);
	if (rc > 0) {
		client->txcount += rc;
		if (client->txcount == client->txsize)
			client->txsize = client->txcount = 0;
	}
	else if (rc < 0) {
		if (SSL_get_error(client->ssl, rc) == SSL_ERROR_WANT_READ) {
			client->writeBlockedOnRead = true;
			return 0;
		}
		else if (SSL_get_error(client->ssl, rc) == SSL_ERROR_WANT_WRITE) {
			return 0;
		}
		else {
			if (SSL_get_error(client->ssl, rc) == SSL_ERROR_SYSCALL)
				Log_warn("Client_write: Error: %s  - Closing connection", strerror(errno));
			else
				Log_warn("Client_write: SSL error: %d - Closing connection.", SSL_get_error(client->ssl, rc));
			Client_free(client);
			return -1;
		}
	}
	if (client->txsize == 0 && !list_empty(&client->txMsgQueue)) {
		message_t *msg;
		msg = list_get_entry(list_get_first(&client->txMsgQueue), message_t, node);
		list_del(list_get_first(&client->txMsgQueue));
		client->txQueueCount--;
		Client_send_message(client, msg);
	}
	return 0;
}

int Client_send_message(client_t *client, message_t *msg)
{
	if (!client->authenticated && msg->messageType != Version) {
		Msg_free(msg);
		return 0;
	}
	if (client->txsize != 0 || !client->SSLready) {
		/* Queue message */
		if ((client->txQueueCount > 5 &&  msg->messageType == UDPTunnel) ||
			client->txQueueCount > 30) {
			Msg_free(msg);
			return -1;
		}
		client->txQueueCount++;
		list_add_tail(&msg->node, &client->txMsgQueue);
		Log_debug("Queueing message");
	} else {
		int len;
		len = Msg_messageToNetwork(msg, client->txbuf);
		doAssert(len < BUFSIZE);

		client->txsize = len;
		client->txcount = 0;
		Client_write(client);
		Msg_free(msg);
	}
	return 0;
}

client_t *Client_iterate(client_t **client_itr)
{
	client_t *c = *client_itr;

	if (list_empty(&clients))
		return NULL;
	
	if (c == NULL) {
		c = list_get_entry(list_get_first(&clients), client_t, node);
	} else {
		if (list_get_next(&c->node) == &clients)
			c = NULL;
		else
			c = list_get_entry(list_get_next(&c->node), client_t, node);
	}
	*client_itr = c;
	return c;
}


int Client_send_message_except(client_t *client, message_t *msg)
{
	client_t *itr = NULL;
	int count = 0;
	
	Msg_inc_ref(msg); /* Make sure a reference is held during the whole iteration. */
	while (Client_iterate(&itr) != NULL) {
		if (itr != client) {
			if (count++ > 0)
				Msg_inc_ref(msg); /* One extra reference for each new copy */
			Log_debug("Msg %d to %s refcount %d",  msg->messageType, itr->username, msg->refcount);
			Client_send_message(itr, msg);
		}
	}
	Msg_free(msg); /* Free our reference to the message */
	
	if (count == 0)
		Msg_free(msg); /* If only 1 client is connected then no message is passed
						* to Client_send_message(). Free it here. */
		
	return 0;
}

static bool_t checkDecrypt(client_t *client, const uint8_t *encrypted, uint8_t *plain, unsigned int len)
{
	if (CryptState_isValid(&client->cryptState) &&
		CryptState_decrypt(&client->cryptState, encrypted, plain, len))
		return true;

	if (Timer_elapsed(&client->cryptState.tLastGood) > 5000000ULL) {
		if (Timer_elapsed(&client->cryptState.tLastRequest) > 5000000ULL) {
			message_t *sendmsg;
			Timer_restart(&client->cryptState.tLastRequest);
			
			sendmsg = Msg_create(CryptSetup);
			Log_info_client(client, "Requesting voice channel crypt resync");		
			Client_send_message(client, sendmsg);
		}
	}
	return false;
}

#define UDP_PACKET_SIZE 1024
int Client_read_udp()
{
	int len;
	struct sockaddr_in from;
	socklen_t fromlen = sizeof(struct sockaddr_in);
	uint64_t key;
	client_t *itr;
	UDPMessageType_t msgType;
	
#if defined(__LP64__)
	uint8_t encbuff[UDP_PACKET_SIZE + 8];
	uint8_t *encrypted = encbuff + 4;
#else
	uint8_t encrypted[UDP_PACKET_SIZE];
#endif
	uint8_t buffer[UDP_PACKET_SIZE];
	
	len = recvfrom(udpsock, encrypted, UDP_PACKET_SIZE, MSG_TRUNC, (struct sockaddr *)&from, &fromlen);
	if (len == 0) {
		return -1;
	} else if (len < 0) {
		return -1;
	} else if (len < 5) {
		// 4 bytes crypt header + type + session
		return 0;
	} else if (len > UDP_PACKET_SIZE) {
		return 0;
	}

	/* Ping packet */
	if (len == 12 && *encrypted == 0) {
		uint32_t *ping = (uint32_t *)encrypted;
		ping[0] = htonl((uint32_t)PROTOCOL_VERSION);
		// 1 and 2 will be the timestamp, which we return unmodified.
		ping[3] = htonl((uint32_t)clientcount);
		ping[4] = htonl((uint32_t)getIntConf(MAX_CLIENTS));
		ping[5] = htonl((uint32_t)getIntConf(MAX_BANDWIDTH));
		
		sendto(udpsock, encrypted, 6 * sizeof(uint32_t), 0, (struct sockaddr *)&from, fromlen);
		return 0;
	}
	
	key = (((uint64_t)from.sin_addr.s_addr) << 16) ^ from.sin_port;
	itr = NULL;
	
	while (Client_iterate(&itr) != NULL) {
		if (itr->key == key) {
			if (!checkDecrypt(itr, encrypted, buffer, len))
				goto out;
			break;
		}
	}	
	if (itr == NULL) { /* Unknown peer */
		while (Client_iterate(&itr) != NULL) {
			if (itr->remote_tcp.sin_addr.s_addr == from.sin_addr.s_addr) {
				if (checkDecrypt(itr, encrypted, buffer, len)) {
					itr->key = key;
					Log_info_client(itr, "New UDP connection port %d", ntohs(from.sin_port));
					memcpy(&itr->remote_udp, &from, sizeof(struct sockaddr_in));
					break;
				}
				else Log_warn("Bad cryptstate from peer");
			}
		} /* while */
	}
	if (itr == NULL) { /* Couldn't find this peer among connected clients */
		goto out;
	}
	
	itr->bUDP = true;
	len -= 4; /* Adjust for crypt header */
	msgType = (UDPMessageType_t)((buffer[0] >> 5) & 0x7);
	switch (msgType) {
	case UDPVoiceSpeex:
	case UDPVoiceCELTAlpha:
	case UDPVoiceCELTBeta:
		Client_voiceMsg(itr, buffer, len);
		break;
	case UDPPing:
		Log_debug("UDP Ping reply len %d", len);
		Client_send_udp(itr, buffer, len);
		break;
	default:
		Log_debug("Unknown UDP message type from %s port %d", inet_ntoa(from.sin_addr), ntohs(from.sin_port));
		break;
	}
	
out:
	return 0;
}

static inline void Client_send_voice(client_t *src, client_t *dst, uint8_t *data, int len, int poslen)
{
	if (IS_AUTH(dst) && dst != src && !dst->deaf) {
		if (poslen > 0 && /* Has positional data */
			src->context != NULL && dst->context != NULL && /* ...both source and destination has context */
			strcmp(src->context, dst->context) == 0) /* ...and the contexts match */
			Client_send_udp(dst, data, len);
		else 
			Client_send_udp(dst, data, len - poslen);
	}
}

/* Handle decrypted voice message */
int Client_voiceMsg(client_t *client, uint8_t *data, int len)
{
	uint8_t buffer[UDP_PACKET_SIZE];
	pds_t *pdi = Pds_create(data + 1, len - 1);
	pds_t *pds = Pds_create(buffer + 1, UDP_PACKET_SIZE - 1);
	unsigned int type = data[0] & 0xe0;
	unsigned int target = data[0] & 0x1f;
	unsigned int poslen, counter;
	int offset, packetsize;
	voicetarget_t *vt;
	
	channel_t *ch = (channel_t *)client->channel;
	struct dlist *itr;
	
	if (!client->authenticated || client->mute)
		goto out;
	
	packetsize = 20 + 8 + 4 + len;
	if (client->availableBandwidth - packetsize < 0)
		goto out; /* Discard */
	client->availableBandwidth -= packetsize;
	
	counter = Pds_get_numval(pdi); /* step past session id */
	do {
		counter = Pds_next8(pdi);
		offset = Pds_skip(pdi, counter & 0x7f);
	} while ((counter & 0x80) && offset > 0);

	poslen = pdi->maxsize - pdi->offset; /* For stripping of positional info */
	
	Pds_add_numval(pds, client->sessionId);
	Pds_append_data_nosize(pds, data + 1, len - 1);
	
	if (target == 0x1f) { /* Loopback */
		buffer[0] = (uint8_t) type;
		Client_send_udp(client, buffer, pds->offset + 1);
	}
	else if (target == 0) { /* regular channel speech */
		buffer[0] = (uint8_t) type;
		
		if (ch == NULL)
			goto out;
		
		list_iterate(itr, &ch->clients) {
			client_t *c;
			c = list_get_entry(itr, client_t, chan_node);
			Client_send_voice(client, c, buffer, pds->offset + 1, poslen);
		}
	} else if ((vt = Voicetarget_get_id(client, target)) != NULL) {	/* Targeted whisper */
		int i;
		channel_t *ch;
		/* Channels */
		for (i = 0; i < TARGET_MAX_CHANNELS && vt->channels[i].channel != -1; i++) {
			buffer[0] = (uint8_t) (type | 1);
			Log_debug("Whisper channel %d", vt->channels[i]);
			ch = Chan_fromId(vt->channels[i].channel);
			if (ch == NULL)
				continue;
			list_iterate(itr, &ch->clients) {
				client_t *c;
				c = list_get_entry(itr, client_t, chan_node);
				Client_send_voice(client, c, buffer, pds->offset + 1, poslen);
			}
			/* Channel links */
			if (vt->channels[i].linked && !list_empty(&ch->channel_links)) {
				struct dlist *ch_itr;
				list_iterate(ch_itr, &ch->channel_links) {
					channel_t *ch_link;
					ch_link = list_get_entry(ch_itr, channel_t, link_node);
					list_iterate(itr, &ch_link->clients) {
						client_t *c;
						c = list_get_entry(itr, client_t, chan_node);
						Log_debug("Linked voice from %s -> %s", ch->name, ch_link->name);
						Client_send_voice(client, c, buffer, pds->offset + 1, poslen);
					}
				}
			}
			/* children */
			if (vt->channels[i].children) {
				struct dlist chanlist, *ch_itr;
				init_list_entry(&chanlist);
				Chan_buildTreeList(ch, &chanlist);
				list_iterate(ch_itr, &chanlist) {
					channel_t *sub;
					sub = list_get_entry(ch_itr, channellist_t, node)->chan;
					list_iterate(itr, &sub->clients) {
						client_t *c;
						c = list_get_entry(itr, client_t, chan_node);
						Log_debug("Child voice from %s -> %s", ch->name, sub->name);
						Client_send_voice(client, c, buffer, pds->offset + 1, poslen);
					}
				}
				Chan_freeTreeList(&chanlist);
			}
		}			
		/* Sessions */
		for (i = 0; i < TARGET_MAX_SESSIONS && vt->sessions[i] != -1; i++) {
			client_t *c;
			buffer[0] = (uint8_t) (type | 2);
			Log_debug("Whisper session %d", vt->sessions[i]);
			while (Client_iterate(&c) != NULL) {
				if (c->sessionId == vt->sessions[i]) {
					Client_send_voice(client, c, buffer, pds->offset + 1, poslen);
					break;
				}
			}
		}
	}
out:
	Pds_free(pds);
	Pds_free(pdi);
	
	return 0;
}


static int Client_send_udp(client_t *client, uint8_t *data, int len)
{
	uint8_t *buf, *mbuf;

	if (client->remote_udp.sin_port != 0 && CryptState_isValid(&client->cryptState) &&
		client->bUDP) {
#if defined(__LP64__)
		buf = mbuf = malloc(len + 4 + 16);
		buf += 4;
#else
		mbuf = buf = malloc(len + 4);
#endif
		if (mbuf == NULL)
			Log_fatal("Out of memory");
		
		CryptState_encrypt(&client->cryptState, data, buf, len);
		
		sendto(udpsock, buf, len + 4, 0, (struct sockaddr *)&client->remote_udp, sizeof(struct sockaddr_in));
		
		free(mbuf);
	} else {
		message_t *msg;
		msg = Msg_CreateVoiceMsg(data, len);
		Client_send_message(client, msg);
	}
	return 0;
}
