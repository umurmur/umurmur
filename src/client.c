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
#include <sys/poll.h>
#include <sys/socket.h>
#include <errno.h>
#include "log.h"
#include "list.h"
#include "client.h"
#include "ssl.h"
#include "messages.h"
#include "messagehandler.h"
#include "pds.h"
#include "conf.h"
#include "channel.h"



static int Client_read(client_t *client);
static int Client_write(client_t *client);
static int Client_voiceMsg(client_t *client, pds_t *pds);
static int Client_send_udp(client_t *client, uint8_t *data, int len);
static void Client_voiceMsg_tunnel(client_t *client, message_t *msg);

declare_list(clients);
static int clientcount; /* = 0 */
static int session = 1;
static int maxBandwidth;

extern int udpsock;

void Client_init()
{
	maxBandwidth = getIntConf(MAX_BANDWIDTH);
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
		Log_debug("Client %s BW available %d", c->playerName, c->availableBandwidth);
		c->availableBandwidth += maxBandwidth;
		if (c->availableBandwidth > bwTop)
			c->availableBandwidth = bwTop;
		
		if (Timer_isElapsed(&c->lastActivity, 1000000LL * INACTICITY_TIMEOUT)) {
			/* No activity from client - assume it is lost and close. */
			Log_info("Session ID %d timeout - closing", c->sessionId);
			Client_free(c);
		}
	}
}

int Client_add(int fd, struct sockaddr_in *remote)
{
	client_t *newclient;

	newclient = malloc(sizeof(client_t));
	if (newclient == NULL)
		Log_fatal("Out of memory");
	memset(newclient, 0, sizeof(client_t));

	newclient->tcpfd = fd;
	memcpy(&newclient->remote_tcp, remote, sizeof(struct sockaddr_in));
	newclient->ssl = SSL_newconnection(newclient->tcpfd, &newclient->SSLready);
	if (newclient->ssl == NULL) {
		Log_warn("SSL negotiation failed");
		free(newclient);
		return -1;
	}
	newclient->availableBandwidth = maxBandwidth;
	Timer_init(&newclient->lastActivity);
	newclient->sessionId = session++; /* XXX - more elaborate? */
	
	init_list_entry(&newclient->txMsgQueue);
	init_list_entry(&newclient->chan_node);
	init_list_entry(&newclient->node);
	
	list_add_tail(&newclient->node, &clients);
	clientcount++;
	return 0;
}

void Client_free(client_t *client)
{
	struct dlist *itr, *save;
	message_t *sendmsg;

	Log_info("Disconnect client ID %d addr %s port %d", client->sessionId,
			 inet_ntoa(client->remote_tcp.sin_addr),
			 ntohs(client->remote_tcp.sin_port));

	if (client->authenticated) {
		sendmsg = Msg_create(ServerLeave);
		sendmsg->sessionId = client->sessionId;
		Client_send_message_except(client, sendmsg);
	}
	list_iterate_safe(itr, save, &client->txMsgQueue) {
		list_del(&list_get_entry(itr, message_t, node)->node);
		Msg_free(list_get_entry(itr, message_t, node));
	}
		
	list_del(&client->node);
	list_del(&client->chan_node);
	if (client->ssl)
		SSL_free(client->ssl);
	close(client->tcpfd);
	clientcount--;
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
		if(fd == list_get_entry(itr, client_t, node)->tcpfd) {
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
			rc = SSL_read(client->ssl, client->rxbuf, 3 - client->rxcount);
		else if (client->drainleft > 0)
			rc = SSL_read(client->ssl, client->rxbuf, client->drainleft > BUFSIZE ? BUFSIZE : client->drainleft);
		else
			rc = SSL_read(client->ssl, &client->rxbuf[client->rxcount], client->msgsize);
		if (rc > 0) {
			message_t *msg;
			if (client->drainleft > 0)
				client->drainleft -= rc;
			else {
				client->rxcount += rc;
				if (!client->msgsize && rc >= 3)
					client->msgsize = ((client->rxbuf[0] & 0xff) << 16) |
						((client->rxbuf[1] & 0xff) << 8) |
						(client->rxbuf[2] & 0xff);
				if (client->msgsize > BUFSIZE - 3 && client->drainleft == 0) {
					Log_warn("Too big message received (%d). Discarding.", client->msgsize);
					client->rxcount = client->msgsize = 0;
					client->drainleft = client->msgsize;
				}
				else if (client->rxcount == client->msgsize + 3) { /* Got all of the message */
					msg = Msg_networkToMessage(&client->rxbuf[3], client->msgsize);
					/* pass messsage to handler */
					if (msg) {
						if (msg->messageType == Speex) /* Tunneled voice message */
							Client_voiceMsg_tunnel(client, msg);
						else 
							Mh_handle_message(client, msg);
					}
					client->rxcount = client->msgsize = 0;
				}
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
				Log_warn("Error: Zero return - closing");
				if (!client->shutdown_wait)
					Client_close(client);
			}
			else {
				if (SSL_get_error(client->ssl, rc) == SSL_ERROR_SYSCALL) {
					/* Hmm. This is where we end up when the client closes its connection.
					 * Kind of strange...
					 */
					Log_info("Connection closed by peer");
				}
				else {
					Log_warn("SSL error: %d - Closing connection.", SSL_get_error(client->ssl, rc));
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
	if (!client->authenticated || !client->SSLready) {
		Msg_free(msg);
		return 0;
	}
	if (client->txsize != 0) {
		/* Queue message */
		if ((client->txQueueCount > 5 &&  msg->messageType == Speex) ||
			client->txQueueCount > 30) {
			Msg_free(msg);
			return -1;
		}
		client->txQueueCount++;
		list_add_tail(&msg->node, &client->txMsgQueue);
	} else {
		int len;
		memset(client->txbuf, 0, BUFSIZE);
		len = Msg_messageToNetwork(msg, &client->txbuf[3], BUFSIZE - 3);
		doAssert(len < BUFSIZE - 3);

		client->txbuf[0] =  (len >> 16) & 0xff;
		client->txbuf[1] =  (len >> 8) & 0xff;
		client->txbuf[2] =  len & 0xff;
		client->txsize = len + 3;
		client->txcount = 0;
		Client_write(client);
		Msg_free(msg);
	}
	return 0;
}

client_t *Client_iterate(client_t **client_itr)
{
	client_t *c = *client_itr;
	
	if (c == NULL && !list_empty(&clients)) {
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
			Log_debug("Msg %d to %s refcount %d",  msg->messageType, itr->playerName, msg->refcount);
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
			
			sendmsg = Msg_create(CryptSync);
			sendmsg->sessionId = client->sessionId;
			sendmsg->payload.cryptSync.empty = true;
			Log_info("Requesting voice channel crypt resync");
			Client_send_message(client, sendmsg);
		}
	}
	return false;
}

int Client_read_udp()
{
	int len;
	struct sockaddr_in from;
	socklen_t fromlen = sizeof(struct sockaddr_in);
	uint64_t key;
	client_t *itr;
	int msgType = 0;
	uint32_t sessionId = 0;
	pds_t *pds;
	
#if defined(__LP64__)
	uint8_t encbuff[512 + 8];
	uint8_t *encrypted = encbuff + 4;
#else
	uint8_t encrypted[512];
#endif
	uint8_t buffer[512];
	
	len = recvfrom(udpsock, encrypted, 512, MSG_TRUNC, (struct sockaddr *)&from, &fromlen);
	if (len == 0) {
		return -1;
	} else if (len < 0) {
		return -1;
	} else if (len < 6) {
		// 4 bytes crypt header + type + session
		return 0;
	} else if (len > 512) {
		return 0;
	}
	
	key = (((uint64_t)from.sin_addr.s_addr) << 16) ^ from.sin_port;
	pds = Pds_create(buffer, len - 4);
	itr = NULL;
	
	while (Client_iterate(&itr) != NULL) {
		if (itr->key == key) {
			if (!checkDecrypt(itr, encrypted, buffer, len))
				goto out;
			msgType = Pds_get_numval(pds);
			sessionId = Pds_get_numval(pds);
			if (itr->sessionId != sessionId)
				goto out;
			break;
		}
	}	
	if (itr == NULL) { /* Unknown peer */
		while (Client_iterate(&itr) != NULL) {
			pds->offset = 0;
			if (itr->remote_tcp.sin_addr.s_addr == from.sin_addr.s_addr) {
				if (checkDecrypt(itr, encrypted, buffer, len)) {
					msgType = Pds_get_numval(pds);
					sessionId = Pds_get_numval(pds);
					if (itr->sessionId == sessionId) { /* Found matching client */
						itr->key = key;
						Log_info("New UDP connection from %s port %d sessionId %d", inet_ntoa(from.sin_addr), ntohs(from.sin_port), sessionId);
						memcpy(&itr->remote_udp, &from, sizeof(struct sockaddr_in));
						break;
					}
				}
				else Log_warn("Bad cryptstate from peer");
			}
		} /* while */
	}
	if (itr == NULL) {
		goto out;
	}
	len -= 4;
	if (msgType != Speex && msgType != Ping)
		goto out;
	
	if (msgType == Ping) {
		Client_send_udp(itr, buffer, len);
	}
	else {
		Client_voiceMsg(itr, pds);
	}
	
out:
	Pds_free(pds);
	return 0;
}

static void Client_voiceMsg_tunnel(client_t *client, message_t *msg)
{
	uint8_t buf[512];
	pds_t *pds = Pds_create(buf, 512);

	Pds_add_numval(pds, msg->messageType);
	Pds_add_numval(pds, msg->sessionId);
	Pds_add_numval(pds, msg->payload.speex.seq);
	Pds_append_data_nosize(pds, msg->payload.speex.data, msg->payload.speex.size);
	if (!pds->bOk)
		Log_warn("Large Speex message from TCP"); /* XXX - pds resize? */
	pds->maxsize = pds->offset;
	Client_voiceMsg(client, pds);
	Pds_free(pds);
}

static int Client_voiceMsg(client_t *client, pds_t *pds)
{
	int seq, flags, msgType, sessionId, packetsize;
	channel_t *ch = (channel_t *)client->channel;
	struct dlist *itr;
	
	if (!client->authenticated || client->mute)
		return 0;

	
	pds->offset = 0;
	msgType = Pds_get_numval(pds);
	sessionId = Pds_get_numval(pds);
	seq = Pds_get_numval(pds);
	flags = Pds_get_numval(pds);

	packetsize = 20 + 8 + 4 + pds->maxsize - pds->offset;
	if (client->availableBandwidth - packetsize < 0)
		return 0; /* Discard */
	
	client->availableBandwidth -= packetsize;
	
	pds->offset = 0;
	
	if (flags & LoopBack) {
		Client_send_udp(client, pds->data, pds->maxsize);
		return 0;
	}
	if (ch == NULL)
		return 0;
	
	list_iterate(itr, &ch->clients) {
		client_t *c;
		c = list_get_entry(itr, client_t, chan_node);
		if (c != client && !c->deaf) {
			Client_send_udp(c, pds->data, pds->maxsize);
		}
	}
	return 0;
}


static int Client_send_udp(client_t *client, uint8_t *data, int len)
{
	uint8_t *buf, *mbuf;
	message_t *sendmsg;

	if (client->remote_udp.sin_port != 0 && CryptState_isValid(&client->cryptState)) {
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
		pds_t *pds = Pds_create(data, len);
		
		sendmsg = Msg_create(Pds_get_numval(pds));
		sendmsg->sessionId = Pds_get_numval(pds);
		
		if (sendmsg->messageType == Speex || sendmsg->messageType == Ping) {
			if (sendmsg->messageType == Speex) {
				sendmsg->payload.speex.seq = Pds_get_numval(pds);
				sendmsg->payload.speex.size = pds->maxsize - pds->offset;
				doAssert(pds->maxsize - pds->offset <= SPEEX_DATA_SIZE);
				memcpy(sendmsg->payload.speex.data, data + pds->offset, pds->maxsize - pds->offset);
			} else { /* Ping */
				sendmsg->payload.ping.timestamp = Pds_get_numval(pds);
			}
			Client_send_message(client, sendmsg);
		} else {
			Log_warn("TCP fallback: Unsupported message type %d", sendmsg->messageType);
			Msg_free(sendmsg);
		}
		Pds_free(pds);
	}
	return 0;
}
