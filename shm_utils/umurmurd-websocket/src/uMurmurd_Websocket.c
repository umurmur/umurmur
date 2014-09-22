/*
 * uMurmurd Websocket server - HTTP/JSON serverexample
 *
 * Copyright (C) 2014 Michael P. Pounders <>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */
#ifdef CMAKE_BUILD
#include "lws_config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#include <syslog.h>

#include <signal.h>

#include <jansson.h>

#include <libwebsockets.h>
#include "../../../src/sharedmemory.h"

int max_poll_elements;

struct pollfd *pollfds;
int *fd_lookup;
int count_pollfds;
int force_exit = 0;

enum demo_protocols {
	/* always first */
	PROTOCOL_HTTP = 0,

	PROTOCOL_JSON_UMURMURD,

	/* always last */
	DEMO_PROTOCOL_COUNT
};



char *resource_path = "../web";

/*
 * We take a strict whitelist approach to stop ../ attacks
 */

struct serveable {
	const char *urlpath;
	const char *mimetype;
}; 

static const struct serveable whitelist[] = {
	{ "/favicon.ico", "image/x-icon" },
  { "/css/mon_umurmurd.css", "text/css" },
  { "/css/json.human.css", "text/css" },
  { "/js/crel.js", "text/javascript" },
  { "/js/json.human.js", "text/javascript" },
  { "/js/jquery.min.js", "text/javascript" },
  
	/* last one is the default served if no match */
	{ "/mon_umurmurd.html", "text/html" },
};

struct per_session_data__http {
	int fd;
};

/* this protocol server (always the first one) just knows how to do HTTP */

static int callback_http( struct libwebsocket_context *context,
		                      struct libwebsocket *wsi,
		                      enum libwebsocket_callback_reasons reason, void *user,
							            void *in, size_t len)
{
#if 0
	char client_name[128];
	char client_ip[128];
#endif
	char buf[256];
	char leaf_path[1024];
	int n, m;
	unsigned char *p;
	static unsigned char buffer[4096];
	struct stat stat_buf;
	struct per_session_data__http *pss =
			(struct per_session_data__http *)user;

	switch (reason) {
	case LWS_CALLBACK_HTTP:

		/* check for the "send a big file by hand" example case */

		if (!strcmp((const char *)in, "/leaf.jpg")) {
			if (strlen(resource_path) > sizeof(leaf_path) - 10)
				return -1;
			sprintf(leaf_path, "%s/leaf.jpg", resource_path);

			/* well, let's demonstrate how to send the hard way */

			p = buffer;

			pss->fd = open(leaf_path, O_RDONLY);

			if (pss->fd < 0)
				return -1;

			fstat(pss->fd, &stat_buf);

			/*
			 * we will send a big jpeg file, but it could be
			 * anything.  Set the Content-Type: appropriately
			 * so the browser knows what to do with it.
			 */

			p += sprintf((char *)p,
				"HTTP/1.0 200 OK\x0d\x0a"
				"Server: libwebsockets\x0d\x0a"
				"Content-Type: image/jpeg\x0d\x0a"
					"Content-Length: %u\x0d\x0a\x0d\x0a",
					(unsigned int)stat_buf.st_size);

			/*
			 * send the http headers...
			 * this won't block since it's the first payload sent
			 * on the connection since it was established
			 * (too small for partial)
			 */

			n = libwebsocket_write(wsi, buffer,
				   p - buffer, LWS_WRITE_HTTP);

			if (n < 0) {
				close(pss->fd);
				return -1;
			}
			/*
			 * book us a LWS_CALLBACK_HTTP_WRITEABLE callback
			 */
			libwebsocket_callback_on_writable(context, wsi);
			break;
		}

		/* if not, send a file the easy way */

		for (n = 0; n < (sizeof(whitelist) / sizeof(whitelist[0]) - 1); n++)
			if (in && strcmp((const char *)in, whitelist[n].urlpath) == 0)
				break;

		sprintf(buf, "%s%s", resource_path, whitelist[n].urlpath);

		if (libwebsockets_serve_http_file(context, wsi, buf, whitelist[n].mimetype))
			return -1; /* through completion or error, close the socket */

		/*
		 * notice that the sending of the file completes asynchronously,
		 * we'll get a LWS_CALLBACK_HTTP_FILE_COMPLETION callback when
		 * it's done
		 */

		break;

	case LWS_CALLBACK_HTTP_FILE_COMPLETION:
//		lwsl_info("LWS_CALLBACK_HTTP_FILE_COMPLETION seen\n");
		/* kill the connection after we sent one file */
		return -1;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		/*
		 * we can send more of whatever it is we were sending
		 */

		do {
			n = read(pss->fd, buffer, sizeof buffer);
			/* problem reading, close conn */
			if (n < 0)
				goto bail;
			/* sent it all, close conn */
			if (n == 0)
				goto bail;
			/*
			 * because it's HTTP and not websocket, don't need to take
			 * care about pre and postamble
			 */
			m = libwebsocket_write(wsi, buffer, n, LWS_WRITE_HTTP);
			if (m < 0)
				/* write failed, close conn */
				goto bail;
			if (m != n)
				/* partial write, adjust */
				lseek(pss->fd, m - n, SEEK_CUR);

		} while (!lws_send_pipe_choked(wsi));
		libwebsocket_callback_on_writable(context, wsi);
		break;

bail:
		close(pss->fd);
		return -1;

	/*
	 * callback for confirming to continue with client IP appear in
	 * protocol 0 callback since no websocket protocol has been agreed
	 * yet.  You can just ignore this if you won't filter on client IP
	 * since the default uhandled callback return is 0 meaning let the
	 * connection continue.
	 */

	case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
#if 0
		libwebsockets_get_peer_addresses(context, wsi, (int)(long)in, client_name,
			     sizeof(client_name), client_ip, sizeof(client_ip));

		fprintf(stderr, "Received network connect from %s (%s)\n",
							client_name, client_ip);
#endif
		/* if we returned non-zero from here, we kill the connection */
		break;

	default:
		break;
	}

	return 0;
}

/*
 * this is just an example of parsing handshake headers, you don't need this
 * in your code unless you will filter allowing connections by the header
 * content
 */

static void
dump_handshake_info(struct libwebsocket *wsi)
{
	int n;
	static const char *token_names[WSI_TOKEN_COUNT] = {
		/*[WSI_TOKEN_GET_URI]       =*/ "GET URI",
		/*[WSI_TOKEN_HOST]		      =*/ "Host",
		/*[WSI_TOKEN_CONNECTION]	  =*/ "Connection",
		/*[WSI_TOKEN_KEY1]		      =*/ "key 1",
		/*[WSI_TOKEN_KEY2]		      =*/ "key 2",
		/*[WSI_TOKEN_PROTOCOL]		  =*/ "Protocol",
		/*[WSI_TOKEN_UPGRADE]		    =*/ "Upgrade",
		/*[WSI_TOKEN_ORIGIN]		    =*/ "Origin",
		/*[WSI_TOKEN_DRAFT]		      =*/ "Draft",
		/*[WSI_TOKEN_CHALLENGE]		  =*/ "Challenge",

		/* new for 04 */
		/*[WSI_TOKEN_KEY]		        =*/ "Key",
		/*[WSI_TOKEN_VERSION]		    =*/ "Version",
		/*[WSI_TOKEN_SWORIGIN]		  =*/ "Sworigin",

		/* new for 05 */
		/*[WSI_TOKEN_EXTENSIONS]	  =*/ "Extensions",

		/* client receives these */
		/*[WSI_TOKEN_ACCEPT]		    =*/ "Accept",
		/*[WSI_TOKEN_NONCE]		      =*/ "Nonce",
		/*[WSI_TOKEN_HTTP]		      =*/ "Http",
		/*[WSI_TOKEN_MUXURL]	      =*/ "MuxURL",
	};
	char buf[256];

	for (n = 0; n < WSI_TOKEN_COUNT; n++) {
		if (!lws_hdr_total_length(wsi, n))
			continue;

		lws_hdr_copy(wsi, buf, sizeof buf, n);

		fprintf(stderr, "    %s = %s\n", token_names[n], buf);
	}
}

void *getJsonData( unsigned char * buf, int *n )
{

int cc;
json_t *jarr1;
char *result = NULL;

json_t *root = NULL, *server = NULL, *client, *clients;

    root = json_object();
    clients = json_object();

          
          server = json_pack( "{s:{:s:i,s:i}}", 
                              "server", 
                              "clients_max", shmptr->server_max_clients, 
                              "clients_connected", shmptr->clientcount );
    
        json_object_update( root, server );
          
        if( shmptr->clientcount )
        {  
          jarr1 = json_array();
              
          for( cc = 0 ; cc < shmptr->server_max_clients ; cc++ )
          {
          
          if( !shmptr->client[cc].authenticated )
            continue;
                                                                               
          client = json_pack( "{:s:s,s:s,s:i,s:s,s:I,s:I,s:I}", "username", 
                                            shmptr->client[cc].username, 
                                            "ipaddress", 
                                            shmptr->client[cc].ipaddress,
                                            "udp_port",
                                            shmptr->client[cc].udp_port,
                                            "channel",
                                            shmptr->client[cc].channel,
                                            "lastactivity",
                                            shmptr->client[cc].lastActivity,
                                            "connecttime",
                                            shmptr->client[cc].connectTime,
                                            "idleTime",
                                            (long long unsigned int)shmptr->client[cc].lastActivity - shmptr->client[cc].idleTime                                            
                                            );                                                                                                                                                   
          json_array_append_new( jarr1, client );           
          } 
 json_object_set_new( clients, "clients", jarr1 );         
 json_object_update( root, clients );
}
  json_dump_file(root, "json.txt", JSON_PRESERVE_ORDER | JSON_INDENT(4) );        
  result = json_dumps(root, JSON_PRESERVE_ORDER | JSON_COMPACT );

  *n = sprintf( (char *)&buf[LWS_SEND_BUFFER_PRE_PADDING], "%s", result  );
     

  if( result )
    free( result );

  json_decref(root);
  return 0;         
}

struct per_session_data__umurmur_json {
	int test;
};

static int
callback_umurmur_json( struct libwebsocket_context *context,
			                 struct libwebsocket *wsi,
			                 enum libwebsocket_callback_reasons reason,
					             void *user, void *in, size_t len)
{
	int m, n;

	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 4096 +
						        LWS_SEND_BUFFER_POST_PADDING];
	
	//struct per_session_data__umurmur_json *pss = (struct per_session_data__umurmur_json *)user;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_info("callback_umurmur_json: LWS_CALLBACK_ESTABLISHED\n");            
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
    getJsonData( buf, &n );
    m = libwebsocket_write(wsi, &buf[LWS_SEND_BUFFER_PRE_PADDING], n, LWS_WRITE_TEXT);  //printf("N: %d M: %d\n", n, m );

    if( m == n )
        return 1;
		break;

	case LWS_CALLBACK_RECEIVE:
  	//fprintf(stderr, "rx %d\n", (int)len);
		if (len < 6)
			break;
		if (strcmp((const char *)in, "update\n") == 0)
			libwebsocket_callback_on_writable_all_protocol(libwebsockets_get_protocol( wsi ));
      
		break;
	/*
	 * this just demonstrates how to use the protocol filter. If you won't
	 * study and reject connections based on header content, you don't need
	 * to handle this callback
	 */

	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		dump_handshake_info(wsi);
		/* you could return non-zero here and kill the connection */
		break;

	default:
		break;
	}

	return 0;
}



/* list of supported protocols and callbacks */

static struct libwebsocket_protocols protocols[] = {
	/* first protocol must always be HTTP handler */

	{
		"http-only",                            /* name */
		callback_http,		                      /* callback */
		sizeof (struct per_session_data__http), /* per_session_data_size */
		0,			                                /* max frame size / rx buffer */
	},
	{
		"umurmur-json-protocol",
		callback_umurmur_json,
		sizeof(struct per_session_data__umurmur_json),
		128,
	},
	{ NULL, NULL, 0, 0 } /* terminator */
};

void sighandler(int sig)
{
	force_exit = 1;
}

static struct option options[] = {
	{ "help",	no_argument,		NULL, 'h' },
	{ "debug",	required_argument,	NULL, 'd' },
	{ "port",	required_argument,	NULL, 'p' },
	{ "ssl",	no_argument,		NULL, 's' },
	{ "interface",  required_argument,	NULL, 'i' },
	{ "daemonize", 	no_argument,		NULL, 'D' },
	{ "resource_path", required_argument,		NULL, 'r' },
	{ NULL, 0, 0, 0 }
};

int main(int argc, char **argv)
{
	char cert_path[1024];
	char key_path[1024];
	int n = 0;
	int use_ssl = 0;
	struct libwebsocket_context *context;
	int opts = 0;
	char interface_name[128] = "";
	const char *iface = NULL;
//	unsigned int oldus = 0;
	struct lws_context_creation_info info;

  int syslog_options = LOG_PID | LOG_PERROR; 

	int debug_level = 7;

	int daemonize = 0;


	memset(&info, 0, sizeof info);
	info.port = 7681;

	while (n >= 0) {
		n = getopt_long(argc, argv, "i:hsp:d:Dr:", options, NULL);
		if (n < 0)
			continue;
		switch (n) {
		case 'D':
			daemonize = 1;
			syslog_options &= ~LOG_PERROR;
			break;

		case 'd':
			debug_level = atoi(optarg);
			break;
		case 's':
			use_ssl = 1;
			break;
		case 'p':
			info.port = atoi(optarg);
			break;
		case 'i':
			strncpy(interface_name, optarg, sizeof interface_name);
			interface_name[(sizeof interface_name) - 1] = '\0';
			iface = interface_name;
			break;
		case 'r':
			resource_path = optarg;
			printf("Setting resource path to \"%s\"\n", resource_path);
			break;
		case 'h':
			fprintf(stderr, "Usage: test-server "
					"[--port=<p>] [--ssl] "
					"[-d <log bitfield>] "
					"[--resource_path <path>]\n");
			exit(1);
		}
	}

key_t key = 0x53021d79;

                    if( ( shmid = shmget( key, 0, 0) ) == -1 )
                    {
                        perror("shmget");
                        printf( "umurmurd doesn't seem to be running\n\r" );                        
                        exit(EXIT_FAILURE);
                    }

                    
                    if( ( shmptr = shmat( shmid,0, 0 ) ) == (void *) -1 )   
                    {
                        perror("shmat");
                        exit(EXIT_FAILURE);
                    }


	/* 
	 * normally lock path would be /var/lock/lwsts or similar, to
	 * simplify getting started without having to take care about
	 * permissions or running as root, set to /tmp/.lwsts-lock
	 */
	if (daemonize && lws_daemonize("/tmp/.lwsts-lock")) {
		fprintf(stderr, "Failed to daemonize\n");
		return 1;
	}


	signal(SIGINT, sighandler);


	/* we will only try to log things according to our debug_level */
	setlogmask(LOG_UPTO (LOG_DEBUG));
	openlog("lwsts", syslog_options, LOG_DAEMON);


	/* tell the library what debug level to emit and to send it to syslog */
	lws_set_log_level(debug_level, lwsl_emit_syslog);

	lwsl_notice("uMurmurd Websocket server - "
			"(C) Copyright 2014 Michael J. Pounders <> - "
						    "licensed under LGPL2.1\n");

	info.iface = iface;
	info.protocols = protocols;

	info.extensions = libwebsocket_get_internal_extensions();

	if (!use_ssl) {
		info.ssl_cert_filepath = NULL;
		info.ssl_private_key_filepath = NULL;
	} else {
		if (strlen(resource_path) > sizeof(cert_path) - 32) {
			lwsl_err("resource path too long\n");
			return -1;
		}
		sprintf(cert_path, "%s/ssl/umurmurd_websocket.pem",
								resource_path);
		if (strlen(resource_path) > sizeof(key_path) - 32) {
			lwsl_err("resource path too long\n");
			return -1;
		}
		sprintf(key_path, "%s/ssl/umurmurd_websocket.key.pem",
								resource_path);

		info.ssl_cert_filepath = cert_path;
		info.ssl_private_key_filepath = key_path;
	}
	info.gid = -1;
	info.uid = -1;
	info.options = opts;

	context = libwebsocket_create_context(&info);
	if (context == NULL) {
		lwsl_err("libwebsocket init failed\n");
		return -1;
	}

	n = 0;
	while (n >= 0 && !force_exit) {
		struct timeval tv;

		gettimeofday(&tv, NULL);

		/*
		 * This provokes the LWS_CALLBACK_SERVER_WRITEABLE for every
		 * live websocket connection using the DUMB_INCREMENT protocol,
		 * as soon as it can take more packets (usually immediately)
		 */

// 		if (((unsigned int)tv.tv_usec - oldus) > 50000) {
// 			libwebsocket_callback_on_writable_all_protocol(&protocols[PROTOCOL_JSON_UMURMURD]);
//       oldus = tv.tv_usec;
//		}


		/*
		 * If libwebsockets sockets are all we care about,
		 * you can use this api which takes care of the poll()
		 * and looping through finding who needed service.
		 *
		 * If no socket needs service, it'll return anyway after
		 * the number of ms in the second argument.
		 */

		n = libwebsocket_service(context, 50);

	}


	libwebsocket_context_destroy(context);

	lwsl_notice("umurmur_websocket server exited cleanly\n");

  shmdt( shmptr );
	closelog();

	return 0;
}
