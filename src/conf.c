/* Copyright (C) 2009-2014, Martin Johansson <martin@fatbob.nu>
   Copyright (C) 2005-2014, Thorvald Natvig <thorvald@natvig.com>

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
#include "conf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libconfig.h>

#include "types.h"
#include "log.h"

static config_t configuration;

#define DEFAULT_WELCOME "Welcome to uMurmur!"
#define DEFAULT_MAX_CLIENTS 10
#define DEFAULT_MAX_BANDWIDTH 48000
#define DEFAULT_BINDPORT 64738
#define DEFAULT_BAN_LENGTH (60*60)
#define DEFAULT_OPUS_THRESHOLD 100

const char defaultconfig[] = DEFAULT_CONFIG;

void Conf_init(const char *conffile)
{
	config_init(&configuration);
	if (conffile == NULL)
		conffile = defaultconfig;
	if (config_read_file(&configuration, conffile) != CONFIG_TRUE) {
		Log_fatal("Error reading config file %s line %d: %s", conffile,
			config_error_line(&configuration), config_error_text(&configuration));
	}
}

bool_t Conf_ok(const char *conffile)
{
	bool_t rc = true;
	config_init(&configuration);
	if (conffile == NULL)
		conffile = defaultconfig;
	if (config_read_file(&configuration, conffile) != CONFIG_TRUE) {
		fprintf(stderr, "Error reading config file %s line %d: %s\n", conffile,
			config_error_line(&configuration), config_error_text(&configuration));
		rc = false;
	}
	config_destroy(&configuration);
	return rc;
}

void Conf_deinit(void)
{
	config_destroy(&configuration);
}

const char *getStrConf(param_t param)
{
	config_setting_t *setting = NULL;
	const char *strsetting = NULL;

	switch (param) {
		case CERTIFICATE:
			setting = config_lookup(&configuration, "certificate");
			if (!setting)
				return "/etc/umurmur/certificate.crt";
			else {
				if ((strsetting = config_setting_get_string(setting)) != NULL)
					return strsetting;
				else
					return "/etc/umurmur/certificate.crt";
			}
			break;
		case KEY:
			setting = config_lookup(&configuration, "private_key");
			if (!setting)
				return "/etc/umurmur/private_key.key";
			else {
				if ((strsetting = config_setting_get_string(setting)) != NULL)
					return strsetting;
				else
					return "/etc/umurmur/private_key.key";
			}
			break;
		case CAPATH:
			setting = config_lookup(&configuration, "ca_path");
			if (!setting)
				return NULL;
			else {
				if ((strsetting = config_setting_get_string(setting)) != NULL)
					return strsetting;
				else
					return NULL;
			}
			break;
		case PASSPHRASE:
			setting = config_lookup(&configuration, "password");
			if (!setting)
				return "";
			else {
				if ((strsetting = config_setting_get_string(setting)) != NULL)
					return strsetting;
				else
					return "";
			}
			break;
		case ADMIN_PASSPHRASE:
			setting = config_lookup(&configuration, "admin_password");
			if (!setting)
				return "";
			else {
				if ((strsetting = config_setting_get_string(setting)) != NULL)
					return strsetting;
				else
					return "";
			}
			break;
		case BINDADDR:
			setting = config_lookup(&configuration, "bindaddr");
			if (!setting)
				return NULL;
			else {
				if ((strsetting = config_setting_get_string(setting)) != NULL)
					return strsetting;
				else
					return NULL;
			}
			break;
		case BINDADDR6:
			setting = config_lookup(&configuration, "bindaddr6");
			if (!setting)
				return NULL;
			else {
				if ((strsetting = config_setting_get_string(setting)) != NULL)
					return strsetting;
				else
					return NULL;
			}
			break;
		case WELCOMETEXT:
			setting = config_lookup(&configuration, "welcometext");
			if (!setting)
				return DEFAULT_WELCOME;
			else {
				if ((strsetting = config_setting_get_string(setting)) != NULL)
					return strsetting;
				else
					return DEFAULT_WELCOME;
			}
			break;
		case DEFAULT_CHANNEL:
			setting = config_lookup(&configuration, "default_channel");
			if (!setting)
				return "";
			else {
				if ((strsetting = config_setting_get_string(setting)) != NULL)
					return strsetting;
				else
					return "";
			}
			break;
		case USERNAME:
			setting = config_lookup(&configuration, "username");
			if (!setting)
				return "";
			else {
				if ((strsetting = config_setting_get_string(setting)) != NULL)
					return strsetting;
				else
					return "";
			}
			break;
		case GROUPNAME:
			setting = config_lookup(&configuration, "groupname");
			if (!setting)
				return "";
			else {
				if ((strsetting = config_setting_get_string(setting)) != NULL)
					return strsetting;
				else
					return "";
			}
			break;
		case LOGFILE:
			setting = config_lookup(&configuration, "logfile");
			if (!setting)
				return NULL;
			else {
				if ((strsetting = config_setting_get_string(setting)) != NULL)
					return strsetting;
				else
					return NULL;
			}
			break;
		case BANFILE:
			setting = config_lookup(&configuration, "banfile");
			if (!setting)
				return NULL;
			else {
				if ((strsetting = config_setting_get_string(setting)) != NULL)
					return strsetting;
				else
					return NULL;
			}
			break;
		default:
			doAssert(false);
			break;
	}
	return NULL;
}

int getIntConf(param_t param)
{
	config_setting_t *setting = NULL;

	switch (param) {
		case BINDPORT:
			setting = config_lookup(&configuration, "bindport");
			if (!setting)
				return DEFAULT_BINDPORT;
			else {
				return config_setting_get_int(setting);
			}
			break;
		case BINDPORT6:
			setting = config_lookup(&configuration, "bindport6");
			if (!setting)
				/* If bindport6 is not specified, we default
				 * to whatever bindport is, rather than always
				 * default to 64738 */
				return getIntConf(BINDPORT);
			else {
				return config_setting_get_int(setting);
			}
			break;
		case BAN_LENGTH:
			setting = config_lookup(&configuration, "ban_length");
			if (!setting)
				return DEFAULT_BAN_LENGTH;
			else {
				return config_setting_get_int(setting);
			}
			break;
		case MAX_BANDWIDTH:
			setting = config_lookup(&configuration, "max_bandwidth");
			if (!setting)
				return DEFAULT_MAX_BANDWIDTH;
			else {
				return config_setting_get_int(setting);
			}
			break;
		case MAX_CLIENTS:
			setting = config_lookup(&configuration, "max_users");
			if (!setting)
				return DEFAULT_MAX_CLIENTS;
			else {
				return config_setting_get_int(setting);
			}
			break;
		case OPUS_THRESHOLD:
			setting = config_lookup(&configuration, "opus_threshold");
			if (!setting)
				return DEFAULT_OPUS_THRESHOLD;
			else {
				return config_setting_get_int(setting);
			}
			break;
		default:
			doAssert(false);
	}
}

bool_t getBoolConf(param_t param)
{
	config_setting_t *setting = NULL;

	switch (param) {
		case ALLOW_TEXTMESSAGE:
			setting = config_lookup(&configuration, "allow_textmessage");
			if (!setting)
				return true;
			else
				return config_setting_get_bool(setting);
			break;
		case ENABLE_BAN:
			setting = config_lookup(&configuration, "enable_ban");
			if (!setting)
				return false;
			else
				return config_setting_get_bool(setting);
			break;
		case SYNC_BANFILE:
			setting = config_lookup(&configuration, "sync_banfile");
			if (!setting)
				return false;
			else
				return config_setting_get_bool(setting);
			break;
		case SHOW_ADDRESSES:
			setting = config_lookup(&configuration, "show_addresses");
			if (!setting)
				return true;
			else
				return config_setting_get_bool(setting);
			break;
		default:
			doAssert(false);
	}
}

int Conf_getNextChannel(conf_channel_t *chdesc, int index)
{
	config_setting_t *setting = NULL;
	int maxconfig = 64, ret = 0;
	char configstr[maxconfig];

	ret = snprintf(configstr, maxconfig, "channels.[%d].name", index);
	setting = config_lookup(&configuration, configstr);
	if (ret >= maxconfig || ret < 0 || setting == NULL)
		return -1; /* Required */
	chdesc->name =  config_setting_get_string(setting);

	ret = snprintf(configstr, maxconfig, "channels.[%d].parent", index);
	setting = config_lookup(&configuration, configstr);
	if (ret >= maxconfig || ret < 0 || setting == NULL)
		return -1; /* Required */
	chdesc->parent = config_setting_get_string(setting);

	ret = snprintf(configstr, maxconfig, "channels.[%d].description", index);
	setting = config_lookup(&configuration, configstr);
	if (ret >= maxconfig || ret < 0 || setting == NULL) /* Optional */
		chdesc->description = NULL;
	else
		chdesc->description = config_setting_get_string(setting);

	ret = snprintf(configstr, maxconfig, "channels.[%d].password", index);
	setting = config_lookup(&configuration, configstr);
	if (ret >= maxconfig || ret < 0 || setting == NULL) /* Optional */
		chdesc->password = NULL;
	else
		chdesc->password = config_setting_get_string(setting);

	ret = snprintf(configstr, maxconfig, "channels.[%d].noenter", index);
	setting = config_lookup(&configuration, configstr);
	if (ret >= maxconfig || ret < 0 || setting == NULL) /* Optional */
		chdesc->noenter = false;
	else
		chdesc->noenter = config_setting_get_bool(setting);

	ret = snprintf(configstr, maxconfig, "channels.[%d].silent", index);
	setting = config_lookup(&configuration, configstr);
	if (ret >= maxconfig || ret < 0 || setting == NULL) /* Optional */
		chdesc->silent = false;
	else
		chdesc->silent = config_setting_get_bool(setting);

	ret = snprintf(configstr, maxconfig, "channels.[%d].allow_temp", index);
	setting = config_lookup(&configuration, configstr);
	if (ret >= maxconfig || ret < 0 || setting == NULL) /* Optional */
		chdesc->allow_temp = false;
	else
		chdesc->allow_temp = config_setting_get_bool(setting);

	ret = snprintf(configstr, maxconfig, "channels.[%d].position", index);
	setting = config_lookup(&configuration, configstr);
	if (ret >= maxconfig || ret < 0 || setting == NULL) /* Optional */
		chdesc->position = 0;
	else
		chdesc->position = config_setting_get_int(setting);

	return 0;
}

int Conf_getNextChannelLink(conf_channel_link_t *chlink, int index)
{
	config_setting_t *setting = NULL;
	int maxconfig = 64, ret = 0;
	char configstr[maxconfig];

	ret = snprintf(configstr, maxconfig, "channel_links.[%d].source", index);
	setting = config_lookup(&configuration, configstr);
	if (ret >= maxconfig || ret < 0 || setting == NULL)
		return -1;
	chlink->source = config_setting_get_string(setting);

	ret = snprintf(configstr, maxconfig, "channel_links.[%d].destination", index);
	setting = config_lookup(&configuration, configstr);
	if (ret >= maxconfig || ret < 0 || setting == NULL)
		return -1;
	chlink->destination = config_setting_get_string(setting);

	return 0;
}
