#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <getopt.h>

#include "log.h"
#include "utils.h"

int conf_parse_args(config_t *conf, int argc, char** argv)
{
	int ch;
	int option_index = 0;
	static struct option long_options[] = {
		{"daemon",       no_argument,       NULL, 1},
		{"pid",          required_argument, NULL, 2},
		{"log",          required_argument, NULL, 3},
		{"log-level",    required_argument, NULL, 4},
		{"config",       required_argument, NULL, 5},
		{"launch-log",   required_argument, NULL, 6},
		{"proxy",        required_argument, NULL, 7},
		{"chnroute",     required_argument, NULL, 8},
		{"channel",      required_argument, NULL, 9},
		{"channel-args", required_argument, NULL, 10},
		{0, 0, 0, 0}
	};

	while ((ch = getopt_long(argc, argv, "hb:p:t:vV", long_options, &option_index)) != -1) {
		switch (ch) {
		case 1:
			conf->daemonize = 1;
			break;
		case 2:
			conf->pid_file = strdup(optarg);
			break;
		case 3:
			conf->log_file = strdup(optarg);
			break;
		case 4:
			conf->log_level = atoi(optarg);
			break;
		case 5:
			conf->config_file = strdup(optarg);
			break;
		case 6:
			conf->launch_log = strdup(optarg);
			break;
		case 7:
			conf->proxy = strdup(optarg);
			break;
		case 8:
			conf->chnroute = strdup(optarg);
			break;
		case 9:
			conf->channel = strdup(optarg);
			break;
		case 10:
			conf->channel_args = strdup(optarg);
			break;
		case 'h':
			conf->is_print_help = 1;
			break;
		case 'b':
			conf->listen_addr = strdup(optarg);
			break;
		case 'p':
			conf->listen_port = strdup(optarg);
			break;
		case 't':
			conf->timeout = atoi(optarg);
			break;
		case 'v':
			conf->log_level++;
			break;
		case 'V':
			conf->is_print_version = 1;
			break;
		default:
			return -1;
		}
	}

	return 0;
}

int conf_check(config_t* conf)
{
	if (conf->listen_addr == NULL) {
		conf->listen_addr = strdup(DEFAULT_LISTEN_ADDR);
	}
	if (conf->listen_port == NULL) {
		conf->listen_port = strdup(DEFAULT_LISTEN_PORT);
	}
	if (conf->timeout <= 0) {
		conf->timeout = DEFAULT_TIMEOUT;
	}
	if (conf->channel == NULL) {
		conf->channel = strdup(DEFAULT_CHANNEL);
	}
	return 0;
}

void conf_print(const config_t* conf)
{
	if (conf->log_file)
		logn("log_file: %s\n", conf->log_file);

	if (conf->chnroute)
		logn("chnroute: %s\n", conf->chnroute);

	if (conf->proxy)
		logn("proxy: %s\n", conf->proxy);

	if (conf->timeout > 0)
		logn("peer timeout: %d\n", conf->timeout);

	if (conf->channel)
		logn("channel: %s\n", conf->channel);

    if (conf->channel_args)
		logn("channel args: %s\n", conf->channel_args);

#ifndef WINDOWS
	if (conf->daemonize) {
		logn("pid file: %s\n", conf->pid_file);
	}
#endif

	logn("\n");
}

/* parse 'option key value' as independent components */
static void parse_option(char* ln, char** option, char** name, char** value)
{
	char* p = ln;

	*option = p;
	*name = NULL;
	*value = NULL;

	while (*p && !isspace((int)(*((unsigned char*)p)))) p++;

	if (!(*p))
		return;

	*p = '\0';

	p = ltrim(p + 1);

	*name = p;

	while (*p && !isspace((int)(*((unsigned char*)p)))) p++;

	if (!(*p))
		return;

	*p = '\0';

	p = ltrim(p + 1);

	*value = trim_quote(p);
}

int conf_load_from_file(config_t* conf, const char* config_file, int force)
{
	FILE* pf;
	char line[2048], * ln;
	char* option, * name, * value;
	int len = 0, cnf_index = -1;

	pf = fopen(config_file, "r");
	if (!pf) {
		loge("failed to open %s\n", config_file);
		return -1;
	}

#define is_true_val(s) \
   (strcmp((s), "1") == 0 || \
    strcmp((s), "on") == 0 || \
	strcmp((s), "true") == 0 || \
	strcmp((s), "yes") == 0 || \
	strcmp((s), "enabled") == 0)

	while (!feof(pf)) {
		memset(line, 0, sizeof(line));
		fgets(line, sizeof(line) - 1, pf);
		ln = line;
		ln = ltrim(ln);
		ln = rtrim(ln);
		if (*ln == '\0' || *ln == '#')
			continue;

		if (strncmp(ln, "config", 6) == 0 &&
			isspace(ln[6]) &&
			strncmp((ln = ltrim(ln + 6)), "cfg", 3) == 0 &&
			(ln[3] == '\0' || isspace((int)(*((unsigned char*)ln + 3))))) {
			cnf_index++;
			if (cnf_index > 0) /*only parse first 'config cfg'*/
				break;
			continue;
		}

		if (cnf_index != 0)
			continue;

		parse_option(ln, &option, &name, &value);

		if (strcmp(option, "option") != 0 || !name || !value || !(*name) || !(*value)) {
			loge("invalid option: %s %s %s\n", option, name, value);
			fclose(pf);
			return -1;
		}

		if (strcmp(name, "bind_addr") == 0 && strlen(value)) {
			if (force || !conf->listen_addr) {
				free(conf->listen_addr);
				conf->listen_addr = strdup(value);
			}
		}
		else if (strcmp(name, "bind_port") == 0 && strlen(value)) {
			if (force || !conf->listen_port) {
				free(conf->listen_port);
				conf->listen_port = strdup(value);
			}
		}
		else if (strcmp(name, "timeout") == 0 && strlen(value)) {
			if (force || conf->timeout <= 0) {
				conf->timeout = atoi(value);
			}
		}
		else if (strcmp(name, "pid_file") == 0 && strlen(value)) {
			if (force || !conf->pid_file) {
				free(conf->pid_file);
				conf->pid_file = strdup(value);
			}
		}
		else if (strcmp(name, "log_file") == 0 && strlen(value)) {
			if (force || !conf->log_file) {
				free(conf->log_file);
				conf->log_file = strdup(value);
			}
		}
		else if (strcmp(name, "log_level") == 0 && strlen(value)) {
			if (force || loglevel == LOG_DEFAULT_LEVEL) {
				loglevel = atoi(value);
			}
		}
		else if (strcmp(name, "chnroute") == 0 && strlen(value)) {
			if (force || !conf->chnroute) {
				free(conf->chnroute);
				conf->chnroute = strdup(value);
			}
		}
		else if (strcmp(name, "proxy") == 0 && strlen(value)) {
			if (force || !conf->proxy) {
				free(conf->proxy);
				conf->proxy = strdup(value);
			}
		}
		else if (strcmp(name, "channel") == 0 && strlen(value)) {
			if (force || !conf->channel) {
				free(conf->channel);
				conf->channel = strdup(value);
			}
		}
        else if (strcmp(name, "channel_args") == 0 && strlen(value)) {
			if (force || !conf->channel_args) {
				free(conf->channel_args);
				conf->channel_args = strdup(value);
			}
		}
		else {
			/*do nothing*/
		}
	}

	fclose(pf);

#undef is_true_val

	return 0;
}

void conf_free(config_t* conf)
{
	free(conf->listen_addr);
	conf->listen_addr = NULL;

	free(conf->listen_port);
	conf->listen_port = NULL;

	free(conf->pid_file);
	conf->pid_file = NULL;

	free(conf->log_file);
	conf->log_file = NULL;

	free(conf->launch_log);
	conf->launch_log = NULL;

	free(conf->config_file);
	conf->config_file = NULL;

	free(conf->chnroute);
	conf->chnroute = NULL;

	free(conf->channel_args);
	conf->channel_args = NULL;

	free(conf->channel);
	conf->channel = NULL;
}
