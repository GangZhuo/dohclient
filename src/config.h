#ifndef DOHCLIENT_CONFIG_H_
#define DOHCLIENT_CONFIG_H_

#define DEFAULT_LISTEN_ADDR "0.0.0.0"
#define DEFAULT_LISTEN_PORT "53"
#define DEFAULT_PID_FILE "/var/run/dohclient.pid"
#define DEFAULT_TIMEOUT 5
#define DEFAULT_CHANNEL "doh"
#define DEFAULT_CHANNEL_ARGS "addr=223.5.5.5:443&host=dns.alidns.com&path=/dns-query&proxy=0"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct config_t {
	char* listen_addr;
	char* listen_port;
	char* pid_file;
	char* log_file;
	int daemonize;
	char* launch_log;
	char* config_file;
	int timeout;
	char* proxy;
	char* chnroute;
	char* blacklist;
	char* hosts;
	char** channels;
	char** channel_args;
	int log_level;
	int is_print_version;
	int is_print_help;
	int is_config_file_readed;
} config_t;

int conf_parse_args(config_t* conf, int argc, char** argv);
int conf_load_from_file(config_t* conf, const char* config_file, int force);
int conf_check(config_t* conf);
void conf_print(const config_t* conf);
void conf_free(config_t* conf);

#ifdef __cplusplus
}
#endif

#endif
