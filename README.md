# dohclient

DoH Client.

### Build on Linux

```
git clone https://github.com/GangZhuo/dohclient.git
cd dohclient
git submodule update --init
make
```

### Build on Windows

```
git clone https://github.com/GangZhuo/dohclient.git
cd dohclient
git submodule update --init
# Put openssl library into windows/openssl directory.
# Follow <https://github.com/GangZhuo/dohclient/blob/master/windows/openssl/Readme.md>
# Open windows/dohclient.sln by Visual Studio.
```

### Build on Termux

```
make MYLIBS=-llog
```

### Usage

```
dohclient [-b BIND_ADDR] [-p BIND_PORT] [--config=CONFIG_PATH]
         [--channel=CHANNEL] [--channel-args=ARGS]
         [--log=LOG_FILE_PATH] [--log-level=LOG_LEVEL]
         [--chnroute=CHNROUTE_FILE] [--proxy=SOCKS5_PROXY]
         [--daemon] [--pid=PID_FILE_PATH] [-v] [-V] [-h]

DoH client.

Options:

  -b BIND_ADDR             Address that listens, default: 0.0.0.0.
                           Use comma to separate multi addresses,
                           e.g. -b 127.0.0.1:5354,[::1]:5354.
  -p BIND_PORT             Port that listen on, default: 53.
                           The port specified in "-b" is priority .
  -t TIMEOUT               Timeout (seconds), default: 5.
  --channel=CHANNEL        Channel name, e.g. os,doh,chinadns.
  --channel-args=ARGS      Channel arguments. e.g. --channel-args="addr=8.8.4.4:443
                           &host=dns.google&path=/dns-query&proxy=1&ecs=1
                           &china-ip4=114.114.114.114/24&china-ip6=2405:2d80::/32
                           &foreign-ip4=8.8.8.8/24&foreign-ip6=2001:df2:8300::/48".
  --daemon                 Daemonize.
  --pid=PID_FILE_PATH      pid file, default: /var/run/dohclient.pid,
                           only available on daemonize.
  --log=LOG_FILE_PATH      Write log to a file.
  --log-level=LOG_LEVEL    Log level, range: [0, 7], default: 5.
  --config=CONFIG_PATH     Config file, find sample at
                           https://github.com/GangZhuo/dohclient.
  --chnroute=CHNROUTE_FILE Path to china route file,
                           e.g.: --chnroute=lan.txt,chnroute.txt,chnroute6.txt.
  --proxy=SOCKS5_PROXY     Socks5 proxy, e.g. --proxy=127.0.0.1:1080
                           or --proxy=[::1]:1080.
                           Only socks5 with no authentication is supported.
  -v                       Verbose logging.
  -h                       Show this help message and exit.
  -V                       Print version and then exit.

Online help: <https://github.com/GangZhuo/dohclient>
```

### Channels

1. os

```
dohclient -b 0.0.0.0 -p 5354 --channel=os
```

Query by OS function getaddrinfo().





