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

Example:
```
dohclient -b 0.0.0.0 -p 5354 --channel=os
```

Query by OS function getaddrinfo().

2. doh

Example:
```
dohclient -b 0.0.0.0 -p 555 --proxy=127.0.0.1:1080 \
          --chnroute="/etc/dohclient/chnroute.txt,/etc/dohclient/chnroute6.txt" \
          --channel=doh \
          --channel-args="addr=172.67.153.110:443&host=doh.beike.workers.dev&path=/dns-query&post=0&keep-alive=1&proxy=0&ecs=1&china-ip4=114.114.114.114/24&china-ip6=2405:2d80::/32&foreign-ip4=8.8.8.8/24&foreign-ip6=2001:df2:8300::/48"
```

ecs=0 时，等同于 DoH 服务的代理。ecs=1 时，使用每一个子网向 DoH 服务查询域名，当查询结果中包含中国 IP 时，选择中国子网的结果返回，否则选择国外子网的结果返回。

#### Channel Arguments

* addr=<IP>[:PORT]

DoH 服务器的地址，第 1 次启动时，通过此地址解析一次域名。

* host=<Domain>

DoH 服务的主机名。

* path=/dns-query

DoH 服务的路径。

* post=<0|1>

是否使用 POST 请求来查询域名。0 - 使用 GET 请求，1 - 使用 POST 请求。默认为 0。

* keep-alive=<0|1>

是否重用 HTTPS 连接 (参考 HTTP 协议)。默认为 1。

* proxy=<0|1>

是否使用代理。仅支持无认证的 Socks5 代理。默认为 0。

* ecs=<0|1>

是否启用 EDNS，如果启用，应至少设置一个子网。默认为 0。

* china-ip4=<子网>

国内 IPv4 子网。当 ecs=1 时有效。

* china-ip6=<子网>

国内 IPv6 子网。当 ecs=1 时有效。

* foreign-ip4=<子网>

国外 IPv4 子网。当 ecs=1 时有效。

* foreign-ip6=<子网>

国外 IPv6 子网。当 ecs=1 时有效。


3. chinadns

Example:
```
dohclient -b 0.0.0.0 -p 555 --proxy=127.0.0.1:1080 \
          --chnroute="/etc/dohclient/chnroute.txt,/etc/dohclient/chnroute6.txt" \
          --channel=chinadns \
          --channel-args="chndoh.channel=udp&chndoh.addr=223.5.5.5:53&chndoh.host=dns.alidns.com&chndoh.path=/dns-query&frndoh.addr=172.67.153.110:443&frndoh.host=doh.beike.workers.dev&frndoh.path=/dns-query&frndoh.post=0&frndoh.keep-alive=1&frndoh.proxy=0&frndoh.ecs=1&frndoh.net=199.19.0.0/24&frndoh.net6=2001:19f0:6401::/48"
```

类似于 ChinaDNS，配置两个上游 DNS 服务器，查询时，同时向两个服务器查询。
当查询结果中包含中国 IP 时，选择中国服务器的结果返回，否则选择国外服务器的结果返回。

两个上游服务器的前缀分别为 chndoh 和 frndoh，chndoh 指定中国服务器，frndoh 指定国外服务器。


#### 服务器参数

* <chndoh|frndoh>.channel=<doh|udp|tcp>

服务器的类型：doh - DoH 服务器，udp - 普通 DNS 服务器 (使用 UDP 协议查询)，tcp - 普通 DNS 服务器 (使用 TCP 协议查询)。

* <chndoh|frndoh>.addr=<IP>[:PORT]

服务器的地址，当 <chndoh|frndoh>.channel=doh 时，为 DoH 服务器的地址，第 1 次启动时，通过此地址解析一次 DoH 服务器的域名。

* <chndoh|frndoh>.host=<Domain>

DoH 服务的主机名，用于 HTTP 请求头中的 Host，也用于验证证书。仅当 <chndoh|frndoh>.channel=doh 时有效。

* <chndoh|frndoh>.path=/dns-query

DoH 服务的路径。仅当 <chndoh|frndoh>.channel=doh 时有效。

* <chndoh|frndoh>.post=<0|1>

是否使用 POST 请求来查询域名。0 - 使用 GET 请求，1 - 使用 POST 请求。默认为 0。仅当 <chndoh|frndoh>.channel=doh 时有效。

* <chndoh|frndoh>.keep-alive=<0|1>

是否重用 HTTPS 连接 (参考 HTTP 协议)。默认为 1。仅当 <chndoh|frndoh>.channel=doh 时有效。

* <chndoh|frndoh>.proxy=<0|1>

是否使用代理。仅支持无认证的 Socks5 代理。默认为 0。当 <chndoh|frndoh>.channel=udp 时*无效*。

* <chndoh|frndoh>.ecs=<0|1>

是否启用 EDNS，如果启用，应至少设置一个子网。默认为 0。

* <chndoh|frndoh>.net=<子网>

国内 IPv4 子网。当 ecs=1 时有效。

* <chndoh|frndoh>.net6=<子网>

国内 IPv6 子网。当 ecs=1 时有效。

