# dohclient

类似于 ChinaDNS，不过使用 DoH 作为上游服务器。

- [dohclient](#dohclient)
    + [Build on Linux](#build-on-linux)
    + [Build on Windows](#build-on-windows)
    + [Build on Termux](#build-on-termux)
    + [Usage](#usage)
    + [Channels](#channels)
      - [1. os](#1-os)
      - [2. os](#2-udp)
      - [3. os](#3-tcp)
      - [4. doh](#4-doh)
      - [5. chinadns](#5-chinadns)
    + [dohclient.config](#dohclientconfig)
    + [Proxy Google DoH By Cloudflare Workers](#proxy-google-doh-by-cloudflare-workers)

You can find a example config at https://github.com/GangZhuo/http-proxy/wiki/%E9%85%8D%E7%BD%AE%E7%A4%BA%E4%BE%8B

### Build on Linux

```
sudo apt-get install libssl-dev
git clone https://github.com/GangZhuo/dohclient.git
cd dohclient
git submodule update --init
make
sudo make install
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
  --blacklist=BLACKLIST_FILE
                           Path to black list file, e.g.: --blacklist=blacklist.txt.
                           The format of the file is same as chnroute file.
  --hosts=HOSTS_FILE       Path to hosts file, e.g.: --hosts=/etc/hosts.
  --proxy=PROXY_URL        Proxy url, e.g. --proxy=[socks5://]127.0.0.1:1080
                           or --proxy=http://username:password@[::1]:80.
                           Supports socks5 (no authentication) and http proxy.
  -v                       Verbose logging.
  -h                       Show this help message and exit.
  -V                       Print version and then exit.

Online help: <https://github.com/GangZhuo/dohclient>
```

### Channels

#### 1. os

Example:
```
dohclient -b 0.0.0.0 -p 5354 --channel=os -vv
```

Query by OS function getaddrinfo().


#### 2. udp

Example:
```
dohclient -b 0.0.0.0 -p 5354 -vv \
          --chnroute="/etc/dohclient/chnroute.txt,/etc/dohclient/chnroute6.txt" \
          --channel=udp \
          --channel-args="upstream=8.8.8.8:53&timeout=5"
```

通过 UDP 协议原样转发查询数据到上游服务器（不支持代理服务器）。

##### Channel Arguments

* upstream=<IP>[:PORT]

上游服务器的地址。

* timeout=<seconds>

查询超时时间，单位为秒。覆盖全局配置的超时时间。


#### 3. tcp

Example:
```
dohclient -b 0.0.0.0 -p 5354 --proxy=127.0.0.1:1080 -vv \
          --chnroute="/etc/dohclient/chnroute.txt,/etc/dohclient/chnroute6.txt" \
          --channel=tcp \
          --channel-args="upstream=8.8.8.8:53&proxy=0&timeout=5"
```

通过 TCP 协议原样转发查询数据到上游服务器。

##### Channel Arguments

* upstream=<IP>[:PORT]

上游服务器的地址。

* proxy=<0|1>

是否启用代理。

* timeout=<seconds>

查询超时时间，单位为秒。覆盖全局配置的超时时间。


#### 4. doh

Example:
```
dohclient -b 0.0.0.0 -p 5354 --proxy=127.0.0.1:1080 -vv \
          --chnroute="/etc/dohclient/chnroute.txt,/etc/dohclient/chnroute6.txt" \
          --channel=doh \
          --channel-args="addr=8.8.8.8:443&host=dns.google&path=/dns-query&post=0&keep-alive=600&proxy=0&ecs=1&china-ip4=114.114.114.114/24&china-ip6=2405:2d80::/32&foreign-ip4=8.8.8.8/24&foreign-ip6=2001:df2:8300::/48"
```

ecs=0 时，等同于 DoH 服务的代理。ecs=1 时，使用每一个子网向 DoH 服务查询域名，当查询结果中包含中国 IP 时，选择中国子网的结果返回，否则选择国外子网的结果返回。

##### Channel Arguments

* addr=<IP>[:PORT]

DoH 服务器的地址，第 1 次启动时，通过此地址解析一次域名。

* host=<Domain>

DoH 服务的主机名。

* path=/dns-query

DoH 服务的路径。

* post=<0|1>

是否使用 POST 请求来查询域名。0 - 使用 GET 请求，1 - 使用 POST 请求。默认为 0。

* keep-alive=<seconds>

是否重用 HTTPS 连接 (参考 HTTP 协议)。
0 表示不重用; 1 表示使用默认值 (20 分钟); 其他值表示连接应该保留多少秒。

* proxy=<0|1>

是否使用代理。默认为 0。

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

* timeout=<seconds>

查询超时时间，单位为秒。覆盖全局配置的超时时间。


#### 5. chinadns

Example:
```
dohclient -b 0.0.0.0 -p 5354 --proxy=127.0.0.1:1080 -vv \
          --chnroute="/etc/dohclient/chnroute.txt,/etc/dohclient/chnroute6.txt" \
          --channel=chinadns \
          --channel-args="chndoh.channel=udp&chndoh.addr=223.5.5.5:53&frndoh.channel=doh&frndoh.addr=8.8.8.8:443&frndoh.host=dns.google&frndoh.path=/dns-query&frndoh.post=0&frndoh.keep-alive=1&frndoh.proxy=0&frndoh.ecs=1&frndoh.net=199.19.0.0/24&frndoh.net6=2001:19f0:6401::/48"
```

类似于 ChinaDNS，配置两个上游 DNS 服务器，查询时，同时向两个服务器查询。
当查询结果中包含中国 IP 时，选择中国服务器的结果返回，否则选择国外服务器的结果返回。

两个上游服务器的前缀分别为 chndoh 和 frndoh，chndoh 指定中国服务器，frndoh 指定国外服务器。
os,udp,tcp 三个通道的配置同上方的说明。

##### Server Arguments

* <chndoh|frndoh>.channel=<doh|udp|tcp>

服务器的类型：doh - DoH 服务器，udp - 普通 DNS 服务器 (使用 UDP 协议查询)，tcp - 普通 DNS 服务器 (使用 TCP 协议查询)。

* <chndoh|frndoh>.name=[name]

通道名称，仅用于打印日志。

* <chndoh|frndoh>.addr=<IP>[:PORT]

服务器的地址，当 <chndoh|frndoh>.channel=doh 时，为 DoH 服务器的地址，第 1 次启动时，通过此地址解析一次 DoH 服务器的域名。

* <chndoh|frndoh>.host=<Domain>

DoH 服务的主机名，用于 HTTP 请求头中的 Host，也用于验证证书。仅当 <chndoh|frndoh>.channel=doh 时有效。

* <chndoh|frndoh>.path=/dns-query

DoH 服务的路径。仅当 <chndoh|frndoh>.channel=doh 时有效。

* <chndoh|frndoh>.resolve=<0|1>

是否自动解析 <chndoh|frndoh>.host 指定的域名。默认为 1。仅当 <chndoh|frndoh>.channel=doh 时有效。

* <chndoh|frndoh>.post=<0|1>

是否使用 POST 请求来查询域名。0 - 使用 GET 请求，1 - 使用 POST 请求。默认为 0。仅当 <chndoh|frndoh>.channel=doh 时有效。

* <chndoh|frndoh>.keep-alive=<seconds>

是否重用 HTTPS 连接 (参考 HTTP 协议)。默认为 1。
0 表示不重用; 1 表示使用默认值 (20 分钟); 其他值表示连接应该保留多少秒。
仅当 <chndoh|frndoh>.channel=doh 时有效。

* <chndoh|frndoh>.proxy=<0|1>

是否使用代理。仅支持无认证的 Socks5 代理。默认为 0。当 <chndoh|frndoh>.channel=udp 时*无效*。

* <chndoh|frndoh>.ecs=<0|1>

是否启用 EDNS，如果启用，应至少设置一个子网。默认为 0。

* <chndoh|frndoh>.net=<子网>

国内 IPv4 子网。当 ecs=1 时有效。

* <chndoh|frndoh>.net6=<子网>

国内 IPv6 子网。当 ecs=1 时有效。

* <chndoh|frndoh>.timeout=<seconds>

查询超时时间，单位为秒。覆盖全局配置的超时时间。


### dohclient.config

Example:
```
dohclient --config=dohclient.config
```

```
# dohclient.config (https://github.com/GangZhuo/dohclient/blob/master/asset/dohclient.config)

config cfg
	option bind_addr '127.0.0.1'
	option bind_port '5354'
	option chnroute '/etc/dohclient/chnroute.txt,/etc/dohclient/chnroute6.txt'
	option timeout '5'
	option log_file '/var/log/dohclient.log'
	option log_level '5'
	option proxy '127.0.0.1:1080'
	option channel 'chinadns'
	option channel_args 'chndoh.channel=udp&chndoh.addr=223.5.5.5:53&frndoh.channel=doh&frndoh.addr=8.8.8.8:443&frndoh.host=dns.google&frndoh.path=/dns-query&frndoh.proxy=1&frndoh.ecs=1&frndoh.net=8.8.0.0/24&frndoh.net6=2001:19f0:6401::/48'
```

### Proxy Google DoH By Cloudflare Workers

参考 https://github.com/GangZhuo/cf-doh

