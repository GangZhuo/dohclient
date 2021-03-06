@echo off

set SERVICE_NAME=dohclient
set SERVICE_DESCRIPTION=DoH Client.

SET CONFIG_FILE=dohclient.config

set CURR_PATH=%~dp0

if not exist "%CURR_PATH%%CONFIG_FILE%" (
	(
		echo.
		echo config cfg
		echo 	option bind_addr '127.0.0.1'
		echo 	option bind_port '53'
		echo 	option chnroute '%CURR_PATH%chnroute.txt,%CURR_PATH%chnroute6.txt'
		echo 	option timeout '3'
		echo 	option log_file '%CURR_PATH%dohclient.log'
		echo 	option log_level '5'
		echo 	option proxy '127.0.0.1:1080'
		echo 	option channel 'doh'
		echo 	option channel_args 'addr=223.5.5.5:443&host=dns.alidns.com&path=/dns-query&proxy=0&ecs=1&china-ip4=223.5.5.5/24&china-ip6=2400:3200::1/32&foreign-ip4=8.8.8.8/24&foreign-ip6=2001:df2:8300::/48'
	)> "%CURR_PATH%%CONFIG_FILE%"
)

sc create "%SERVICE_NAME%" binpath= "\"%CURR_PATH%dohclient.exe\" --daemon --config=\"%CURR_PATH%%CONFIG_FILE%\" --launch-log=\"%CURR_PATH%dohclient-launch-log.log\"" displayname= "%SERVICE_NAME%" depend= Tcpip start= auto  

sc description "%SERVICE_NAME%" "%SERVICE_DESCRIPTION%"

pause

@echo on
