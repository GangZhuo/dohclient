Put openssl library into there.
You can download openssl from 
https://windows.php.net/downloads/php-sdk/deps/vs16/x86/openssl-1.1.1h-vs16-x86.zip
https://windows.php.net/downloads/php-sdk/deps/vs16/x64/openssl-1.1.1h-vs16-x64.zip

After that, the dohclient's source file tree should be like:

```
workspace
|- asset
|- rbtree
|- src
|- windows
   |- argp
   |- openssl
      |- x86
      |  |- bin
	  |  |- include
	  |  |- lib
	  |  |- openssl.cnf
      |- x64
      |  |- bin
	  |  |- include
	  |  |- lib
	  |  |- openssl.cnf
	  |- Readme.txt (This file)
```
