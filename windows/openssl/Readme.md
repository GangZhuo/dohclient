Put openssl library into there.
You can download openssl from 
https://windows.php.net/downloads/php-sdk/deps/vs16/x86/openssl-1.1.1g-vs16-x86.zip

After that, the dohclient's source file tree should be like:

workspace
|- asset
|- rbtree
|- src
|- windows
   |- argp
   |- openssl
      |- bin
	  |- include
	  |- lib
	  |- openssl.cnf
	  |- Readme.txt (This file)

