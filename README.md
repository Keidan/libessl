libessl
===

(GPL) Easy SSL is a FREE library based on OpenSSL libraries.


This library aims to simplify the use of some functions proposed by OpenSSL:

	B64 (strings, stream)
	MD2 hash (strings, stream, files)
	MD4 hash (strings, stream, files)
	MD5 hash (strings, stream, files)
	SHA1 hash (strings, stream, files)
	SSL socket (connect/accept)
	Etc ... See the demo applications for the list of supported modules.

To build this library you should have installed the OpenSSL devel package

This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY.



Instructions
============


Make targets:

     all: Build the library and the demo targets.
     lib: Build the library target.
     demo: Build the demo target.
     clean: Clean the generated files.
     exec: Starts all the demo applications.


Download the software :

	mkdir devel
	cd devel
	git clone git://github.com/Keidan/libessl.git
	cd libessl
	make
  

License (like GPL)
==================

	You can:
		- Redistribute the sources code and binaries.
		- Modify the Sources code.
		- Use a part of the sources (less than 50%) in an other software, just write somewhere "libessl is great" visible by the user (on your product or on your website with a link to my page).
		- Redistribute the modification only if you want.
		- Send me the bug-fix (it could be great).
		- Pay me a beer or some other things.
		- Print the source code on WC paper ...
	You can NOT:
		- Earn money with this Software (But I can).
		- Add malware in the Sources.
		- Do something bad with the sources.
		- Use it to travel in the space with a toaster.
	
	I reserve the right to change this licence. If it change the version of the copy you have keep its own license


