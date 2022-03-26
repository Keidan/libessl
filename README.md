# libessl
[![Linux CI](https://github.com/Keidan/libessl/actions/workflows/linux.yml/badge.svg)][linuxCI]
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)][license]

(GPL) Easy SSL is a FREE library based on OpenSSL libraries.


This library aims to simplify the use of certain functions offered by OpenSSL:

	B64 (strings, stream)
	MD2 hash (strings, stream, files)
	MD4 hash (strings, stream, files)
	MD5 hash (strings, stream, files)
	SHA1 hash (strings, stream, files)
	AES ecryption/decryption (strings)
	SSL socket (connect/accept)
	Etc ... See the demo applications for the list of supported modules.

To build this library, you must have the OpenSSL development package installed (libssl-dev).

This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY.



## Instructions

Download the software :

	mkdir devel
	cd devel
	git clone https://github.com/Keidan/libessl.git
	cd libessl
	cmake -S . -B build -DDISTRIBUTION=[debug|release] .
	cmake --build build
	See deploy/[processor]/*.elf


## License

[GPLv3](https://github.com/Keidan/libessl/blob/master/license.txt)

[linuxCI]: https://github.com/Keidan/libessl/actions?query=workflow%3ALinux
[license]: https://github.com/Keidan/libessl/blob/master/license.txt
