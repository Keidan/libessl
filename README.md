# libessl
[![Linux CI](https://github.com/Keidan/libessl/actions/workflows/linux.yml/badge.svg)][linuxCI]
[![CodeFactor](https://www.codefactor.io/repository/github/keidan/libessl/badge)][codefactor]
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)][license]

(GPL) Easy SSL is a FREE library based on OpenSSL libraries.


This library aims to simplify the use of some functions offered by OpenSSL :

	Base64 (strings)
	MD2 hashing (strings)
	MD4 hashing (strings)
	MD5 hashing (strings)
	SHA1 hashing (strings, files)
	AES encryption/decryption (strings)
	Socket SSL (connect/accept/write/read/close)
	Etc ... See the demo applications for the list of supported modules.

To build this library, you must have installed the OpenSSL development package (libssl-dev).

**Note:** The modules ssl\_connect and ssl\_accept are deliberately excluded from the tests.py file.

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
[codefactor]: https://www.codefactor.io/repository/github/keidan/libessl
[license]: https://github.com/Keidan/libessl/blob/master/license.txt
