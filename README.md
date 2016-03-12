DCAS - Laird's Device Client Api Server
=======================================


Licenses
--------

DCAS is Copyright 2016 Laird and licensed under the ISC
libssh is licensed under the LGPL v2
OpenSSL is licensed under the OpenSSL license

Requirements
--------------

OpenSSL
cmake
libssh
cppcheck

Quick Start
-----------

Quick Start is a misnomer perhaps, because our build system doesn't quite do everything necessary to allow you to build. You must first install the requirements:

1. Install cppcheck - this tool does static analysis on our source code. `sudo apt-get install cppcheck`
2. Install cmake - this is a tool necessary for building libssh. `sudo apt-get install cmake`
3. Install OpenSSL - libssh uses this `sudo apt-get install libssl-dev`
4. Do the build for libssh: `make libssh`
5. Install libssh - for now our makefiles assume a system-install of libssh, the default puts it into /usr/local/bin so it's not a big deal: `sudo make libssh-install`
6. After this, you should be able to build dcas: `make` *if successful, dcas will be running*
7. In a *second terminal window*, build dcas-client and test: `make dcas-test`

*NOTE:* The two previous steps will automatically do a test of the dcas client-server model. The make target for dcas automatically start it to test, and the `make dcas-test` will not only build the dcas-client, but it will also run the dcas-client to test against the server. This is why the above instructions specify a second terminal window for the client build/test. After the test, both programs will quit. They will respond to a ^C if you need to quit them.


TODO:
-----

### Build system ###
* have Makefile check for cppcheck and ignore the test if not installed
