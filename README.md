DCAS - Laird's Device Client Api Server
=======================================


Licenses
--------

DCAS is Copyright 2016 Laird and licensed under the ISC
libssh is licensed under the LGPL v2
OpenSSL is licensed under the OpenSSL license

Requirements
--------------

### Tools ###

cmake
cppcheck
FlatCC

### Libraries ###

OpenSSL
libssh
FlatCC

Quick Start
-----------

Quick Start is a misnomer perhaps, because our build system doesn't quite do everything necessary to allow you to build. You must first install the requirements:

1. Install cppcheck - this tool does static analysis on our source code. `sudo apt-get install cppcheck`
2. Install cmake - this is a tool necessary for building libssh. `sudo apt-get install cmake`
3. Install OpenSSL - libssh uses this `sudo apt-get install libssl-dev`
4. Do the build for libssh: `make libssh`
5. Install libssh - for now our makefiles assume a system-install of libssh, the default puts it into /usr/local/bin so it's not a big deal: `sudo make libssh_install`
6. Build FlatCC - flatcc both provides a build tool and is a library that dcas utilizes. `make flatcc`
7. After this, you should be able to build dcas: `make` *if successful, dcas will be running*
8. In a *second terminal window*, build dcas-client and test: `make dcas-test`

*NOTE:* The two previous steps will automatically do a test of the dcas client-server model. The make target for dcas automatically start it to test, and the `make dcas-test` will not only build the dcas-client, but it will also run the dcas-client to test against the server. This is why the above instructions specify a second terminal window for the client build/test. After the test, both programs will quit. They will respond to a ^C if you need to quit them.

*BUG:* `make dcas-test` will fail the first time you run it on your system if you haven't previously accepted a host key for 127.0.0.1. It will prompt you to accept and save and then proceed to work. It works, but the validation check fails for some reason. Restart dcas in the other terminal and then rerun `make dcas-test` and it should work.

Build for WB
------------

The build isn't integrated into the WB buildroot build system yet. For now, there's a helper makefile script. Note:

* It's designed to build for a WB from the location dcas should be deployed: `wb/buildroot/package/lrd/externals/dcas`
* It does not build libssh. Buildroot is able to build that, so this assumes that buildroot has built it for the relevant image first.
* It does build flatcc. It'll deploy flatcc into host tools and libraries into staging in the wb build.
* The WB buildroot build must be done both before and after running this build. Before to get tools and dependancies taken care of. After to get dcas integrated into the final rootfs image.
* Repeated builds are bugged, so make clean between each build.
* Making clean won't remove the build products from the rootfs image however.

To build:

    make -f wb-external.mk clean
    make -f wb-external.mk WB=wb45n_devel
--or--

    make -f wb-external.mk clean
    make -f wb-external.mk WB=wb50n_devel

TODO:
-----

### DCAS ###

* add additional functionality to complete API

### Tests ###

* Unit tests
* System test runner
* Fix first-run `make dcas-test` problem
