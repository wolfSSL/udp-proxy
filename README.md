udp-proxy
=========

simple udp proxy for testing only


requirements
============

This tool requires [libevent](http://libevent.org).


building for \*nix
======================

Install libevent as a shared library using either your package manager of
choice or download the sources from their site and install with their
directions.

In the udp-proxy source directory build by:

    $ gcc -Wall udp_proxy.c -o udp_proxy -levent

It should be ready to run.


building for Windows
====================

Download the sources and extract them into your project directory. Both
libevent and the udp\_proxy sources at the same level in your project directory:

    ...\Project\
        -> libevent\
        -> udp_proxy\

Libevent normally names its source directory with the version number, rename
it as "libevent". It uses an nmake Makefile to build, which requires using
the command line. Open the appropriate command line shell from the Visual
Studio directory in the Start menu, depending on 32-bit or 64-bit builds.
Change directories into the libevent directory and run:

    ...\Project\libevent> nmake /f Makefile.nmake

This should build the library.

Open the solution file, udp\_proxy.sln. Select either Win32 for 32-bit or x64
for 64-bit builds. You can do a debug or release build. The solution references
the libevent headers and libraries assuming they are in a directory named
`libevent` as the same level as `udp_proxy`.


running
=======

From the udp\_proxy directory:

    $ ./udp_proxy -p 12345 -s 127.0.0.1:11111

For use with wolfSSL example server with client talking to proxy on port 12345:

    $ ./examples/server/server -u
    $ ./examples/client/client -u -p 12345

 Under Windows, you don't need all the path information, run each how you
 normally would.

