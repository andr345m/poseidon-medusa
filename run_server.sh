#!/bin/bash

runpath=`pwd`'/lib/.libs'
etc=`pwd`'/etc'

if [ "$1" == "-d" ]; then
	LD_LIBRARY_PATH=$runpath ./libtool --mode=execute gdb --args poseidon $etc/poseidon-medusa
elif [ "$1" == "-v" ]; then
	LD_LIBRARY_PATH=$runpath ./libtool --mode=execute valgrind --leak-check=full --log-file='valgrind.log' poseidon $etc/poseidon-medusa
elif [ "$1" == "-vgdb" ]; then
	LD_LIBRARY_PATH=$runpath ./libtool --mode=execute valgrind --vgdb=yes --vgdb-error=0 --leak-check=full --log-file='valgrind.log' poseidon $etc/poseidon-medusa
else
	LD_LIBRARY_PATH=$runpath poseidon $etc/poseidon-medusa
fi
