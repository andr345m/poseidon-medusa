ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = foreign subdir-objects
AM_CPPFLAGS = -Wall -Wextra -Werror -Wsign-conversion -Wno-error=unused-parameter -Wno-missing-field-initializers -pipe -fPIC -DPIC
AM_CXXFLAGS =

%.hpp.gch: %.hpp
	$(CXX) -x c++-header @DEFS@ $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CXXFLAGS) $(CXXFLAGS) $< -o $@

BUILT_SOURCES = \
	src/precompiled.hpp.gch

CLEANFILES = \
	src/precompiled.hpp.gch

lib_LTLIBRARIES = \
	lib/libposeidon-medusa.la

lib_libposeidon_medusa_la_SOURCES = \
	src/singletons/proxy_server.cpp	\
	src/singletons/fetch_client.cpp	\
	src/singletons/fetch_server.cpp	\
	src/singletons/dns_daemon.cpp	\
	src/proxy_session.cpp	\
	src/fetch_session.cpp	\
	src/encryption.cpp	\
	src/mmain.cpp

pkgsysconfdir = $(sysconfdir)/@PACKAGE@
pkgsysconf_DATA = \
	etc/poseidon-medusa/main-template.conf	\
	etc/poseidon-medusa/medusa-template.conf
