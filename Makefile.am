ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = foreign subdir-objects
AM_CPPFLAGS = -Wall -Wextra -Werror -Wsign-conversion -Wno-error=unused-parameter -Winvalid-pch -Wno-missing-field-initializers	\
	-Wwrite-strings -Wsuggest-attribute=noreturn -Wundef -Wshadow -Wstrict-aliasing=2 -Wstrict-overflow=2	\
	-pipe -fPIC -DPIC -pthread
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
	src/singletons/fetch_server.cpp	\
	src/singletons/fetch_connector.cpp	\
	src/proxy_session.cpp	\
	src/fetch_session.cpp	\
	src/fetch_client.cpp	\
	src/encryption.cpp	\
	src/mmain.cpp

lib_libposeidon_medusa_la_LDFLAGS = \
	-no-undefined -version-info 0:0:0

pkgsysconfdir = $(sysconfdir)/@PACKAGE@
pkgsysconf_DATA = \
	etc/poseidon-medusa/main-template.conf	\
	etc/poseidon-medusa/medusa-template.conf
