h_sources = turon.h turon_md5.h turon_sha256.h
cc_sources = md5.c sha256.c

library_includedir=$(includedir)/$(GENERIC_LIBRARY_NAME)-$(GENERIC_API_VERSION)/$(GENERIC_LIBRARY_NAME)
library_include_HEADERS = $(h_sources)

INCLUDES = -I$(top_srcdir)

lib_LTLIBRARIES= libturon-1.0.la
libturon_1_0_la_SOURCES= $(h_sources) $(cc_sources)
libturon_1_0_la_LDFLAGS= -version-info $(GENERIC_LIBRARY_VERSION) -release $(GENERIC_RELEASE)

