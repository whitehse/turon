#SUBDIRS =

bin_PROGRAMS=turon
AM_CXXFLAGS = $(INTI_CFLAGS)

AM_CPPFLAGS = -I$(top_srcdir)

turon_SOURCES=turon.c examples.h
turon_LDADD = $(INTI_LIBS) -L../turon/.libs -lturon-1.0
#select_LDFLAGS = -static
