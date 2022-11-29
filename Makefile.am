## Process this file with automake to produce Makefile.in

SUBDIRS = include
EXTRA_DIST = LICENSE

DISTCLEANFILES= config.log config.status include/peerreview/config.h.in
MAINTAINERCLEANFILES= aclocal.m4 depcomp config.guess config.sub ltmain.sh mkinstalldirs stamp-h.in stamp-h1 install-sh missing config.h.in configure Makefile.in compile $(PACKAGE)-$(VERSION).tar.gz

if WITH_VRF
VRF_SOURCES              = src/vrf/verifiableprng.cc src/vrf/vrf.cc src/vrf/randomwrapper.cc src/vrf/extinfo.cc
else
VRF_SOURCES              =
endif

lib_LTLIBRARIES          = libpeerreview.la
libpeerreview_la_SOURCES = src/audit.cc src/authpush.cc src/authstore.cc src/challenge.cc \
                           src/commitment.cc src/evidence.cc src/history.cc src/infostore.cc \
                           src/misbehavior.cc src/peerreview.cc src/statement.cc \
                           src/tools.cc src/verifier.cc src/simpleprng.cc src/evtool.cc \
                           $(VRF_SOURCES)

bin_PROGRAMS = dumphistory

dumphistory_SOURCES = src/tools/dumphistory.cc

dumphistory_LDADD = -lpeerreview -lcrypto
