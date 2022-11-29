## Process this file with automake to produce Makefile.in

if WITH_VRF
VRF_HDRS = peerreview/vrf.h
else
VRF_HDRS =
endif

include_HEADERS = peerreview.h
nobase_include_HEADERS = peerreview/identity.h peerreview/tools.h peerreview/transport.h peerreview/entrytypes.h peerreview/history.h $(VRF_HDRS)
