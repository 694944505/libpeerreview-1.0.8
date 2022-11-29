#include "peerreview/vrf.h"

#define SUBSYSTEM "VrfExtInfoPolicy"

VrfExtInfoPolicy::VrfExtInfoPolicy(VerifiablePRNG *vprng) : ExtInfoPolicy()
{
  this->vprng = vprng;
}

VrfExtInfoPolicy::~VrfExtInfoPolicy()
{
}

int VrfExtInfoPolicy::storeExtInfo(SecureHistory *history, long long followingSeq, unsigned char *buffer, unsigned int maxlen)
{
  int extInfoLen = vprng->storeExtInfo(buffer, maxlen);
  if (extInfoLen > 0) {
    unsigned char ty = EVT_VRF;
    int ne = history->findNextEntry(&ty, 1, followingSeq);
    if (ne >= 0) {
      //plog(3, "GETTING VRF @%d/%lld", ne, followingSeq);
      extInfoLen = history->getEntry(ne, buffer, maxlen);
      //plog(3, "=> %d", extInfoLen);
    }
  }
  
  return extInfoLen;
}
