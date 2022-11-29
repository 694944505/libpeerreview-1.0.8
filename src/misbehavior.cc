#include <stdlib.h>
#include <string.h>

#include "peerreview.h"

#define SUBSYSTEM "peerreview"
#undef plog
#define plog(x, a...) do { peerreview->logText(SUBSYSTEM, x, a); } while (0)

Misbehavior::Misbehavior(PeerReview *peerreview, const char *misbehaviorString, int signatureSizeBytes, int hashSizeBytes, AuthenticatorStore *authOutStore, IdentityTransport *transport, SecureHistory *history)
{
  this->peerreview = peerreview;
  this->type = GOOD;
  this->subject = NULL;
  this->subject2 = NULL;
  this->start = -1;
  this->lastSeq = -1;
  this->signatureSizeBytes = signatureSizeBytes;
  this->hashSizeBytes = hashSizeBytes;
  this->authOutStore = authOutStore;
  this->transport = transport;
  this->history = history;
  this->arg = -1;

  if (misbehaviorString) {  
    char buf1[200];
    strncpy(buf1, misbehaviorString, sizeof(buf1));
    
    char *stype = strtok(buf1, ",");
    char *sa1 = stype ? strtok(NULL, ",") : NULL;
    char *sa2 = sa1 ? strtok(NULL, ",") : NULL;
    char *sa3 = sa2 ? strtok(NULL, ",") : NULL;
    
    if (!strcasecmp(stype, "ignorenode")) {
      if (!sa1 || !sa2)
        panic("Format: misbehavior=ignorenode,<nodeID>,<startMicros>");
        
      type = IGNORE_NODE;
      subject = peerreview->readIdentifierFromString(sa1);
      start = atoll(sa2);
    } else if (!strcasecmp(stype, "ignoreexcept2")) {
      if (!sa1 || !sa2 || !sa3)
        panic("Format: misbehavior=ignoreexcept2,<nodeID>,<nodeID>,<startMicros>");
        
      type = IGNOREEXCEPT2;
      subject = peerreview->readIdentifierFromString(sa1);
      subject2 = peerreview->readIdentifierFromString(sa2);
      start = atoll(sa3);
    } else if (!strcasecmp(stype, "duplicateauth")) {
      if (!sa1)
        panic("Format: misbehavior=duplicateauth,<startMicros>");
    
      type = DUPLICATE_AUTH;
      start = atoll(sa1);
    } else if (!strcasecmp(stype, "spuriousauth")) {
      if (!sa1)
        panic("Format: misbehavior=spuriousauth,<timeMicros>[,<seq>]");
    
      type = SPURIOUS_AUTH;
      start = atoll(sa1);
      arg = sa2 ? atoll(sa2) : -1;
    } else if (!strcasecmp(stype, "silent")) {
      if (!sa1)
        panic("Format: misbehavior=silent,<startMicros>");
    
      type = SILENT;
      start = atoll(sa1);
    } else if (!strcasecmp(stype, "reluctant")) {
      if (!sa1)
        panic("Format: misbehavior=reluctant,<startMicros>");
    
      type = RELUCTANT;
      start = atoll(sa1);
    } else if (!strcasecmp(stype, "tamperwithdata")) {
      if (!sa1)
        panic("Format: misbehavior=tamperwithdata,<startMicros>");
    
      type = TAMPER_WITH_DATA;
      start = atoll(sa1);
    } else {
      panic("Unknown misbehavior: '%s'", stype);
    }
    
    plog(2, "Instantiating misbehavior '%s'", stype);
  }
}

Misbehavior::~Misbehavior()
{
  if (subject)
    delete subject;
  if (subject2)
    delete subject2;
}

/* Called directly from PeerReview's receive() method, before any other processing is done */

bool Misbehavior::dropIncomingMessage(NodeHandle *handle, bool datagram, unsigned char *message, int msglen)
{
  char buf1[256], buf2[256];

  if ((type == IGNORE_NODE) && subject->equals(handle->getIdentifier()) && (peerreview->getTime() >= start)) {
    plog(2, "MISCHIEF: Dropping incoming message type 0x%02X from %s", message[0], handle->render(buf1));
    return true;
  }

  if ((type == IGNOREEXCEPT2) && !subject->equals(handle->getIdentifier()) && !subject2->equals(handle->getIdentifier()) && (peerreview->getTime() >= start)) {
    if (message[0] == MSG_CHALLENGE) {
      plog(2, "MISCHIEF: Dropping incoming message type 0x%02X from %s [xc2]", message[0], handle->render(buf1));
      return true;
    }
  }

  return false;
}

/* Called from CommitmentProtocol::handleOutgoingMessage() */

bool Misbehavior::dropAfterLogging(NodeHandle *handle, unsigned char *message, int msglen)
{
  char buf1[256];
  
  if ((type == RELUCTANT) && (peerreview->getTime() >= start)) {
    plog(2, "MISCHIEF: Reluctant; dropping outgoing message to %s", handle->render(buf1));
    return true;
  }

  return false;
}

/* Called immediately before we hand an outgoing message to the transport layer */

bool Misbehavior::dropOutgoingMessage(NodeHandle *handle, bool datagram, unsigned char *message, int msglen)
{
  char buf1[256], buf2[256];

  if ((type == IGNORE_NODE) && subject->equals(handle->getIdentifier()) && (peerreview->getTime() >= start)) {
    plog(2, "MISCHIEF: Dropping outgoing message type 0x%02X to %s", message[0], handle->render(buf1));
    return true;
  }

  if ((type == IGNOREEXCEPT2) && !subject->equals(handle->getIdentifier()) && !subject2->equals(handle->getIdentifier()) && (peerreview->getTime() >= start)) {
    if (message[0] == MSG_USERDATA) {
      plog(2, "MISCHIEF: Dropping outgoing message type 0x%02X to %s [xc2]", message[0], handle->render(buf1));
      return true;
    }
  }

  if ((type == SILENT) && (peerreview->getTime() >= start)) {
    plog(2, "MISCHIEF: Silent; dropping outgoing message type 0x%02X to %s", message[0], handle->render(buf1));
    return true;
  }

  return false;
}

/* Called from the Commitment protocol */

void Misbehavior::maybeChangeSeqInUserMessage(long long *topSeq)
{
  if ((type == SPURIOUS_AUTH) && (peerreview->getTime() >= start)) {
    long long unusedSeq = (arg>0) ? arg : history->getLastSeq()-1;
    while (history->findSeq(unusedSeq)>=0)
      unusedSeq --;
    
    plog(2, "MISCHIEF: Sending spurious authenticator with non-existent sequence no. %lld", unusedSeq);

    unsigned char auth2[sizeof(long long)+hashSizeBytes+signatureSizeBytes];
    *(long long*)&auth2 = unusedSeq;
    for (int i=0; i<hashSizeBytes; i++)
      auth2[sizeof(long long)+i] = i;
    unsigned char hToSign2[hashSizeBytes];
    peerreview->hash(hToSign2, auth2, sizeof(long long)+hashSizeBytes);
    transport->sign(hToSign2, sizeof(hToSign2), &auth2[sizeof(long long)+hashSizeBytes]);
    authOutStore->addAuthenticator(transport->getLocalHandle()->getIdentifier(), auth2);
    type = GOOD;
  }

  if ((type == DUPLICATE_AUTH) && (peerreview->getTime() >= start) && (lastSeq >= 0)) {
    plog(2, "MISCHIEF: Using sequence no. %lld a second time", lastSeq);
#if 1
    unsigned char auth2[sizeof(long long)+hashSizeBytes+signatureSizeBytes];
    *(long long*)&auth2 = *topSeq;
    for (int i=0; i<hashSizeBytes; i++)
      auth2[sizeof(long long)+i] = i;
    unsigned char hToSign2[hashSizeBytes];
    peerreview->hash(hToSign2, auth2, sizeof(long long)+hashSizeBytes);
    transport->sign(hToSign2, sizeof(hToSign2), &auth2[sizeof(long long)+hashSizeBytes]);
    authOutStore->addAuthenticator(transport->getLocalHandle()->getIdentifier(), auth2);

#else
    *topSeq = lastSeq;
#endif
    type = GOOD;
  } else {
    lastSeq = *topSeq;
  }
}

/* Called directly after we got an outgoing message from the application */

void Misbehavior::maybeTamperWithData(unsigned char *message, int msglen)
{
  if ((type == TAMPER_WITH_DATA) && (peerreview->getTime() >= start)) {
    plog(2, "MISCHIEF: Tampering with a %d-byte packet", msglen);
    message[msglen-1] ^= 0xFF;
    type = GOOD;
  }
}
