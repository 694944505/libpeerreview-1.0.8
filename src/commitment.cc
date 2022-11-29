#include <stdlib.h>
#include <string.h>

#include "peerreview.h"

#define SUBSYSTEM "peerreview"

CommitmentProtocol::CommitmentProtocol(PeerReview *peerreview, IdentityTransport *transport, PeerInfoStore *infoStore, AuthenticatorStore *authStore, SecureHistory *history, PeerReviewCallback *app, Misbehavior *misbehavior, long long timeToleranceMicros)
{
  this->peerreview = peerreview;
  this->myHandle = transport->getLocalHandle()->clone();
  this->signatureSizeBytes = transport->getSignatureSizeBytes();
  this->hashSizeBytes = transport->getHashSizeBytes();
  this->transport = transport;
  this->infoStore = infoStore;
  this->authStore = authStore;
  this->history = history;
  this->app = app;
  this->misbehavior = misbehavior;
  this->nextReceiveCacheEntry = 0;
  this->numPeers = 0;
  this->timeToleranceMicros = timeToleranceMicros;
  
  for (int i=0; i<RECEIVE_CACHE_SIZE; i++) {
    receiveCache[i].sender = NULL;
    receiveCache[i].senderSeq = 0;
    receiveCache[i].indexInLocalHistory = 0;
  }
    
  initReceiveCache();
  transport->scheduleTimer(this, TI_PROGRESS, peerreview->getTime() + PROGRESS_INTERVAL_MICROS);
}

CommitmentProtocol::~CommitmentProtocol()
{
  for (int i=0; i<numPeers; i++) {
    while (peer[i].xmitQueue) {
      struct packetInfo *pi = peer[i].xmitQueue;
      peer[i].xmitQueue = peer[i].xmitQueue->next;
      free(pi->message);
      free(pi);
    }

    while (peer[i].recvQueue) {
      struct packetInfo *pi = peer[i].recvQueue;
      peer[i].recvQueue = peer[i].recvQueue->next;
      free(pi->message);
      free(pi);
    }

    delete peer[i].handle;
  }

  for (int i=0; i<RECEIVE_CACHE_SIZE; i++)
    if (receiveCache[i].sender)
      delete receiveCache[i].sender;
  
  delete myHandle;
}

void CommitmentProtocol::timerExpired(int timerID)
{
  assert(timerID == TI_PROGRESS);
  
  for (int i=0; i<numPeers; i++) 
    makeProgress(i);
    
  transport->scheduleTimer(this, TI_PROGRESS, peerreview->getTime() + PROGRESS_INTERVAL_MICROS);
}

void CommitmentProtocol::initReceiveCache()
{
  int entriesFound = 0;
  
  for (int i=history->getNumEntries()-1; (i>=1) && (entriesFound<RECEIVE_CACHE_SIZE); i--) {
    unsigned char type;
    history->statEntry(i, NULL, &type, NULL, NULL, NULL);
    if (type == EVT_RECV) {
      unsigned char buf[MAX_HANDLE_SIZE+sizeof(long long)];
      unsigned int pos = 0;

      history->getEntry(i, buf, sizeof(buf));
      NodeHandle *thisSender = peerreview->readNodeHandle(buf, &pos, sizeof(buf));
      addToReceiveCache(thisSender->getIdentifier(), *(long long*)&buf[pos], i);
      delete thisSender;
    }
  }
}

void CommitmentProtocol::addToReceiveCache(Identifier *id, long long senderSeq, int indexInLocalHistory)
{
  if (receiveCache[nextReceiveCacheEntry].sender)
    delete receiveCache[nextReceiveCacheEntry].sender;
    
  receiveCache[nextReceiveCacheEntry].sender = id->clone();
  receiveCache[nextReceiveCacheEntry].senderSeq = senderSeq;
  receiveCache[nextReceiveCacheEntry].indexInLocalHistory = indexInLocalHistory;
  nextReceiveCacheEntry = (nextReceiveCacheEntry+1) % RECEIVE_CACHE_SIZE;
}

int CommitmentProtocol::lookupPeer(NodeHandle *handle)
{
  for (int i=0; i<numPeers; i++) {
    if (peer[i].handle->equals(handle))
      return i;
  }
  
  if (numPeers >= MAX_PEERS)
    panic("Peer table overflow");
    
  peer[numPeers].handle = handle->clone();
  peer[numPeers].numOutstandingPackets = 0;
  peer[numPeers].lastTransmit = 0;
  peer[numPeers].xmitQueue = NULL;
  peer[numPeers].recvQueue = NULL;
  peer[numPeers].currentTimeout = 0;
  peer[numPeers].retransmitsSoFar = 0;
  peer[numPeers].lastChallenge = -1;
  peer[numPeers].currentChallengeInterval = INITIAL_CHALLENGE_INTERVAL_MICROS;
  peer[numPeers].isReceiving = false;
  return numPeers ++;
}

struct CommitmentProtocol::packetInfo *CommitmentProtocol::enqueueTail(struct packetInfo *queueHead, unsigned char *message, int msglen)
{
  struct packetInfo *pi = (struct packetInfo*) malloc(sizeof(struct packetInfo));
  pi->next = NULL;
  pi->message = message;
  pi->msglen = msglen;
  
  if (!queueHead)
    return pi;
    
  struct packetInfo *iter = queueHead;
  while (iter->next != NULL)
    iter = iter->next;
    
  iter->next = pi;
  
  return queueHead;
}

void CommitmentProtocol::notifyCertificateAvailable(Identifier *id)
{
  for (int i=0; i<numPeers; i++) {
    if (peer[i].handle->getIdentifier()->equals(id))
      makeProgress(i);
  }
}

/* Checks whether an incoming message is already in the log (which can happen with duplicates).
   If not, it adds the message to the log. */

int CommitmentProtocol::logMessageIfNew(unsigned char *message, int msglen, unsigned char *ackMessage, int ackMaxLen, bool *loggedPreviously)
{
  unsigned int pos = 0;
  long long seq = readLongLong(message, &pos);
  NodeHandle *handle = peerreview->readNodeHandle(message, &pos, msglen);
  const unsigned char *hTopMinusOne = &message[pos];
  const unsigned char *signature = &message[pos+hashSizeBytes];
  unsigned char relevantCode = message[pos+hashSizeBytes+signatureSizeBytes];
  int headerLen = pos + hashSizeBytes + signatureSizeBytes + 1;
  const unsigned char *payload = &message[headerLen];
  int payloadLen = msglen - headerLen;
  int relevantLen = (relevantCode == 0xFF) ? payloadLen : relevantCode;

  unsigned char myHashTopMinusOne[hashSizeBytes];
  unsigned char myHashTop[hashSizeBytes];
  long long seqOfRecvEntry;
  int indexOfRecvEntry;

  /* Check whether the log contains a matching RECV entry, i.e. one with a message
     from the same node and with the same send sequence number */

  indexOfRecvEntry = findRecvEntry(handle->getIdentifier(), seq);

  /* If there is no such RECV entry, we append one */

  if (indexOfRecvEntry < 0) {
    unsigned char header[MAX_HANDLE_SIZE+sizeof(long long)+1];
    unsigned int logHdrSize = 0;
    handle->write(header, &logHdrSize, sizeof(header));
    writeLongLong(header, &logHdrSize, seq);
    writeByte(header, &logHdrSize, (relevantLen < payloadLen) ? 1 : 0);

    /* Construct the RECV entry and append it to the log */

    history->getTopLevelEntry(myHashTopMinusOne, NULL);
    if (relevantLen < payloadLen) {
      unsigned char *buffer = (unsigned char*) malloc(relevantLen + hashSizeBytes);
      if (relevantLen > 0)
        memcpy(&buffer[0], payload, relevantLen);
      transport->hash(&buffer[relevantLen], &payload[relevantLen], payloadLen - relevantLen);
      history->appendEntry(EVT_RECV, true, buffer, relevantLen + hashSizeBytes, &header, logHdrSize);
      free(buffer);
    } else {
      history->appendEntry(EVT_RECV, true, payload, payloadLen, &header, logHdrSize);
    }
    
    history->getTopLevelEntry(myHashTop, &seqOfRecvEntry);
    addToReceiveCache(handle->getIdentifier(), seq, history->getNumEntries() - 1);
    plog(2, "New message logged as seq#%lld", seqOfRecvEntry);

    /* Construct the SIGN entry and append it to the log */

    unsigned char signEntry[hashSizeBytes+signatureSizeBytes];
    memcpy(&signEntry[0], hTopMinusOne, hashSizeBytes);
    memcpy(&signEntry[hashSizeBytes], signature, signatureSizeBytes);
    history->appendEntry(EVT_SIGN, true, signEntry, sizeof(signEntry));
    *loggedPreviously = false;
  } else {
    *loggedPreviously = true;
    
    /* If the RECV entry already exists, retrieve it */
    
    unsigned char type;
    bool ok = true;
    ok &= history->statEntry(indexOfRecvEntry, &seqOfRecvEntry, &type, NULL, NULL, myHashTop);
    ok &= history->statEntry(indexOfRecvEntry-1, NULL, NULL, NULL, NULL, myHashTopMinusOne);
    plog(2, "This message has already been logged as seq#%lld", seqOfRecvEntry);
    assert(ok && (type == EVT_RECV));
  }

  /* Generate ACK = (MSG_ACK, myID, remoteSeq, localSeq, myTopMinusOne, signature) */

  unsigned char hToSign[hashSizeBytes]; 
  transport->hash(hToSign, (unsigned char*)&seqOfRecvEntry, sizeof(seqOfRecvEntry), myHashTop, sizeof(myHashTop));

  assert(ackMaxLen >= (17 + peerreview->getIdentifierSizeBytes() + hashSizeBytes + signatureSizeBytes));
  pos = 0;
  writeByte(ackMessage, &pos, MSG_ACK);
  myHandle->getIdentifier()->write(ackMessage, &pos, ackMaxLen);
  writeLongLong(ackMessage, &pos, seq);
  writeLongLong(ackMessage, &pos, seqOfRecvEntry);
  writeBytes(ackMessage, &pos, myHashTopMinusOne, hashSizeBytes);

  /* ... and sign it */

  unsigned int siglen = signatureSizeBytes;
  transport->sign((const unsigned char*)&hToSign, sizeof(hToSign), (unsigned char*)&ackMessage[pos]);
  pos += signatureSizeBytes;

  /* We don't send the ACK here; the caller does that, if appropriate */

  delete handle;
  return pos;
}

void CommitmentProtocol::notifyStatusChange(Identifier *id, int newStatus)
{
  for (int i=0; i<numPeers; i++) {
    if (peer[i].handle->getIdentifier()->equals(id)) 
      makeProgress(i);
  }
}

/* Tries to make progress on the message queue of the specified peer, e.g. after that peer
   has become TRUSTED, or after it has sent us an acknowledgment */

void CommitmentProtocol::makeProgress(int idx)
{
  char buf1[256], buf2[256];
  assert((0<=idx) && (idx<numPeers));

  if (!peer[idx].xmitQueue && !peer[idx].recvQueue)
    return;
  
  /* Get the public key. If we don't have it (yet), ask the peer to send it */

  if (!transport->haveCertificate(peer[idx].handle->getIdentifier())) {
    transport->requestCertificate(peer[idx].handle, peer[idx].handle->getIdentifier());
    return;
  }

  /* Transmit queue: If the peer is suspected, challenge it; otherwise, send the next message
     or retransmit the one currently in flight */

  if (peer[idx].xmitQueue) {
    int status = infoStore->getStatus(peer[idx].handle->getIdentifier());
    switch (status) {
      case STATUS_EXPOSED: /* Node is already exposed; no point in sending it any further messages */
        warning("Releasing messages sent to an exposed node");
        while (peer[idx].xmitQueue) {
          struct packetInfo *pi = peer[idx].xmitQueue;
          peer[idx].xmitQueue = peer[idx].xmitQueue->next;
          free(pi->message);
          free(pi);
        }
        return;
      case STATUS_SUSPECTED: /* Node is suspected; send the first unanswered challenge */
        if (peer[idx].lastChallenge < (peerreview->getTime() - peer[idx].currentChallengeInterval)) {
          warning("Pending message for SUSPECTED node %s; challenging node (interval=%lldus)", peer[idx].handle->render(buf1), peer[idx].currentChallengeInterval);
          peer[idx].lastChallenge = peerreview->getTime();
          peer[idx].currentChallengeInterval *= 2;
          peerreview->challengeSuspectedNode(peer[idx].handle);
        }
        return;
      case STATUS_TRUSTED: /* Node is trusted; continue below */
        peer[idx].lastChallenge = -1;
        peer[idx].currentChallengeInterval = INITIAL_CHALLENGE_INTERVAL_MICROS;
        break;
    }
  
    /* If there are no unacknowledged packets to that node, transmit the next packet */
  
    if (!peer[idx].numOutstandingPackets) {
      peer[idx].numOutstandingPackets ++;
      peer[idx].lastTransmit = peerreview->getTime();
      peer[idx].currentTimeout = INITIAL_TIMEOUT_MICROS;
      peer[idx].retransmitsSoFar = 0;
      peerreview->transmit(peer[idx].handle, false, peer[idx].xmitQueue->message, peer[idx].xmitQueue->msglen);
    } else if (peerreview->getTime() > (peer[idx].lastTransmit + peer[idx].currentTimeout)) {
    
      /* Otherwise, retransmit the current packet a few times, up to the specified limit */
    
      if (peer[idx].retransmitsSoFar < MAX_RETRANSMISSIONS) {
        warning("Retransmitting a %d-byte message to %s (lastxmit=%lld, timeout=%lld, type=%d)", peer[idx].xmitQueue->msglen, peer[idx].handle->render(buf1), peer[idx].lastTransmit, peer[idx].currentTimeout, peer[idx].xmitQueue->message[0]);
        peer[idx].retransmitsSoFar ++;
        peer[idx].currentTimeout = RETRANSMIT_TIMEOUT_MICROS;
        peer[idx].lastTransmit = peerreview->getTime();
        peerreview->transmit(peer[idx].handle, false, peer[idx].xmitQueue->message, peer[idx].xmitQueue->msglen);
      } else {
      
        /* If the peer still won't acknowledge the message, file a SEND challenge with its witnesses */
      
        warning("%s has not acknowledged our message after %d retransmissions; filing as evidence", peer[idx].handle->render(buf1), peer[idx].retransmitsSoFar);
        long long evidenceSeq = peerreview->getEvidenceSeq();
        peer[idx].xmitQueue->message[0] = CHAL_SEND;
        infoStore->addEvidence(myHandle->getIdentifier(), peer[idx].handle->getIdentifier(), evidenceSeq, peer[idx].xmitQueue->message, peer[idx].xmitQueue->msglen);
        peerreview->sendEvidenceToWitnesses(peer[idx].handle->getIdentifier(), evidenceSeq, peer[idx].xmitQueue->message, peer[idx].xmitQueue->msglen);

        struct packetInfo *pi = peer[idx].xmitQueue;
        peer[idx].xmitQueue = peer[idx].xmitQueue->next;
        peer[idx].numOutstandingPackets --;
        free(pi->message);
        free(pi);
      }
    }
  }

  /* Receive queue */

  if (peer[idx].recvQueue && !peer[idx].isReceiving) {
    peer[idx].isReceiving = true;
  
    /* Dequeue the packet. After this point, we must either deliver it or discard it */

    struct packetInfo *pi = peer[idx].recvQueue;
    peer[idx].recvQueue = pi->next;

    /* Extract the authenticator */
    
    unsigned char *message = pi->message;
    int msglen = pi->msglen;

    unsigned int pos = 0;
    long long seq = readLongLong(message, &pos);
    NodeHandle *handle = peerreview->readNodeHandle(message, &pos, msglen);
    unsigned char *hTopMinusOne = &message[pos];
    pos += hashSizeBytes;
    unsigned char *signature = &message[pos];
    pos += signatureSizeBytes;
    unsigned char relevantCode = readByte(message, &pos);
    int headerLen = pos;
    assert(msglen >= headerLen);
    unsigned char *payload = &message[pos];
    int payloadLen = msglen - headerLen;
    int relevantLen = (relevantCode == 0xFF) ? payloadLen : relevantCode;
    
    unsigned char innerHash[hashSizeBytes];
    if (relevantLen < payloadLen) {
      unsigned char irrelevantHash[hashSizeBytes];
      unsigned char header[MAX_ID_SIZE+1];
      unsigned int hdr2size = 0;
      myHandle->getIdentifier()->write(header, &hdr2size, sizeof(header));
      writeByte(header, &hdr2size, 1);
      transport->hash(irrelevantHash, &payload[relevantLen], payloadLen - relevantLen);
      transport->hash(innerHash, (const unsigned char*)&header, hdr2size, (const unsigned char*)payload, relevantLen, irrelevantHash, hashSizeBytes);
    } else {
      unsigned char header[MAX_ID_SIZE+1];
      unsigned int hdr2size = 0;
      myHandle->getIdentifier()->write(header, &hdr2size, sizeof(header));
      writeByte(header, &hdr2size, 0);
      transport->hash(innerHash, (const unsigned char*)&header, hdr2size, (const unsigned char*)payload, payloadLen);
    }
    
    unsigned char authenticator[sizeof(seq) + hashSizeBytes + signatureSizeBytes];
    if (peerreview->extractAuthenticator(handle->getIdentifier(), seq, EVT_SEND, innerHash, hTopMinusOne, signature, authenticator)) {

      /* At this point, we are convinced that:
            - The remote node is TRUSTED [TODO!!]
            - The message has an acceptable sequence number
            - The message is properly signed
         Now we must check our log for an existing RECV entry:
            - If we already have such an entry, we generate the ACK from there
            - If we do not yet have the entry, we log the message and deliver it  */

      unsigned char ackMessage[17 + MAX_ID_SIZE + hashSizeBytes + signatureSizeBytes];
      bool loggedPreviously;
      
      int ackSize = logMessageIfNew(message, msglen, ackMessage, sizeof(ackMessage), &loggedPreviously);

      /* Since the message is not yet in the log, deliver it to the application */

      if (!loggedPreviously) {
        plog(2, "Delivering message from %s via %s (%d bytes; %d/%d relevant)", handle->render(buf2), peer[idx].handle->render(buf1), payloadLen, relevantLen, payloadLen);
        app->receive(handle, false, payload, payloadLen); 
      } else {
        plog(2, "Message from %s via %s was previously logged; not delivered", handle->render(buf2), peer[idx].handle->render(buf1));
      }

      /* Send the ACK */

      plog(2, "Returning ACK to %s", peer[idx].handle->render(buf1));
      peerreview->transmit(peer[idx].handle, false, ackMessage, ackSize);
    } else {
      warning("Cannot verify signature on message %lld from %s; discarding", seq, peer[idx].handle->render(buf1));
    }
    
    /* Release the message */

    free(message);
    free(pi);   
    delete handle; 
    peer[idx].isReceiving = false;
    makeProgress(idx);
  }
}

int CommitmentProtocol::findRecvEntry(Identifier *id, long long seq)
{
  for (int i=0; i<RECEIVE_CACHE_SIZE; i++) {
    if ((seq == receiveCache[i].senderSeq) && receiveCache[i].sender && (receiveCache[i].sender->equals(id)))
      return receiveCache[i].indexInLocalHistory;
  }

  return -1;
}

long long CommitmentProtocol::findAckEntry(Identifier *id, long long seq)
{
  return -1;
}

/* Handle an incoming USERDATA message */

void CommitmentProtocol::handleIncomingMessage(NodeHandle *source, unsigned char *message, int msglen)
{
  char buf1[256];
  assert(message[0] == MSG_USERDATA);

  /* Sanity checks */

  if (msglen < (17 + hashSizeBytes + signatureSizeBytes)) {
    warning("Short application message from %s; discarding", source->render(buf1));
    return;
  }

  /* Check whether the timestamp (in the sequence number) is close enough to our local time.
     If not, the node may be trying to roll forward its clock, so we discard the message. */

  long long seq = *(long long*)&message[1];
  long long txmit = (seq / MAX_ENTRIES_PER_US);

  if ((txmit < (peerreview->getTime()-timeToleranceMicros)) || (txmit > (peerreview->getTime()+timeToleranceMicros))) {
    warning("Invalid sequence no #%lld on incoming message (dt=%lld); discarding", seq, (txmit-peerreview->getTime()));
    return;
  }

  /* Append a copy of the message to our receive queue. If the node is trusted,
     the message is going to be delivered directly by makeProgress(); otherwise
     a challenge is sent. */

  unsigned char *buf = (unsigned char*) malloc(msglen-1);
  memcpy(buf, &message[1], msglen-1);

  int idx = lookupPeer(source);
  peer[idx].recvQueue = enqueueTail(peer[idx].recvQueue, buf, msglen-1);

  makeProgress(idx);
}

long long CommitmentProtocol::handleOutgoingMessage(NodeHandle *target, unsigned char *message, int msglen, int relevantlen)
{
  assert(relevantlen >= 0);

  /* Append a SEND entry to our local log */
  
  unsigned char hTopMinusOne[hashSizeBytes], hTop[hashSizeBytes], hToSign[hashSizeBytes];
  long long topSeq;
  history->getTopLevelEntry(hTopMinusOne, NULL);
  if (relevantlen < msglen) {
    unsigned int logEntryMaxlen = MAX_ID_SIZE + 1 + relevantlen + hashSizeBytes;
    unsigned char *logEntry = (unsigned char*) malloc(logEntryMaxlen);
    unsigned int logEntryLen = 0;
    target->getIdentifier()->write(logEntry, &logEntryLen, logEntryMaxlen);
    writeByte(logEntry, &logEntryLen, 1);
    if (relevantlen > 0) {
      memcpy(&logEntry[logEntryLen], message, relevantlen);
      logEntryLen += relevantlen;
    }
    transport->hash(&logEntry[logEntryLen], &message[relevantlen], msglen - relevantlen);
    logEntryLen += hashSizeBytes;
    
    history->appendEntry(EVT_SEND, true, logEntry, logEntryLen);
    free(logEntry);
  } else {
    unsigned char header[MAX_ID_SIZE+1];
    unsigned int headerSize = 0;
    target->getIdentifier()->write(header, &headerSize, sizeof(header));
    writeByte(header, &headerSize, 0);
    history->appendEntry(EVT_SEND, true, message, msglen, header, headerSize);
  }
  
  history->getTopLevelEntry(hTop, &topSeq);
  
  /* Maybe we need to do some mischief for testing? */
  
  if (misbehavior)
    misbehavior->maybeChangeSeqInUserMessage(&topSeq);

  /* Sign the authenticator */
    
  transport->hash(hToSign, (unsigned char*)&topSeq, sizeof(topSeq), hTop, sizeof(hTop));

  unsigned char signature[signatureSizeBytes + 200];
  transport->sign((const unsigned char*)&hToSign, sizeof(hToSign), signature);
  
  /* Append a SENDSIGN entry */
  
  history->appendEntry(EVT_SENDSIGN, true, &message[relevantlen], msglen-relevantlen, signature, signatureSizeBytes);
  
  /* Maybe do some more mischief for testing? */

  if (misbehavior->dropAfterLogging(target, message, msglen))
    return topSeq;
  
  /* Construct a USERDATA message... */
  
  assert((relevantlen == msglen) || (relevantlen < 255));
  unsigned char relevantCode = (relevantlen == msglen) ? 0xFF : (unsigned char)relevantlen;
  unsigned int maxLen = 1 + sizeof(topSeq) + MAX_HANDLE_SIZE + hashSizeBytes + signatureSizeBytes + sizeof(relevantCode) + msglen;
  unsigned char *buf = (unsigned char *)malloc(maxLen);
  unsigned int totalLen = 0;
  
  writeByte(buf, &totalLen, MSG_USERDATA);
  writeLongLong(buf, &totalLen, topSeq);
  myHandle->write(buf, &totalLen, maxLen);
  writeBytes(buf, &totalLen, hTopMinusOne, hashSizeBytes);
  writeBytes(buf, &totalLen, signature, signatureSizeBytes);
  writeByte(buf, &totalLen, relevantCode);
  writeBytes(buf, &totalLen, message, msglen);
  assert(totalLen <= maxLen);
  
  /* ... and put it into the send queue. If the node is trusted and does not have any
     unacknowledged messages, makeProgress() will simply send it out. */
  
  int idx = lookupPeer(target);
  peer[idx].xmitQueue = enqueueTail(peer[idx].xmitQueue, buf, totalLen);
  makeProgress(idx);
  
  return topSeq;
}

/* This is called if we receive an acknowledgment from another node */

void CommitmentProtocol::handleIncomingAck(NodeHandle *source, unsigned char *message, int msglen)
{
  char buf1[256];
  assert(message && (message[0] == MSG_ACK));
  
  /* Sanity check */
  
  if (msglen < (17 + peerreview->getIdentifierSizeBytes() + hashSizeBytes + signatureSizeBytes))
    return;
      
  /* Acknowledgment: Log it (if we don't have it already) and send the next message, if any */

  plog(1, "Received an ACK from %s", source->render(buf1));

  unsigned int pos = 0;
  readByte(message, &pos);
  Identifier *remoteId = peerreview->readIdentifier(message, &pos, msglen);
  long long ackedSeq = readLongLong(message, &pos);
  long long hisSeq = readLongLong(message, &pos);
  unsigned char *hTopMinusOne = &message[pos];
  unsigned char *signature = &message[pos + hashSizeBytes];

  if (transport->haveCertificate(remoteId)) {
    int idx = lookupPeer(source);
    long long expectedSeq = -1;
    if (peer[idx].xmitQueue) {
      assert(peer[idx].xmitQueue->msglen >= 13);
      expectedSeq = *(long long*)&peer[idx].xmitQueue->message[1];
    }

    /* The ACK must acknowledge the sequence number of the packet that is currently
       at the head of the send queue */

    if (peer[idx].xmitQueue && (ackedSeq == expectedSeq)) {
      unsigned char innerHash[hashSizeBytes];
      unsigned int headerSize = 0;
      readByte(peer[idx].xmitQueue->message, &headerSize);
      long long sendSeq = readLongLong(peer[idx].xmitQueue->message, &headerSize);
      NodeHandle *sendHandle = peerreview->readNodeHandle(peer[idx].xmitQueue->message, &headerSize, peer[idx].xmitQueue->msglen);
      headerSize += signatureSizeBytes + hashSizeBytes;
      unsigned char relevantCode = readByte(peer[idx].xmitQueue->message, &headerSize);
      unsigned char *payload = &peer[idx].xmitQueue->message[headerSize];
      int payloadLen = peer[idx].xmitQueue->msglen - headerSize;
      int relevantLen = (relevantCode == 0xFF) ? payloadLen : relevantCode;

      /* The peer will have logged a RECV entry, and the signature is calculated over that
         entry. To verify the signature, we must reconstruct that RECV entry locally */

      unsigned int recvEntryHeaderMaxlen = MAX_HANDLE_SIZE+sizeof(long long)+1;
      unsigned char recvEntryHeader[recvEntryHeaderMaxlen];
      unsigned int recvEntryHeaderLen = 0;
      sendHandle->write(recvEntryHeader, &recvEntryHeaderLen, recvEntryHeaderMaxlen);
      writeLongLong(recvEntryHeader, &recvEntryHeaderLen, sendSeq);
      writeByte(recvEntryHeader, &recvEntryHeaderLen, (relevantLen < payloadLen) ? 1 : 0);
      delete sendHandle;
      
      if (relevantLen < payloadLen) {
        unsigned char irrelevantHash[hashSizeBytes];
        transport->hash(irrelevantHash, &payload[relevantLen], payloadLen - relevantLen);
        transport->hash(innerHash, recvEntryHeader, recvEntryHeaderLen, payload, relevantLen, irrelevantHash, hashSizeBytes);
      } else {
        transport->hash(innerHash, recvEntryHeader, recvEntryHeaderLen, payload, payloadLen);
      }

      /* Now we're ready to check the signature */

      unsigned char authenticator[sizeof(long long) + hashSizeBytes + signatureSizeBytes];
      if (peerreview->extractAuthenticator(remoteId, hisSeq, EVT_RECV, innerHash, hTopMinusOne, signature, authenticator)) {

        /* Signature is okay... append an ACK entry to the log */

        dlog(2, "ACK is okay; logging");
        unsigned char entry[2*sizeof(long long) + MAX_ID_SIZE + hashSizeBytes + signatureSizeBytes];
        unsigned int pos = 0;
        remoteId->write(entry, &pos, sizeof(entry));
        writeLongLong(entry, &pos, ackedSeq);
        writeLongLong(entry, &pos, hisSeq);
        writeBytes(entry, &pos, hTopMinusOne, hashSizeBytes);
        writeBytes(entry, &pos, signature, signatureSizeBytes);
        history->appendEntry(EVT_ACK, true, entry, pos);
        app->sendComplete(ackedSeq);

        /* Remove the message from the xmit queue */

        struct packetInfo *pi = peer[idx].xmitQueue;
        peer[idx].xmitQueue = peer[idx].xmitQueue->next;
        peer[idx].numOutstandingPackets --;
        free(pi->message);
        free(pi);

        /* Make progress (e.g. by sending the next message) */

        makeProgress(idx);
      } else {
        warning("Invalid ACK from <%s>; discarding", remoteId->render(buf1));
      }
    } else {
      if (findAckEntry(remoteId, ackedSeq) < 0) {
        warning("<%s> has ACKed something we haven't sent (%lld); discarding", remoteId->render(buf1), ackedSeq);
      } else {
        warning("Duplicate ACK from <%s>; discarding", remoteId->render(buf1));
      }
    }
  } else {
    warning("We got an ACK from <%s>, but we don't have the certificate; discarding", remoteId->render(buf1));
  }
  
  delete remoteId;
}
