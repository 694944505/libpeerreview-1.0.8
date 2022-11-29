#include <stdlib.h>

#include "peerreview.h"

/* app must return only closest IDs */

#define cacheEntryValid(idx) ((idx>=0) && witnessCache[idx].haveWitnesses && (witnessCache[idx].validUntil >= peerreview->getTime()))

#define SUBSYSTEM "peerreview"
#undef plog
#define plog(a...) do { peerreview->logText(SUBSYSTEM, a); } while (0)

EvidenceTransferProtocol::EvidenceTransferProtocol(PeerReview *peerreview, PeerReviewCallback *app, IdentityTransport *transport, PeerInfoStore *infoStore)
{
  this->peerreview = peerreview;
  this->app = app;
  this->numCacheEntries = 0;
  this->numPendingMessages = 0;
  this->numPendingQueries = 0;
  this->transport = transport;
  this->infoStore = infoStore;
}

EvidenceTransferProtocol::~EvidenceTransferProtocol()
{
  while (numCacheEntries)
    removeCacheEntry(0);
  
  while (numPendingMessages)
    removePendingMessage(0);
  
  while (numPendingQueries)
    removePendingQuery(0);
}

void EvidenceTransferProtocol::removeCacheEntry(int idx)
{
  assert((0<=idx) && (idx<numCacheEntries));

  delete witnessCache[idx].subject;
  if (witnessCache[idx].haveWitnesses) {
    for (int j=0; j<witnessCache[idx].numWitnesses; j++)
      delete witnessCache[idx].witness[j];
    free(witnessCache[idx].witness);
  }
  
  witnessCache[idx] = witnessCache[--numCacheEntries];
}

void EvidenceTransferProtocol::removePendingMessage(int idx)
{
  assert((0<=idx) && (idx<numPendingMessages));

  delete pendingMessage[idx].subject;
  free(pendingMessage[idx].message);

  pendingMessage[idx] = pendingMessage[--numPendingMessages];
}

void EvidenceTransferProtocol::removePendingQuery(int idx)
{
  assert((0<=idx) && (idx<numPendingQueries));

  for (int j=0; j<pendingQuery[idx].numSubjects; j++) {
    delete pendingQuery[idx].subjectList[j];

    if (pendingQuery[idx].witness[j]) {
      for (int k=0; k<pendingQuery[idx].numWitnesses[j]; k++)
        delete pendingQuery[idx].witness[j][k];

      if (pendingQuery[idx].witness[j])
        free(pendingQuery[idx].witness[j]);
    }
  }

  free(pendingQuery[idx].witness);
  free(pendingQuery[idx].numWitnesses);
  free(pendingQuery[idx].subjectList);
  
  pendingQuery[idx] = pendingQuery[--numPendingQueries];  
}

int EvidenceTransferProtocol::lookupInCache(Identifier *subject)
{
  for (int i=0; i<numCacheEntries; i++) {
    if (subject->equals(witnessCache[i].subject))
      return i;
  }
      
  return -1;
}

/* Called when the local node learns about the members of another node's witness set */

void EvidenceTransferProtocol::notifyWitnessSet(Identifier *subject, int numWitnesses, NodeHandle **witnesses)
{
  assert(subject && (numWitnesses >= 0) && (witnesses || !numWitnesses));

  /* Create a cache entry, if necessary */

  int idx = lookupInCache(subject);
  if (idx < 0)
    idx = makeCacheEntry(subject);
    
  /* If the entry already contains (old) witnesses, remove them */
    
  if (witnessCache[idx].haveWitnesses) {
    for (int i=0; i<witnessCache[idx].numWitnesses; i++) {
      assert(witnessCache[idx].witness && witnessCache[idx].witness[i]);
      delete witnessCache[idx].witness[i];
    }
    
    if (witnessCache[idx].witness)
      free(witnessCache[idx].witness);
    
    witnessCache[idx].haveWitnesses = false;
    witnessCache[idx].numWitnesses = -1;
    witnessCache[idx].witness = NULL;
  }
  
  /* Store the witnesses in the cache entry and make it valid */
  
  witnessCache[idx].witnessesRequested = false;
  witnessCache[idx].haveWitnesses = true;
  witnessCache[idx].numWitnesses = numWitnesses;
  witnessCache[idx].witness = NULL;
  if (numWitnesses > 0) {
    witnessCache[idx].witness = (NodeHandle**) malloc(numWitnesses * sizeof(NodeHandle*));
    for (int i=0; i<numWitnesses; i++)
      witnessCache[idx].witness[i] = witnesses[i]->clone();
  }
  
  witnessCache[idx].validUntil = peerreview->getTime() + WITNESS_SET_VALID_MICROS;

  /* If we have any waiting messages for this witness set, we deliver them */

  bool madeProgress = true;
  while (madeProgress) {
    madeProgress = false;
    for (int i=0; (i<numPendingMessages) && !madeProgress; i++) {
      if (subject->equals(pendingMessage[i].subject)) {
        doSendMessageToWitnesses(idx, pendingMessage[i].datagram, pendingMessage[i].message, pendingMessage[i].msglen);
        removePendingMessage(i);
        madeProgress = true;
      }
    }
  }
  
  /* If this witness set was part of a query, we update the results and answer if possible */
  
  madeProgress = true;
  while (madeProgress) {
    madeProgress = false;
    for (int i=0; (i<numPendingQueries) && !madeProgress; i++) {
      bool hasUnresolvedEntries = false;
      for (int j=0; j<pendingQuery[i].numSubjects; j++) {
        if (pendingQuery[i].numWitnesses[j] < 0) {
          if (subject->equals(pendingQuery[i].subjectList[j])) {
            assert(pendingQuery[i].witness[j] == NULL);
            pendingQuery[i].numWitnesses[j] = numWitnesses;

            if (numWitnesses > 0) {
              pendingQuery[i].witness[j] = (NodeHandle**) malloc(numWitnesses * sizeof(NodeHandle*));
              for (int k=0; k<numWitnesses; k++)
                pendingQuery[i].witness[j][k] = witnesses[k]->clone();
            }
          } else {
            hasUnresolvedEntries = true;
          }
        }
      }
        
      if (!hasUnresolvedEntries) {
        deliverWitnesses(i);
        madeProgress = true;
      }
    }
  }
}

int EvidenceTransferProtocol::makeCacheEntry(Identifier *subject)
{
  if (numCacheEntries >= MAX_CACHE_ENTRIES)
    panic("Too many entries in witness cache");

  int idx = numCacheEntries ++;
  witnessCache[idx].subject = subject->clone();
  witnessCache[idx].witnessesRequested = false;
  witnessCache[idx].haveWitnesses = false;
  witnessCache[idx].numWitnesses = -1;
  witnessCache[idx].witness = NULL;
  witnessCache[idx].validUntil = -1;

  return idx;
}

void EvidenceTransferProtocol::doSendMessageToWitnesses(int idx, bool datagram, unsigned char *message, int msglen)
{
  assert((0<=idx) && (idx<numCacheEntries) && cacheEntryValid(idx));
  
  for (int i=0; i<witnessCache[idx].numWitnesses; i++)
    peerreview->transmit(witnessCache[idx].witness[i], datagram, message, msglen);
}

/* Send a message to all the members of the target node's witness set. If the witness set
   is not known, we need to make an upcall to the application first */

void EvidenceTransferProtocol::sendMessageToWitnesses(Identifier *subject, bool datagram, unsigned char *message, int msglen)
{
  int idx = lookupInCache(subject);
  
  if ((idx>=0) && witnessCache[idx].haveWitnesses && cacheEntryValid(idx)) {
    doSendMessageToWitnesses(idx, datagram, message, msglen);
    return;
  }
  
  /* Keep the message for later */
  
  if (numPendingMessages >= MAX_PENDING_MESSAGES)
    panic("Too many pending messages!");
  
  int slot = numPendingMessages ++;
  pendingMessage[slot].subject = subject->clone();
  pendingMessage[slot].datagram = datagram;
  pendingMessage[slot].message = (unsigned char*) malloc(msglen);
  memcpy(pendingMessage[slot].message, message, msglen);
  pendingMessage[slot].msglen = msglen;
  
  /* If we don't have a cache entry yet, create one */
  
  if (idx<0)
    idx = makeCacheEntry(subject);
    
  /* Ask the app for the witness set, if we haven't already */
  
  if (!witnessCache[idx].witnessesRequested) {
    witnessCache[idx].witnessesRequested = true;
    app->getWitnesses(subject, this);
  }
}

/* Requests witness sets for several nodes */

void EvidenceTransferProtocol::requestWitnesses(Identifier **subjectList, int numSubjects)
{
  if (numPendingQueries >= MAX_PENDING_QUERIES)
    panic("Too many pending queries for witness sets!");
    
  int idx = numPendingQueries ++;
  pendingQuery[idx].numSubjects = numSubjects;
  pendingQuery[idx].subjectList = (Identifier**) malloc(numSubjects * sizeof(Identifier*));
  for (int i=0; i<numSubjects; i++)
    pendingQuery[idx].subjectList[i] = subjectList[i]->clone();

  bool mustRequestWitnesses[numSubjects];
  for (int i=0; i<numSubjects; i++)
    mustRequestWitnesses[i] = false;

  pendingQuery[idx].witness = (NodeHandle***) malloc(numSubjects * sizeof(NodeHandle**));
  pendingQuery[idx].numWitnesses = (int*) malloc(numSubjects * sizeof(int));
  
  bool allWitnessesCached = true;
  for (int i=0; i<numSubjects; i++) {
    int ci = lookupInCache(subjectList[i]);
    
    if ((ci>=0) && cacheEntryValid(ci)) {
      pendingQuery[idx].witness[i] = (NodeHandle**) malloc(witnessCache[ci].numWitnesses * sizeof(NodeHandle*));
      pendingQuery[idx].numWitnesses[i] = witnessCache[ci].numWitnesses;
      for (int j=0; j<witnessCache[ci].numWitnesses; j++)
        pendingQuery[idx].witness[i][j] = witnessCache[ci].witness[j]->clone();
    } else {
      pendingQuery[idx].witness[i] = NULL;
      pendingQuery[idx].numWitnesses[i] = -1;
      allWitnessesCached = false;

      if (ci < 0)
        ci = makeCacheEntry(subjectList[i]);
        
      if (!witnessCache[ci].witnessesRequested) {
        witnessCache[ci].witnessesRequested = true;
        mustRequestWitnesses[i] = true;
      }
    }
  }

  for (int i=0; i<numSubjects; i++) {
    if (mustRequestWitnesses[i]) 
      app->getWitnesses(subjectList[i], this);
  }

  if (allWitnessesCached)
    deliverWitnesses(idx);
}

/* After a call to requestWitnesses(), the witness sets are resolved in parallel.
   Once all the answers are know, this function is called to inform PeerReview. */

void EvidenceTransferProtocol::deliverWitnesses(int idx)
{ 
  assert((0<=idx) && (idx<numPendingQueries));
  
  int numWitnessesTotal = 0;
  for (int i=0; i<pendingQuery[idx].numSubjects; i++) {
    assert(pendingQuery[idx].numWitnesses[i] >= 0);
    numWitnessesTotal += pendingQuery[idx].numWitnesses[i];
  }
  
  int pos = 0;
  NodeHandle **witnesses = (NodeHandle**) malloc(numWitnessesTotal * sizeof(NodeHandle*));

  for (int i=0; i<pendingQuery[idx].numSubjects; i++) {
    for (int j=0; j<pendingQuery[idx].numWitnesses[i]; j++) 
      witnesses[pos++] = pendingQuery[idx].witness[i][j];
  }
  
  assert(pos == numWitnessesTotal);
  
  peerreview->notifyWitnessesExt(pendingQuery[idx].numSubjects, pendingQuery[idx].subjectList, pendingQuery[idx].numWitnesses, witnesses);
  free(witnesses);
  removePendingQuery(idx);
}

/* When this is called, some node has asked us for evidence about another node, 
   and we have found either (a) an unanswered challenge, or (b) a proof of 
   misbehavior. We send back an ACCUSATION message that contains the evidence. */

void EvidenceTransferProtocol::sendEvidence(NodeHandle *target, Identifier *subject)
{
  char buf1[256], buf2[256];
  plog(2, "sendEvidence(%s, subject=%s)", target->render(buf1), subject->render(buf2));
  
  int status = infoStore->getStatus(subject);
  assert(status != STATUS_TRUSTED);
  
  Identifier *originator;
  long long timestamp;
  int evidenceLen;
  bool ok;
  
  /* Get the evidence */
  
  if (status == STATUS_EXPOSED) 
    ok = infoStore->statProof(subject, &originator, &timestamp, &evidenceLen);
  else 
    ok = infoStore->statFirstUnansweredChallenge(subject, &originator, &timestamp, &evidenceLen);
    
  assert(ok);

  /* Put together an ACCUSATION message */

  unsigned int maxAccusationLen = 1 + 2*MAX_ID_SIZE + sizeof(long long) + evidenceLen;
  unsigned char *accusation = (unsigned char*) malloc(maxAccusationLen);
  unsigned int ptr = 0;
  accusation[ptr++] = MSG_ACCUSATION;
  originator->write(accusation, &ptr, maxAccusationLen);
  subject->write(accusation, &ptr, maxAccusationLen);
  writeLongLongSafe(timestamp, accusation, &ptr, maxAccusationLen);
  infoStore->getEvidence(originator, subject, timestamp, &accusation[ptr], evidenceLen);
  ptr += evidenceLen;

  assert(ptr <= maxAccusationLen);

  /* ... and send it */

  plog(3, "Sending %d-byte %s to %s", evidenceLen, (status==STATUS_EXPOSED) ? "proof" : "challenge", target->render(buf1));
  transport->send(target, false, accusation, ptr);
  free(accusation);    
}
