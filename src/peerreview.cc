#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <openssl/pem.h>
#include <assert.h>
#include <ctype.h>

#include "peerreview.h"
#include "config.h"

#define SUBSYSTEM "peerreview"

#define ddump(a, b) do { } while (0)

PeerReview::PeerReview(IdentityTransport *transport)
{
  this->commitmentProtocol = NULL;
  this->challengeProtocol = NULL;
  this->infoStore = NULL;
  this->history = NULL;
  this->signatureSizeBytes = 0;
  this->hashSizeBytes = 0;
  this->app = NULL;
  this->transport = transport;
  this->initialized = false;
  this->authOutStore = NULL;
  this->authInStore = NULL;
  this->authPendingStore = NULL;
  this->authCacheStore = NULL;
  this->evidenceTransferProtocol = NULL;
  this->auditProtocol = NULL;
  this->statementProtocol = NULL;
  this->misbehavior = NULL;
  this->nextEvidenceSeq = 0;
  this->authenticatorSizeBytes = 0;
  this->lastLogEntry = -1;
  this->numStatusInfo = 0;
  this->timeToleranceMicros = DEFAULT_TIME_TOLERANCE_MICROS;
  this->authPushIntervalMicros = DEFAULT_AUTH_PUSH_INTERVAL_MICROS;
  this->checkpointIntervalMicros = DEFAULT_CHECKPOINT_INTERVAL_MICROS;
  this->prng = NULL;
  this->prngEnabled = false;
  this->extInfoPolicy = NULL;
}

/* PeerReview checks the timestamps on messages against the local clock, and ignores
   them if the timestamp is too far out of sync. The definition of 'too far' can
   be controlled with this method. */

void PeerReview::setTimeToleranceMicros(long long timeToleranceMicros)
{
  this->timeToleranceMicros = timeToleranceMicros;
  if (commitmentProtocol)
    commitmentProtocol->setTimeToleranceMicros(timeToleranceMicros);
}

/* Writes a message to the log. Called by various other PeerReview classes. */

void PeerReview::logText(const char *subsystem, int level, const char *format, ...)
{
  char buffer[4096];
  va_list ap;
  va_start (ap, format);
  if (vsnprintf (buffer, sizeof(buffer), format, ap) > sizeof(buffer)) {
//    panic("Buffer overflow in PeerReview::logText()");
    buffer[sizeof(buffer)-1] = 0;
    for (int i=0; i<3; i++)
      buffer[sizeof(buffer)-(2+i)] = '.';
  }
  
  transport->logText(subsystem, level, "%s", buffer);
  va_end (ap);
}

/* Writes a hexdump to the log. Useful e.g. for logging the contents of a message. */

void PeerReview::dump(int level, const unsigned char *payload, int len)
{
#ifndef WARNINGSONLY
  int i, off = 0;
  char linebuf[400];
  
  while (off < len) {
    sprintf(linebuf, "%04X   ", off);
    for (i=0; i<16; i++) {
      if ((i+off) < len)
        sprintf(&linebuf[strlen(linebuf)], "%02X ", payload[i+off]);
      else
        strcat(linebuf, "   ");
    }
    
    strcat(linebuf, "   ");
    
    for (i=0; i<16; i++) {
      if ((i+off) < len)
        sprintf(&linebuf[strlen(linebuf)], "%c", isprint(payload[i+off]) ? payload[i+off] : '.');
    }
    
    off += 16;
    plog(level, "%s", linebuf);
  }
#endif
}

/* Gets a fresh, unique sequence number for evidence */

long long PeerReview::getEvidenceSeq()
{
  if (nextEvidenceSeq < getTime())
    nextEvidenceSeq = getTime();
    
  return nextEvidenceSeq ++;
}

/* PeerReview only updates its internal clock when it returns to the main loop, but not
   in between (e.g. while it is handling messages). When the clock needs to be
   updated, this function is called. */

void PeerReview::updateLogTime()
{
  long long now = transport->getTime();

  if (now > lastLogEntry) {
    if (!history->setNextSeq(now * 1000))
      panic("PeerReview: Cannot roll back history sequence number from %lld to %lld; did you change the local time?", history->getLastSeq(), now*1000);
      
    lastLogEntry = now;
  }
}

/* Called by applications to log some application-specific event, such as PAST_GET. */

void PeerReview::logEvent(char type, const void *entry, int size)
{
  assert(initialized && (type > EVT_MAX_RESERVED));
  updateLogTime();
  history->appendEntry(type, true, entry, size);   
}

/* Called internally to log events */

void PeerReview::logEventInternal(char type, const void *entry, int size)
{
  assert(initialized && (type <= EVT_MAX_RESERVED));
  updateLogTime();
  history->appendEntry(type, true, entry, size);   
}

/* Called by applications to send a message to another node */

long long PeerReview::send(NodeHandle *target, bool datagram, unsigned char *message, int msglen, int relevantlen)
{
  /* If the 'datagram' flag is set, the message is passed through to the transport
     layer. This is used e.g. for liveness/proximity pings in Pastry. */

  if (datagram) {
    unsigned char *buf = (unsigned char*) malloc(msglen+1);
    buf[0] = MSG_USERDGRAM;
    memcpy(&buf[1], message, msglen);
    transport->send(target, true, buf, msglen+1, msglen+1);
    free(buf);
    return -1;
  }

  /* If someone sets relevantLen=-1, it means the whole message is relevant. */

  assert(!datagram);
  if (relevantlen < 0)
    relevantlen = msglen;

  assert(initialized && (0<=relevantlen) && (relevantlen<=msglen));
  
  /* Maybe do some mischief for testing? */
  
  if (misbehavior)
    misbehavior->maybeTamperWithData((unsigned char*)message, msglen);

  updateLogTime();
  
  /* Pass the message to the Commitment protocol */
  
  return commitmentProtocol->handleOutgoingMessage(target, message, msglen, relevantlen);
}

/* Called by the application to request a wake-up call at a specified time */

void PeerReview::scheduleTimer(TimerCallback *callback, int timerID, long long when)
{
  assert(initialized && (timerID > TI_MAX_RESERVED));
  transport->scheduleTimer(callback, timerID, when);
}

/* Called by the application to cancel a timer */

void PeerReview::cancelTimer(TimerCallback *callback, int timerID)
{
  assert(initialized);
  transport->cancelTimer(callback, timerID);
}

/* Called by the application during initialization; informs PeerReview where to
   send upcalls such as receive(). */

void PeerReview::setCallback(PeerReviewCallback *callback)
{
  this->app = callback;
}

/* Called by the transport layer when we receive a message */

void PeerReview::receive(NodeHandle *handle, bool datagram, unsigned char *message, int msglen)
{
  char buf1[256];
  assert(initialized && (msglen>0));

  if (infoStore->getStatus(handle->getIdentifier()) == STATUS_EXPOSED) {
    warning("Received a message (type %d) from an exposed node -- ignoring", message[0]);
    return;
  }
  
  /* Maybe do some mischief for testing */
  
  if (misbehavior->dropIncomingMessage(handle, datagram, message, msglen))
    return;

//  plog(1, "Received %s from %s (%d bytes)", datagram ? "DATAGRAM" : "MESSAGE", handle->render(buf1), msglen);
//  dump(2, message, msglen);
  
  /* Deliver datagrams */
  
  if (datagram) {
    switch (message[0]) {
      case MSG_AUTHPUSH :
        authPushProtocol->handleIncomingAuthenticators(handle, message, msglen);
        break;
      case MSG_AUTHREQ :
      case MSG_AUTHRESP :
        auditProtocol->handleIncomingDatagram(handle, message, msglen);
        break;
      case MSG_USERDGRAM :
        app->receive(handle, true, &message[1], msglen-1);
        break;
      default:
        panic("Unknown datagram type in PeerReview: #%d", message[0]);
        break;
    }
    
    return;
  }
  
  updateLogTime();

  /* Deliver messages */

  switch (message[0]) {
    case MSG_ACK:
      commitmentProtocol->handleIncomingAck(handle, message, msglen);
      break;
    case MSG_CHALLENGE:
      challengeProtocol->handleChallenge(handle, message, msglen);
      break;
    case MSG_ACCUSATION:
    case MSG_RESPONSE:
      statementProtocol->handleIncomingStatement(handle, message, msglen);
      break;
    case MSG_USERDATA:
      challengeProtocol->handleIncomingMessage(handle, message, msglen);
      break;
    default:
      panic("Unknown message type in PeerReview: #%d", message[0]);
      break;
  }
}

/* Destructor */

PeerReview::~PeerReview()
{
  if (initialized) {
    delete challengeProtocol;
    delete authPushProtocol;
    delete commitmentProtocol;
    delete auditProtocol;
    delete statementProtocol;
    delete authOutStore;
    delete authInStore;
    delete authPendingStore;
    delete authCacheStore;
    delete evidenceTransferProtocol;
    delete infoStore;
    delete misbehavior;
    delete history;
    delete app;
    initialized = false;
  }
  
#warning this stuff does not belong here; impose proper ordering!
  for (int i=0; i<numStatusInfo; i++) 
    delete statusInfo[i].id;
}

/* Helper function called internally from the library. It takes a (potentially new) authenticator
   and adds it to our local store if (a) it hasn't been recorded before, and (b) its signature
   is valid. */

bool PeerReview::addAuthenticatorIfValid(AuthenticatorStore *store, Identifier *subject, unsigned char *auth)
{
  long long seq = *(long long*)auth;
  unsigned char existingAuth[authenticatorSizeBytes];
  
  /* Do we already have an authenticator with the same sequence number and from the same node? */
  
  if (store && store->statAuthenticator(subject, seq, existingAuth)) {
  
    /* If yes, then it should be bit-wise identical to the new one */
  
    if (memcmp(auth, existingAuth, authenticatorSizeBytes)) {
    
      /* But it isn't... maybe the new authenticator is a forgery? Let's check the signature! 
         If the signature doesn't check out, then we simply discard the 'authenticator' and
         move on. */
    
      unsigned char signedHash[hashSizeBytes];
      hash(signedHash, auth, sizeof(long long)+hashSizeBytes);

      assert(transport->haveCertificate(subject));
    
      int sigResult = transport->verify(subject, signedHash, hashSizeBytes, &auth[sizeof(long long)+hashSizeBytes]);
      assert((sigResult == SIGNATURE_OK) || (sigResult == SIGNATURE_BAD));
      if (sigResult != SIGNATURE_OK)
        return false;

      /* The signature checks out, so the node must have signed two different authenticators
         with the same sequence number! This is a proof of misbehavior, and we must
         notify the witness set! */

      char buf1[1000];
      warning("Authenticator conflict for %s seq #%lld", subject->render(buf1), seq);
      plog(2, "Existing: [%s]", renderBytes(existingAuth, authenticatorSizeBytes, buf1));
      plog(2, "New:      [%s]", renderBytes(auth, authenticatorSizeBytes, buf1));
      
      unsigned char proof[1+MAX_ID_SIZE+1+2*authenticatorSizeBytes];
      unsigned int pos = 0;
      writeByte(proof, &pos, PROOF_INCONSISTENT);
      writeBytes(proof, &pos, auth, authenticatorSizeBytes);
      writeByte(proof, &pos, 0);
      writeBytes(proof, &pos, existingAuth, authenticatorSizeBytes);
      assert(pos <= sizeof(proof));

      long long evidenceSeq = getEvidenceSeq();
      infoStore->addEvidence(transport->getLocalHandle()->getIdentifier(), subject, evidenceSeq, proof, pos);
      sendEvidenceToWitnesses(subject, evidenceSeq, proof, pos);
      return false;
    }
  } else {
    
    /* We haven't seen this authenticator... let's check the signature. If it doesn't check out,
       we discard the 'authenticator'. */
  
    unsigned char signedHash[hashSizeBytes];
    hash(signedHash, auth, sizeof(long long)+hashSizeBytes);

    assert(transport->haveCertificate(subject));
    
    int sigResult = transport->verify(subject, signedHash, hashSizeBytes, &auth[sizeof(long long)+hashSizeBytes]);
    assert((sigResult == SIGNATURE_OK) || (sigResult == SIGNATURE_BAD));
    if (sigResult != SIGNATURE_OK)
      return false;

    /* Signature is ok, so we keep the new authenticator in our store. */

    if (store)
      store->addAuthenticator(subject, auth);
  }
  
  return true;
}

/* Called by the transport layer when it receives a certificate for a new nodeID. We notify
   all the classes that might be interested. */

void PeerReview::notifyCertificateAvailable(Identifier *id) 
{ 
  commitmentProtocol->notifyCertificateAvailable(id); 
  authPushProtocol->notifyCertificateAvailable(id);
  statementProtocol->notifyCertificateAvailable(id);
}

void PeerReview::writeCheckpoint()
{
  const int maxlen = 1048576*96;
  unsigned char *buffer = (unsigned char*) malloc(maxlen);
  int size = 0;

  if (prng)
    size += prng->storeCheckpoint(&buffer[size], maxlen - size);
  size += app->storeCheckpoint(&buffer[size], maxlen - size);

  if ((size < 0) || (size >= maxlen))
    panic("Cannot write checkpoint (size=%d)", size);

  updateLogTime();
  plog(1, "Writing checkpoint (%d bytes)", size);
  history->appendEntry(EVT_CHECKPOINT, true, buffer, size);
  free(buffer);
}

void PeerReview::timerExpired(int timerID)
{
  switch (timerID) {
    case TI_MAINTENANCE: /* Periodic maintenance timer; used to garbage-collect old authenticators */
      plog(1, "Doing maintenance");
      authInStore->garbageCollect();
      authOutStore->garbageCollect();
      authPendingStore->garbageCollect();
      transport->scheduleTimer(this, TI_MAINTENANCE, transport->getTime() + MAINTENANCE_INTERVAL_MICROS);
      break;
    case TI_AUTH_PUSH: /* Periodic timer for pushing batches of authenticators to the witnesses */
      plog(1, "Doing authenticator push");
      authPushProtocol->push();
      transport->scheduleTimer(this, TI_AUTH_PUSH, transport->getTime() + authPushIntervalMicros);
      break;
    case TI_STATUS_INFO: /* Send status updates to the application AFTER all other events */
    {
      for (int i=0; i<numStatusInfo; i++) {
        app->statusChange(statusInfo[i].id, statusInfo[i].newStatus);
        delete statusInfo[i].id;
      }
      
      numStatusInfo = 0;
      break;
    }
    case TI_CHECKPOINT: /* Periodic timer for writing checkpoints */
    {
      long long topSeq;
      history->getTopLevelEntry(NULL, &topSeq);
      int topIdx = history->findSeq(topSeq);
      unsigned char topType = 0;
      history->statEntry(topIdx, NULL, &topType, NULL, NULL, NULL);
      if (topType != EVT_CHECKPOINT)
        writeCheckpoint();
        
      transport->scheduleTimer(this, TI_CHECKPOINT, transport->getTime() + checkpointIntervalMicros);
      break;
    }
    default:
      panic("Unknown timer #%d expired in PeerReview", timerID);
  }
}

/* Called by our local classes when a node's status changes (e.g. from TRUSTED to SUSPECTED). 
   We must not notify the application until all other events have been processed; otherwise
   cross-dependencies can cause weird bugs. We use a buffer and a one-shot timer to do this. */

void PeerReview::notifyStatusChange(Identifier *id, int newStatus)
{
  char buf1[256];
  plog(1, "Status change: <%s> becomes %s", id->render(buf1), renderStatus(newStatus));
  challengeProtocol->notifyStatusChange(id, newStatus);
  commitmentProtocol->notifyStatusChange(id, newStatus);
  
  if (numStatusInfo >= MAX_STATUS_INFO)
    panic("Too many pending status notifications");
    
  statusInfo[numStatusInfo].id = id->clone();
  statusInfo[numStatusInfo].newStatus = newStatus;
  numStatusInfo ++;
  transport->scheduleTimer(this, TI_STATUS_INFO, transport->getTime() + 3);
}

/* Initialization */

void PeerReview::init(const char *dirname, const char *misbehaviorString)
{
  assert(!initialized && (app != NULL));
  char namebuf[200], buf1[200], sectionbuf[200];

  plog(2, "Initializing %s %s (built on %s %s)", PACKAGE, VERSION, __DATE__, __TIME__);

  struct stat statbuf;
  if (stat(dirname, &statbuf) < 0)
    panic("Cannot open PeerReview directory: %s", dirname);
  
  /* Initialize certificate store */

  sprintf(namebuf, "%s/peers", dirname);
  infoStore = new PeerInfoStore(transport);
  infoStore->setStatusChangeListener(this);
  
  /* Open history */
  
  bool newLogCreated = false;
  char historyName[200];
  sprintf(historyName, "%s/local", dirname);
  history = SecureHistory::open(historyName, "w", transport);
  if (!history) {
    unsigned char baseHash[transport->getHashSizeBytes()];
    memset(baseHash, 0, sizeof(baseHash));
    history = SecureHistory::create(historyName, 0, baseHash, transport);
    newLogCreated = true;
    if (!history)
      panic("Cannot create local history: %s", historyName);
  }

  updateLogTime();

  hashSizeBytes = transport->getHashSizeBytes();
  signatureSizeBytes = transport->getSignatureSizeBytes();
  authenticatorSizeBytes = sizeof(long long) + hashSizeBytes + signatureSizeBytes;
  infoStore->setAuthenticatorSize(authenticatorSizeBytes);
  if (!infoStore->setStorageDirectory(namebuf))
    panic("Cannot open info storage directory '%s'", namebuf);

  /* Initialize authenticator store */
  
  sprintf(namebuf, "%s/authenticators.in", dirname);
  authInStore = new AuthenticatorStore(this, authenticatorSizeBytes);
  if (!authInStore->setFilename(namebuf))
    panic("Cannot open authenticator store '%s'", namebuf);

  sprintf(namebuf, "%s/authenticators.out", dirname);
  authOutStore = new AuthenticatorStore(this, authenticatorSizeBytes);
  if (!authOutStore->setFilename(namebuf))
    panic("Cannot open authenticator store '%s'", namebuf);

  sprintf(namebuf, "%s/authenticators.pending", dirname);
  authPendingStore = new AuthenticatorStore(this, authenticatorSizeBytes, true);
  if (!authPendingStore->setFilename(namebuf))
    panic("Cannot open authenticator store '%s'", namebuf);

  sprintf(namebuf, "%s/authenticators.cache", dirname);
  authCacheStore = new AuthenticatorStore(this, authenticatorSizeBytes, true);
  if (!authCacheStore->setFilename(namebuf))
    panic("Cannot open authenticator store '%s'", namebuf);

  /* Remaining protocols */
  
  evidenceTransferProtocol = new EvidenceTransferProtocol(this, app, transport, infoStore);
  misbehavior = new Misbehavior(this, misbehaviorString, signatureSizeBytes, hashSizeBytes, authOutStore, transport, history);
  commitmentProtocol = new CommitmentProtocol(this, transport, infoStore, authOutStore, history, app, misbehavior, timeToleranceMicros);
  authPushProtocol = new AuthenticatorPushProtocol(this, authInStore, authOutStore, authPendingStore, transport, app, infoStore, hashSizeBytes, evidenceTransferProtocol);
  auditProtocol = new AuditProtocol(this, history, infoStore, authInStore, transport, app, authOutStore, evidenceTransferProtocol, authCacheStore);
  challengeProtocol = new ChallengeResponseProtocol(this, transport, infoStore, history, authOutStore, auditProtocol, commitmentProtocol, app);
  statementProtocol = new StatementProtocol(this, challengeProtocol, infoStore, transport, hashSizeBytes, app);

  transport->scheduleTimer(this, TI_MAINTENANCE, transport->getTime() + MAINTENANCE_INTERVAL_MICROS);
  transport->scheduleTimer(this, TI_AUTH_PUSH, transport->getTime() + authPushIntervalMicros);
  transport->scheduleTimer(this, TI_CHECKPOINT, transport->getTime() + (newLogCreated ? 1 : checkpointIntervalMicros));

  if (extInfoPolicy)
    challengeProtocol->setExtInfoPolicy(extInfoPolicy);

  /* PRNG */

  if (prngEnabled)
    prng = new SimplePRNG();

  /* OK; we're ready to go */

  initialized = true;

  /* Append an INIT entry to the log */

  unsigned char handlebuf[MAX_HANDLE_SIZE];
  unsigned int size = 0;
  transport->getLocalHandle()->write(handlebuf, &size, sizeof(handlebuf));
  history->appendEntry(EVT_INIT, true, handlebuf, size);

  app->init();
  writeCheckpoint();
}

/* Called internally by other classes if they have found evidence against one of our peers.
   We ask the EvidenceTransferProtocol to send it to the corresponding witness set. */

void PeerReview::sendEvidenceToWitnesses(Identifier *subject, long long evidenceSeq, const unsigned char *evidence, int evidenceLen)
{
  unsigned int accusationMaxlen = 1 + 2*MAX_ID_SIZE + sizeof(long long) + evidenceLen + signatureSizeBytes;
  unsigned char *accusation = (unsigned char*) malloc(accusationMaxlen);
  unsigned int accusationLen = 0;
  char buf1[256];

  accusation[accusationLen++] = MSG_ACCUSATION;
  transport->getLocalHandle()->getIdentifier()->write(accusation, &accusationLen, accusationMaxlen);
  subject->write(accusation, &accusationLen, accusationMaxlen);
  writeLongLong(accusation, &accusationLen, evidenceSeq);
  memcpy(&accusation[accusationLen], evidence, evidenceLen);
  accusationLen += evidenceLen;
  
  plog(2, "Relaying evidence to <%s>'s witnesses", subject->render(buf1));
  evidenceTransferProtocol->sendMessageToWitnesses(subject, false, accusation, accusationLen);

  free(accusation);
}

/* A helper function that extracts an authenticator from an incoming message and adds it to our local store. */

bool PeerReview::extractAuthenticator(Identifier *id, long long seq, unsigned char entryType, const unsigned char *entryHash, const unsigned char *hTopMinusOne, unsigned char *signature, unsigned char *authenticator)
{
  *(long long*)&authenticator[0] = seq;
  hash(&authenticator[sizeof(seq)], (const unsigned char*)&seq, sizeof(seq), &entryType, sizeof(entryType), hTopMinusOne, hashSizeBytes, entryHash, hashSizeBytes);
  memcpy(&authenticator[sizeof(seq)+hashSizeBytes], signature, signatureSizeBytes);
  return addAuthenticatorIfValid(authOutStore, id, authenticator);
}

/* Called by the application if an expected message has not arrived */

void PeerReview::investigate(NodeHandle *target, long long since)
{
  auditProtocol->investigate(target, since);
}

void PeerReview::transmit(NodeHandle *target, bool datagram, unsigned char *message, int msglen)
{
  if (!misbehavior || !misbehavior->dropOutgoingMessage(target, datagram, message, msglen))
    transport->send(target, datagram, message, msglen);
}

void PeerReview::notifyWitnessesExt(int numSubjects, Identifier **subjects, int *witnessesPerSubject, NodeHandle **witnesses)
{
  authPushProtocol->continuePush(numSubjects, subjects, witnessesPerSubject, witnesses);
}

/* Choose a random number generator */

int PeerReview::getRandom(int range)
{
  if (!prng)
    panic("Call enableRandomNumberGenerator() before using it!");
    
  return prng->getRandom(range);
}

void PeerReview::disableAuthenticatorProcessing()
{
  assert(initialized);

  transport->cancelTimer(this, TI_MAINTENANCE);
  authInStore->disableMemoryBuffer();
  authOutStore->disableMemoryBuffer();
  authPendingStore->disableMemoryBuffer();
}
