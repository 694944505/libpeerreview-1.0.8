#include "peerreview/vrf.h"

#define SUBSYSTEM "RandomWrapper"

RandomWrapper::RandomWrapper(PeerReview *peerreview, PeerReviewCallback *app, const char *keyname)
{
  assert(keyname != NULL);
  this->transport = peerreview;
  this->app = app;
  VerifiablePRNG *vprng = new VerifiablePRNG(keyname, peerreview, T2);
  this->wrapperApp = vprng;
  this->prng = vprng;
  peerreview->setExtInfoPolicy(new VrfExtInfoPolicy(vprng));
}

RandomWrapper::RandomWrapper(ReplayWrapper *verifier, PeerReviewCallback *app)
{
  this->transport = verifier;
  VerifiablePRNGChecker *checker = new VerifiablePRNGChecker(verifier, true);
  this->app = app;
  this->wrapperApp = checker;
  this->prng = checker;

  verifier->registerCallback(checker);
  verifier->registerEvent(checker, EVT_CHOOSE_Q);
  verifier->registerEvent(checker, EVT_CHOOSE_RAND);
}

RandomWrapper::~RandomWrapper()
{
  delete app;
}

void hashStar(unsigned char *outbuf, int outsize, const unsigned char *inbuf, const int insize, const unsigned char *nodeID, int idSizeBytes, int i);

void RandomWrapper::receive(NodeHandle *source, bool datagram, unsigned char *msg, int msglen)
{
  char buf1[256];

  if (!datagram && (msg[0] == MSG_PREFIX)) {
    switch (msg[1]) {
      case MSG_PREFIX:
        msg += 2;
        msglen -= 2;
        break;
      case MSG_RW_Q:
        plog(2, "Received Q from %s", source->render(buf1));
        if (prng->validateQ(&msg[2], msglen-2, T2, transport->getIdentifierSizeBytes())) {
          if (state.numRequesters < MAX_REQUESTERS) {
            int index = state.numRequesters ++;
            state.requester[index].handle = source->clone();
            state.requester[index].r = (unsigned char*) malloc(t4Bytes);
            wrapperApp->getRandomness(state.requester[index].r, t4Bytes);
            
            unsigned char msg[2+transport->getHashSizeBytes()];
            msg[0] = MSG_PREFIX;
            msg[1] = MSG_RW_R_HASHED;
            transport->hash(&msg[2], state.requester[index].r, t4Bytes);
            transport->send(source, false, msg, sizeof(msg));
          }
        }
        
        return;
      case MSG_RW_R_HASHED:
      {
        plog(2, "Received H(R) from %s", source->render(buf1));
        
        bool accepted = false;
        for (int i=0; i<state.numWitnesses; i++) {
          if (state.witness[i].handle->getIdentifier()->equals(source->getIdentifier())) {
            if (state.witness[i].phase == PHASE_Q_SENT) {
              assert(!state.witness[i].val);
              state.witness[i].val = (unsigned char*) malloc(msglen-2);
              memcpy(state.witness[i].val, &msg[2], msglen-2);
              state.witness[i].phase = PHASE_H_RECEIVED;
              accepted = true;
            }
          }
        }

        plog(3, accepted ? "Accepted" : "Rejected");
        
        bool haveAllNow = true;
        for (int i=0; i<state.numWitnesses; i++) {
          if (state.witness[i].phase != PHASE_H_RECEIVED)
            haveAllNow = false;
        }
        
        if (accepted && haveAllNow) {
          plog(3, "Have all H(R) values now; calculating R-block");
        
          assert(!state.myR);
          state.myR = (unsigned char*) malloc(t4Bytes);
          wrapperApp->getRandomness(state.myR, t4Bytes);
          
          unsigned char msg[2+(state.numWitnesses+1)*SHA_DIGEST_LENGTH];
          msg[0] = MSG_PREFIX;
          msg[1] = MSG_RW_R_BLOCK;
          transport->hash(&msg[2], state.myR, SHA_DIGEST_LENGTH);
          for (int i=0; i<state.numWitnesses; i++) 
            memcpy(&msg[2+(i+1)*SHA_DIGEST_LENGTH], state.witness[i].val, SHA_DIGEST_LENGTH);
            
          for (int i=0; i<state.numWitnesses; i++) {
            plog(3, "Sending R-block to %s", state.witness[i].handle->render(buf1));
            transport->send(state.witness[i].handle, false, msg, sizeof(msg));
            state.witness[i].phase = PHASE_H_BLOCK_SENT;
          }
        }
        
        return;
      }
      case MSG_RW_R_BLOCK:
      {
        plog(2, "Received R-block from %s", source->render(buf1));
        
        int index = -1;
        for (int i=0; i<state.numRequesters; i++) {
          if (state.requester[i].handle->getIdentifier()->equals(source->getIdentifier())) 
            index = i;
        }
        
        if (index >= 0) {
          assert(transport->getHashSizeBytes() == SHA_DIGEST_LENGTH);
          unsigned char rHash[SHA_DIGEST_LENGTH];
          transport->hash(rHash, state.requester[index].r, t4Bytes);
          
          bool found = false;
          for (int j=0; j<((msglen-2)/SHA_DIGEST_LENGTH); j++) {
            bool same = true;
            for (int k=0; k<SHA_DIGEST_LENGTH; k++)
              if (msg[2+j*SHA_DIGEST_LENGTH+k] != rHash[k])
                same = false;
                
            if (same)
              found = true;
          }
          
          if (found) {
            unsigned char msg[2+t4Bytes];
            msg[0] = MSG_PREFIX;
            msg[1] = MSG_RW_R;
            memcpy(&msg[2], state.requester[index].r, t4Bytes);
            
            plog(3, "Found our own H(R); returning our R value");
            transport->send(state.requester[index].handle, false, msg, sizeof(msg));
            
            free(state.requester[index].r);
            delete state.requester[index].handle;
            state.requester[index] = state.requester[--(state.numRequesters)];
          } else {
            warning("Cannot find our H(r) in the R-block; ignoring request");
          }
            
        } else {
          warning("R-block received but no matching requester found; ignoring");
        }
        
        return;
      }
      case MSG_RW_R:
      {
        plog(2, "Received R from %s", source->render(buf1));
        
        bool accepted = false;
        for (int i=0; i<state.numWitnesses; i++) {
          if (state.witness[i].handle->getIdentifier()->equals(source->getIdentifier())) {
            if (state.witness[i].phase == PHASE_H_BLOCK_SENT) {
              assert(state.witness[i].val);
              free(state.witness[i].val);
              state.witness[i].val = (unsigned char*) malloc(msglen-2);

              memcpy(state.witness[i].val, &msg[2], msglen-2);
              state.witness[i].phase = PHASE_R_RECEIVED;
              accepted = true;
            }
          }
        }

        plog(3, accepted ? "Accepted" : "Rejected");
        
        bool haveAllNow = true;
        for (int i=0; i<state.numWitnesses; i++) {
          if (state.witness[i].phase != PHASE_R_RECEIVED)
            haveAllNow = false;
        }
        
        if (accepted && haveAllNow) {
          unsigned char outcome[t4Bytes];
          memset(&outcome, 0, sizeof(outcome));
          
          plog(3, "Have all responses now; computing outcome");
          
          memcpy(outcome, state.myR, t4Bytes);
          for (int i=0; i<state.numWitnesses; i++) {
            for (int j=0; j<t4Bytes; j++)
              outcome[j] ^= state.witness[i].val[j];
          }
  
          plog(3, "Resetting PRNG");
  
          prng->resetAfterCoinToss(outcome, t4Bytes);
          
          plog(2, "Setup phase completed");
          plog(3, "Deleting state");
          
          free(state.myR);
          state.myR = NULL;
          
          for (int i=0; i<state.numWitnesses; i++) {
            delete state.witness[i].handle;
            free(state.witness[i].val);
          }
          
          state.numWitnesses = 0;
          state.setupComplete = true;
          
          plog(3, "Initializing application");
          app->init();
        }
        
        return;
      }
      default:
        warning("Unknown RandomWrapper message type: %d", msg[1]);
panic("X1");        
        return;
    }
  }
  
  app->receive(source, datagram, msg, msglen);
}

void RandomWrapper::sendComplete(long long id)
{
#warning must filter setup messages here
  app->sendComplete(id);
}

void RandomWrapper::statusChange(Identifier *id, int newStatus)
{
  app->statusChange(id, newStatus);
}

void RandomWrapper::notifyCertificateAvailable(Identifier *id)
{
  app->notifyCertificateAvailable(id);
}

long long RandomWrapper::getTime()
{
  assert(state.setupComplete);
  return transport->getTime();
}

void RandomWrapper::scheduleTimer(TimerCallback *callback, int timerID, long long when)
{
  assert(state.setupComplete);
  transport->scheduleTimer(callback, timerID, when);
}

void RandomWrapper::cancelTimer(TimerCallback *callback, int timerID)
{
  assert(state.setupComplete);
  transport->cancelTimer(callback, timerID);
}

bool RandomWrapper::haveCertificate(Identifier *id)
{
  assert(state.setupComplete);
  return transport->haveCertificate(id);
}

void RandomWrapper::requestCertificate(NodeHandle *source, Identifier *id)
{
  assert(state.setupComplete);
  transport->requestCertificate(source, id);
}

void RandomWrapper::sign(const unsigned char *data, int dataLength, unsigned char *signatureBuffer)
{
  assert(state.setupComplete);
  transport->sign(data, dataLength, signatureBuffer);
}

int RandomWrapper::verify(Identifier *id, const unsigned char *data, const int dataLength, unsigned char *signature)
{
  assert(state.setupComplete);
  return transport->verify(id, data, dataLength, signature);
}

int RandomWrapper::getSignatureSizeBytes()
{ 
  return transport->getSignatureSizeBytes();
}

long long RandomWrapper::send(NodeHandle *target, bool datagram, unsigned char *message, int msglen, int relevantlen)
{
  assert(state.setupComplete);
  return transport->send(target, datagram, message, msglen, relevantlen);
}

int RandomWrapper::getMSS()
{
  return transport->getMSS();
}

NodeHandle *RandomWrapper::getLocalHandle()
{
  return transport->getLocalHandle();
}

int RandomWrapper::getIdentifierSizeBytes()
{
  return transport->getIdentifierSizeBytes();
}

Identifier *RandomWrapper::readIdentifier(unsigned char *buf, unsigned int *pos, unsigned int maxlen)
{
  return transport->readIdentifier(buf, pos, maxlen);
}

Identifier *RandomWrapper::readIdentifierFromString(const char *str)
{
  return transport->readIdentifierFromString(str);
}

NodeHandle *RandomWrapper::readNodeHandle(unsigned char *buf, unsigned int *pos, unsigned int maxlen)
{
  return transport->readNodeHandle(buf, pos, maxlen);
}

NodeHandle *RandomWrapper::readNodeHandleFromString(const char *str)
{
  return transport->readNodeHandleFromString(str);
}

void RandomWrapper::logEvent(char type, const void *entry, int size)
{
  transport->logEvent(type, entry, size);
}

void RandomWrapper::logText(const char *subsystem, int level, const char *format, ...)
{
  char buffer[2048];
  va_list ap;
  va_start (ap, format);
  if (vsnprintf (buffer, sizeof(buffer), format, ap) > sizeof(buffer))
    panic("Buffer overflow in PeerReview::logText()");
  transport->logText(subsystem, level, "%s", buffer);
  va_end (ap);
}

void RandomWrapper::incrementCounter(int code, int value)
{
  transport->incrementCounter(code, value);
}

int RandomWrapper::getRandom(int range)
{
  return prng->getRandom(range);
}

void RandomWrapper::investigate(NodeHandle *target, long long since)
{
  transport->investigate(target, since);
}

void RandomWrapper::init()
{
//  app->init();
  plog(2, "VRF startup protocol initialized; getting witnesses");

  state.numWitnesses = 0;
  state.numRequesters = 0;
  state.setupComplete = false;
  state.myR = NULL;
  state.startupBegin = transport->getTime() + 1000;
  transport->scheduleTimer(this, TI_STARTUP, state.startupBegin);
}

void RandomWrapper::timerExpired(int timerID)
{
  assert(timerID == TI_STARTUP);
  plog(2, "Startup timer expired");  
  app->getWitnesses(transport->getLocalHandle()->getIdentifier(), this);  
  state.startupBegin = -1;
}

void RandomWrapper::notifyWitnessSet(Identifier *subject, int numWitnesses, NodeHandle **witnesses)
{
  plog(2, "NWS %d", numWitnesses);
  if (!numWitnesses && !state.setupComplete) {
    unsigned char r[t4Bytes];
    wrapperApp->getRandomness(r, t4Bytes);
    prng->resetAfterCoinToss(r, t4Bytes);
    state.setupComplete = true;
          
    plog(2, "Setup phase completed (no witnesses)");
    plog(3, "Initializing application");
    app->init();
    return;
  }
  
  if (!state.setupComplete && numWitnesses && !state.numWitnesses) {
    if (numWitnesses > MAX_WITNESSES)
      numWitnesses = MAX_WITNESSES;
      
    plog(2, "Startup protocol found %d witnesses; requesting Q", numWitnesses);
  
    for (int i=0; i<numWitnesses; i++) {
      state.witness[i].handle = witnesses[i]->clone();
      state.witness[i].phase = PHASE_INIT;
      state.witness[i].val = NULL;
    }
    
    state.numWitnesses = numWitnesses;
    wrapperApp->getQ(this);
  }
}

void RandomWrapper::notifyQ(unsigned char *qbuf, int qlen)
{
  char buf1[256];

  if (!state.setupComplete && state.numWitnesses) {
    unsigned char *qmsg = (unsigned char*) malloc(qlen + 2);
    qmsg[0] = MSG_PREFIX;
    qmsg[1] = MSG_RW_Q;
    memcpy(&qmsg[2], qbuf, qlen);
    
    plog(2, "Startup protocol received Q");
    
    for (int i=0; i<state.numWitnesses; i++) {
      if (state.witness[i].phase == PHASE_INIT) {
        plog(3, "Sending Q to witness %s", state.witness[i].handle->render(buf1));
        transport->send(state.witness[i].handle, false, qmsg, qlen + 2);
        state.witness[i].phase = PHASE_Q_SENT;
      }
    }
  }
}

int RandomWrapper::storeCheckpoint(unsigned char *buffer, unsigned int maxlen)
{
  unsigned int ptr = 0;
  ptr += prng->storeCheckpoint(&buffer[ptr], maxlen - ptr);
  
  writeByteSafe(state.setupComplete ? 1 : 0, buffer, &ptr, maxlen);
  writeInt(state.numRequesters, buffer, &ptr, maxlen);
  for (int i=0; i<state.numRequesters; i++) {
    state.requester[i].handle->write(buffer, &ptr, maxlen);
    writeBytes(buffer, &ptr, state.requester[i].r, t4Bytes);
  }
  
  if (!state.setupComplete) {
    writeLongLongSafe(state.startupBegin, buffer, &ptr, maxlen);
    writeInt(state.numWitnesses, buffer, &ptr, maxlen);
    if (state.myR) {
      writeByteSafe(1, buffer, &ptr, maxlen);
      writeBytes(buffer, &ptr, state.myR, t4Bytes);
    } else {
      writeByteSafe(0, buffer, &ptr, maxlen);
    }
    
    for (int i=0; i<state.numWitnesses; i++) {
      state.witness[i].handle->write(buffer, &ptr, maxlen);
      writeByteSafe(state.witness[i].phase, buffer, &ptr, maxlen);
      if ((state.witness[i].phase == PHASE_H_RECEIVED) || (state.witness[i].phase == PHASE_H_BLOCK_SENT))
        writeBytes(buffer, &ptr, state.witness[i].val, SHA_DIGEST_LENGTH);
      else if (state.witness[i].phase == PHASE_R_RECEIVED)
        writeBytes(buffer, &ptr, state.witness[i].val, t4Bytes);
    }
  }

  ptr += app->storeCheckpoint(&buffer[ptr], maxlen - ptr);
  return ptr;
}

bool RandomWrapper::loadCheckpoint(unsigned char *buffer, unsigned int len)
{
  unsigned int ptr = 0;
  if (!prng->loadCheckpoint(&buffer[ptr], &ptr, len-ptr))
    return false;
  
  state.setupComplete = (readByteSafe(buffer, &ptr, len, 0) != 0);
  state.numRequesters = readIntSafe(buffer, &ptr, len, 0);
  for (int i=0; i<state.numRequesters; i++) {
    state.requester[i].handle = transport->readNodeHandle(buffer, &ptr, len);
    state.requester[i].r = (unsigned char*) malloc(t4Bytes);
    readBytes(buffer, &ptr, state.requester[i].r, t4Bytes);
  }
  
  if (!state.setupComplete) {
    state.startupBegin = readLongLongSafe(buffer, &ptr, len, -1);
    if (state.startupBegin >= 0)
      transport->scheduleTimer(this, TI_STARTUP, state.startupBegin);
      
    state.numWitnesses = readIntSafe(buffer, &ptr, len, 0);
      
    if (readByteSafe(buffer, &ptr, len, 0) > 0) {
      state.myR = (unsigned char*) malloc(t4Bytes);
      readBytes(buffer, &ptr, state.myR, t4Bytes);
    } else {
      state.myR = NULL;
    }
    
    for (int i=0; i<state.numWitnesses; i++) {
      state.witness[i].handle = transport->readNodeHandle(buffer, &ptr, len);
      state.witness[i].phase = readByteSafe(buffer, &ptr, len, PHASE_INIT);
      if ((state.witness[i].phase == PHASE_H_RECEIVED) || (state.witness[i].phase == PHASE_H_BLOCK_SENT)) {
        state.witness[i].val = (unsigned char*) malloc(SHA_DIGEST_LENGTH);
        readBytes(buffer, &ptr, state.witness[i].val, SHA_DIGEST_LENGTH);
      } else if (state.witness[i].phase == PHASE_R_RECEIVED) {
        state.witness[i].val = (unsigned char*) malloc(t4Bytes);
        readBytes(buffer, &ptr, state.witness[i].val, t4Bytes);
      } else {
        state.witness[i].val = NULL;
      }
    }
  }
    
  return app->loadCheckpoint(&buffer[ptr], len - ptr);
}

void RandomWrapper::getWitnesses(Identifier *subject, WitnessListener *callback)
{
  app->getWitnesses(subject, callback);
}

int RandomWrapper::getMyWitnessedNodes(NodeHandle **nodes, int maxResults)
{
  return app->getMyWitnessedNodes(nodes, maxResults);
}

PeerReviewCallback *RandomWrapper::getReplayInstance(ReplayWrapper *replayWrapper)
{
  PeerReviewCallback *appInstance = app->getReplayInstance(replayWrapper);
  RandomWrapper *instance = new RandomWrapper(replayWrapper, appInstance);
  appInstance->setTransport(instance);

  return instance;
}

int RandomWrapper::getHashSizeBytes()
{
  return transport->getHashSizeBytes();
}

void RandomWrapper::hash(unsigned char *outbuf, const unsigned char *inbuf1, const int insize1, const unsigned char *inbuf2, const int insize2, const unsigned char *inbuf3, const int insize3, const unsigned char *inbuf4, const int insize4)
{
  transport->hash(outbuf, inbuf1, insize1, inbuf2, insize2, inbuf3, insize3, inbuf4, insize4);
}
