#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "peerreview.h"

#define SUBSYSTEM "peerreview"
//#define VERBOSE

#ifdef VERBOSE
#define vlog(a...) plog(a)
#define vdump(b, c) transport->dump(2, b, c)
#else
#define vlog(a...) do { } while (0)
#define vdump(a...) do { } while (0)
#endif

Verifier::Verifier(PeerReview *peerreview, SecureHistory *history, NodeHandle *localHandle, int signatureSizeBytes, int hashSizeBytes, int firstEntryToReplay, long long initialTime, unsigned char *extInfo, int extInfoLen) : ReplayWrapper()
{
  this->history = history;
  this->app = NULL;
  this->numEventCallbacks = 0;
  this->transport = peerreview;
  this->localHandle = localHandle->clone();
  this->now = initialTime;
  this->foundFault = false;
  this->haveNextEvent = false;
  this->nextEventIndex = firstEntryToReplay-1;
  this->initialized = false;
  this->signatureSizeBytes = signatureSizeBytes;
  this->hashSizeBytes = hashSizeBytes;
  this->numTimers = 0;
  this->prng = (peerreview->getPRNG()) ? peerreview->getPRNG()->getChecker(this) : NULL;
  
  for (int i=0; i<256; i++)
    eventToCallback[i] = -1;
    
  fetchNextEvent();
  if (!haveNextEvent)
    foundFault = true;
    
  if (extInfo && (extInfoLen > 0)) {
    this->extInfo = (unsigned char*) malloc(extInfoLen);
    this->extInfoLen = extInfoLen;
    memcpy(this->extInfo, extInfo, extInfoLen);
  } else {
    this->extInfo = NULL;
    this->extInfoLen = 0;
  }
}

int Verifier::getExtInfo(unsigned char *buf, int maxlen)
{
  if (!extInfo || (extInfoLen < 1))
    return 0;
    
  int retlen = (maxlen<extInfoLen) ? maxlen : extInfoLen;
  memcpy(buf, extInfo, retlen);
  return retlen;
}

/* Fetch the next log entry, or set the EOF flag */

void Verifier::fetchNextEvent()
{
  haveNextEvent = false;
  nextEventIndex ++;

  unsigned char chash[hashSizeBytes];
  if (!history->statEntry(nextEventIndex, &nextEventSeq, &nextEventType, &nextEventSize, chash, NULL))
    return;
    
  if (nextEventSize<0) {
    nextEventIsHashed = true;
    nextEventSize = hashSizeBytes;
    memcpy(nextEvent, chash, hashSizeBytes);
    vlog(2, "Fetched log entry #%d (type %d, hashed, seq=%lld)", nextEventIndex, nextEventType, nextEventSeq);
  } else {
    nextEventIsHashed = false;
    assert(nextEventSize < (int)sizeof(nextEvent));
    history->getEntry(nextEventIndex, nextEvent, nextEventSize);
    vlog(2, "Fetched log entry #%d (type %d, size %d bytes, seq=%lld)", nextEventIndex, nextEventType, nextEventSize, nextEventSeq);
    vdump(nextEvent, nextEventSize);
  }
  
  haveNextEvent = true;
}

Verifier::~Verifier()
{
  for (int i=0; i<numEventCallbacks; i++)
    delete eventCallback[i];
 
  if (app)
    delete app;   
    
  delete history;
  delete localHandle;
}

int Verifier::getIdentifierSizeBytes() 
{ 
  return transport->getIdentifierSizeBytes(); 
}

Identifier *Verifier::readIdentifier(unsigned char *buf, unsigned int *pos, unsigned int maxlen)
{ 
  return transport->readIdentifier(buf, pos, maxlen); 
}

Identifier *Verifier::readIdentifierFromString(const char *str) 
{ 
  return transport->readIdentifierFromString(str); 
}

NodeHandle *Verifier::readNodeHandle(unsigned char *buf, unsigned int *pos, unsigned int maxlen) 
{ 
  return transport->readNodeHandle(buf, pos, maxlen); 
}

/* This is called by the application when a second instance is created for replay.
   It registers a handler for application-specific events, such as PAST_GET. */

void Verifier::registerCallback(EventCallback *callback)
{
  if (numEventCallbacks >= MAX_EVENT_CALLBACKS)
    panic("Too many event callbacks in Verifier");
    
  eventCallback[numEventCallbacks++] = callback;
}

/* This binds specific event types to one of the handlers */

void Verifier::registerEvent(EventCallback *callback, unsigned char eventType)
{
  int idx = -1;
  for (int i=0; i<numEventCallbacks; i++)
    if (eventCallback[i] == callback)
      idx = i;
      
  if (idx < 0)
    panic("registerEvent() called without prior call to registerCallback()");
  if (eventToCallback[eventType] != -1)
    panic("Event #%d registered twice", eventType);  
  
  eventToCallback[eventType] = idx;
}

void Verifier::setApplication(PeerReviewCallback *app)
{
  this->app = app;
}

/* The application is not supposed to call this during replay */

void Verifier::logEvent(char type, const void *entry, int size)
{ 
  panic("Verifier cannot log an event");
}

/* This is called by the Audit protocol to make another replay step; it returns true
   if further calls are necessary, and false if the replay has finished. The idea
   is that we can stop calling this if there is more important work to do, e.g. 
   handle foreground requests */

bool Verifier::makeProgress()
{
  if (foundFault || !haveNextEvent)
    return false;
    
  if (!initialized && (nextEventType != EVT_CHECKPOINT)) {
    warning("Replay: No INIT or CHECKPOINT found at the beginning of the log; marking as invalid");
    foundFault = true;
    return false;
  }
  
  /* Handle any pending timers. Note that we have to be sure to call them in the exact same
     order as in the main code; otherwise there can be subtle bugs and side-effects. */
  
  bool timerProgress = true;
  while (timerProgress) {
    now = nextEventSeq / 1000;
    timerProgress = false;

    int best = -1;
    for (int i=0; i<numTimers; i++) {
      if ((timer[i].time <= now) && ((best<0) || (timer[i].time<timer[best].time) || ((timer[i].time==timer[best].time) && (timer[i].id<timer[best].id))))
        best = i;
    }

    if (best >= 0) {
      int id = timer[best].id;
      TimerCallback *callback = timer[best].callback;
      now = timer[best].time;
      timer[best] = timer[--numTimers];
      vlog(2, "Verifier: Timer expired (#%d, now=%lld)", id, now);
      callback->timerExpired(id);
      timerProgress = true;
    }
  }
  
  /* If we're done with this replay, return false */

  if (!haveNextEvent)
    return false;  

  /* Sanity checks */

  vlog(3, "Replaying event #%d (type %d, seq=%lld, now=%lld)", nextEventIndex, nextEventType, nextEventSeq, now);
    
  if (nextEventIsHashed && (nextEventType != EVT_CHECKPOINT)) {
    warning("Replay: Trying to replay hashed event");
    foundFault = true;
    return false;
  }
    
  /* Replay the next event */
    
  switch (nextEventType) {
    case EVT_VRF : /* VRF events should have been handled by PRNG::checker */
    {
#if 0
      warning("Replay: Encountered EVT_VRF; marking as invalid");
      transport->dump(2, nextEvent, nextEventSize);
      foundFault = true;
panic("encountered EVT_VRF");      
      return false;
#endif
      fetchNextEvent();
      break;
    }
    case EVT_SEND : /* SEND events should have been handled by Verifier::send() */
    {
      warning("Replay: Encountered EVT_SEND; marking as invalid");
      transport->dump(2, nextEvent, nextEventSize);
      foundFault = true;
      return false;
    }
    case EVT_RECV : /* Incoming message; feed it to the state machine */
    {
      unsigned int pos = 0;
      NodeHandle *sender = transport->readNodeHandle(nextEvent, &pos, nextEventSize);
      long long senderSeq = readLongLong(nextEvent, &pos);
      unsigned char hashed = readByte(nextEvent, &pos);
      int headerSize = pos;
      int msglen = nextEventSize - headerSize;
      int relevantlen = hashed ? (msglen-hashSizeBytes) : msglen;

      unsigned char *msgbuf = (unsigned char*) malloc(msglen);
      memcpy(msgbuf, &nextEvent[headerSize], msglen);

      /* The next event is going to be a SIGN; skip it, since it's irrelevant here */

      fetchNextEvent();
      if (!haveNextEvent || (nextEventType != EVT_SIGN) || (nextEventSize != (int)(hashSizeBytes+signatureSizeBytes))) {
        warning("Replay: RECV event not followed by SIGN; marking as invalid");
        foundFault = true;
        delete sender;
        free(msgbuf);
        return false;
      }
      
      fetchNextEvent();
      
      /* Deliver the message to the state machine */
      
      app->receive(sender, false, msgbuf, msglen);

      delete sender;
      free(msgbuf);
      break;
    }
    case EVT_SIGN : /* SIGN events should have been handled by the preceding RECV */
    {
      warning("Replay: Spurious SIGN event; marking as invalid");
      foundFault = true;
      return false;
    }
    case EVT_ACK : /* Skip ACKs */
    {
      unsigned int pos = 0;
      Identifier *id = transport->readIdentifier(nextEvent, &pos, nextEventSize);
      long long ackedSeq = readLongLong(nextEvent, &pos);
      app->sendComplete(ackedSeq);
      fetchNextEvent();
      delete id;
      break;
    }
    case EVT_SENDSIGN : /* Skip SENDSIGN events; they are not relevant during replay */
    {
      fetchNextEvent();
      break;
    }
    case EVT_CHECKPOINT : /* Verify CHECKPOINTs */
    {
      if (!initialized) {
        if (!nextEventIsHashed) {
        
          /* If the state machine hasn't been initialized yet, we can use this checkpoint */
        
          initialized = true;

          unsigned int ptr = 0;
          if (prng) {
            if (!prng->loadCheckpoint(nextEvent, &ptr, nextEventSize)) {
              warning("Cannot load checkpoint");
              foundFault = true;
            }
          }
          
          if (!app->loadCheckpoint(&nextEvent[ptr], nextEventSize - ptr)) {
            warning("Cannot load checkpoint");
            foundFault = true;
          }
        } else {
          warning("Replay: Initial checkpoint is hashed; marking as invalid");
          foundFault = true;
        }
      } else {
      
        /* Ask the state machine to do a checkpoint now ... */
      
        int maxlen = 1048576*4;
        unsigned char *buf = (unsigned char *)malloc(maxlen);
        int actualCheckpointSize = 0;
        if (prng)
          actualCheckpointSize += prng->storeCheckpoint(&buf[actualCheckpointSize], maxlen - actualCheckpointSize);
        actualCheckpointSize += app->storeCheckpoint(&buf[actualCheckpointSize], maxlen - actualCheckpointSize);

        /* ... and compare it to the contents of the CHECKPOINT entry */

        if (!nextEventIsHashed) {
          if (actualCheckpointSize != nextEventSize) {
            warning("Replay: Checkpoint has different size (expected %d bytes, but got %d); marking as invalid", nextEventSize, actualCheckpointSize);
            plog(2, "Expected:");
            transport->dump(2, nextEvent, nextEventSize);
            plog(2, "Found:");
            transport->dump(2, buf, actualCheckpointSize);
            foundFault = true;
            free(buf);
            return false;
          }
        
          if (memcmp(buf, nextEvent, nextEventSize) != 0) {
            warning("Replay: Checkpoint does not match");
            plog(2, "Expected:");
            transport->dump(2, nextEvent, nextEventSize);
            plog(2, "Found:");
            transport->dump(2, buf, nextEventSize);

            foundFault = true;
            free(buf);
            return false;
          }
        } else {
          if (nextEventSize != hashSizeBytes) {
            warning("Replay: Checkpoint is hashed but has the wrong length?!?");
            foundFault = true;
            free(buf);
            return false;
          }
        
          unsigned char checkpointHash[hashSizeBytes];
          hash(checkpointHash, buf, actualCheckpointSize);
          if (memcmp(checkpointHash, nextEvent, hashSizeBytes) != 0) {
            warning("Replay: Checkpoint is hashed, but does not match hash value in the log");
            foundFault = true;
            free(buf);
            return false;
          }

          vlog(4, "Hashed checkpoint is OK");
          history->upgradeHashedEntry(nextEventIndex, buf, actualCheckpointSize);
        }
        
        free(buf);
      }
        
      fetchNextEvent();
      break;
    }
    case EVT_INIT : /* State machine is reinitialized; issue upcall */
    {
      initialized = true;
      app->init();
      fetchNextEvent();
      break;
    }
    default :
    {
      if (eventToCallback[nextEventType] < 0) {
        warning("Replay: Unregistered event #%d; marking as invalid", nextEventType);
        foundFault = true;
        return false;
      }

      unsigned char thisType = nextEventType;      
      unsigned char *buf = (unsigned char*)malloc(nextEventSize);
      memcpy(buf, nextEvent, nextEventSize);
      int thisSize = nextEventSize;
      fetchNextEvent();
      eventCallback[eventToCallback[thisType]]->replayEvent(thisType, buf, thisSize);
      free(buf);
      break;
    }
  }
  
  return true;
}

/* Called by the state machine when it wants to send a message */

long long Verifier::send(NodeHandle *target, bool datagram, unsigned char *message, int msglen, int relevantlen)
{
  assert(!datagram);

  if (relevantlen < 0)
    relevantlen = msglen;

  char buf1[256], buf2[256];
  vlog(2, "Verifier::send(%s, %d/%d bytes)", target->render(buf1), msglen, relevantlen);
  vdump(message, msglen);
  
  /* Sanity checks */
  
  if (!haveNextEvent) {
    warning("Replay: Send event after end of segment; marking as invalid");
    foundFault = true;
    return -1;
  }
  
  if (nextEventType == EVT_INIT) {
    vlog(3, "Skipped; next event is an INIT");
    return -1;
  }
  
  if (nextEventType != EVT_SEND) {
    warning("Replay: SEND event during replay, but next event in log is #%d; marking as invalid", nextEventType);
    foundFault = true;
    return -1;
  }

  long long sendSeq = nextEventSeq;

  /* If the SEND is hashed, simply compare it to the predicted entry */
  
  if (nextEventIsHashed) {
    assert(relevantlen < 1024);
    unsigned char buf[MAX_ID_SIZE+1+1024+hashSizeBytes];
    unsigned int pos = 0;
    target->getIdentifier()->write(buf, &pos, sizeof(buf));
    buf[pos++] = (relevantlen<msglen) ? 1 : 0;
    if (relevantlen>0) {
      memcpy(&buf[pos], message, relevantlen);
      pos += relevantlen;
    }
    
    assert(pos<(sizeof(buf)-hashSizeBytes));
    if (relevantlen<msglen) {
#warning ugly; this should be an argument
      if (msglen == (relevantlen+hashSizeBytes))
        memcpy(&buf[pos], &message[relevantlen], hashSizeBytes);
      else
        hash(&buf[pos], &message[relevantlen], msglen-relevantlen);
        
      pos += hashSizeBytes;
    }
    
    unsigned char chash[hashSizeBytes];
    hash(chash, buf, pos);
    if (memcmp(chash, nextEvent, hashSizeBytes)) {
      warning("Replay: SEND is hashed, but hash of predicted SEND entry does not match hash in the log");
      foundFault = true;
      return sendSeq;
    }
  
    fetchNextEvent();
    assert(nextEventType == EVT_SENDSIGN);
    fetchNextEvent();
    return sendSeq;
  }

  /* Are we sending to the same destination? */

  unsigned int pos = 0;
  Identifier *logReceiver = transport->readIdentifier(nextEvent, &pos, nextEventSize);
  bool logIsHashed = readByte(nextEvent, &pos) > 0;
  assert(nextEventSize >= (int)pos);
  if (!logReceiver->equals(target->getIdentifier())) {
    warning("Replay: SEND to %s during replay, but log shows SEND to %s; marking as invalid", target->getIdentifier()->render(buf1), logReceiver->render(buf2));
    foundFault = true;
    delete logReceiver;
    return sendSeq;
  }
  
  delete logReceiver;

  /* Check the message against the message in the log */

  if (logIsHashed) {
    if (relevantlen >= msglen) {
      warning("Replay: Message sent during replay is entirely relevant, but log entry is partly hashed; marking as invalid");
      foundFault = true;
      return sendSeq;
    }
    
    int logRelevantLen = nextEventSize - (pos+hashSizeBytes);
    unsigned char *logHash = &nextEvent[nextEventSize - hashSizeBytes];
    assert(logRelevantLen >= 0);
    
    if (relevantlen != logRelevantLen) {
      warning("Replay: Message sent during replay has %d relevant bytes, but log entry has %d; marking as invalid", relevantlen, logRelevantLen);
      foundFault = true;
      return sendSeq;
    }

    if ((relevantlen > 0) && memcmp(message, &nextEvent[pos], relevantlen)) {
      warning("Replay: Relevant part of partly hashed message differs");
      plog(2, "Expected: [%s]", renderBytes(&nextEvent[pos], relevantlen, buf1));
      plog(2, "Actual:   [%s]", renderBytes(message, relevantlen, buf1));
      foundFault = true;
      return sendSeq;
    }
    
    assert(msglen == (relevantlen + hashSizeBytes));
    if (memcmp(&message[relevantlen], logHash, hashSizeBytes)) {
      warning("Replay: Hashed part of partly hashed message differs");
      plog(2, "Expected: [%s]", renderBytes(logHash, hashSizeBytes, buf1));
      plog(2, "Actual:   [%s]", renderBytes(&message[relevantlen], hashSizeBytes, buf1));
      foundFault = true;
      return sendSeq;
    }
  } else {
    if (relevantlen < msglen) {
      warning("Replay: Message sent during replay is only partly relevant, but log entry is not hashed; marking as invalid");
      foundFault = true;
      return sendSeq;
    }

    int logMsglen = nextEventSize - (pos);
    if (msglen != logMsglen) {
      warning("Replay: Message sent during replay has %d bytes, but log entry has %d; marking as invalid", msglen, logMsglen);
      foundFault = true;
      return sendSeq;
    }
    
    if ((msglen > 0) && memcmp(message, &nextEvent[pos], msglen)) {
      warning("Replay: Message sent during replay differs from message in the log");
      foundFault = true;
      return sendSeq;
    }
  }

  fetchNextEvent();
  assert(nextEventType == EVT_SENDSIGN);
  fetchNextEvent();
  
  return sendSeq;
}

void Verifier::logText(const char *subsystem, int level, const char *format, ...)
{
  char buffer[1024];
  va_list ap;
  va_start (ap, format);
  vsprintf (buffer, format, ap);
#ifdef VERBOSE  
  transport->logText(subsystem, level, "RPL %lld  %s", now, buffer);
#endif
  va_end (ap);
}

void Verifier::scheduleTimer(TimerCallback *callback, int timerID, long long when)
{
#ifdef VERBOSE
  plog(2, "Verifier: scheduleTimer(#%d, t=%lld)", timerID, when);
#endif
  if (numTimers >= MAX_TIMERS)
    panic("Verifier: Too many timers scheduled");
    
  timer[numTimers].time = when;
  timer[numTimers].id = timerID;
  timer[numTimers].callback = callback;

  numTimers ++;
}

void Verifier::cancelTimer(TimerCallback *callback, int timerID)
{
#ifdef VERBOSE
  plog(2, "Verifier: cancelTimer(#%d)", timerID);
#endif
  
  for (int i=0; i<numTimers; ) {
    if ((timer[i].id == timerID) && (timer[i].callback == callback)) 
      timer[i] = timer[--numTimers];
    else
      i++;
  }
}

int Verifier::getHashSizeBytes() 
{ 
  return transport->getHashSizeBytes(); 
}

void Verifier::hash(unsigned char *outbuf, const unsigned char *inbuf1, const int insize1, const unsigned char *inbuf2, const int insize2, const unsigned char *inbuf3, const int insize3, const unsigned char *inbuf4, const int insize4)
{ 
  transport->hash(outbuf, inbuf1, insize1, inbuf2, insize2, inbuf3, insize3, inbuf4, insize4); 
}

int Verifier::getRandom(int range)
{
  if (!prng)
    panic("Verifier::getRandom() was called, but PeerReview::enableRandomNumberGenerator() was not?!?");
    
  return prng->getRandom(range);
}

bool Verifier::statNextEvent(unsigned char *type, int *size, long long *seq, bool *isHashed, unsigned char **buf)
{
  if (!haveNextEvent)
    return false;

  if (type)
    *type = nextEventType;
    
  if (size)
    *size = nextEventSize;
  
  if (seq)
    *seq = nextEventSeq;
    
  if (isHashed)
    *isHashed = nextEventIsHashed;
    
  if (buf)
    *buf = nextEvent;
    
  return true;
}

int Verifier::getNextEntryOfType(unsigned char type, unsigned char *buf, unsigned int maxlen, bool includeCurrent)
{
  int index = history->findNextEntry(&type, 1, nextEventSeq+(includeCurrent ? 0 : 1));
  vlog(2, "getNextEntryOfType(%d) -> idx=%d [IC %s]", type, index, includeCurrent ? "yes" : "no");
  
  if (index < 0)
    return -1;
    
  int size;
  if (!history->statEntry(index, NULL, NULL, &size, NULL, NULL))
    panic("Cannot stat entry returned by findNextEntry");
    
  if (size < maxlen)
    size = maxlen;
    
  history->getEntry(index, buf, size);
  
  return size;
}
