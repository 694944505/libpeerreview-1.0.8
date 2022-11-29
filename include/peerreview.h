#ifndef __peerreview_h__
#define __peerreview_h__

/* Defines the interface to the PeerReview library */

#include <stdlib.h>   
#include <stdio.h>
#include <time.h>
#include <limits.h>

#include "peerreview/transport.h"
#include "peerreview/identity.h"
#include "peerreview/tools.h"
#include "peerreview/history.h"
#include "peerreview/entrytypes.h"

#define panic(a...) do { fprintf(stderr, a); fprintf(stderr, "\n"); abort(); } while (0)
#define dlog(a...) do { } while (0)

#ifndef NOLOGGING
#ifndef WARNINGSONLY
#define plog(x, a...) do { transport->logText(SUBSYSTEM, x, a); } while (0)
#else
#define plog(x, a...) do { } while (0)
#endif
#define warning(a...) do { transport->logText("warning", 0, "WARNING: " a); } while (0)
#else
#define plog(a...) do { } while (0)
#endif

/* Constants for reporting the status of a remote node to the application */

#define STATUS_TRUSTED 0
#define STATUS_SUSPECTED 1
#define STATUS_EXPOSED 2

/* Message types used in PeerReview */

#define MSG_USERDATA 16            /* Contains data the application has sent */
#define MSG_ACK 17                       /* Acknowledges an USERDATA message */
#define MSG_ACCUSATION 18            /* Contains evidence about a third node */
#define MSG_CHALLENGE 19            /* Contains evidence about the recipient */
#define MSG_RESPONSE 20                      /* Answers a previous CHALLENGE */
#define MSG_AUTHPUSH 21        /* Sent to a witness; contains authenticators */
#define MSG_AUTHREQ 22    /* Asks a witness to return a recent authenticator */
#define MSG_AUTHRESP 23                    /* Responds to a previous AUTHREQ */
#define MSG_USERDGRAM 24    /* Contains a datagram from the app (not logged) */

/* Evidence types (challenges and proofs) */

#define CHAL_AUDIT 1    
#define CHAL_SEND 2
#define PROOF_INCONSISTENT 3
#define PROOF_NONCONFORMANT 4

/* Flags for AUDIT challenges */

#define FLAG_INCLUDE_CHECKPOINT 1                /* Include a full checkpoint */
#define FLAG_FULL_MESSAGES_SENDER 2 /* Don't hash outgoing messages to sender */
#define FLAG_FULL_MESSAGES_ALL 4          /* Don't hash any outgoing messages */

/* Different types of PRNGs */

#define PRNG_NONE        0
#define PRNG_SIMPLE      1
#define PRNG_VRF         2

/* Internal constants */

#define MAX_ENTRIES_PER_US 1000      /* Max number of entries per microsecond */
#define T2 5

char *renderBytes(const unsigned char *bytes, int len, char *buf);
const char *renderStatus(const int status);

class ReplayWrapper;
class PeerReview;
class Misbehavior;

/* Interface of classes that need to be notified when a witness set changes */

class WitnessListener {
public:
  WitnessListener() {};
  virtual ~WitnessListener() {};
  virtual void notifyWitnessSet(Identifier *subject, int numWitnesses, NodeHandle **witnesses) = 0;
};

/* Callback interface that all PeerReview-enabled applications must implement. 
   During normal operation, PeerReview uses this interface to checkpoint the
   application, and to inquire about the witness set of another node. */

class PeerReviewCallback : public IdentityTransportCallback {
public:
  PeerReviewCallback() : IdentityTransportCallback() {};
  virtual ~PeerReviewCallback() {};
  virtual void init() = 0;
  virtual int storeCheckpoint(unsigned char *buffer, unsigned int maxlen) = 0;
  virtual bool loadCheckpoint(unsigned char *buffer, unsigned int len) = 0;
  virtual void getWitnesses(Identifier *subject, WitnessListener *callback) = 0;
  virtual int getMyWitnessedNodes(NodeHandle **nodes, int maxResults) = 0;
  virtual PeerReviewCallback *getReplayInstance(ReplayWrapper *replayWrapper) = 0;
  virtual void setTransport(IdentityTransport *transport) = 0;
  virtual int storeExtInfo(unsigned char *buffer, unsigned int maxlen) { return 0; };
};

/* Callback interface to the replay helper. When PeerReview needs to replay
   another node's log, the following happens:
    
      1. PeerReview calls getReplayInstance() on the application via the
         PeerReviewCallback interface and gives it a new transport layer
         (ReplayWrapper). The application creates a second instance of 
         the state machine that sits on top of the new transport layer.
         
      2. The application creates an instance of EventCallback and registers
         it with the new transport. The purpose of this callback is to
         recreate calls from the application into the state machine 
         (e.g. a PAST::Get or a Pastry::route). The EventCallback must 
         register any such application-specific events with the new transport.
         
      3. PeerReview calls loadCheckpoint() on the second instance and
         then feeds messages (via the second transport) and application
         events (via the EventCallback) to this instance. 
         
      4. Once the replay is complete, PeerReview calls the destructors 
         of the (a) second instance and (b) the EventCallback. No other
         upcalls are made. The application must ensure that all objects
         created by the second instance are deleted. */

class EventCallback {
public:
  EventCallback() { };
  virtual ~EventCallback() { };
  virtual void replayEvent(unsigned char type, unsigned char *entry, int entrySize) { assert(false); };
};

/* Additional calls found only on transports that are passed to getReplayInstance().
   For an explanation, see EventCallback. */

class PRNG;

class ReplayWrapper : public IdentityTransport {
public:
  ReplayWrapper() : IdentityTransport() {};
  virtual ~ReplayWrapper() {};
  virtual void registerCallback(EventCallback *callback) = 0;
  virtual void registerEvent(EventCallback *callback, unsigned char eventType) = 0;
  virtual bool statNextEvent(unsigned char *type, int *size, long long *seq, bool *isHashed, unsigned char **buf) = 0;
  virtual int getNextEntryOfType(unsigned char type, unsigned char *buf, unsigned int maxlen, bool includeCurrent) = 0;
  virtual void fetchNextEvent() = 0;
  virtual void markFaulty() = 0;
  virtual int getExtInfo(unsigned char *buf, int maxlen) = 0;
};

/* This class is used for random number generators, which can be simple random()-style
   ones or VRFs */

class Verifier;

class PRNG {
public:
  PRNG() {};
  virtual ~PRNG() {};
  virtual int getRandom(int range) = 0;
  virtual int storeCheckpoint(unsigned char *buffer, unsigned int maxlen) = 0;
  virtual bool loadCheckpoint(unsigned char *buffer, unsigned int *ptr, unsigned int maxlen) = 0;
  virtual PRNG *getChecker(Verifier *verifier) = 0;
  virtual int storeExtInfo(unsigned char *buffer, unsigned int maxlen) { return 0; };
};

class SimplePRNG : public PRNG {
protected:
  struct drand48_data seed;
  
public:
  SimplePRNG();
  virtual int getRandom(int range);
  virtual int storeCheckpoint(unsigned char *buffer, unsigned int maxlen);
  virtual bool loadCheckpoint(unsigned char *buffer, unsigned int *ptr, unsigned int maxlen);
  virtual PRNG *getChecker(Verifier *verifier) { return new SimplePRNG(); };
};

class VPRNG : public PRNG {
public:
  VPRNG() : PRNG() {};
  bool validateQ(unsigned char *qbuf, int qbufLen, int t2, int idSizeBytes);
  virtual void resetAfterCoinToss(unsigned char *s, int sLen) = 0;
};

class RandomWrapper;

class RandomWrapperApp {
public:
  RandomWrapperApp() {};
  virtual ~RandomWrapperApp() {};
  virtual void getQ(RandomWrapper *callback) = 0;
  virtual void getRandomness(unsigned char *buf, int bytes) = 0;
};

class ExtInfoPolicy {
public:
  ExtInfoPolicy() {};
  virtual ~ExtInfoPolicy() {};
  virtual int storeExtInfo(SecureHistory *history, long long followingSeq, unsigned char *buffer, unsigned int maxlen) = 0;
};  

class StatusChangeListener {
public:
  StatusChangeListener() {};
  virtual ~StatusChangeListener() {};
  virtual void notifyStatusChange(Identifier *id, int newStatus) = 0;
};

/* In this class, the PeerReview library keeps information about its peers. Specifically, 
   it stores the last checked authenticator plus any challenges, responses or proofs
   that are known about the peer. */

class PeerInfoStore {
protected:
  struct evidenceRecord {
    struct evidenceRecord *next;
    struct evidenceRecord *nextUnanswered;
    struct evidenceRecord *prevUnanswered;
    Identifier *originator;
    long long timestamp;
    int evidenceLen;
    NodeHandle *interestedParty;
    bool isProof;
    bool haveResponse;
  };
    
  struct peerInfoRecord {
    struct peerInfoRecord *next;
    Identifier *id;
    unsigned char *lastCheckedAuth;
    int status;
    struct evidenceRecord *evidence;
    struct evidenceRecord *unansweredEvidence;
  };
  
  char dirname[200];
  struct peerInfoRecord *head;
  int authenticatorSizeBytes;
  IdentityTransport *transport;
  StatusChangeListener *listener;
  bool notificationEnabled;

  bool isProof(const unsigned char *evidence);
  struct peerInfoRecord *find(Identifier *id, bool create = false);
  struct evidenceRecord *findEvidence(Identifier *originator, Identifier *subject, long long timestamp, bool create = false);
  void markEvidenceAvailable(Identifier *originator, Identifier *subject, long long timestamp, int length, bool isProof, NodeHandle *interestedParty = NULL);
  void markResponseAvailable(Identifier *originator, Identifier *subject, long long timestamp);

public:
  PeerInfoStore(IdentityTransport *transport);
  ~PeerInfoStore();
  void setStatusChangeListener(StatusChangeListener *listener) { this->listener = listener; };
  void setAuthenticatorSize(int sizeBytes);
  bool setStorageDirectory(const char *dir);
  bool getLastCheckedAuth(Identifier *id, unsigned char *buffer);
  void addEvidence(Identifier *originator, Identifier *subject, long long timestamp, const unsigned char *evidence, int evidenceLen, NodeHandle *interestedParty = NULL);
  bool statEvidence(Identifier *originator, Identifier *subject, long long timestamp, int *evidenceLen, bool *isProof, bool *haveResponse, NodeHandle **interestedParty);
  void getEvidence(Identifier *originator, Identifier *subject, long long timestamp, unsigned char *evidenceBuf, int buflen);
  void addResponse(Identifier *originator, Identifier *subject, long long timestamp, const unsigned char *response, int responseLen);
  int getStatus(Identifier *id);
  void getHistoryName(Identifier *id, char *buf);
  void setLastCheckedAuth(Identifier *id, unsigned char *buffer);
  bool statFirstUnansweredChallenge(Identifier *subject, Identifier **originator, long long *timestamp, int *evidenceLen);
  bool statProof(Identifier *subject, Identifier **originator, long long *timestamp, int *evidenceLen);
};

/* Witnesses use instances of this class to store authenticators. Typically there
   are three instances: authInStore, authPendingStore and authOutStore. The former
   two contain authenticators about nodes for which the local node is a witness,
   while the latter contains authenticators about other nodes which haven't been
   sent to the corresponding witness sets yet. */

class AuthenticatorStore {
protected:
  struct authenticatorRecord {
    struct authenticatorRecord *next;
    unsigned char authenticator[];
  };
  
  struct subjectRecord {
    struct subjectRecord *next;
    Identifier *id;
    int numAuthenticators;
    struct authenticatorRecord *authList;
  };

  struct subjectRecord *head;
  int authenticatorSizeBytes;
  PeerReview *peerreview;
  bool allowDuplicateSeqs;
  char filename[200];
  int numSubjects;
  int authFile;
  bool memoryBufferDisabled;
  
  void addAuthenticatorToMemory(Identifier *id, const unsigned char *authenticator);
  void flushAuthenticatorsFromMemory(Identifier *id, long long minseq, long long maxseq);
  struct subjectRecord *findSubject(Identifier *id);
  bool isSorted(struct subjectRecord *rec);
  
public:
  AuthenticatorStore(PeerReview *peerreview, int authenticatorSizeBytes, bool allowDuplicateSeqs = false);
  ~AuthenticatorStore();
  bool setFilename(const char *filename);
  void addAuthenticator(Identifier *id, const unsigned char *authenticator);
  void flushAll();
  void flush(Identifier *subject);
  void garbageCollect();
  Identifier *getSubject(int index);
  int getNumSubjects() { return numSubjects; };
  int numAuthenticatorsFor(Identifier *id);
  int numAuthenticatorsFor(Identifier *id, long long minseq, long long maxseq);
  bool statAuthenticator(Identifier *id, long long seq, unsigned char *buffer);
  void flushAuthenticatorsFor(Identifier *id, long long minseq = LONG_LONG_MIN, long long maxseq = LONG_LONG_MAX) { flushAuthenticatorsFromMemory(id, minseq, maxseq); };
  int getAuthenticators(Identifier *subject, unsigned char *buffer, int bufferSizeBytes, long long minseq = LONG_LONG_MIN, long long maxseq = LONG_LONG_MAX);
  int getAuthenticatorSizeBytes() { return authenticatorSizeBytes; };
  bool getOldestAuthenticator(Identifier *id, unsigned char *buffer);
  bool getMostRecentAuthenticator(Identifier *id, unsigned char *buffer);
  bool getLastAuthenticatorBefore(Identifier *id, long long seq, unsigned char *buffer);
  void disableMemoryBuffer() { this->memoryBufferDisabled = true; };
};  

/* This protocol attaches signatures to outgoing messages and acknowledges
   incoming messages. It also has transmit and receive queues where
   messages can be held while acknowledgments are pending, and it can
   retransmit messages a few times when an acknowledgment is not received. */

class CommitmentProtocol : public TimerCallback, Basics {
protected:
  static const int MAX_PEERS = 250;
  static const int INITIAL_TIMEOUT_MICROS = 1000000;
  static const int RETRANSMIT_TIMEOUT_MICROS = 1000000;
  static const int RECEIVE_CACHE_SIZE = 100;
  static const int MAX_RETRANSMISSIONS = 2;
  static const int TI_PROGRESS = 1;
  static const int PROGRESS_INTERVAL_MICROS = 1000000;
  static const int INITIAL_CHALLENGE_INTERVAL_MICROS = 30000000;
 
  struct packetInfo {
    struct packetInfo *next;
    unsigned char *message;
    int msglen;
  };
 
  /* We cache a few recently received messages, so we can recognize duplicates.
     We also remember the location of the corresponding RECV entry in the log,
     so we can reproduce the matching acknowledgment */
 
  struct receiveInfo {
    Identifier *sender;
    long long senderSeq;
    int indexInLocalHistory;
  } receiveCache[RECEIVE_CACHE_SIZE];
 
 /* We need to keep some state for each peer, including separate transmit and
    receive queues */
 
  struct peerInfo {
    NodeHandle *handle;
    int numOutstandingPackets;
    long long lastTransmit;
    long long currentTimeout;
    int retransmitsSoFar;
    long long lastChallenge;
    long long currentChallengeInterval;
    struct packetInfo *xmitQueue;
    struct packetInfo *recvQueue;
    bool isReceiving;
  } peer[MAX_PEERS];

  AuthenticatorStore *authStore;
  SecureHistory *history;
  PeerReviewCallback *app;
  PeerReview *peerreview;
  PeerInfoStore *infoStore;
  IdentityTransport *transport;
  NodeHandle *myHandle;
  Misbehavior *misbehavior;
  long long timeToleranceMicros;
  int nextReceiveCacheEntry;
  int signatureSizeBytes;
  int hashSizeBytes;
  int numPeers;

  int lookupPeer(NodeHandle *handle);
  struct packetInfo *enqueueTail(struct packetInfo *queue, unsigned char *message, int msglen);
  void makeProgress(int idx);
  int findRecvEntry(Identifier *id, long long seq);
  long long findAckEntry(Identifier *id, long long seq);
  void initReceiveCache();
  void addToReceiveCache(Identifier *id, long long senderSeq, int indexInLocalHistory);

public:
  CommitmentProtocol(PeerReview *peerreview, IdentityTransport *transport, PeerInfoStore *infoStore, AuthenticatorStore *authStore, SecureHistory *history, PeerReviewCallback *app, Misbehavior *misbehavior, long long timeToleranceMicros);
  ~CommitmentProtocol();
  virtual void timerExpired(int timerID);
  int logMessageIfNew(unsigned char *message, int msglen, unsigned char *ackBuf, int ackMaxLen, bool *loggedPreviously);
  void handleIncomingMessage(NodeHandle *source, unsigned char *message, int msglen);
  long long handleOutgoingMessage(NodeHandle *target, unsigned char *message, int msglen, int relevantlen);
  void handleIncomingAck(NodeHandle *source, unsigned char *message, int msglen);
  void notifyCertificateAvailable(Identifier *id);
  void notifyStatusChange(Identifier *id, int newStatus);
  void setTimeToleranceMicros(long long timeToleranceMicros) { this->timeToleranceMicros = timeToleranceMicros; };
};

class EvidenceTool : Basics {
protected:

public:
  enum checkResult { VALID, INVALID, CERT_MISSING };

  EvidenceTool() {};
  static checkResult checkSnippet(unsigned char *snippet, unsigned int snippetLen, Identifier **missingCertID, IdentityTransport *transport);
  static checkResult isAuthenticatorValid(unsigned char *authenticator, Identifier *subject, IdentityTransport *transport);
  static bool checkSnippetSignatures(unsigned char *snippet, int snippetLen, long long firstSeq, unsigned char *baseHash, NodeHandle *subjectHandle, AuthenticatorStore *authStoreOrNull, unsigned char flags, IdentityTransport *transport, PeerReview *peerreview, CommitmentProtocol *commitmentProtocol, unsigned char *keyNodeHash, long long keyNodeMaxSeq);
  static bool checkNoEntriesHashed(unsigned char *snippet, unsigned int snippetLen, unsigned char *typesToIgnore, int numTypesToIgnore, IdentityTransport *transport);
  static void appendSnippetToHistory(unsigned char *snippet, int snippetLen, SecureHistory *history, IdentityTransport *transport, long long firstSeq, long long skipEverythingBeforeSeq);
  static bool checkHashChainContains(unsigned char *snippet, int snippetLen, long long firstSeq, unsigned char *baseHash, unsigned char *keyNodeHash, long long keyNodeSeq, IdentityTransport *transport);
};

/* This protocol transfers evidence to the witnesses */

class EvidenceTransferProtocol : public WitnessListener, Basics {
protected:
  static const int MAX_CACHE_ENTRIES = 500;
  static const int MAX_PENDING_MESSAGES = 100;
  static const int MAX_PENDING_QUERIES = 100;
  static const int WITNESS_SET_VALID_MICROS = 300*1000000;

  PeerReview *peerreview;
  IdentityTransport *transport;
  PeerInfoStore *infoStore;
  PeerReviewCallback *app;
  
  /* Since applications like ePOST must communicate to determine the current witness
     set of a node (which is expensive), we cache witness sets for a while. An entry
     in this cache can also be half-complete, meaning that an upcall has been made
     to the application to determine the witness set, but the result has not been
     received yet. */
  
  struct cacheInfo {
    Identifier *subject;
    bool witnessesRequested;
    bool haveWitnesses;
    int numWitnesses;
    NodeHandle **witness;
    long long validUntil;
  } witnessCache[MAX_CACHE_ENTRIES];
  
  /* When we have a message for a node whose witness set is not (yet) known, it is
     queued in here */
  
  struct messageInfo {
    Identifier *subject;
    bool datagram;
    unsigned char *message;
    int msglen;
  } pendingMessage[MAX_PENDING_MESSAGES];    
  
  /* Here we remember all the questions we've asked the application about witness sets */
  
  struct queryInfo {
    int numSubjects;
    Identifier **subjectList;
    NodeHandle ***witness;
    int *numWitnesses;
  } pendingQuery[MAX_PENDING_QUERIES];
  
  int numCacheEntries;
  int numPendingMessages;
  int numPendingQueries;

  void removeCacheEntry(int idx);
  void removePendingMessage(int idx);
  void removePendingQuery(int idx);
  int lookupInCache(Identifier *subject);
  int makeCacheEntry(Identifier *subject);
  void doSendMessageToWitnesses(int idx, bool datagram, unsigned char *message, int msglen);
  void deliverWitnesses(int idx);

public:
  EvidenceTransferProtocol(PeerReview *peerreview, PeerReviewCallback *app, IdentityTransport *transport, PeerInfoStore *infoStore);
  ~EvidenceTransferProtocol();
  void sendMessageToWitnesses(Identifier *subject, bool datagram, unsigned char *message, int msglen);
  void requestWitnesses(Identifier **subjectList, int numSubjects);
  virtual void notifyWitnessSet(Identifier *subject, int numWitnesses, NodeHandle **witnesses);
  void sendEvidence(NodeHandle *target, Identifier *subject);
};

/* This protocol collects authenticators from incoming messages and, once in a while,
   batches them together and sends them to the witnesses. */

class AuthenticatorPushProtocol : Basics {
protected:
  static const int MAX_SUBJECTS_PER_WITNESS = 110;
  static const int MAX_WITNESSES_PER_SUBJECT = 110;

  AuthenticatorStore *authOutStore;
  AuthenticatorStore *authInStore;
  AuthenticatorStore *authPendingStore;
  PeerInfoStore *infoStore;
  int authenticatorSizeBytes;
  int signatureSizeBytes;
  int hashSizeBytes;
  PeerReview *peerreview;
  IdentityTransport *transport;
  PeerReviewCallback *app;
  EvidenceTransferProtocol *evidenceTransferProtocol;
  bool probabilistic;
  double pXmit;
  
  void addAuthenticatorsIfValid(unsigned char *message, int numAuths, Identifier *id);
  
public:
  AuthenticatorPushProtocol(PeerReview *peerreview, AuthenticatorStore *inStore, AuthenticatorStore *outStore, AuthenticatorStore *pendingStore, IdentityTransport *transport, PeerReviewCallback *app, PeerInfoStore *infoStore, int hashSizeBytes, EvidenceTransferProtocol *evidenceTransferProtocol);
  void handleIncomingAuthenticators(NodeHandle *source, unsigned char *message, int msglen);
  void notifyCertificateAvailable(Identifier *id);
  void push();
  void continuePush(int numSubjects, Identifier **subjects, int *witnessesPerSubject, NodeHandle **witnesses);
  void enableProbabilisticChecking(double pXmit) { this->probabilistic = true; this->pXmit = pXmit; };
};

/* This class does all the hard work during replay. It reads entries from the log
   and feeds them to the application via an EventCallback or a special transport
   layer; also, it intercepts send() calls from the application and checks the log
   for a corresponding SEND event (for this purpose, it implements the same
   interface as a transport layer). When replay has been completed, this class
   reports whether or not it has found a discrepancy. */

class Verifier : public ReplayWrapper, Basics {
protected:
  static const int MAX_TIMERS = 10;

  /* If the application schedules timers during replay, we remember them here. */

  struct timerStruct {
    long long time;
    int id;
    TimerCallback *callback;
  } timer[MAX_TIMERS];

  static const int MAX_EVENT_CALLBACKS = 10;
  EventCallback *eventCallback[MAX_EVENT_CALLBACKS];
  unsigned char *extInfo;
  int extInfoLen;
  int numEventCallbacks;
  long long now;
  int eventToCallback[256];
  NodeHandle *localHandle;
  SecureHistory *history;
  PeerReviewCallback *app;
  bool foundFault;
  bool haveNextEvent;
  unsigned char nextEvent[50000];
  int nextEventSize;
  unsigned char nextEventType;
  long long nextEventSeq;
  int nextEventIndex;
  bool nextEventIsHashed;
  bool initialized;
  int numTimers;
  int signatureSizeBytes;
  int hashSizeBytes;
  PeerReview *transport;
  PRNG *prng;

public:
  Verifier(PeerReview *peerreview, SecureHistory *history, NodeHandle *localHandle, int signatureSizeBytes, int hashSizeBytes, int firstEntryToReplay, long long initialTime, unsigned char *extInfo, int extInfoLen);
  virtual ~Verifier();
  virtual void registerCallback(EventCallback *callback);
  virtual void registerEvent(EventCallback *callback, unsigned char eventType);
  virtual long long getTime() { return now; };
  virtual void logEvent(char type, const void *entry, int size);
  virtual long long send(NodeHandle *target, bool datagram, unsigned char *message, int msglen, int relevantlen = -1);
  virtual void scheduleTimer(TimerCallback *callback, int timerID, long long when);
  virtual void cancelTimer(TimerCallback *callback, int timerID);
  virtual NodeHandle *getLocalHandle() { return localHandle; };
  virtual void requestCertificate(NodeHandle *handle, Identifier *id) { assert(false); };
  virtual bool haveCertificate(Identifier *id) { assert(false); };
  virtual void sign(const unsigned char *data, int dataLength, unsigned char *signatureBuffer) { assert(false); };
  virtual int verify(Identifier *id, const unsigned char *data, const int dataLength, unsigned char *signature) { assert(false); };
  virtual int getSignatureSizeBytes() { return signatureSizeBytes; };
  virtual int getMSS() { assert(false); return 0; }; 
  virtual void logText(const char *subsystem, int level, const char *format, ...);
  virtual int getIdentifierSizeBytes();
  virtual void investigate(NodeHandle *target, long long since) { };
  virtual Identifier *readIdentifier(unsigned char *buf, unsigned int *pos, unsigned int maxlen);
  virtual Identifier *readIdentifierFromString(const char *str);
  virtual NodeHandle *readNodeHandle(unsigned char *buf, unsigned int *pos, unsigned int maxlen);
  virtual NodeHandle *readNodeHandleFromString(const char *str) { assert(false); return NULL; };
  virtual void incrementCounter(int code, int value) { };
  virtual int getHashSizeBytes();
  virtual int getRandom(int range);
  virtual void hash(unsigned char *outbuf, const unsigned char *inbuf1, const int insize1, const unsigned char *inbuf2 = NULL, const int insize2 = 0, const unsigned char *inbuf3 = NULL, const int insize3 = 0, const unsigned char *inbuf4 = NULL, const int insize4 = 0);
  
  void setApplication(PeerReviewCallback *app);
  virtual bool statNextEvent(unsigned char *type, int *size, long long *seq, bool *isHashed, unsigned char **buf);
  virtual int getNextEntryOfType(unsigned char type, unsigned char *buf, unsigned int maxlen, bool includeCurrent);
  virtual void fetchNextEvent();
  virtual void markFaulty() { foundFault = true; };
  bool makeProgress();
  bool verifiedOK() { return !foundFault; };
  virtual PRNG *getPRNG() { return prng; };
  virtual int getExtInfo(unsigned char *buf, int maxlen);
};

/* This class periodically sends audit requests to nodes for which the local
   node is a witness, and it checks whether the response is valid. Furthermore, 
   it responds to incoming audit requests, and it can perform proactive audits
   if the local node finds that an expected message has not (yet) arrived. */
   
class AuditProtocol : public TimerCallback, Basics {
protected:
  static const long long DEFAULT_AUDIT_INTERVAL_MICROS = 10000000LL;
  static const int PROGRESS_INTERVAL_MICROS = 100000;
  static const int INVESTIGATION_INTERVAL_MICROS = 250000;
  static const int DEFAULT_LOG_DOWNLOAD_TIMEOUT = 2000000;
  static const int MAX_WITNESSED_NODES = 110;
  static const int MAX_ACTIVE_AUDITS = 500;
  static const int MAX_ACTIVE_INVESTIGATIONS = 10;
  static const int MAX_ENTRIES_BETWEEN_CHECKPOINTS = 100;
  static const int AUTH_CACHE_INTERVAL = 500000;
  
  static const int TI_START_AUDITS = 3;
  static const int TI_MAKE_PROGRESS = 4;

  static const int STATE_SEND_AUDIT = 1;
  static const int STATE_WAIT_FOR_LOG = 2;

  /* Here we remember calls to investigate() that have not been resolved yet */

  struct activeInvestigationInfo {
    NodeHandle *target;
    long long since;
    long long currentTimeout;
    unsigned char *authFrom;
    unsigned char *authTo;
  } activeInvestigation[MAX_ACTIVE_INVESTIGATIONS];

  /* Here we keep state about audits for which (a) we have not received a
     response yet, or (b) we are currently replaying the log */

  struct activeAuditInfo {
    NodeHandle *target;
    bool shouldBeReplayed;
    bool isReplaying;
    long long currentTimeout;
    unsigned char *request;
    int requestLen;
    long long evidenceSeq;
    Verifier *verifier;
  } activeAudit[MAX_ACTIVE_AUDITS];
  
  int numActiveAudits;
  int numActiveInvestigations;
  bool progressTimerActive;
  int signatureSizeBytes;
  int hashSizeBytes;
  int authenticatorSizeBytes;
  PeerReview *peerreview;
  PeerInfoStore *infoStore;
  AuthenticatorStore *authInStore;
  IdentityTransport *transport;
  SecureHistory *history;
  PeerReviewCallback *app;
  NodeHandle *myHandle;
  AuthenticatorStore *authOutStore;
  AuthenticatorStore *authCacheStore;
  EvidenceTransferProtocol *evidenceTransferProtocol;
  int logDownloadTimeout;
  bool replayEnabled;
  long long lastAuditStarted;
  long long auditIntervalMicros;
  
  void startAudits();
  void cleanupAudits();
  void makeProgressOnInvestigations();
  void sendInvestigation(int idx);
  void terminateAudit(int idx);
  void terminateInvestigation(int idx);
  void beginAudit(NodeHandle *target, unsigned char *authFrom, unsigned char *authTo, unsigned char needPrevCheckpoint, bool replayAnswer);
  int findOngoingAudit(Identifier *subject, long long evidenceSeq);
  
public:
  AuditProtocol(PeerReview *peerreview, SecureHistory *history, PeerInfoStore *infoStore, AuthenticatorStore *authInStore, IdentityTransport *transport, PeerReviewCallback *app, AuthenticatorStore *authOutStore, EvidenceTransferProtocol *evidenceTransferProtocol, AuthenticatorStore *authCacheStore);
  ~AuditProtocol();
  virtual void timerExpired(int timerID);
  bool statOngoingAudit(Identifier *subject, long long evidenceSeq, unsigned char **evidence, int *evidenceLen);
  void processAuditResponse(Identifier *subject, long long evidenceSeq, unsigned char *snippet, int snippetLen);
  void handleIncomingDatagram(NodeHandle *handle, unsigned char *message, int msglen);
  void investigate(NodeHandle *target, long long since);
  void setLogDownloadTimeout(int timeoutMicros) { this->logDownloadTimeout = timeoutMicros; };
  void disableReplay() { this->replayEnabled = false; };
  void setAuditInterval(long long newIntervalMicros);
};

/* This class implements the challenge/response protocol. For each incoming message,
   it checks whether the sender is currently suspected. If so, it responds with a
   challenge and queues the message until the challenge is answered. It also 
   responds to incoming challenges from other nodes. */

class ChallengeResponseProtocol : Basics {
protected:
  struct packetInfo {
    struct packetInfo *next;
    NodeHandle *source;
    unsigned char *message;
    int msglen;
    bool isAccusation;
    Identifier *subject;
    Identifier *originator;
    long long evidenceSeq;
  };

  AuthenticatorStore *authOutStore;
  IdentityTransport *transport;
  PeerReview *peerreview;
  PeerInfoStore *infoStore;
  SecureHistory *history;
  AuditProtocol *auditProtocol;
  CommitmentProtocol *commitmentProtocol;
  struct packetInfo *queueHead;
  int signatureSizeBytes;
  int hashSizeBytes;
  int authenticatorSizeBytes;
  PeerReviewCallback *app;
  ExtInfoPolicy *extInfoPolicy;
  
  bool isValidResponse(Identifier *subject, unsigned char *evidence, int evidenceLen, unsigned char *response, int responseLen, bool extractAuthsFromResponse = false);
  void copyAndEnqueueTail(NodeHandle *source, unsigned char *message, int msglen, bool isAccusation, Identifier *subject = 0, Identifier *originator = 0, long long evidenceSeq = 0);
  void maybeSendNextChallenge(NodeHandle *target);
  void deliver(struct packetInfo *pi);

public:
  ChallengeResponseProtocol(PeerReview *peerreview, IdentityTransport *transport, PeerInfoStore *infoStore, SecureHistory *history, AuthenticatorStore *authOutStore, AuditProtocol *auditProtocol, CommitmentProtocol *commitmentProtocol, PeerReviewCallback *app);
  ~ChallengeResponseProtocol();
  void handleChallenge(NodeHandle *source, unsigned char *challenge, int challengeLen);
  void handleStatement(NodeHandle *source, unsigned char *statement, int statementLen);
  void handleResponse(Identifier *originator, Identifier *subject, long long timestamp, unsigned char *payload, int payloadLen);
  void handleIncomingMessage(NodeHandle *source, unsigned char *message, int msglen);
  void notifyStatusChange(Identifier *id, int newStatus);
  void challengeSuspectedNode(NodeHandle *target);
  void setExtInfoPolicy(ExtInfoPolicy *eip) { this->extInfoPolicy = eip; };
};

/* The purpose of this protocol is to make sure that we have all the nodeID certificates
   we need. For each incoming message, it checks whether any additional certificates
   are needed, e.g. to check evidence about another node. If yes, it temporarily queues
   the message and requests the certificate from the sender. */

class StatementProtocol : public TimerCallback, Basics {
protected:
  static const int MAX_INCOMPLETE_STATEMENTS = 250;
  static const int PROGRESS_INTERVAL_MICROS = 1000000;
  static const int STATEMENT_COMPLETION_TIMEOUT_MICROS = 1000000;

  static const int TI_MAKE_PROGRESS = 5;

  /* This is where we queue messages for which we need additional certificates. */

  struct incompleteStatementInfo {
    bool finished;
    NodeHandle *sender;
    long long currentTimeout;
    unsigned char *statement;
    int statementLen;
    bool isMissingCertificate;
    Identifier *missingCertificateID;
  } incompleteStatement[MAX_INCOMPLETE_STATEMENTS];
  
  ChallengeResponseProtocol *challengeProtocol;
  IdentityTransport *transport;
  PeerReview *peerreview;
  PeerInfoStore *infoStore;
  bool progressTimerActive;
  PeerReviewCallback *app;
  int numIncompleteStatements;
  int signatureSizeBytes;
  int hashSizeBytes;
  int authenticatorSizeBytes;

  void makeProgressOnStatement(int idx);
  void cleanupIncompleteStatements();
  int checkSnippetAndRequestCertificates(unsigned char *snippet, unsigned int snippetLen, int idx);

public:
  StatementProtocol(PeerReview *peerreview, ChallengeResponseProtocol *auditProtocol, PeerInfoStore *infoStore, IdentityTransport *transport, int hashSizeBytes, PeerReviewCallback *app);
  ~StatementProtocol();
  virtual void timerExpired(int timerID);
  void handleIncomingStatement(NodeHandle *source, const unsigned char *statement, int statementLen);
  void notifyCertificateAvailable(Identifier *id);
};

/* This class is used for testing; it can be configured to perform various types
   of mischief, such as forking the log, or ignoring another node completely. */

class Misbehavior {
protected:
  static const int GOOD = 0;
  static const int IGNORE_NODE = 1;
  static const int DUPLICATE_AUTH = 2;
  static const int TAMPER_WITH_DATA = 3;
  static const int SILENT = 4;
  static const int RELUCTANT = 5;
  static const int IGNOREEXCEPT2 = 6;
  static const int SPURIOUS_AUTH = 7;

  PeerReview *peerreview;
  SecureHistory *history;
  int type;
  Identifier *subject;
  Identifier *subject2;
  long long start;
  long long lastSeq;
  long long arg;
  int signatureSizeBytes;
  int hashSizeBytes;
  AuthenticatorStore *authOutStore;
  IdentityTransport *transport;

public:
  Misbehavior(PeerReview *peerreview, const char *misbehaviorString, int signatureSizeBytes, int hashSizeBytes, AuthenticatorStore *authOutStore, IdentityTransport *transport, SecureHistory *history);
  ~Misbehavior();
  bool dropIncomingMessage(NodeHandle *handle, bool datagram, unsigned char *message, int msglen);
  bool dropOutgoingMessage(NodeHandle *handle, bool datagram, unsigned char *message, int msglen);
  bool dropAfterLogging(NodeHandle *handle, unsigned char *message, int msglen);
  void maybeTamperWithData(unsigned char *message, int msglen);
  void maybeChangeSeqInUserMessage(long long *topSeq);
};  

/* This is the main PeerReview class. It actually does very little, except for 
   relaying calls to other classes and handling startup. */

class PeerReview : public IdentityTransport, public IdentityTransportCallback, public TimerCallback, public StatusChangeListener, Basics {
protected:
  static const int DEFAULT_AUTH_PUSH_INTERVAL_MICROS = 5000000;
  static const long long DEFAULT_CHECKPOINT_INTERVAL_MICROS = 10000000LL;
  static const int MAINTENANCE_INTERVAL_MICROS = 10000000;
  static const int DEFAULT_TIME_TOLERANCE_MICROS = 60000000;

  static const int TI_CHECKPOINT = 99;
  static const int TI_MAINTENANCE = 6;
  static const int TI_AUTH_PUSH = 7;
  static const int TI_MAX_RESERVED = TI_AUTH_PUSH;
  static const int TI_STATUS_INFO = 101;
  static const int MAX_STATUS_INFO = 100;

  ChallengeResponseProtocol *challengeProtocol;
  AuthenticatorPushProtocol *authPushProtocol;
  CommitmentProtocol *commitmentProtocol;
  AuditProtocol *auditProtocol;
  StatementProtocol *statementProtocol;
  AuthenticatorStore *authOutStore;
  AuthenticatorStore *authInStore;
  AuthenticatorStore *authPendingStore;
  AuthenticatorStore *authCacheStore;
  EvidenceTransferProtocol *evidenceTransferProtocol;
  Misbehavior *misbehavior;
  PeerInfoStore *infoStore;
  SecureHistory *history;
  int authenticatorSizeBytes;
  int signatureSizeBytes;
  int hashSizeBytes;
  PeerReviewCallback *app;
  IdentityTransport *transport;
  long long lastLogEntry;
  long long nextEvidenceSeq;
  long long timeToleranceMicros;
  long long checkpointIntervalMicros;
  long long authPushIntervalMicros;
  bool prngEnabled;
  PRNG *prng;
  bool initialized;
  ExtInfoPolicy *extInfoPolicy;
  
  void updateLogTime();
  void writeCheckpoint();

  struct statusInfoStruct {
    Identifier *id;
    int newStatus;
  } statusInfo[MAX_STATUS_INFO];
  int numStatusInfo;

public:
  PeerReview(IdentityTransport *transport);
  virtual ~PeerReview();
  virtual long long getTime() { return transport->getTime(); };
  virtual void logEvent(char type, const void *entry, int size);
  virtual long long send(NodeHandle *target, bool datagram, unsigned char *message, int msglen, int relevantlen = -1);
  virtual void scheduleTimer(TimerCallback *callback, int timerID, long long when);
  virtual void cancelTimer(TimerCallback *callback, int timerID);
  virtual NodeHandle *getLocalHandle() { return transport->getLocalHandle(); };
  virtual void timerExpired(int timerID);
  virtual void receive(NodeHandle *source, bool datagram, unsigned char *msg, int msglen);
  virtual void statusChange(Identifier *id, int newStatus) { };
  virtual void requestCertificate(NodeHandle *source, Identifier *id) { transport->requestCertificate(source, id); };
  virtual bool haveCertificate(Identifier *id) { return transport->haveCertificate(id); };
  virtual void sign(const unsigned char *data, int dataLength, unsigned char *signatureBuffer) { transport->sign(data, dataLength, signatureBuffer); };
  virtual int verify(Identifier *id, const unsigned char *data, const int dataLength, unsigned char *signature) { return transport->verify(id, data, dataLength, signature); };
  virtual int getSignatureSizeBytes() { return signatureSizeBytes; };
  virtual int getMSS() { assert(false); return 0; }; 
  virtual void logText(const char *subsystem, int level, const char *format, ...);
  virtual int getIdentifierSizeBytes() { return transport->getIdentifierSizeBytes(); };
  virtual Identifier *readIdentifier(unsigned char *buf, unsigned int *pos, unsigned int maxlen) { return transport->readIdentifier(buf, pos, maxlen); };
  virtual Identifier *readIdentifierFromString(const char *str) { return transport->readIdentifierFromString(str); };
  virtual NodeHandle *readNodeHandle(unsigned char *buf, unsigned int *pos, unsigned int maxlen) { return transport->readNodeHandle(buf, pos, maxlen); };
  virtual NodeHandle *readNodeHandleFromString(const char *str) { return transport->readNodeHandleFromString(str); };
  virtual void incrementCounter(int code, int value) { transport->incrementCounter(code, value); };
  virtual int getRandom(int range);
  virtual void sendComplete(long long id) { };

  void investigate(NodeHandle *target, long long since);
  long long getEvidenceSeq();
  int getHashSizeBytes() { return transport->getHashSizeBytes(); };
  void setCallback(PeerReviewCallback *callback);
  SecureHistory *getHistory() { return history; };
  void init(const char *dirname, const char *misbehaviorString = NULL);
  void notifyCertificateAvailable(Identifier *id);
  virtual void notifyStatusChange(Identifier *id, int newStatus);
  void notifyAuthenticatorConflict(Identifier *id, unsigned char *auth1, unsigned char *auth2);
  void dump(int level, const unsigned char *payload, int len);
  void sendEvidenceToWitnesses(Identifier *subject, long long timestamp, const unsigned char *evidence, int evidenceLen);
  bool addAuthenticatorIfValid(AuthenticatorStore *store, Identifier *subject, unsigned char *auth);
  bool extractAuthenticator(Identifier *id, long long seq, unsigned char entryType, const unsigned char *entryHash, const unsigned char *hTopMinusOne, unsigned char *signature, unsigned char *authenticator);
  void challengeSuspectedNode(NodeHandle *handle) { challengeProtocol->challengeSuspectedNode(handle); };
  void transmit(NodeHandle *target, bool datagram, unsigned char *message, int msglen);
  void notifyWitnessesExt(int numSubjects, Identifier **subjects, int *witnessesPerSubject, NodeHandle **witnesses);
  void setTimeToleranceMicros(long long timeToleranceMicros);
  void setLogDownloadTimeout(int timeoutMicros) { assert(auditProtocol); auditProtocol->setLogDownloadTimeout(timeoutMicros); };
  void setAuthenticatorPushInterval(long long intervalMicros) { this->authPushIntervalMicros = intervalMicros; };
  void enableProbabilisticChecking(double pXmit) { authPushProtocol->enableProbabilisticChecking(pXmit); };
  void enableRandomNumberGenerator() { this->prngEnabled = true; };
  virtual void hash(unsigned char *outbuf, const unsigned char *inbuf1, const int insize1, const unsigned char *inbuf2 = NULL, const int insize2 = 0, const unsigned char *inbuf3 = NULL, const int insize3 = 0, const unsigned char *inbuf4 = NULL, const int insize4 = 0) { transport->hash(outbuf, inbuf1, insize1, inbuf2, insize2, inbuf3, insize3, inbuf4, insize4); };
  PRNG *getPRNG() { return prng; };
  void logEventInternal(char type, const void *entry, int size);
  void setExtInfoPolicy(ExtInfoPolicy *eip) { extInfoPolicy = eip; if (challengeProtocol) challengeProtocol->setExtInfoPolicy(eip); };
  void disableReplay() { assert(auditProtocol); auditProtocol->disableReplay(); };
  void setCheckpointInterval(long long intervalMicros) { this->checkpointIntervalMicros = intervalMicros; };
  void setAuditInterval(long long newIntervalMicros) { assert(auditProtocol); auditProtocol->setAuditInterval(newIntervalMicros); };
  void disableAuthenticatorProcessing();
};

#endif /* defined(__peerreview_h__) */
