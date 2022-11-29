#ifndef __vrf_h__
#define __vrf_h__

#include <peerreview.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#define RAND_SIZE 20

class VRF {
protected:
  BIGNUM *sP;
  BIGNUM *td;
  BIGNUM *m1, *m2, *qInv;
  BIGNUM *dP_d, *dQ_d;
  BIGNUM *p1, *q1, *p2, *q2;
  BIGNUM *sPunhashed;
  int keylenBytes;
  BN_CTX *ctx;
  RSA *privkey;
  unsigned char *sPprecomp;
  unsigned char *nodeID;
  int idSizeBytes;
  bool havePrecomp;
  bool enablePrecomp;
  int hashStarOutputBytes;
  int i;
  int t;

  void BN_exp_mod_N(BIGNUM *output, BIGNUM *base, BIGNUM *exp);
  void precompute();

public:
  VRF(RSA *privkey, int i, int t, unsigned char *sP, unsigned char *nodeID, int idSizeBytes, bool enablePrecomp = true);
  ~VRF();
  void getRandom(unsigned char *buf, unsigned char *spBuf);
  bool justHashed() { return ((i%t) == 0); };
  void writeN(unsigned char *buf, unsigned int *ptr, unsigned int maxlen);
  void getCurrentSi(unsigned char *sPbuf);
  int getI() { return i; };
  int getT() { return t; };
  void getQ(unsigned char *qbuf, int qbufLen, int t2);
  void resetAfterCoinToss(unsigned char *s, int sLen);
};

class VRFChecker {
protected:
  BIGNUM *sP, *s2, *s3;
  unsigned char *nodeID;
  int idSizeBytes;
  int keylenBytes;
  int keylenDwords;
  int hashStarOutputBytes;
  BN_CTX *ctx;
  BIGNUM *n;
  int i;
  int t;

  unsigned char *duplicateList;
  int numEntriesInDuplicateList;
  int duplicateListIndex[256];
  int duplicateListEntrySizeBytes;

  unsigned char *precompHashes;
  int precompHashesAvailable;

  void flushDuplicateList();
  bool isDuplicate(unsigned char *sP);
  void addToDuplicateList(unsigned char *sP);
  
public:
  VRFChecker(BIGNUM *n, int keylenBytes, int i, int t, unsigned char *sP, unsigned char *nodeID, int idSizeBytes);
  ~VRFChecker();
  bool update(unsigned char *sP_in, unsigned char *hash_out = NULL);
  int getI() { return i; };
  int getT() { return t; };
  void writeN(unsigned char *buf, unsigned int *ptr, unsigned int maxlen);
  void getCurrentSi(unsigned char *sPbuf);
  void resetAfterCoinToss(unsigned char *s, int sLen);
  bool precompGetNextHash(unsigned char *outbuf);
  bool precompAddSi(unsigned char *sbuf);
};

class VerifiablePRNGChecker : public VPRNG, public RandomWrapperApp, public EventCallback, Basics {
protected:
  unsigned char *nodeID;
  int idSizeBytes;
  ReplayWrapper *verifier;
  VRFChecker *checker;
  int keylenBytes;
  unsigned char *qbuf;
  bool useBatching;
  bool extInfoUsed;
  int qlen;
  
public:
  VerifiablePRNGChecker(ReplayWrapper *verifier, bool useBatching = false);
  virtual ~VerifiablePRNGChecker();
  virtual int getRandom(int range);
  virtual int storeCheckpoint(unsigned char *buffer, unsigned int maxlen);
  virtual bool loadCheckpoint(unsigned char *buffer, unsigned int *ptr, unsigned int maxlen);
  virtual PRNG *getChecker(Verifier *verifier) { panic("Cannot clone a checker!"); return NULL; };
  virtual void resetAfterCoinToss(unsigned char *s, int sLen);
  virtual void getQ(RandomWrapper *callback);
  virtual void getRandomness(unsigned char *buf, int bytes);
  virtual void replayEvent(unsigned char type, unsigned char *entry, int entrySize);
};

class VerifiablePRNG : public VPRNG, public RandomWrapperApp, Basics {
protected:
  const static bool useBatching = true;
  const static int t1 = 100;
  PeerReview *peerreview;
  int keylenBytes;
  VRF *vrf;
  int t2;
  
public:
  VerifiablePRNG(const char *keyname, PeerReview *peerreview, int t2);
  virtual int getRandom(int range);
  virtual int storeCheckpoint(unsigned char *buffer, unsigned int maxlen);
  virtual bool loadCheckpoint(unsigned char *buffer, unsigned int *ptr, unsigned int maxlen);
  virtual VPRNG *getChecker(Verifier *verifier) { return new VerifiablePRNGChecker(verifier, useBatching); };
  virtual void getQ(RandomWrapper *callback);
  virtual void getRandomness(unsigned char *buf, int bytes);
  virtual void resetAfterCoinToss(unsigned char *s, int sLen);
  int storeExtInfo(unsigned char *buffer, unsigned int maxlen);
};

class VrfExtInfoPolicy : public ExtInfoPolicy {
protected:
  VerifiablePRNG *vprng;
  
public:
  VrfExtInfoPolicy(VerifiablePRNG *vprng);
  virtual ~VrfExtInfoPolicy();
  virtual int storeExtInfo(SecureHistory *history, long long followingSeq, unsigned char *buffer, unsigned int maxlen);
};  

class RandomWrapper : public IdentityTransport, public PeerReviewCallback, public WitnessListener, public TimerCallback, Basics {
protected:
  const static int MAX_WITNESSES = 50;
  const static int MAX_REQUESTERS = 20;
  const static int PHASE_INIT = 0;
  const static int PHASE_Q_SENT = 1;
  const static int PHASE_H_RECEIVED = 2;
  const static int PHASE_H_BLOCK_SENT = 3;
  const static int PHASE_R_RECEIVED = 4;
  const static int MSG_PREFIX = 0xFF;
  const static int MSG_RW_Q = 0;
  const static int MSG_RW_R_HASHED = 1;
  const static int MSG_RW_R_BLOCK = 2;
  const static int MSG_RW_R = 3;
  const static int TI_STARTUP = 8;
  
  const static int t4Bytes = 60;

  IdentityTransport *transport;
  RandomWrapperApp *wrapperApp;
  PeerReviewCallback *app;
  VPRNG *prng;

  struct {
    bool setupComplete;
    long long startupBegin;
    int numWitnesses;
    int numRequesters;
    unsigned char *myR;
    struct {
      NodeHandle *handle;
      unsigned char phase;
      unsigned char *val;
    } witness[MAX_WITNESSES];
    struct {
      NodeHandle *handle;
      unsigned char *r;
    } requester[MAX_REQUESTERS];
  } state;

  RandomWrapper(ReplayWrapper *verifier, PeerReviewCallback *app);

public:
  RandomWrapper(PeerReview *peerreview, PeerReviewCallback *app, const char *keyname);
  virtual ~RandomWrapper();
  virtual void receive(NodeHandle *source, bool datagram, unsigned char *msg, int msglen);
  virtual void statusChange(Identifier *id, int newStatus);
  virtual void notifyCertificateAvailable(Identifier *id);
  virtual long long getTime();
  virtual void scheduleTimer(TimerCallback *callback, int timerID, long long when);
  virtual void cancelTimer(TimerCallback *callback, int timerID);
  virtual bool haveCertificate(Identifier *id);
  virtual void requestCertificate(NodeHandle *source, Identifier *id);
  virtual void sign(const unsigned char *data, int dataLength, unsigned char *signatureBuffer);
  virtual int verify(Identifier *id, const unsigned char *data, const int dataLength, unsigned char *signature);
  virtual int getSignatureSizeBytes();
  virtual long long send(NodeHandle *target, bool datagram, unsigned char *message, int msglen, int relevantlen = -1);
  virtual void sendComplete(long long id);
  virtual int getMSS();
  virtual NodeHandle *getLocalHandle();
  virtual int getIdentifierSizeBytes();
  virtual Identifier *readIdentifier(unsigned char *buf, unsigned int *pos, unsigned int maxlen);
  virtual Identifier *readIdentifierFromString(const char *str);
  virtual NodeHandle *readNodeHandle(unsigned char *buf, unsigned int *pos, unsigned int maxlen);
  virtual NodeHandle *readNodeHandleFromString(const char *str);
  virtual void logEvent(char type, const void *entry, int size);
  virtual void logText(const char *subsystem, int level, const char *format, ...);
  virtual void incrementCounter(int code, int value);
  virtual int getRandom(int range);
  virtual void investigate(NodeHandle *target, long long since);
  virtual void init();
  virtual int storeCheckpoint(unsigned char *buffer, unsigned int maxlen);
  virtual bool loadCheckpoint(unsigned char *buffer, unsigned int len);
  virtual void getWitnesses(Identifier *subject, WitnessListener *callback);
  virtual int getMyWitnessedNodes(NodeHandle **nodes, int maxResults);
  virtual PeerReviewCallback *getReplayInstance(ReplayWrapper *replayWrapper);
  virtual int getHashSizeBytes();
  virtual void hash(unsigned char *outbuf, const unsigned char *inbuf1, const int insize1, const unsigned char *inbuf2 = NULL, const int insize2 = 0, const unsigned char *inbuf3 = NULL, const int insize3 = 0, const unsigned char *inbuf4 = NULL, const int insize4 = 0);
  virtual void setTransport(IdentityTransport *transport) { this->transport = transport; };
  virtual void notifyWitnessSet(Identifier *subject, int numWitnesses, NodeHandle **witnesses);
  virtual void timerExpired(int timerID);
  virtual int storeExtInfo(unsigned char *buffer, unsigned int maxlen) { return prng->storeExtInfo(buffer, maxlen); };
  void notifyQ(unsigned char *qbuf, int qlen);
};

#endif /* defined(__vrf_h__) */
