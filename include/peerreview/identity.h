#ifndef __peerreview_identity_h__
#define __peerreview_identity_h__

#include <netinet/in.h>
#include <assert.h>
#include <string.h>

#include "transport.h"

#define MAX_ID_SIZE 100
#define MAX_HANDLE_SIZE 200

class Identifier {
public:
  Identifier() {};
  virtual ~Identifier() {};
  virtual bool equals(Identifier *other) = 0;
  virtual Identifier *clone() = 0;
  virtual char *render(char *buf) = 0;
  virtual bool write(unsigned char *buf, unsigned int *ptr, unsigned int maxlen) = 0;
  virtual int getSizeBytes() = 0;
  virtual bool isBiggerThan(Identifier *other) = 0;
  virtual bool isCloserThan(Identifier *basis, Identifier *other) = 0;
  virtual bool isBetween(Identifier *from, Identifier *to) = 0;
  virtual int getDigit(int digitNr, int bitsPerDigit) = 0;
  virtual int commonPrefixLength(Identifier *other, int bitsPerDigit) = 0;
  virtual Identifier *makeIdHalfwayTo(Identifier *other) = 0;
  virtual int operator %(int modulo) { assert(false); };
  virtual int size() = 0;
  bool operator ==(Identifier *other) { assert(false); };
};

class NodeHandle {
public:
  NodeHandle() {};
  virtual ~NodeHandle() {};
  virtual Identifier *getIdentifier() = 0;
  virtual NodeHandle *clone() = 0;
  virtual char *render(char *buf) = 0;
  virtual bool write(unsigned char *buf, unsigned int *ptr, unsigned int maxlen) = 0;
  virtual bool equals(NodeHandle *other) = 0;
  virtual int size() = 0;
};

class IdentityTransportCallback {
public:
  IdentityTransportCallback() {};
  virtual ~IdentityTransportCallback() {};
  virtual void receive(NodeHandle *source, bool datagram, unsigned char *msg, int msglen) = 0;
  virtual void sendComplete(long long id) = 0;
  virtual void statusChange(Identifier *id, int newStatus) = 0;
  virtual void notifyCertificateAvailable(Identifier *id) = 0;
};

class HashProvider {
public:
  HashProvider() {};
  virtual ~HashProvider() {};
  virtual int getHashSizeBytes() = 0;
  virtual void hash(unsigned char *outbuf, const unsigned char *inbuf1, const int insize1, const unsigned char *inbuf2 = NULL, const int insize2 = 0, const unsigned char *inbuf3 = NULL, const int insize3 = 0, const unsigned char *inbuf4 = NULL, const int insize4 = 0) = 0;
};

class IdentityTransport : public HashProvider {
public:
  const static int NO_CERTIFICATE = -1;
  const static int SIGNATURE_BAD = 0;
  const static int SIGNATURE_OK = 1;

  IdentityTransport() : HashProvider() {};
  virtual ~IdentityTransport() {};

  /* Timer functions */
  virtual long long getTime() = 0;
  virtual void scheduleTimer(TimerCallback *callback, int timerID, long long when) = 0;
  virtual void cancelTimer(TimerCallback *callback, int timerID) = 0;

  /* Crypto functions */
  virtual bool haveCertificate(Identifier *id) = 0;
  virtual void requestCertificate(NodeHandle *source, Identifier *id) = 0;
  virtual void sign(const unsigned char *data, int dataLength, unsigned char *signatureBuffer) = 0;
  virtual int verify(Identifier *id, const unsigned char *data, const int dataLength, unsigned char *signature) = 0;
  virtual int getSignatureSizeBytes() = 0;

  /* Communication functions */
  virtual long long send(NodeHandle *target, bool datagram, unsigned char *message, int msglen, int relevantlen = -1) = 0;
  virtual int getMSS() = 0;

  /* Identifier/handle functions */
  virtual NodeHandle *getLocalHandle() = 0;
  virtual int getIdentifierSizeBytes() = 0;
  virtual Identifier *readIdentifier(unsigned char *buf, unsigned int *pos, unsigned int maxlen) = 0;
  virtual Identifier *readIdentifierFromString(const char *str) = 0;
  virtual NodeHandle *readNodeHandle(unsigned char *buf, unsigned int *pos, unsigned int maxlen) = 0;
  virtual NodeHandle *readNodeHandleFromString(const char *str) = 0;

  /* Logging and profiling */
  virtual void logEvent(char type, const void *entry, int size) = 0;
  virtual void logText(const char *subsystem, int level, const char *format, ...) = 0;
  virtual void incrementCounter(int code, int value) = 0;

  /* Miscellaneous */
  virtual int getRandom(int range) = 0;
  virtual void investigate(NodeHandle *target, long long since) = 0;
};

#endif /* defined(__peerreview_identity_h__) */
