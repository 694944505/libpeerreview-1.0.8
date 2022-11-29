#ifndef __peerreview_transport_h__
#define __peerreview_transport_h__

#include <netinet/in.h>

#define CTR_MSG_TOTAL 0
#define CTR_BYTES_TOTAL 1
#define CTR_MSG_APP 2
#define CTR_BYTES_APP 3
#define CTR_BYTES_MSG0 4
//...
#define CTR_BYTES_MSG24 28

class TimerCallback {
public:
  TimerCallback() {};
  virtual ~TimerCallback() {};
  virtual void timerExpired(int timerID) = 0;
};

class TransportCallback {
public:
  TransportCallback() {};
  virtual ~TransportCallback() {};
  virtual void recv(in_addr_t source, bool datagram, unsigned char *message, int msglen) = 0;
  virtual void sendComplete(long long id) = 0;
};  

class Transport {
public:
  Transport() {};
  virtual ~Transport() {};
  virtual long long send(in_addr_t target, bool datagram, unsigned char *message, int msglen) = 0;
  virtual int getMSS() = 0;
  virtual void scheduleTimer(TimerCallback *callback, int timerID, long long when) = 0;
  virtual void cancelTimer(TimerCallback *callback, int timerID) = 0;
  virtual void logText(const char *subsystem, int level, const char *format, ...) = 0;
  virtual long long getTime() = 0;
  virtual void setCallback(TransportCallback *callback) = 0;
  virtual in_addr_t getLocalIP() = 0;
  virtual void incrementCounter(int code, int value) = 0;
};

#endif /* defined(__peerreview_transport_h__) */
