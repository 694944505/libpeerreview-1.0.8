#ifndef __peerreview_tools_h__
#define __peerreview_tools_h__

#include <arpa/inet.h>

class Basics {
public:
  static void writeLongLong(unsigned char *buf, unsigned int *ptr, long long value);
  static bool writeLongLongSafe(long long value, unsigned char *buf, unsigned int *ptr, unsigned int maxlen);
  static void writeShort(unsigned char *buf, unsigned int *ptr, unsigned short value);
  static bool writeInt(int value, unsigned char *buf, unsigned int *ptr, unsigned int maxlen);
  static bool writeUnsignedInt(unsigned int value, unsigned char *buf, unsigned int *ptr, unsigned int maxlen);
  static void writeByte(unsigned char *buf, unsigned int *ptr, unsigned char value);
  static bool writeByteSafe(unsigned char value, unsigned char *buf, unsigned int *ptr, unsigned int maxlen);
  static void writeBytes(unsigned char *buf, unsigned int *ptr, unsigned char *values, int numValues);
  static long long readLongLong(unsigned char *buf, unsigned int *ptr);
  static long long readLongLongSafe(unsigned char *buf, unsigned int *ptr, unsigned int maxlen, long long safeValue);
  static int readInt(unsigned char *buf, unsigned int *ptr, unsigned int maxlen);
  static int readIntSafe(unsigned char *buf, unsigned int *ptr, unsigned int maxlen, int safeValue);
  static unsigned int readUnsignedIntSafe(unsigned char *buf, unsigned int *ptr, unsigned int maxlen, unsigned int safeValue);
  static unsigned short readShort(unsigned char *buf, unsigned int *ptr);
  static unsigned char readByte(unsigned char *buf, unsigned int *ptr);
  static unsigned char readByteSafe(unsigned char *buf, unsigned int *ptr, unsigned int maxlen, unsigned char safeValue);
  static void readBytes(unsigned char *buf, unsigned int *ptr, unsigned char *valueBuf, int numValues);
  static char *ipdisp(in_addr_t iaddr, char *buf);
  static char *renderBytes(const unsigned char *bytes, int len, char *buf);
  static const char *renderStatus(const int status);
  
  Basics() {};
};

#endif /* defined(__peerreview_tools_h__) */
