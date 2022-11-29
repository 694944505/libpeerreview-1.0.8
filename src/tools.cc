#include <openssl/pem.h>

#include "peerreview.h"

char *Basics::renderBytes(const unsigned char *bytes, int len, char *buf)
{
  if (len < 1) {
    buf[0] = 0;
  } else {
    sprintf(buf, "%02X", bytes[0]);
    for (int i=1; i<len; i++)
      sprintf(&buf[3*i-1], " %02X", bytes[i]);
  }

  return buf;
}

const char *Basics::renderStatus(const int status)
{
  switch (status) {
    case STATUS_TRUSTED:
      return "TRUSTED";
    case STATUS_SUSPECTED:
      return "SUSPECTED";
    case STATUS_EXPOSED:
      return "EXPOSED";
    default:
      return "UNKNOWN";
  }
}

void Basics::writeLongLong(unsigned char *buf, unsigned int *ptr, long long value)
{
  *(long long*)&buf[*ptr] = value;
  (*ptr) += sizeof(long long);
}

bool Basics::writeLongLongSafe(long long value, unsigned char *buf, unsigned int *ptr, unsigned int maxlen)
{
  if (((*ptr)+sizeof(long long)) <= maxlen)
    *(long long*)&buf[*ptr] = value;
    
  (*ptr) += sizeof(long long);
  return ((*ptr)<=maxlen);
}

void Basics::writeByte(unsigned char *buf, unsigned int *ptr, unsigned char value)
{
  *(unsigned char*)&buf[*ptr] = value;
  (*ptr) += sizeof(unsigned char);
}

bool Basics::writeUnsignedInt(unsigned int value, unsigned char *buf, unsigned int *ptr, unsigned int maxlen)
{
  if (((*ptr)+sizeof(unsigned int)) <= maxlen)
    *(unsigned int*)&buf[*ptr] = value;
    
  (*ptr) += sizeof(unsigned int);
  return ((*ptr)<=maxlen);
}

bool Basics::writeByteSafe(unsigned char value, unsigned char *buf, unsigned int *ptr, unsigned int maxlen)
{
  if (((*ptr)+sizeof(unsigned char)) <= maxlen)
    buf[*ptr] = value;
    
  (*ptr) += sizeof(unsigned char);
  return ((*ptr)<=maxlen);
}

void Basics::writeShort(unsigned char *buf, unsigned int *ptr, unsigned short value)
{
  *(unsigned short*)&buf[*ptr] = value;
  (*ptr) += sizeof(unsigned short);
}

bool Basics::writeInt(int value, unsigned char *buf, unsigned int *ptr, unsigned int maxlen)
{
  if (((*ptr)+sizeof(int)) <= maxlen)
    *(int*)&buf[*ptr] = value;
    
  (*ptr) += sizeof(int);
  return ((*ptr)<=maxlen);
}

void Basics::writeBytes(unsigned char *buf, unsigned int *ptr, unsigned char *values, int numValues)
{
  if (numValues > 0) {
    memcpy(&buf[*ptr], values, numValues);
    (*ptr) += numValues;
  }
}

char *Basics::ipdisp(in_addr_t iaddr, char *buf)
{
  sprintf(buf, "%d.%d.%d.%d", 
    (int)(iaddr&0xFF), (int)((iaddr>>8)&0xFF), 
    (int)((iaddr>>16)&0xFF), (int)(iaddr>>24)
  );
  
  return buf;
}

unsigned int Basics::readUnsignedIntSafe(unsigned char *buf, unsigned int *ptr, unsigned int maxlen, unsigned int safeValue)
{
  unsigned int value = safeValue;
  if (((*ptr)+sizeof(unsigned int))<=maxlen)
    value = *(unsigned int*)&buf[*ptr];
    
  (*ptr) += sizeof(unsigned int);
  return value;
}

long long Basics::readLongLong(unsigned char *buf, unsigned int *ptr)
{
  long long value = *(long long*)&buf[*ptr];
  (*ptr) += sizeof(long long);
  return value;
}

unsigned char Basics::readByte(unsigned char *buf, unsigned int *ptr)
{
  unsigned char value = *(unsigned char*)&buf[*ptr];
  (*ptr) += sizeof(unsigned char);
  return value;
}

unsigned char Basics::readByteSafe(unsigned char *buf, unsigned int *ptr, unsigned int maxlen, unsigned char safeValue)
{
  unsigned char result = safeValue;
  if (((*ptr)+sizeof(unsigned char))<=maxlen)
    result = buf[*ptr];
  
  (*ptr) += sizeof(unsigned char);
  return result;
}

unsigned short Basics::readShort(unsigned char *buf, unsigned int *ptr)
{
  unsigned short value = *(unsigned short*)&buf[*ptr];
  (*ptr) += sizeof(unsigned short);
  return value;
}

int Basics::readInt(unsigned char *buf, unsigned int *ptr, unsigned int maxlen)
{
  int value = 0;
  if (((*ptr)+sizeof(int))<=maxlen)
    value = *(int*)&buf[*ptr];
    
  (*ptr) += sizeof(int);
  return value;
}

int Basics::readIntSafe(unsigned char *buf, unsigned int *ptr, unsigned int maxlen, int safeValue)
{
  int value = safeValue;
  if (((*ptr)+sizeof(int))<=maxlen)
    value = *(int*)&buf[*ptr];
    
  (*ptr) += sizeof(int);
  return value;
}

long long Basics::readLongLongSafe(unsigned char *buf, unsigned int *ptr, unsigned int maxlen, long long safeValue)
{
  long long value = safeValue;
  if (((*ptr)+sizeof(long long))<=maxlen)
    value = *(long long*)&buf[*ptr];
    
  (*ptr) += sizeof(long long);
  return value;
}

void Basics::readBytes(unsigned char *buf, unsigned int *ptr, unsigned char *valueBuf, int numValues)
{
  if (numValues > 0) {
    memcpy(valueBuf, &buf[*ptr], numValues);
    (*ptr) += numValues;
  }
}
