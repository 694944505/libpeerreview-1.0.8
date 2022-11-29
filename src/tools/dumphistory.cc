#include <stdlib.h>
#include <ctype.h>
#include <peerreview.h>
#include <openssl/sha.h>

class SHA1HashProvider : public HashProvider {
public:
  SHA1HashProvider() : HashProvider() {};
  virtual ~SHA1HashProvider() {};
  virtual int getHashSizeBytes() { return 20; };
  virtual void hash(unsigned char *outbuf, const unsigned char *inbuf1, const int insize1, const unsigned char *inbuf2 = NULL, const int insize2 = 0, const unsigned char *inbuf3 = NULL, const int insize3 = 0, const unsigned char *inbuf4 = NULL, const int insize4 = 0);
};

void SHA1HashProvider::hash(unsigned char *outbuf, const unsigned char *inbuf1, const int insize1, const unsigned char *inbuf2, const int insize2, const unsigned char *inbuf3, const int insize3, const unsigned char *inbuf4, const int insize4)
{
  SHA_CTX c;
  SHA1_Init(&c);
  SHA1_Update(&c, inbuf1, insize1);
  if (inbuf2)
    SHA1_Update(&c, inbuf2, insize2);
  if (inbuf3)
    SHA1_Update(&c, inbuf3, insize3);
  if (inbuf4)
    SHA1_Update(&c, inbuf4, insize4);
  SHA1_Final((unsigned char*)outbuf, &c);
}  

void dump(FILE *stream, const unsigned char *payload, int len)
{
  int i, off = 0;
  while (off < len) {
    fprintf(stream, "%04X   ", off);
    for (i=0; i<16; i++) {
      if ((i+off) < len)
        fprintf(stream, "%02X ", payload[i+off]);
      else
        fprintf(stream, "   ");
    }
    
    fprintf(stream, "   ");
    
    for (i=0; i<16; i++) {
      if ((i+off) < len)
        fprintf(stream, "%c", isprint(payload[i+off]) ? payload[i+off] : '.');
    }
    
    off += 16;
    fprintf(stream, "\n");
  }
}

char *renderBytes(const unsigned char *bytes, int len, char *buf)
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

int main(int argc, char *argv[])
{ 
  if (argc != 2)
    panic("Syntax: dumphistory <historyname>");
    
  SHA1HashProvider *shaprov = new SHA1HashProvider();
  SecureHistory *history = SecureHistory::open(argv[1], "r", shaprov);
  if (!history)
    panic("Cannot open history: %s", argv[1]);
  
  int hashSizeBytes = shaprov->getHashSizeBytes();
  char buf1[256];
  int idx = 0;
  
  long long seq;
  unsigned char type;
  int sizeBytes;
  unsigned char contentHash[hashSizeBytes];
  unsigned char nodeHash[hashSizeBytes];
  
  while (history->statEntry(idx, &seq, &type, &sizeBytes, contentHash, nodeHash)) {
    printf("=== #%lld (type %d, %d bytes)\n", seq, type, sizeBytes);
    printf("Content hash: [%s]\n", renderBytes(contentHash, hashSizeBytes, buf1));
    printf("Node hash:    [%s]\n", renderBytes(nodeHash, hashSizeBytes, buf1));
    
    if (sizeBytes > 0) {
      unsigned char *buffer = (unsigned char*) malloc(sizeBytes + 1);
      int ret = history->getEntry(idx, buffer, sizeBytes + 1);
      if (ret != sizeBytes)
        panic("Cannot read entry #%d", idx);
      
      printf("\n");
      dump(stdout, buffer, sizeBytes);
      free(buffer);
    }
    
    printf("\n");
    idx ++;
  }
  
  delete history;
  
  return 0;
}
