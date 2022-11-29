#include <sys/time.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

#include "peerreview/vrf.h"

//#define USE_REAL_RANDOMNESS

// Generate key file with: openssl genrsa -3 -out node.pem 1024
// [openssl rsa -in node.pem -pubout -out node_pub.pem]

VerifiablePRNG::VerifiablePRNG(const char *keyname, PeerReview *peerreview, int t2)
{
  FILE *fp = fopen(keyname, "r");
  if (!fp)
    panic("Cannot open VRF key file '%s'", keyname);
    
  RSA *key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
  if (!key) {
    panic("Cannot read VRF key from '%s'", keyname);
  }

  fclose(fp);
  
  keylenBytes = RSA_size(key);
  
  unsigned char s0[keylenBytes];
  for (int i=0; i<keylenBytes; i++)
    s0[i] = (i>0) ? 1 : 0;
  
  unsigned char id[peerreview->getIdentifierSizeBytes() + 100];
  unsigned int idSizeBytes = 0;
  peerreview->getLocalHandle()->getIdentifier()->write(id, &idSizeBytes, sizeof(id));
  
  this->vrf = new VRF(key, 0, t1, s0, id, idSizeBytes, useBatching);
  this->peerreview = peerreview;
  this->t2 = t2;
}

void VerifiablePRNG::getRandomness(unsigned char *buf, int bytes)
{
#ifdef USE_REAL_RANDOMNESS
  assert((bytes%4)==0);
  struct drand48_data seed;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  srand48_r(tv.tv_usec ^ tv.tv_sec, &seed);
  for (int k=0; k<(bytes/4); k++) {
    long int result;
    lrand48_r(&seed, &result);
    *(unsigned int*)&buf[k*4] = (unsigned int)result;
  }
#else
  for (int i=0; i<bytes; i++)
    buf[i] = 0xAA;
#endif

  peerreview->logEventInternal(EVT_CHOOSE_RAND, buf, bytes);
}

void VerifiablePRNG::resetAfterCoinToss(unsigned char *s, int sLen)
{
  vrf->resetAfterCoinToss(s, sLen);
}

int VerifiablePRNG::getRandom(int range)
{
  unsigned char sp[4+keylenBytes];
  unsigned char randbuf[SHA_DIGEST_LENGTH];
  
  vrf->getRandom(randbuf, &sp[4]);
  *(unsigned int*)&sp[0] = htonl(vrf->getI());
  
//BIGNUM *b = BN_bin2bn(sp, sizeof(sp), NULL);  
//printf("s%d=%s\n", vrf->getI(), BN_bn2dec(b));
//BN_free(b);
  
  if (vrf->justHashed() || !useBatching)
    peerreview->logEventInternal(EVT_VRF, sp, sizeof(sp));
    
  return (range>1) ? ((*(unsigned int*)&randbuf)%range) : 0;
}

int VerifiablePRNG::storeCheckpoint(unsigned char *buffer, unsigned int maxlen)
{ 
  unsigned int ptr = 0;
  writeShort(buffer, &ptr, keylenBytes*8);
  writeShort(buffer, &ptr, vrf->getT());
  writeInt(vrf->getI(), buffer, &ptr, maxlen);
  vrf->writeN(buffer, &ptr, maxlen);
  vrf->getCurrentSi(&buffer[ptr]);
  ptr += keylenBytes;
  return ptr;
}

int VerifiablePRNG::storeExtInfo(unsigned char *buffer, unsigned int maxlen)
{
  assert((keylenBytes+4) <= maxlen);
  vrf->getCurrentSi(&buffer[4]);
  *(unsigned int*)&buffer[0] = htonl(vrf->getI());
  return keylenBytes+4;
}

bool VerifiablePRNG::loadCheckpoint(unsigned char *buffer, unsigned int *ptr, unsigned int maxlen)
{
  panic("VPRNG cannot load checkpoint");
}

void VerifiablePRNG::getQ(RandomWrapper *callback)
{
  // nBits:2, n:nBytes, qX:t2*nBytes
  unsigned char qbuf[2+(t2+1)*keylenBytes];
  vrf->getQ(qbuf, sizeof(qbuf), t2);
  peerreview->logEventInternal(EVT_CHOOSE_Q, qbuf, sizeof(qbuf));
  callback->notifyQ(qbuf, sizeof(qbuf));
}

void hashStar(unsigned char *outbuf, int outsize, const unsigned char *inbuf, const int insize, const unsigned char *nodeID, int idSizeBytes, int i);

bool VPRNG::validateQ(unsigned char *qbuf, int qbufLen, int t2, int idSizeBytes)
{
  int qkeyBytes = ntohs(*(unsigned short*)&qbuf[0])/8;
  if ((qkeyBytes < 16) || (qkeyBytes > 1024))
    return false;

  if (qbufLen != (2+(t2+1)*qkeyBytes))
    return false;
    
  int hashStarOutputBytes = 0;
  while (hashStarOutputBytes < qkeyBytes)
    hashStarOutputBytes += SHA_DIGEST_LENGTH;
  hashStarOutputBytes += SHA_DIGEST_LENGTH;
    
  BIGNUM *qn = BN_bin2bn(&qbuf[2], qkeyBytes, NULL);
  BN_CTX *ctx = BN_CTX_new();
  BN_CTX_init(ctx);
  unsigned char pk[idSizeBytes];
  for (int k=0; k<sizeof(pk); k++)
    pk[k] = 0xFF;
  
  bool ok = true;
  for (int k=0; k<t2; k++) {
    BIGNUM *mu = BN_bin2bn(&qbuf[2+(k+1)*qkeyBytes], qkeyBytes, NULL);
    BIGNUM *fnmu = BN_new();
    BN_mod_mul(fnmu, mu, mu, qn, ctx);
    BN_mod_mul(fnmu, fnmu, mu, qn, ctx);
    
    unsigned char bufStar[hashStarOutputBytes];
    hashStar(bufStar, sizeof(bufStar), &qbuf[2], qkeyBytes, pk, sizeof(pk), 1+k);
    BIGNUM *hmun = BN_bin2bn(bufStar, sizeof(bufStar), NULL);
    BN_mod(hmun, hmun, qn, ctx);

    if (BN_cmp(hmun, fnmu) != 0)
      ok = false;
      
    BN_free(mu);
    BN_free(fnmu);
    BN_free(hmun);
  }

  BN_free(qn);
  BN_CTX_free(ctx);

  return ok;
}

VerifiablePRNGChecker::VerifiablePRNGChecker(ReplayWrapper *verifier, bool useBatching)
{
  this->checker = NULL;
  this->keylenBytes = 0;
  this->verifier = verifier;
  this->idSizeBytes = verifier->getIdentifierSizeBytes();
  assert(idSizeBytes > 0);
  this->nodeID = (unsigned char*) malloc(idSizeBytes + 100);
  this->qbuf = NULL;
  this->qlen = -1;
  this->useBatching = useBatching;
  this->extInfoUsed = false;
  
  unsigned int ptr = 0;
  verifier->getLocalHandle()->getIdentifier()->write(nodeID, &ptr, idSizeBytes + 10);
  assert(ptr == idSizeBytes);
}

VerifiablePRNGChecker::~VerifiablePRNGChecker()
{
  free(nodeID);
  if (checker)
    delete checker;
}

void VerifiablePRNGChecker::resetAfterCoinToss(unsigned char *s, int sLen)
{
  checker->resetAfterCoinToss(s, sLen);
}

void VerifiablePRNGChecker::getQ(RandomWrapper *callback)
{
  unsigned char evtType = 0xFF;
  int evtSize = -1;
  bool evtIsHashed = true;
  unsigned char *evtBuf = NULL;

  if (verifier->statNextEvent(&evtType, &evtSize, NULL, &evtIsHashed, &evtBuf)) {
    if ((evtType == EVT_CHOOSE_Q) && !evtIsHashed) {
      if (validateQ(evtBuf, evtSize, T2, verifier->getIdentifierSizeBytes())) {
        unsigned char *qbuf = (unsigned char*) malloc(evtSize);
        memcpy(qbuf, evtBuf, evtSize);
        verifier->fetchNextEvent();
        callback->notifyQ(qbuf, evtSize);      
        free(qbuf);
        return;
      } else {
        printf("Cannot validate Q\n");
      }
    } else {
      printf("Expected EVT_CHOOSE_Q, but found type %d\n", evtType);
    }
  } else {
    printf("Cannot stat next event\n");
  }

  verifier->markFaulty();
}

void VerifiablePRNGChecker::getRandomness(unsigned char *buf, int bytes)
{
  unsigned char evtType = 0xFF;
  int evtSize = -1;
  bool evtIsHashed = true;
  unsigned char *evtBuf = NULL;

  if (verifier->statNextEvent(&evtType, &evtSize, NULL, &evtIsHashed, &evtBuf)) {
    if ((evtType == EVT_CHOOSE_RAND) && !evtIsHashed && (evtSize==bytes)) {
      memcpy(buf, evtBuf, bytes);
      verifier->fetchNextEvent();
      return;
    } else {
      printf("Expected EVT_CHOOSE_RAND\n");
    }
  } else {
    printf("Cannot stat next event\n");
  }

  verifier->markFaulty();
}

void VerifiablePRNGChecker::replayEvent(unsigned char type, unsigned char *entry, int entrySize)
{
  if (type == EVT_CHOOSE_Q) {
#warning need to find a more intelligent solution here
    if (!validateQ(entry, entrySize, T2, verifier->getIdentifierSizeBytes()))
      panic("Incorrect Q chosen");
      
    if (qbuf) 
      free(qbuf);
      
    qbuf = (unsigned char*) malloc(entrySize);
    memcpy(qbuf, entry, entrySize);
    qlen = entrySize;
    return;
  }
  
  panic("VPRNGC::replayEvent(%d)", type);
}

int VerifiablePRNGChecker::getRandom(int range)
{
  assert(checker && keylenBytes);

  if (!useBatching) {
    unsigned char evtType = 0xFF;
    int evtSize = -1;
    bool evtIsHashed = true;
    unsigned char *evtBuf = NULL;

    if (verifier->statNextEvent(&evtType, &evtSize, NULL, &evtIsHashed, &evtBuf)) {
      if ((evtType == EVT_VRF) && !evtIsHashed && (evtSize == (keylenBytes+4))) {
        unsigned char hash[SHA_DIGEST_LENGTH];
        if (checker->update(&evtBuf[4], hash)) {
          verifier->fetchNextEvent();
          return (range>1) ? ((*(unsigned int*)&hash)%range) : 0;
        } else {
          printf("*** checker cannot validate\n");
        }
      } else {
        printf("*** wrong event\n");
      }
    } else {
      printf("*** cannot stat next event\n");
    }
  } else {
    unsigned char hash[SHA_DIGEST_LENGTH];
    if (checker->precompGetNextHash(hash)) 
      return (range>1) ? ((*(unsigned int*)&hash)%range) : 0;

    /* We don't have anything precomputed any more; let's find the next EVT_VRF */
  
    long long seq = -1;
    if (verifier->statNextEvent(NULL, NULL, &seq, NULL, NULL)) {
      unsigned char sbuf[keylenBytes + 4 + 1];
      int size = verifier->getNextEntryOfType(EVT_VRF, sbuf, keylenBytes+4, true);
      verifier->logText("VPRNGC", 3, "Get EVT_VRF #1: size=%d i=%d", size, (size>=4) ? ntohl(*(unsigned int*)&sbuf) : 0);

      if ((size == (keylenBytes+4)) && (ntohl(*(unsigned int*)&sbuf) <= checker->getI())) {
        size = verifier->getNextEntryOfType(EVT_VRF, sbuf, keylenBytes+4, false);
        verifier->logText("VPRNGC", 3, "Get EVT_VRF #2: size=%d i=%d", size, (size>=4) ? ntohl(*(unsigned int*)&sbuf) : 0);
      }

      if ((size < 0) && !extInfoUsed) {
        extInfoUsed = true;
        size = verifier->getExtInfo(sbuf, sizeof(sbuf));
        verifier->logText("VPRNGC", 3, "Get EVT_VRF #3: size=%d i=%d", size, (size>=4) ? ntohl(*(unsigned int*)&sbuf) : 0);
      }
      
      verifier->logText("VPRNGC", 3, "Got EVT_VRF i=%d (checker->i=%d)", ntohl(*(unsigned int*)&sbuf[0]), checker->getI());
      
      if (size == (keylenBytes+4)) {
        if (checker->precompAddSi(&sbuf[4])) {
          if (checker->precompGetNextHash(hash))
            return (range>1) ? ((*(unsigned int*)&hash)%range) : 0;
            
          panic("AddSi did not have any effect?!?");
        }
    
        panic("f^-{1..t}(si) does not match expected value; cannot precompute -- node is misbehaving!");
      }
      
      panic("size is not keylen bytes plus four (%d)", size);
    }
  }
  
panic("VPRNGC::getRandom() found a fault");

  verifier->markFaulty();
  return 0;
}

int VerifiablePRNGChecker::storeCheckpoint(unsigned char *buffer, unsigned int maxlen)
{
  unsigned int ptr = 0;
  writeShort(buffer, &ptr, keylenBytes*8);
  writeShort(buffer, &ptr, checker->getT());
  writeInt(checker->getI(), buffer, &ptr, maxlen);
  checker->writeN(buffer, &ptr, maxlen);
  checker->getCurrentSi(&buffer[ptr]);

  ptr += keylenBytes;
  return ptr;
}

bool VerifiablePRNGChecker::loadCheckpoint(unsigned char *buffer, unsigned int *ptr, unsigned int maxlen)
{
  if (checker)
    delete checker;

  this->keylenBytes = readShort(buffer, ptr) / 8;
  int t = readShort(buffer, ptr);
  int i = readIntSafe(buffer, ptr, maxlen, 0);
verifier->logText("VPRNGC", 3, "LC i=%d, t=%d", i, t);  

  unsigned char nBytes[keylenBytes];
  readBytes(buffer, ptr, nBytes, sizeof(nBytes));
  BIGNUM *n = BN_bin2bn(nBytes, sizeof(nBytes), NULL);
  
  unsigned char sPbuf[keylenBytes];
  readBytes(buffer, ptr, sPbuf, sizeof(sPbuf));
  
  checker = new VRFChecker(n, keylenBytes, i, t, sPbuf, nodeID, idSizeBytes);
}
