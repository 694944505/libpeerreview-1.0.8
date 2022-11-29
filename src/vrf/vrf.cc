#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

#include "peerreview/vrf.h"

#ifndef panic
#define panic(a...) do { fprintf(stderr, a); fprintf(stderr, "\n"); exit(1); } while (0)
#endif

#define USE_CRT_OPTIMIZATION
//#define CHECK_FOR_DUPLICATES   -- obsolete

static void bn2binFixed(BIGNUM *num, unsigned char *buf, int targetlen);

VRF::VRF(RSA *privkey, int i, int t, unsigned char *sP, unsigned char *nodeID, int idSizeBytes, bool enablePrecomp)
{
  this->i = i;
  this->t = t;
  this->privkey = privkey;
  this->keylenBytes = RSA_size(privkey);
  this->sP = BN_bin2bn(sP, keylenBytes, NULL);
  this->sPunhashed = BN_dup(this->sP);
  this->ctx = BN_CTX_new();
  this->td = BN_dup(privkey->d);
  this->sPprecomp = (unsigned char*) malloc(keylenBytes * t);
  this->havePrecomp = false;
  this->enablePrecomp = enablePrecomp;
  this->idSizeBytes = idSizeBytes;
  this->nodeID = (unsigned char*) malloc(idSizeBytes);
  memcpy(this->nodeID, nodeID, idSizeBytes);

  BN_CTX_init(ctx);
  BN_mod(this->sP, this->sP, privkey->n, ctx);
  
  BIGNUM *phiOfN = BN_dup(privkey->n);
  BN_sub(phiOfN, phiOfN, privkey->p);
  BN_sub(phiOfN, phiOfN, privkey->q);
  BN_add_word(phiOfN, 1);
  
  BIGNUM *tt = BN_new();
  BN_set_word(tt, t);
  BN_mod_exp(td, td, tt, phiOfN, ctx);
  BN_free(tt);

  if (!BN_is_word(privkey->e, 3))
    panic("Exponent must be three (use openssl genrsa -3)");
  if (t < 1)
    panic("Require t>=1");
    
  hashStarOutputBytes = 0;
  while (hashStarOutputBytes < keylenBytes)
    hashStarOutputBytes += SHA_DIGEST_LENGTH;
    
  hashStarOutputBytes += SHA_DIGEST_LENGTH;
  assert(hashStarOutputBytes >= (keylenBytes + SHA_DIGEST_LENGTH));
    
  m1 = BN_new();
  m2 = BN_new();
  qInv = BN_mod_inverse(NULL, privkey->q, privkey->p, ctx);

  /* Exponentiation with d (Chinese remainder theorem) */

  BN_sub(m1, privkey->p, BN_value_one());
  dP_d = BN_mod_inverse(NULL, privkey->e, m1, ctx);
  BN_sub(m1, privkey->q, BN_value_one());
  dQ_d = BN_mod_inverse(NULL, privkey->e, m1, ctx);
  
  assert(BN_cmp(privkey->p, privkey->q) > 0);

  /* Exponentiation with d^t (Chinese remainder theorem) */

  p1 = BN_mod_inverse(NULL, privkey->p, privkey->q, ctx);
  q1 = BN_mod_inverse(NULL, privkey->q, privkey->p, ctx);
  p2 = BN_new();
  BN_mod_mul(p2, p1, privkey->p, privkey->n, ctx);
  BN_mod_sub(p2, BN_value_one(), p2, privkey->n, ctx);
  q2 = BN_new();
  BN_mod_mul(q2, q1, privkey->q, privkey->n, ctx);
  BN_mod_sub(q2, BN_value_one(), q2, privkey->n, ctx);

  if (enablePrecomp)
    precompute();
}

VRF::~VRF()
{
  free(sP);
  free(nodeID);
  BN_CTX_free(ctx);
}

static void bn2binFixed(BIGNUM *num, unsigned char *buf, int targetlen)
{
  int len = BN_num_bytes(num);
  assert(len <= targetlen);
  BN_bn2bin(num, &buf[targetlen-len]);
  for (int j=0; j<(targetlen-len); j++) 
    buf[j] = 0;
}

void VRF::precompute()
{
  /* precompute values */

  BIGNUM *tmp = BN_new();
  BIGNUM *tmp2 = BN_new();
  BN_exp_mod_N(tmp, sP, td);

  for (int j=0; j<t; j++) {
    bn2binFixed(tmp, &sPprecomp[(t-(1+j))*keylenBytes], keylenBytes);
    BN_mod_mul(tmp2, tmp, tmp, privkey->n, ctx);
    BN_mod_mul(tmp, tmp, tmp2, privkey->n, ctx);
  }

  BN_free(tmp);
  BN_free(tmp2);
  havePrecomp = true;
}

void VRF::getCurrentSi(unsigned char *sPbuf)
{
  if ((i%t) == 0) 
    bn2binFixed(this->sPunhashed, sPbuf, keylenBytes);
  else
    bn2binFixed(this->sP, sPbuf, keylenBytes);
}

void hashStar(unsigned char *outbuf, int outsize, const unsigned char *inbuf, const int insize, const unsigned char *nodeID, int idSizeBytes, int i)
{
  unsigned char iteration = 0;
  int byteIndex = 0;
  int iMinusOne = htonl(i-1);
  
  while (true) {
    SHA_CTX c;
    SHA1_Init(&c);
    SHA1_Update(&c, nodeID, idSizeBytes);
    SHA1_Update(&c, (unsigned char*)&iMinusOne, sizeof(iMinusOne));
    SHA1_Update(&c, inbuf, insize);
    SHA1_Update(&c, &iteration, sizeof(iteration));
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1_Final(hash, &c);
    
    for (int k=0; k<SHA_DIGEST_LENGTH; k++) {
      outbuf[byteIndex++] = hash[k];
      if (byteIndex == outsize)
        return;
    }
    
    iteration ++;
  }
}

void hashSimple(unsigned char *outbuf, const unsigned char *inbuf, const int size, const unsigned char *nodeID, int idSizeBytes, int i)
{
  int iNB = htonl(i);

  SHA_CTX c;
  SHA1_Init(&c);
  SHA1_Update(&c, nodeID, idSizeBytes);
  SHA1_Update(&c, (unsigned char*)&iNB, sizeof(iNB));
  SHA1_Update(&c, inbuf, size);
  SHA1_Final(outbuf, &c);
}

void VRF::getQ(unsigned char *qbuf, int qbufLen, int t2)
{
  assert(qbufLen == (2+(t2+1)*keylenBytes));
  *(unsigned short*)qbuf = htons(keylenBytes*8);
  bn2binFixed(privkey->n, &qbuf[2], keylenBytes);

  for (int k=0; k<t2; k++) {
    unsigned char pk[idSizeBytes];
    for (int m=0; m<sizeof(pk); m++)
      pk[m] = 0xFF;
      
    unsigned char bufStar[hashStarOutputBytes];
    hashStar(bufStar, sizeof(bufStar), &qbuf[2], keylenBytes, pk, sizeof(pk), 1+k);

    BIGNUM *temp = BN_bin2bn(bufStar, sizeof(bufStar), NULL);
    BN_mod(temp, temp, privkey->n, ctx);
    BN_exp_mod_N(temp, temp, privkey->d);
    bn2binFixed(temp, &qbuf[2+(1+k)*keylenBytes], keylenBytes);
  }
}

void VRF::BN_exp_mod_N(BIGNUM *output, BIGNUM *base, BIGNUM *exp)
{
#ifdef USE_CRT_OPTIMIZATION
  BN_mod_exp(m1, base, exp, privkey->p, ctx);
  BN_mod_mul(m1, m1, p2, privkey->n, ctx);
  BN_mod_exp(m2, base, exp, privkey->q, ctx);
  BN_mod_mul(m2, m2, q2, privkey->n, ctx);
  BN_mod_add(output, m1, m2, privkey->n, ctx);
#else
  BN_mod_exp(output, base, exp, privkey->n, ctx);
#endif
}

void VRF::getRandom(unsigned char *buf, unsigned char *spBuf)
{
  if (!havePrecomp) {
    BN_exp_mod_N(sP, sP, privkey->d);
    bn2binFixed(sP, spBuf, keylenBytes);
  } else {
    int iModT = i%t;
    memcpy(spBuf, &sPprecomp[iModT*keylenBytes], keylenBytes);
    BN_bin2bn(spBuf, keylenBytes, sP);
  }

  i ++;
  
  if ((i%t) == 0) {
    BN_copy(sPunhashed, sP);
    unsigned char bufStar[hashStarOutputBytes];
    hashStar(bufStar, sizeof(bufStar), spBuf, keylenBytes, nodeID, idSizeBytes, i);
    BN_bin2bn(bufStar, sizeof(bufStar), sP);
    BN_mod(sP, sP, privkey->n, ctx);

    if (enablePrecomp)
      precompute();
  }
  
  hashSimple(buf, spBuf, keylenBytes, nodeID, idSizeBytes, i);
}

void VRF::writeN(unsigned char *buf, unsigned int *ptr, unsigned int maxlen)
{
  if ((maxlen-(*ptr))>=keylenBytes) {
    bn2binFixed(privkey->n, &buf[*ptr], keylenBytes);
    *ptr += keylenBytes;
  } else {
    *ptr = maxlen;
  }
}

VRFChecker::VRFChecker(BIGNUM *n, int keylenBytes, int i, int t, unsigned char *sP, unsigned char *nodeID, int idSizeBytes)
{
  this->i = i;
  this->t = t;
  this->n = BN_dup(n);
  this->keylenBytes = keylenBytes;
  this->sP = BN_bin2bn(sP, keylenBytes, NULL);
  this->s2 = BN_new();
  this->s3 = BN_new();
  this->ctx = BN_CTX_new();
  BN_CTX_init(ctx);
  flushDuplicateList();
  
  this->idSizeBytes = idSizeBytes;
  this->nodeID = (unsigned char*) malloc(idSizeBytes);
  memcpy(this->nodeID, nodeID, idSizeBytes);
  
  if ((keylenBytes%4) != 0)
    panic("Length of RSA modulus must be a multiple of 32 bits");
    
  this->keylenDwords = keylenBytes/4;
  this->duplicateListEntrySizeBytes = 4+keylenBytes;
  this->duplicateList = (unsigned char*) malloc(t*duplicateListEntrySizeBytes);
  this->numEntriesInDuplicateList = 0;
  
  hashStarOutputBytes = 0;
  while (hashStarOutputBytes < keylenBytes)
    hashStarOutputBytes += SHA_DIGEST_LENGTH;
    
  hashStarOutputBytes += SHA_DIGEST_LENGTH;
  assert(hashStarOutputBytes >= (keylenBytes + SHA_DIGEST_LENGTH));
  
  this->precompHashes = NULL;
  this->precompHashesAvailable = 0;
}

VRFChecker::~VRFChecker()
{
  BN_free(sP);
  BN_free(s2);
  BN_free(s3);
  BN_free(n);
  free(nodeID);
  BN_CTX_free(ctx);
}

void VRFChecker::writeN(unsigned char *buf, unsigned int *ptr, unsigned int maxlen)
{
  if ((maxlen-(*ptr))>=keylenBytes) {
    bn2binFixed(n, &buf[*ptr], keylenBytes);
    *ptr += keylenBytes;
  } else {
    *ptr = maxlen;
  }
}

void VRFChecker::getCurrentSi(unsigned char *sPbuf)
{
  bn2binFixed(sP, sPbuf, keylenBytes);
}

void VRFChecker::flushDuplicateList()
{
  for (int k=0; k<256; k++)
    duplicateListIndex[k] = -1;
  
  numEntriesInDuplicateList = 0;
}

bool VRFChecker::isDuplicate(unsigned char *sP)
{
  int p = duplicateListIndex[sP[0]];
  int *s2 = (int*) sP;

  while (p>=0) {
    assert((0<=p) && (p<t));
    int entryBegin = p*duplicateListEntrySizeBytes;
    p = *(int*)&duplicateList[entryBegin];
    
    bool duplicateFound = true;
    int *s1 = (int*)&duplicateList[entryBegin+4];
    for (int k=0; k<keylenDwords; k++) {
      if (s1[k] != s2[k]) {
        duplicateFound = false;
        break;
      }
    }
    
    if (duplicateFound)
      return true;
  }
  
  return false;
}

void VRFChecker::addToDuplicateList(unsigned char *sP)
{
  assert(numEntriesInDuplicateList < t);
  int entryIndex = numEntriesInDuplicateList ++;
  int entryBegin = entryIndex * duplicateListEntrySizeBytes;
  *(int*)&duplicateList[entryBegin] = duplicateListIndex[sP[0]];

  memcpy(&duplicateList[entryBegin+4], sP, keylenBytes);
  duplicateListIndex[sP[0]] = entryIndex;
}

bool VRFChecker::update(unsigned char *sP, unsigned char *hashOut)
{
  /* Calculate sP^3 and do a range check */

  BN_bin2bn(sP, keylenBytes, s3);
  if (BN_cmp(s3, n) >= 0) 
    return false;
  
  BN_mod_mul(s2, s3, s3, n, ctx);
  BN_mod_mul(s2, s2, s3, n, ctx);
  
  /* The result must match our 'expected' value */
  
  if (BN_cmp(s2, this->sP))
    return false;

  /* Also, this value must not have occurred earlier; otherwise we've found a cycle */
    
#ifdef CHECK_FOR_DUPLICATES    
  if (isDuplicate(sP))
    return false;
#endif
    
  /* Update our counter */
    
  i ++;
  
  /* Update our 'expected' value. When i=0 mod t, the next value is 
     H(sP), otherwise it is simply sP. */
  
  if ((i%t) == 0) { 
    unsigned char hashBytes[hashStarOutputBytes];
    hashStar(hashBytes, sizeof(hashBytes), sP, keylenBytes, nodeID, idSizeBytes, i);
    BN_bin2bn(hashBytes, sizeof(hashBytes), this->sP);
    BN_mod(this->sP, this->sP, n, ctx);

#ifdef CHECK_FOR_DUPLICATES
    bn2binFixed(this->sP, hashBytes, keylenBytes);
    flushDuplicateList();
    addToDuplicateList(hashBytes);
#endif
   } else {
#ifdef CHECK_FOR_DUPLICATES
    addToDuplicateList(sP);
#endif
    BN_copy(this->sP, s3);
  }

  if (hashOut)
    hashSimple(hashOut, sP, keylenBytes, nodeID, idSizeBytes, i);
  
  return true;
}

void VRF::resetAfterCoinToss(unsigned char *s, int sLen)
{
  this->i = 0;

  unsigned char bufStar[hashStarOutputBytes];
  hashStar(bufStar, sizeof(bufStar), s, sLen, nodeID, idSizeBytes, -1);

  BN_bin2bn(bufStar, sizeof(bufStar), sP);
  BN_mod(sP, sP, privkey->n, ctx);

  if (enablePrecomp)
    precompute();
}

void VRFChecker::resetAfterCoinToss(unsigned char *s, int sLen)
{
  this->i = 0;

  unsigned char bufStar[hashStarOutputBytes];
  hashStar(bufStar, sizeof(bufStar), s, sLen, nodeID, idSizeBytes, -1);

  BN_bin2bn(bufStar, sizeof(bufStar), sP);
  BN_mod(sP, sP, n, ctx);
  
  flushDuplicateList();
}

bool VRFChecker::precompGetNextHash(unsigned char *outbuf)
{
  if (precompHashesAvailable < 1)
    return false;
  
  i++;  
  BN_bin2bn(&precompHashes[(precompHashesAvailable-1) * keylenBytes], keylenBytes, sP);
  hashSimple(outbuf, &precompHashes[(precompHashesAvailable-1) * keylenBytes], keylenBytes, nodeID, idSizeBytes, i);
  precompHashesAvailable --;
}

bool VRFChecker::precompAddSi(unsigned char *sbuf)
{
  if (precompHashes)
    free(precompHashes);
    
  int maxDistance = 3*t;
  precompHashes = (unsigned char*) malloc(maxDistance * keylenBytes);
  precompHashesAvailable = 0;

  BIGNUM *expected = NULL;
  if (i>0) {
    if((i%t) == 0) {
      unsigned char sPbuf[keylenBytes];
      bn2binFixed(sP, sPbuf, sizeof(sPbuf));
      unsigned char hashBytes[hashStarOutputBytes];
      hashStar(hashBytes, sizeof(hashBytes), sPbuf, keylenBytes, nodeID, idSizeBytes, i);
      expected = BN_bin2bn(hashBytes, sizeof(hashBytes), NULL);
      BN_mod(expected, expected, n, ctx);
    } else {
      expected = BN_dup(sP);
    }
  } else {
    assert(i == 0);
    expected = BN_dup(sP);
  }

  BIGNUM *cur = BN_bin2bn(sbuf, keylenBytes, NULL);
  BIGNUM *tmp = BN_new();
  
  for (int m=0; m<maxDistance; m++) {
    assert(precompHashesAvailable < maxDistance);
    bn2binFixed(cur, &precompHashes[precompHashesAvailable * keylenBytes], keylenBytes);
    precompHashesAvailable ++;
  
    BN_mod_mul(tmp, cur, cur, n, ctx);
    BN_mod_mul(cur, tmp, cur, n, ctx);
    
    if (!BN_cmp(cur, expected)) {
      BN_free(cur);
      BN_free(tmp);
      BN_bin2bn(sbuf, keylenBytes, sP);
      return true;
    }
  }
  
  panic("NOT FOUND");
  return false;
}
