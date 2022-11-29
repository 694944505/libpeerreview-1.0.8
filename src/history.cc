#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <openssl/sha.h>

#include "peerreview.h"

SecureHistory::SecureHistory(FILE *indexFile, FILE *dataFile, bool readonly, HashProvider *hashprov)
{
  assert(indexFile && dataFile);
  assert(hashprov->getHashSizeBytes() == HASH_LENGTH);
  
  struct indexEntry firstEntry;
  fseek(indexFile, 0, SEEK_SET);
  fread(&firstEntry, sizeof(firstEntry), 1, indexFile);
  baseSeq = firstEntry.seq;
  fseek(indexFile, -sizeof(topEntry), SEEK_END);
  fread(&topEntry, sizeof(topEntry), 1, indexFile);
  numEntries = ftell(indexFile) / sizeof(topEntry);
  fseek(dataFile, 0, SEEK_END);
  nextSeq = topEntry.seq + 1;
  pointerAtEnd = true;
  
  this->indexFile = indexFile;
  this->dataFile = dataFile;
  this->readonly = readonly;
  this->hashprov = hashprov;
}

/* Creates a new history (aka log). Histories are stored as two files: The 'index' file has a 
   fixed-size record for each entry, which contains the sequence number, content and node
   hashes, as well as an index into the data file. The 'data' file just contains the raw
   bytes for each entry. Note that the caller must specify the node hash and the sequence
   number of the first log entry, which forms the base of the hash chain. */

SecureHistory *SecureHistory::create(const char *name, long long baseSeq, const unsigned char *baseHash, HashProvider *hashprov)
{
  FILE *indexFile, *dataFile;
  
  if (name) {
    char indexName[200], dataName[200];

    sprintf(indexName, "%s.index", name);
    sprintf(dataName, "%s.data", name);

    indexFile = fopen(indexName, "w+");
    if (!indexFile) 
      return NULL;

    dataFile = fopen64(dataName, "w+");
    if (!dataFile) {
      fclose(indexFile);
      unlink(indexName);
      return NULL;
    }
  } else {
    indexFile = tmpfile();
    dataFile = tmpfile();
  }
  
  /* Write the initial record to the index file. The data file remains empty. */
  
  struct indexEntry entry;
  entry.seq = baseSeq;
  entry.fileIndex = 0;
  entry.type = 0;
  entry.sizeInFile = -1;
  memset(&entry.contentHash, 0, sizeof(entry.contentHash));
  memcpy(&entry.nodeHash, baseHash, HASH_LENGTH);

  fwrite(&entry, sizeof(entry), 1, indexFile);

  return new SecureHistory(indexFile, dataFile, false, hashprov);
}

/* Opens an existing history (aka log). The 'mode' can either be 'r' (read-only) or
   'w' (read/write). */

SecureHistory *SecureHistory::open(const char *name, const char *mode, HashProvider *hashprov)
{
  char namebuf[200];
  bool readonly = false;
  
  if (!strcmp(mode, "r"))
    readonly = true;
  else if (strcmp(mode, "w"))
    return NULL;
  
  sprintf(namebuf, "%s.index", name);
  FILE *indexFile = fopen(namebuf, readonly ? "r" : "r+");
  if (!indexFile) 
    return NULL;
    
  sprintf(namebuf, "%s.data", name);
  FILE *dataFile = fopen64(namebuf, readonly ? "r" : "r+");
  if (!dataFile) {
    fclose(indexFile);
    return NULL;
  }
  
  return new SecureHistory(indexFile, dataFile, readonly, hashprov);
}

/* Returns the node hash and the sequence number of the most recent log entry */

void SecureHistory::getTopLevelEntry(void *nodeHash, long long *seq)
{
  assert(indexFile && dataFile);
  
  if (nodeHash) 
    memcpy(nodeHash, &topEntry.nodeHash, sizeof(topEntry.nodeHash));
  
  if (seq)
    *seq = topEntry.seq;
}

/* Appends a new entry to the log. If 'storeFullEntry' is false, only the hash of the
   entry is stored. If 'header' is not NULL, the log entry is formed by concatenating
   'header' and 'entry'; otherwise, only 'entry' is used. */
   
void SecureHistory::appendEntry(char type, bool storeFullEntry, const void *entry, int size, const void *header, int headerSize)
{
  assert(indexFile && dataFile);
  
  /* Sanity check (for debugging) */
  
  if (readonly)
    panic("Cannot append entry to readonly history");
  
  /* As an optimization, the log 'remembers' the last entry that was read or written.
     However, this means that the file pointers do not necessarily point to the 
     end of the index and data files. If they don't, we must reset them. */
  
  if (!pointerAtEnd) {
    fseek(indexFile, 0, SEEK_END);
    fseek(dataFile, 0, SEEK_END);
    pointerAtEnd = true;
  }
  
  struct indexEntry e;
  e.seq = nextSeq++;
  
  /* Calculate the content hash */
  
  if (header)
    hashprov->hash(e.contentHash, (const unsigned char*) header, headerSize, (const unsigned char*) entry, size);
  else
    hashprov->hash(e.contentHash, (const unsigned char*) entry, size);

  /* Calculate the node hash. Note that this also covers the sequence number and
     the entry type. */

  hashprov->hash(e.nodeHash, (const unsigned char*)&e.seq, sizeof(e.seq), (const unsigned char*)&type, sizeof(type), topEntry.nodeHash, sizeof(topEntry.nodeHash), e.contentHash, sizeof(e.contentHash));

  /* Write the entry to the data file */

  e.type = type;
  e.fileIndex = ftell(dataFile);
  if (storeFullEntry) {
    e.sizeInFile = size;
    if (header) {
      fwrite(header, headerSize, 1, dataFile);
      e.sizeInFile += headerSize;
    }
    fwrite(entry, size, 1, dataFile);
  } else {
    e.sizeInFile = -1;
  }
  
  /* Optionally, the index file entries can be padded to a multiple of 16 bytes,
     so they're easier to read in a hexdump. */
  
#ifdef USE_PADDING
  for (int i=0; i<sizeof(e.padding); i++)
    e.padding[i] = 0xEE;
#endif

  /* Write the entry to the index file */

  topEntry = e;
  fwrite(&topEntry, sizeof(topEntry), 1, indexFile);
  numEntries ++;
}

/* Append a new hashed entry to the log. Unlike appendEntry(), this only keeps
   the content type, sequence number, and hash values. No entry is made in
   the data file. */

void SecureHistory::appendHash(char type, const unsigned char *hash)
{
  assert(indexFile && dataFile);
  
  if (readonly)
    panic("Cannot append hash to readonly history");
  
  /* Reset the file pointers, if necessary */
  
  if (!pointerAtEnd) {
    fseek(indexFile, 0, SEEK_END);
    fseek(dataFile, 0, SEEK_END);
    pointerAtEnd = true;
  }
  
  struct indexEntry e;
  e.seq = nextSeq++;
  memcpy(e.contentHash, hash, hashprov->getHashSizeBytes());

  /* Calculate the node hash (the content hash is already given) */

  hashprov->hash(e.nodeHash, (const unsigned char*)&e.seq, sizeof(e.seq), (const unsigned char*)&type, sizeof(type), topEntry.nodeHash, sizeof(topEntry.nodeHash), e.contentHash, sizeof(e.contentHash));
  e.type = type;
  e.fileIndex = -1;
  e.sizeInFile = -1;
#ifdef USE_PADDING
  for (int i=0; i<sizeof(e.padding); i++)
    e.padding[i] = 0xEE;
#endif

  /* Write an entry to the index file */

  topEntry = e;
  fwrite(&topEntry, sizeof(topEntry), 1, indexFile);
  numEntries ++;
}

/* Sets the next sequence number to be used. The PeerReview library typically
   uses the format <xxxx...xxxyyyy>, where X is a timestamp in microseconds
   and Y a sequence number. The sequence numbers need not be contigious
   (and usually aren't) */

bool SecureHistory::setNextSeq(long long nextSeq) 
{
  if (nextSeq < this->nextSeq)
    return false;
    
  this->nextSeq = nextSeq;
  return true;
}

SecureHistory::~SecureHistory()
{
  assert(indexFile && dataFile);
  fclose(indexFile);
  fclose(dataFile);
}

/* Look up a given sequence number, or the first sequence number that is 
   not lower than a given number. The return value is the number of
   the corresponding record in the index file, or -1 if no matching
   record was found. */

int SecureHistory::findSeqOrHigher(long long seq, bool allowHigher)
{
  assert(indexFile && dataFile);

  /* Some special cases where we know the answer without looking */

  if (seq > topEntry.seq)
    return -1;
  
  if (allowHigher && (seq < baseSeq))
    return 0;
      
  if (seq == topEntry.seq)
    return numEntries - 1;
  
  /* Otherwise, do a binary search */
  
  pointerAtEnd = false;
  
  fseek(indexFile, 0, SEEK_END);
  int rbegin = 1;
  int rend = (ftell(indexFile) / sizeof(struct indexEntry)) - 1;
  
  while (rbegin != rend) {
    assert(rend >= rbegin);

    int pivot = (rbegin+rend)/2;
    fseek(indexFile, pivot*sizeof(struct indexEntry), SEEK_SET);

    struct indexEntry ie;
    fread(&ie, sizeof(ie), 1, indexFile);
    if (ie.seq >= seq)
      rend = pivot;
    else 
      rbegin = pivot+1;
  }

  if (allowHigher)
    return rbegin;

  struct indexEntry ie;
  fseek(indexFile, rbegin * sizeof(struct indexEntry), SEEK_SET);
  fread(&ie, sizeof(ie), 1, indexFile);
  if (ie.seq != seq)
    return -1;

  return rbegin;  
}

/* Serialize a given range of entries, and write the result to the specified file.
   This is used when we need to send a portion of our log to some other node,
   e.g. during an audit. The format of the serialized log segment is as follows:
          1. base hash value (size depends on hash function)
          2. entry type (1 byte)
          3. entry size in bytes (1 byte); 0x00=entry is hashed; 0xFF=16-bit size follows
          4. entry content (size as specified; omitted if entry is hashed)
          5. difference to next sequence number (1 byte)
                0x00: increment by one
                0xFF: 64-bit sequence number follows
                Otherwise:  Round down to nearest multiple of 1000, then add specified
                    value times 1000
          6. repeat 2-5 as often as necessary; 5 is omitted on last entry.
   Note that the idxFrom and idxTo arguments are record numbers, NOT sequence numbers.
   Use findSeqOrHigher() to get these if only sequence numbers are known. */

bool SecureHistory::serializeRange(int idxFrom, int idxTo, HashPolicy *hashPolicy, FILE *outfile)
{
  assert((0 < idxFrom) && (idxFrom <= idxTo) && (idxTo < numEntries));
  struct indexEntry ie;

  /* Write base hash value */

  pointerAtEnd = false;  
  fseek(indexFile, (idxFrom-1) * sizeof(ie), SEEK_SET);
  fread(&ie, sizeof(ie), 1, indexFile);
  fwrite(&ie.nodeHash, sizeof(ie.nodeHash), 1, outfile);
  
  /* Go through entries one by one */
  
  long long previousSeq = -1;
  for (int idx=idxFrom; idx<=idxTo; idx++) {
  
    /* Read index entry */
  
    if (fread(&ie, sizeof(ie), 1, indexFile) != 1)
      panic("History read error");
      
    char header[200];
    int bytesInHeader = 0;
    
    assert((previousSeq == -1) || (ie.seq > previousSeq));
    
    /* Encode difference to previous sequence number (unless this is the first entry) */
    
    if (previousSeq >= 0) {
      if (ie.seq == (previousSeq+1)) {
        header[bytesInHeader++] = 0;
      } else {
        long long dhigh = ((long long)(ie.seq/1000)) - ((long long)(previousSeq/1000));
        if ((dhigh < 255) && ((ie.seq%1000)==0)) {
          header[bytesInHeader++] = (unsigned char)dhigh;
        } else {
          header[bytesInHeader++] = 0xFF;
          *(long long*)&header[bytesInHeader] = ie.seq;
          bytesInHeader += sizeof(long long);
        }
      }
    }
    
    previousSeq = ie.seq;
    
    /* Append entry type */
    
    header[bytesInHeader++] = ie.type;
    
    /* If entry is not hashed, read contents from the data file */
    
    unsigned char *buffer = NULL;
    if (ie.sizeInFile > 0) {
      buffer = (unsigned char*) malloc(ie.sizeInFile);
      assert(ie.fileIndex >= 0);
      fseek(dataFile, ie.fileIndex, SEEK_SET);
      fread(buffer, ie.sizeInFile, 1, dataFile);
    }
    
    /* The entry is hashed if (a) it is already hashed in the log file,
       or (b) the hash policy tells us to. */
    
    bool hashIt = (ie.sizeInFile<0) || (hashPolicy && hashPolicy->hashEntry(ie.type, buffer, ie.sizeInFile));

    /* Encode the size of the entry */

    if (hashIt) {
      header[bytesInHeader++] = 0;
      for (unsigned i=0; i<sizeof(ie.contentHash); i++)
        header[bytesInHeader++] = ie.contentHash[i];
    } else if (ie.sizeInFile < 254) {
      header[bytesInHeader++] = (unsigned char) ie.sizeInFile;
    } else if (ie.sizeInFile < 65536) {
      header[bytesInHeader++] = 0xFF;
      *(unsigned short*)&header[bytesInHeader] = (unsigned short) ie.sizeInFile;
      bytesInHeader += sizeof(unsigned short);
    } else {
      header[bytesInHeader++] = 0xFE;
      *(unsigned int*)&header[bytesInHeader] = (unsigned int) ie.sizeInFile;
      bytesInHeader += sizeof(unsigned int);
    }
    
    /* Write the entry to the output file */
    
    fwrite(&header, bytesInHeader, 1, outfile);

    if (!hashIt) 
      fwrite(buffer, ie.sizeInFile, 1, outfile);
    
    if (buffer) 
      free(buffer);
  }
  
  return true;
}

/* Retrieve information about a given record */

bool SecureHistory::statEntry(int idx, long long *seq, unsigned char *type, int *sizeBytes, unsigned char *contentHash, unsigned char *nodeHash)
{
  if ((idx < 0) || (idx >= numEntries))
    return false;
    
  struct indexEntry ie;
  
  pointerAtEnd = false;
  fseek(indexFile, idx*sizeof(ie), SEEK_SET);
  if (fread(&ie, sizeof(ie), 1, indexFile) != 1)
    return false;
    
  if (seq)
    *seq = ie.seq;
  if (type)
    *type = (unsigned char) ie.type;
  if (sizeBytes)
    *sizeBytes = ie.sizeInFile;
  if (contentHash)
    memcpy(contentHash, ie.contentHash, HASH_LENGTH);
  if (nodeHash)
    memcpy(nodeHash, ie.nodeHash, HASH_LENGTH);
    
  return true;
}

/* Get the content of a log entry, specified by its record number */

int SecureHistory::getEntry(int idx, unsigned char *buffer, int buflen)
{
  if ((idx < 0) || (idx >= numEntries))
    return -1;
    
  struct indexEntry ie;
  
  pointerAtEnd = false;
  fseek(indexFile, idx*sizeof(ie), SEEK_SET);
  if (fread(&ie, sizeof(ie), 1, indexFile) != 1)
    return -1;
    
  if (ie.sizeInFile < 0)
    return -1;
    
  fseek(dataFile, ie.fileIndex, SEEK_SET);
  int bytesToRead = (buflen>=ie.sizeInFile) ? ie.sizeInFile : buflen;
  if (fread(buffer, bytesToRead, 1, dataFile) != 1)
    return -1;
    
  return bytesToRead;
}

/* If the log already contains an entry in 'hashed' form and we learn the actual
   contents later, this function is called. */

bool SecureHistory::upgradeHashedEntry(int idx, const void *entry, int size)
{
  if (readonly)
    panic("Cannot upgrade hashed entry in readonly history");
  
  if ((idx<0) || (idx>=numEntries))
    return false;
    
  pointerAtEnd = false;
  
  struct indexEntry ie;
  fseek(indexFile, idx*sizeof(ie), SEEK_SET);
  if (fread(&ie, sizeof(ie), 1, indexFile) != 1)
    return false;
    
  if (ie.sizeInFile >= 0)
    return false;
    
  fseek(dataFile, 0, SEEK_END);
  ie.fileIndex = ftell(dataFile);
  ie.sizeInFile = size;
  
  fwrite(entry, size, 1, dataFile);
  fseek(indexFile, idx*sizeof(ie), SEEK_SET);
  fwrite(&ie, sizeof(ie), 1, indexFile);
  
  return true;
}

/* Find the most recent entry whose type is in the specified set. Useful e.g. for
   locating the last CHECKPOINT or INIT entry. */

int SecureHistory::findLastEntry(unsigned char *types, int numTypes, long long maxSeq)
{
  int maxIdx = findSeqOrHigher((maxSeq>topEntry.seq) ? topEntry.seq : maxSeq, true);
  int currentIdx = maxIdx;
  
  while (currentIdx >= 0) {
    unsigned char thisType;
    if (!statEntry(currentIdx, NULL, &thisType, NULL, NULL, NULL))
      panic("Cannot stat history entry #%d (num=%d)", currentIdx, numEntries);
      
    for (int i=0; i<numTypes; i++)
      if (thisType == types[i])
        return currentIdx;
        
    currentIdx --;
  }
  
  return -1;
}

/* Find the first entry after a certain point whose type is in the specified set. Useful e.g. 
   for locating the next VRF entry. */

int SecureHistory::findNextEntry(unsigned char *types, int numTypes, long long minSeq)
{
  int minIdx = findSeqOrHigher(minSeq, true);
  int currentIdx = minIdx;

  while (currentIdx < numEntries) {
    unsigned char thisType;
    if (!statEntry(currentIdx, NULL, &thisType, NULL, NULL, NULL))
      panic("Cannot stat history entry #%d (num=%d)", currentIdx, numEntries);
      
    for (int i=0; i<numTypes; i++)
      if (thisType == types[i])
        return currentIdx;
        
    currentIdx ++;
  }
  
  return -1;
}
