#ifndef __peerreview_history_h__
#define __peerreview_history_h__

#include "peerreview/identity.h"

/* Policy given to a SecureHistory to tell it which event types to hash when
   serializing a sequence of events. For example, such a policy might tell
   the SecureHistory to hash all SEND and SENDSIGN events, plus all CHECKPOINT
   events except for the first one. */

class HashPolicy {
public:
  HashPolicy() {};
  virtual ~HashPolicy() {};
  virtual bool hashEntry(unsigned int type, unsigned char *content, int contentLen) = 0;
};

/* The following class implements PeerReview's log. A log entry consists of
   a sequence number, a type, and a string of bytes. On disk, the log is
   stored as two files: An index file and a data file. */

class SecureHistory {
protected:
 static const int HASH_LENGTH = 20;

  struct indexEntry {
    long long seq;
    int fileIndex;
    int sizeInFile;
    int type;
    unsigned char contentHash[HASH_LENGTH];
    unsigned char nodeHash[HASH_LENGTH];
  };

  HashProvider *hashprov;
  bool pointerAtEnd;
  indexEntry topEntry;
  long long baseSeq;
  long long nextSeq;
  int numEntries;
  FILE *indexFile;
  FILE *dataFile;
  bool readonly;
  
  int findSeqOrHigher(long long seq, bool allowHigher);
  
  SecureHistory(FILE *indexFile, FILE *dataFile, bool readonly, HashProvider *hashprov);
  
public:
  static SecureHistory *createTemp(long long baseSeq, const unsigned char *baseHash, HashProvider *hashprov) { return create(NULL, baseSeq, baseHash, hashprov); };
  static SecureHistory *create(const char *name, long long baseSeq, const unsigned char *baseHash, HashProvider *hashprov);
  static SecureHistory *open(const char *name, const char *mode, HashProvider *hashprov);

  ~SecureHistory();  
  void appendEntry(char type, bool storeFullEntry, const void *entry, int size, const void *header = NULL, int headerSize = 0);
  void appendHash(char type, const unsigned char *hash);
  void getTopLevelEntry(void *nodeHash, long long *seq);
  long long getLastSeq() { return topEntry.seq; };
  bool setNextSeq(long long nextSeq);
  int getNumEntries() { return numEntries; };
  long long getBaseSeq() { return baseSeq; };
  bool statEntry(int idx, long long *seq, unsigned char *type, int *sizeBytes, unsigned char *contentHash, unsigned char *nodeHash);
  int getEntry(int idx, unsigned char *buffer, int buflen);
  bool serializeRange(int idxFrom, int idxTo, HashPolicy *hashPolicy, FILE *outfile);
  int findLastEntry(unsigned char *types, int numTypes, long long maxSeq);
  int findNextEntry(unsigned char *types, int numTypes, long long minSeq);
  int findSeq(long long seq) { return findSeqOrHigher(seq, false); };
  bool upgradeHashedEntry(int idx, const void *entry, int size);
};

#endif /* defined(__peerreview_history_h__) */
