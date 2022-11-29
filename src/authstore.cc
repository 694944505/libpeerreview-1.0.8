#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#include "peerreview.h"

AuthenticatorStore::AuthenticatorStore(PeerReview *peerreview, int authenticatorSizeBytes, bool allowDuplicateSeqs)
{
  this->authenticatorSizeBytes = authenticatorSizeBytes;
  this->allowDuplicateSeqs = allowDuplicateSeqs;
  this->head = NULL;
  this->authFile = 0;
  this->numSubjects = 0;
  this->peerreview = peerreview;
  this->filename[0] = 0;
  this->memoryBufferDisabled = false;
}

AuthenticatorStore::~AuthenticatorStore()
{ 
  while (head)
    flushAuthenticatorsFromMemory(head->id, LONG_LONG_MIN, LONG_LONG_MAX);
    
  if (authFile) {
    close(authFile);
    authFile = 0;
  }
}

static inline long long getSeq(const unsigned char *auth)
{ 
  return *(long long*)auth;
}

/* Discard the authenticators in a certain sequence range (presumably because we just checked 
   them against the corresponding log segment, and they were okay) */

void AuthenticatorStore::flushAuthenticatorsFromMemory(Identifier *id, long long minseq, long long maxseq)
{
  /* Find the node record */

  struct subjectRecord *prev = NULL, *rec = head;
  while (rec && !rec->id->equals(id)) {
    prev = rec;
    rec = rec->next;
  }

  if (!rec)
    return;

  /* Eat authenticators from beginning */
  
  while (rec->authList) {
    long long thisSeq = getSeq(rec->authList->authenticator);
    if ((thisSeq<minseq) || (thisSeq>maxseq))
      break;

    struct authenticatorRecord *auth = rec->authList;
    rec->authList = rec->authList->next;
    rec->numAuthenticators --;
    free(auth);
  }

  /* Continue eating authenticators along the chain */
  
  struct authenticatorRecord *iter = rec->authList;
  while (iter && iter->next) {
    long long thisSeq = getSeq(iter->next->authenticator);
    if ((thisSeq<minseq) || (thisSeq>maxseq)) {
      iter = iter->next;
      continue;
    }
    
    struct authenticatorRecord *auth = iter->next;
    iter->next = iter->next->next;
    rec->numAuthenticators --;
    free(auth);
  }
    
  /* Dequeue and free the node record if necessary */
    
  if (!rec->authList) {
    assert(rec->numAuthenticators == 0);
    
    if (prev) 
      prev->next = rec->next;
    else
      head = rec->next;
    
    delete rec->id;
    free(rec);
    numSubjects --;
  }
}

/* Each instance of this class has just a single file in which to store authenticators.
   The file format is (<id> <auth>)*; authenticators from different peers can be
   mixed. This method sets the name of the file and reads its current contents
   into memory. */

bool AuthenticatorStore::setFilename(const char *filename)
{
  if (authFile) {
    close(authFile);
    authFile = 0;
  }

  authFile = open(filename, O_RDWR | O_CREAT, 0644);
  if (authFile < 0) {
    authFile = 0;
    return false;
  }

  strcpy(this->filename, filename);
  
  unsigned char authenticator[authenticatorSizeBytes];  
  int authenticatorsRead = 0;
  int bytesRead = 0;
  unsigned char idbuf[peerreview->getIdentifierSizeBytes()];
  while (read(authFile, &idbuf, sizeof(idbuf)) == (int)sizeof(idbuf)) {
    if (read(authFile, &authenticator, authenticatorSizeBytes) != authenticatorSizeBytes)
      break;

    unsigned int pos = 0;
    Identifier *id = peerreview->readIdentifier(idbuf, &pos, sizeof(idbuf));

    addAuthenticatorToMemory(id, authenticator);
    delete id;
    
    bytesRead += sizeof(idbuf) + authenticatorSizeBytes;
    authenticatorsRead ++;
  }
  
  ftruncate(authFile, bytesRead);
  lseek(authFile, 0, SEEK_END);
  
  return true;
}

/* Add a new authenticator. Note that in memory, the authenticators are sorted by nodeID
   and by sequence number, whereas on disk, they are not sorted at all. */

void AuthenticatorStore::addAuthenticatorToMemory(Identifier *id, const unsigned char *authenticator)
{
  struct subjectRecord *rec = head;
  while (rec && !id->equals(rec->id))
    rec = rec->next;

  if (!rec) {
    rec = (struct subjectRecord*) malloc(sizeof(struct subjectRecord));
    assert(rec != NULL);
    rec->next = head;
    rec->id = id->clone();
    rec->numAuthenticators = 0;
    rec->authList = NULL;
    head = rec;
    numSubjects ++;
  }
  
  struct authenticatorRecord *arec = (struct authenticatorRecord*) malloc(sizeof(void*) + authenticatorSizeBytes);
  assert(arec != NULL); 
  memcpy(&arec->authenticator, authenticator, authenticatorSizeBytes);

  long long newSeq = getSeq(authenticator);
  if (!rec->authList || (newSeq > getSeq(rec->authList->authenticator))) {
    arec->next = rec->authList;
    rec->authList = arec;
  } else {
    struct authenticatorRecord *insertAfter = rec->authList;
    while (insertAfter->next && (newSeq < getSeq(insertAfter->next->authenticator)))
      insertAfter = insertAfter->next;
    if (insertAfter->next && (newSeq == getSeq(insertAfter->next->authenticator)) && !allowDuplicateSeqs)
      panic("Adding duplicate auths for the same sequence number is not allowed for this store");
    arec->next = insertAfter->next;
    insertAfter->next = arec;
  }

  rec->numAuthenticators ++;
#ifdef PARANOID
  assert(isSorted(rec));
#endif
}

bool AuthenticatorStore::isSorted(struct subjectRecord *rec)
{
  long long prevSeq = LONG_LONG_MAX;
  struct authenticatorRecord *iter = rec->authList;

  while (iter) {
    long long thisSeq = getSeq(iter->authenticator);
    if ((thisSeq > prevSeq) || ((thisSeq == prevSeq) && !allowDuplicateSeqs))
      return false;
      
    prevSeq = thisSeq;
    iter = iter->next;
  }
  
  return true;
}

bool AuthenticatorStore::getMostRecentAuthenticator(Identifier *id, unsigned char *buffer)
{
  struct subjectRecord *subject = findSubject(id);
  if (!subject || !subject->authList)
    return false;
    
  memcpy(buffer, &subject->authList->authenticator, authenticatorSizeBytes);
  return true;
}

bool AuthenticatorStore::getOldestAuthenticator(Identifier *id, unsigned char *buffer)
{
  struct subjectRecord *subject = findSubject(id);
  if (!subject || !subject->authList)
    return false;
    
  struct authenticatorRecord *iter = subject->authList;
  while (iter->next)
    iter = iter->next;
    
  memcpy(buffer, &iter->authenticator, authenticatorSizeBytes);
  return true;
}

bool AuthenticatorStore::getLastAuthenticatorBefore(Identifier *id, long long seq, unsigned char *buffer)
{
  struct subjectRecord *subject = findSubject(id);
  if (!subject || !subject->authList)
    return false;
    
  struct authenticatorRecord *iter = subject->authList;
  while (((*(long long*)&iter->authenticator[0])>=seq) && iter->next)
    iter = iter->next;
    
  if (!iter)
    return false;
    
  memcpy(buffer, &iter->authenticator, authenticatorSizeBytes);
  return true;
}

struct AuthenticatorStore::subjectRecord *AuthenticatorStore::findSubject(Identifier *id)
{
  struct subjectRecord *iter = head;
  while (iter && !id->equals(iter->id))
    iter = iter->next;

  return iter;    
}

void AuthenticatorStore::addAuthenticator(Identifier *id, const unsigned char *authenticator)
{
  if (authFile) {
    unsigned char idbuf[peerreview->getIdentifierSizeBytes()];
    unsigned int pos = 0;
    id->write(idbuf, &pos, sizeof(idbuf));
    if (write(authFile, &idbuf, sizeof(idbuf)) < (int)sizeof(idbuf))
      panic("Cannot append authenticator ID; write error (%s)", strerror(errno));
    if (write(authFile, authenticator, authenticatorSizeBytes) < authenticatorSizeBytes)
      panic("Cannot append authenticator data; write error");
  }
  
  if (!memoryBufferDisabled)
    addAuthenticatorToMemory(id, authenticator);
}

/* Since the authenticator file on disk is append-only, we need to garbage collect it
   from time to time. When this becomes necessary, we truncate the file and then
   write out the authenticators currently in memory. */

void AuthenticatorStore::garbageCollect()
{
  if (!authFile) 
    return;
    
  ftruncate(authFile, 0);
  lseek(authFile, 0, SEEK_SET);
  
  struct subjectRecord *iterN = head;
  while (iterN) {
    struct authenticatorRecord *iterA = iterN->authList;
    while (iterA) {
      if (write(authFile, &iterN->id, sizeof(iterN->id)) < (int)sizeof(iterN->id))
        panic("Cannot write authenticator ID during garbage collection");
      if (write(authFile, &iterA->authenticator, authenticatorSizeBytes) < authenticatorSizeBytes)
        panic("Cannot write authenticator data during garbage collection");
        
      iterA = iterA->next;
    }
  
    iterN = iterN->next;
  }
}

int AuthenticatorStore::numAuthenticatorsFor(Identifier *id)
{
  struct subjectRecord *rec = findSubject(id);
  return rec ? (rec->numAuthenticators) : 0;
}

int AuthenticatorStore::numAuthenticatorsFor(Identifier *id, long long minseq, long long maxseq)
{
  struct subjectRecord *rec = findSubject(id);
  if (!rec)
    return 0;
    
  struct authenticatorRecord *iter = rec->authList;    
  int result = 0;
  while (iter) {
    long long thisSeq = getSeq(iter->authenticator);
    if ((thisSeq>=minseq) && (thisSeq<=maxseq))
      result ++;

    iter = iter->next;
  }
  
  return result;
}

bool AuthenticatorStore::statAuthenticator(Identifier *id, long long seq, unsigned char *buffer)
{
  struct subjectRecord *rec = findSubject(id);
  
  if (rec) {
    struct authenticatorRecord *iter = rec->authList;    
    while (iter) {
      long long thisSeq = getSeq(iter->authenticator);
      if (thisSeq == seq) {
        memcpy(buffer, iter->authenticator, authenticatorSizeBytes);
        return true;
      }

      iter = iter->next;
    }
  }
  
  return false;
}

/* Retrieve all the authenticators within a given range of sequence numbers */

int AuthenticatorStore::getAuthenticators(Identifier *subject, unsigned char *buffer, int bufferSizeBytes, long long minseq, long long maxseq)
{
  struct subjectRecord *rec = findSubject(subject);
  if (!rec)
    return 0;

  struct authenticatorRecord *iter = rec->authList;    
  int writeptr = 0;
  while (iter && ((writeptr+authenticatorSizeBytes)<=bufferSizeBytes)) {
    long long thisSeq = getSeq(iter->authenticator);
    if ((thisSeq>=minseq) && (thisSeq<=maxseq)) {
      memcpy(&buffer[writeptr], &iter->authenticator, authenticatorSizeBytes);
      writeptr += authenticatorSizeBytes;
    }
    iter = iter->next;
  }
  
  return writeptr;
}

Identifier *AuthenticatorStore::getSubject(int index)
{
  assert((0<=index) && (index<numSubjects) && head);
  
  struct subjectRecord *iter = head;
  while (index>0) {
    assert(iter && iter->next);
    iter = iter->next;
    index --;
  }

  return iter->id;    
}

void AuthenticatorStore::flush(Identifier *subject)
{
  flushAuthenticatorsFromMemory(subject, LONG_LONG_MIN, LONG_LONG_MAX);

  if (head == NULL) {
    ftruncate(authFile, 0);
    lseek(authFile, 0, SEEK_SET);
  }
}

void AuthenticatorStore::flushAll()
{
  while (head != NULL)
    flushAuthenticatorsFromMemory(head->id, LONG_LONG_MIN, LONG_LONG_MAX);
    
  ftruncate(authFile, 0);
  lseek(authFile, 0, SEEK_SET);
}
