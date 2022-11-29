#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "peerreview.h"

#define SUBSYSTEM "peerreview"

PeerInfoStore::PeerInfoStore(IdentityTransport *transport)
{
  this->authenticatorSizeBytes = -1;
  this->head = NULL;
  this->dirname[0] = 0;
  this->notificationEnabled = true;
  this->transport = transport;
  this->listener = NULL;
}

PeerInfoStore::~PeerInfoStore()
{
  while (head) {
    struct peerInfoRecord *rec = head;
    head = head->next;
    
    if (rec->lastCheckedAuth)
      free(rec->lastCheckedAuth);
    
    while (rec->evidence) {
      struct evidenceRecord *er = rec->evidence;
      rec->evidence = rec->evidence->next;
      delete er->originator;
      free(er);
    }
    
    /* unanswered evidence is a subset of evidence; no deletion necessary */
    
    delete rec->id;
    free(rec);
  }
}

void PeerInfoStore::setAuthenticatorSize(int sizeBytes)
{
  assert((authenticatorSizeBytes < 0) && (sizeBytes > 0));
  authenticatorSizeBytes = sizeBytes; 
}

bool PeerInfoStore::isProof(const unsigned char *evidence)
{
  switch (evidence[0]) {
    case CHAL_AUDIT :
      return false;
    case CHAL_SEND :
      return false;
    case PROOF_INCONSISTENT :
      return true;
    case PROOF_NONCONFORMANT :
      return true;
    default:
      panic("Cannot evaluate isProof(%d)", evidence[0]);
  }
  
  return false;
}

/* Locates evidence, or creates a new entry if 'create' is set to true */

struct PeerInfoStore::evidenceRecord *PeerInfoStore::findEvidence(Identifier *originator, Identifier *subject, long long timestamp, bool create)
{
  struct peerInfoRecord *rec = find(subject, create);
  if (!rec)
    return NULL;
    
  struct evidenceRecord *iter = rec->evidence;
  while (iter) {
    if ((iter->originator->equals(originator)) && (iter->timestamp == timestamp))
      return iter;
      
    iter = iter->next;
  }

  if (!create)
    return NULL;
    
  struct evidenceRecord *evi = (struct evidenceRecord*) malloc(sizeof(struct evidenceRecord));
  evi->originator = originator->clone();
  evi->timestamp = timestamp;
  evi->isProof = false;
  evi->haveResponse = false;
  evi->next = rec->evidence;
  evi->nextUnanswered = rec->unansweredEvidence;
  evi->prevUnanswered = NULL;
  evi->evidenceLen = -1;
  evi->interestedParty = NULL;

  if (rec->unansweredEvidence) {
    assert(rec->unansweredEvidence->prevUnanswered == NULL);
    rec->unansweredEvidence->prevUnanswered = evi;
  }
  
  rec->evidence = evi;
  rec->unansweredEvidence = evi;
  
  return evi;
}

/* This is called when new evidence becomes available, or (during startup) for all evidence
   files on disk. We only keep some metadata in memory; the actual evidence is stored
   in a separate file on disk. */

void PeerInfoStore::markEvidenceAvailable(Identifier *originator, Identifier *subject, long long timestamp, int length, bool isProof, NodeHandle *interestedParty)
{
  struct peerInfoRecord *rec = find(subject, true);
  struct evidenceRecord *evi = findEvidence(originator, subject, timestamp, true);
  assert(rec && evi);
  
  /* Create or update metadata */
  
  evi->isProof = isProof;
  evi->evidenceLen = length;
  if (interestedParty) {
    if (evi->interestedParty)
      delete evi->interestedParty;
    evi->interestedParty = interestedParty->clone();
  }
  
  /* This may cause the node to become SUSPECTED or EXPOSED */
  
  if (isProof && (rec->status != STATUS_EXPOSED)) {
    rec->status = STATUS_EXPOSED;
    if (notificationEnabled && listener)
      listener->notifyStatusChange(subject, STATUS_EXPOSED);
  } else if (!isProof && (rec->status == STATUS_TRUSTED)) {
    rec->status = STATUS_SUSPECTED;
    if (notificationEnabled && listener)
      listener->notifyStatusChange(subject, STATUS_SUSPECTED);
  }
}

/* This is called when another node answers one of our challenges. Again, we only update
   the metadata in memory; the actual response is kept in a file on disk. */

void PeerInfoStore::markResponseAvailable(Identifier *originator, Identifier *subject, long long timestamp)
{
  struct peerInfoRecord *rec = find(subject, true);
  struct evidenceRecord *evi = findEvidence(originator, subject, timestamp, true);
  assert(!evi->isProof);
  evi->haveResponse = true;
  
  /* Remove this from the list of unanswered challenges */
  
  if (evi->prevUnanswered) 
    evi->prevUnanswered->nextUnanswered = evi->nextUnanswered;
  
  if (evi->nextUnanswered)
    evi->nextUnanswered->prevUnanswered = evi->prevUnanswered;

  if (evi == rec->unansweredEvidence)
    rec->unansweredEvidence = evi->nextUnanswered;

  evi->prevUnanswered = NULL;
  evi->nextUnanswered = NULL;
  
  /* If this was the last unanswered challenge to a SUSPECTED node, it goes back to TRUSTED */
  
  if ((rec->status == STATUS_SUSPECTED) && !rec->unansweredEvidence) {
    rec->status = STATUS_TRUSTED;
    if (notificationEnabled && listener)
      listener->notifyStatusChange(subject, STATUS_TRUSTED);
  }    
}

/* Add a new piece of evidence */

void PeerInfoStore::addEvidence(Identifier *originator, Identifier *subject, long long timestamp, const unsigned char *evidence, int evidenceLen, NodeHandle *interestedParty)
{
  char namebuf[200], buf1[200], buf2[200];
  plog(2, "addEvidence(orig=%s, subj=%s, seq=%lld)", originator->render(buf1), subject->render(buf2), timestamp);

  bool proof = isProof(evidence);

  /* Write the actual evidence to disk */

  sprintf(namebuf, "%s/%s-%s-%lld.%s", dirname, subject->render(buf1), originator->render(buf2), timestamp, proof ? "proof" : "challenge");
  
  FILE *outfile = fopen(namebuf, "w+");
  if (!outfile) 
    panic("Cannot create '%s'", namebuf);
    
  fwrite(evidence, evidenceLen, 1, outfile);
  fclose(outfile);
  
  /* Update metadata in memory */
  
  markEvidenceAvailable(originator, subject, timestamp, evidenceLen, proof, interestedParty);
}

/* Find out whether a node is TRUSTED, SUSPECTED or EXPOSED */

int PeerInfoStore::getStatus(Identifier *id)
{
  struct peerInfoRecord *rec = find(id);
  return rec ? rec->status : STATUS_TRUSTED;
}

/* Called during startup to inform the store where its files are located */

bool PeerInfoStore::setStorageDirectory(const char *dirname)
{
  DIR *dir = opendir(dirname);
  
  /* Create the directory if it doesn't exist yet */
  
  if (!dir) {
    if (mkdir(dirname, 0755) < 0)
      return false;
    if ((dir = opendir(dirname)) == NULL)
      return false;
  }
    
  strncpy(this->dirname, dirname, sizeof(this->dirname));

  /* To prevent a flood of status updates, we temporarily disable updates
     while we inspect the existing evidence on disk */

  bool notificationWasEnabled = notificationEnabled;
  notificationEnabled = false;
    
  /* Read the entire directory */
    
  struct dirent *ent = readdir(dir);
  while (ent) {
    if (strstr(ent->d_name, ".challenge") || strstr(ent->d_name, ".response") || strstr(ent->d_name, ".proof") || strstr(ent->d_name, ".info")) {
      char namebuf[200];
      struct stat statbuf;
      sprintf(namebuf, "%s/%s", dirname, ent->d_name);
      int statRes = stat(namebuf, &statbuf);
      assert(statRes == 0);

      /* INFO files contain the last checked authenticator */

      if (strstr(ent->d_name, ".info")) {
        strncpy(namebuf, ent->d_name, sizeof(namebuf));
        char *ssubject = strtok(namebuf, ".");
        Identifier *id = transport->readIdentifierFromString(ssubject);

        sprintf(namebuf, "%s/%s", dirname, ent->d_name);
        FILE *infile = fopen(namebuf, "r");
        if (!infile)
          panic("Cannot read peer info: '%s'", namebuf);
          
        assert(authenticatorSizeBytes>0);
        
        unsigned char lastAuth[authenticatorSizeBytes];
        int ret = fread(lastAuth, sizeof(lastAuth), 1, infile);
        if (ret != 1)
          panic("Cannot read info from '%s' (ret=%d)", namebuf, ret);
        fclose(infile);

        setLastCheckedAuth(id, lastAuth);
        delete id;
      } else {      
      
        /* PROOF, CHALLENGE and RESPONSE files */
      
        strncpy(namebuf, ent->d_name, sizeof(namebuf));
        char *ssubject = strtok(namebuf, "-");
        char *soriginator = ssubject ? strtok(NULL, "-") : NULL;
        char *sseq = soriginator ? strtok(NULL, ".") : NULL;
        char *stype = sseq ? strtok(NULL, "\r") : NULL;

        if (stype) {
          Identifier *subject = transport->readIdentifierFromString(ssubject);
          Identifier *originator = transport->readIdentifierFromString(soriginator);
          long long seq = atoll(sseq);

          if (!strcmp(stype, "challenge"))
            markEvidenceAvailable(originator, subject, seq, statbuf.st_size, false);
          else if (!strcmp(stype, "proof"))
            markEvidenceAvailable(originator, subject, seq, statbuf.st_size, true);
          else if (!strcmp(stype, "response"))
            markResponseAvailable(originator, subject, seq);

          delete subject;
          delete originator;
        }
      }
    }
    
    ent = readdir(dir);
  }
  
  closedir(dir);
  notificationEnabled = notificationWasEnabled;
  
  return true;
}

struct PeerInfoStore::peerInfoRecord *PeerInfoStore::find(Identifier *id, bool create)
{
  struct peerInfoRecord *iter = head;

  while (iter != NULL) {
    if (iter->id->equals(id))
      return iter;
      
    iter = iter->next;
  }
  
  if (create) {
    struct peerInfoRecord *rec = (struct peerInfoRecord*) malloc(sizeof(struct peerInfoRecord));
    rec->next = head;
    rec->id = id->clone();
    rec->lastCheckedAuth = NULL;
    rec->evidence = NULL;
    rec->unansweredEvidence = NULL;
    rec->status = STATUS_TRUSTED;
    head = rec;
    return rec;
  } else {
    return NULL;
  }
}

bool PeerInfoStore::getLastCheckedAuth(Identifier *id, unsigned char *buffer)
{
  struct peerInfoRecord *rec = find(id);
  if (!rec || !(rec->lastCheckedAuth))
    return false;
    
  memcpy(buffer, rec->lastCheckedAuth, authenticatorSizeBytes);
  return true;
}

void PeerInfoStore::setLastCheckedAuth(Identifier *id, unsigned char *buffer)
{
  struct peerInfoRecord *rec = find(id, true);
  if (!rec->lastCheckedAuth)
    rec->lastCheckedAuth = (unsigned char*) malloc(authenticatorSizeBytes);
    
  memcpy(rec->lastCheckedAuth, buffer, authenticatorSizeBytes);

  char namebuf[500], buf1[256];
  sprintf(namebuf, "%s/%s.info", dirname, id->render(buf1));
  FILE *outfile = fopen(namebuf, "w+");
  if (!outfile)
    panic("Cannot write peer info to '%s'", namebuf);
    
  fwrite(buffer, authenticatorSizeBytes, 1, outfile);
  fclose(outfile);
}

/* Retrieve some information about a given piece of evidence */

bool PeerInfoStore::statEvidence(Identifier *originator, Identifier *subject, long long timestamp, int *evidenceLen, bool *isProof, bool *haveResponse, NodeHandle **interestedParty)
{
  struct evidenceRecord *evi = findEvidence(originator, subject, timestamp);
  if (!evi)
    return false;
    
  if (evidenceLen)
    *evidenceLen = evi->evidenceLen;
  if (isProof)
    *isProof = evi->isProof;
  if (haveResponse)
    *haveResponse = evi->haveResponse;
  if (interestedParty)
    *interestedParty = evi->interestedParty;
  
  return true;
}

/* Get the actual bytes of a piece of evidence */

void PeerInfoStore::getEvidence(Identifier *originator, Identifier *subject, long long timestamp, unsigned char *evidenceBuf, int buflen)
{
  struct evidenceRecord *evi = findEvidence(originator, subject, timestamp);
  assert(evi && (evi->evidenceLen >= 0) && (evi->evidenceLen == buflen));
  
  char namebuf[200], buf1[200], buf2[200];
  sprintf(namebuf, "%s/%s-%s-%lld.%s", dirname, subject->render(buf1), originator->render(buf2), timestamp, evi->isProof ? "proof" : "challenge");
  
  FILE *infile = fopen(namebuf, "r");
  if (!infile) 
    panic("Cannot read '%s'", namebuf);
    
  fread(evidenceBuf, buflen, 1, infile);
  fclose(infile);
}

/* Record a response to a challenge */

void PeerInfoStore::addResponse(Identifier *originator, Identifier *subject, long long timestamp, const unsigned char *response, int responseLen)
{
  struct evidenceRecord *evi = findEvidence(originator, subject, timestamp);
  assert(evi && !evi->isProof && !evi->haveResponse);
  
  char namebuf[200], buf1[200], buf2[200];
  sprintf(namebuf, "%s/%s-%s-%lld.response", dirname, subject->render(buf1), originator->render(buf2), timestamp);
  
  FILE *outfile = fopen(namebuf, "w+");
  if (!outfile) 
    panic("Cannot create '%s'", namebuf);
    
  fwrite(response, responseLen, 1, outfile);
  fclose(outfile);
  
  markResponseAvailable(originator, subject, timestamp);
}

void PeerInfoStore::getHistoryName(Identifier *subject, char *buffer)
{
  char buf1[200];
  sprintf(buffer, "%s/%s-log", dirname, subject->render(buf1));
}

/* Look up the first unanswered challenge to a given node */

bool PeerInfoStore::statFirstUnansweredChallenge(Identifier *subject, Identifier **originator, long long *timestamp, int *evidenceLen)
{
  struct peerInfoRecord *rec = find(subject);
  if (!rec || !rec->unansweredEvidence)
    return false;
    
  struct evidenceRecord *evi = rec->unansweredEvidence;
  if (originator)
    *originator = evi->originator;
  if (timestamp)
    *timestamp = evi->timestamp;
  if (evidenceLen)
    *evidenceLen = evi->evidenceLen;
    
  return true;
}

bool PeerInfoStore::statProof(Identifier *subject, Identifier **originator, long long *timestamp, int *evidenceLen)
{
  struct peerInfoRecord *rec = find(subject);
  if (!rec)
    return false;
    
  struct evidenceRecord *evi = rec->evidence;
  while (evi && !evi->isProof)
    evi = evi->next;

  if (!evi)
    return false;
  
  if (originator)
    *originator = evi->originator;
  if (timestamp)
    *timestamp = evi->timestamp;
  if (evidenceLen)
    *evidenceLen = evi->evidenceLen;
    
  return true;
}
