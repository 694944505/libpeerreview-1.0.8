#include <stdlib.h>
#include <string.h>

#include "peerreview.h"

#define SUBSYSTEM "peerreview"

#ifdef VERBOSE
#define vlog(a...) plog(a...)
#else
#define vlog(a...) do { } while (0)
#endif

/**
  * TODO:
  *   - Keep some of the older authenticators around to cover the history (use in accusations if auth is not signed)
 */

AuditProtocol::AuditProtocol(PeerReview *peerreview, SecureHistory *history, PeerInfoStore *infoStore, AuthenticatorStore *authInStore, IdentityTransport *transport, PeerReviewCallback *app, AuthenticatorStore *authOutStore, EvidenceTransferProtocol *evidenceTransferProtocol, AuthenticatorStore *authCacheStore)
{
  this->signatureSizeBytes = transport->getSignatureSizeBytes();
  this->hashSizeBytes = transport->getHashSizeBytes();
  this->authenticatorSizeBytes = sizeof(long long) + hashSizeBytes + signatureSizeBytes;
  this->infoStore = infoStore;
  this->authInStore = authInStore;
  this->authCacheStore = authCacheStore;
  this->transport = transport;
  this->app = app;
  this->history = history;
  this->numActiveAudits = 0;
  this->peerreview = peerreview;
  this->myHandle = transport->getLocalHandle()->clone();
  this->progressTimerActive = false;
  this->authOutStore = authOutStore;
  this->numActiveInvestigations = 0;
  this->evidenceTransferProtocol = evidenceTransferProtocol;
  this->logDownloadTimeout = DEFAULT_LOG_DOWNLOAD_TIMEOUT;
  this->replayEnabled = true;
  this->lastAuditStarted = peerreview->getTime();
  this->auditIntervalMicros = DEFAULT_AUDIT_INTERVAL_MICROS;
  transport->scheduleTimer(this, TI_START_AUDITS, lastAuditStarted + auditIntervalMicros);
}

AuditProtocol::~AuditProtocol()
{
  while (numActiveAudits > 0)
    terminateAudit(0);
    
  while (numActiveInvestigations > 0)
    terminateInvestigation(0);
    
  delete myHandle;
}

/* Starts to audit a node */

void AuditProtocol::beginAudit(NodeHandle *target, unsigned char *authFrom, unsigned char *authTo, unsigned char needPrevCheckpoint, bool replayAnswer)
{
  unsigned int auditRequestMaxLen = 1 + MAX_ID_SIZE + sizeof(long long) + 2 + 2*authenticatorSizeBytes;
  unsigned char *auditRequest = (unsigned char*) malloc(auditRequestMaxLen);
  unsigned int auditRequestLen = 0;
  long long evidenceSeq = peerreview->getEvidenceSeq();

  /* Put together an AUDIT challenge */

  writeByte(auditRequest, &auditRequestLen, MSG_CHALLENGE);
  myHandle->getIdentifier()->write(auditRequest, &auditRequestLen, auditRequestMaxLen);
  writeLongLong(auditRequest, &auditRequestLen, evidenceSeq);
  writeByte(auditRequest, &auditRequestLen, CHAL_AUDIT);
  writeByte(auditRequest, &auditRequestLen, needPrevCheckpoint);
  writeBytes(auditRequest, &auditRequestLen, authFrom, authenticatorSizeBytes);
  writeBytes(auditRequest, &auditRequestLen, authTo, authenticatorSizeBytes);
  assert(auditRequestLen <= auditRequestMaxLen);

  /* Create an entry in our audit buffer */

  int idx = numActiveAudits++;
  activeAudit[idx].target = target->clone();
  activeAudit[idx].shouldBeReplayed = replayAnswer;
  activeAudit[idx].isReplaying = false;
  activeAudit[idx].currentTimeout = peerreview->getTime() + logDownloadTimeout;
  activeAudit[idx].request = auditRequest;
  activeAudit[idx].requestLen = auditRequestLen;
  activeAudit[idx].evidenceSeq = evidenceSeq;
  activeAudit[idx].verifier = NULL;

  /* Send the AUDIT challenge to the target node */

  char buf1[256];
  plog(2, "Sending AUDIT request to %s (range=%lld-%lld,eseq=%lld)", activeAudit[idx].target->render(buf1), *(long long*)authFrom, *(long long*)authTo, evidenceSeq);
  peerreview->transmit(target, false, auditRequest, auditRequestLen);
}

void AuditProtocol::startAudits()
{
  /* Find out which nodes we are currently witnessing */

  NodeHandle **buffer = (NodeHandle**) malloc(sizeof(NodeHandle*)*MAX_WITNESSED_NODES);
  int numNodes = app->getMyWitnessedNodes(buffer, MAX_WITNESSED_NODES);
  char buf1[256];
  
  /* For each of these nodes ... */
  
  for (int i=0; i<numNodes; i++) {
  
    /* If the node is not trusted, we don't audit */
  
    int status = infoStore->getStatus(buffer[i]->getIdentifier());
    if (status != STATUS_TRUSTED) {
      plog(2, "Node %s is %s; skipping audit", buffer[i]->render(buf1), renderStatus(status));
      continue;
    }
  
    /* If a previous audit of this node is still in progress, we skip this round */
  
    int idx = -1;
    for (int j=0; j<numActiveAudits; j++) {
      if (activeAudit[j].target == buffer[i])
        idx = j;
    }
    
    if (idx < 0) {
      if (numActiveAudits >= MAX_ACTIVE_AUDITS)
        panic("Too many active audits");
        
      /* Retrieve the node's newest and last-checked authenticators. Note that we need
         at least two distinct authenticators to be able to audit a node. */
        
      unsigned char authFrom[authenticatorSizeBytes];
      unsigned char authTo[authenticatorSizeBytes];
      bool haveEnoughAuthenticators = true;
      unsigned char needPrevCheckpoint = 0;

      plog(1, "Starting to audit %s", buffer[i]->render(buf1));

      if (!infoStore->getLastCheckedAuth(buffer[i]->getIdentifier(), authFrom)) {
        if (authInStore->getOldestAuthenticator(buffer[i]->getIdentifier(), authFrom)) {
          plog(2, "We haven't audited this node before; using oldest authenticator");
          needPrevCheckpoint = 1;
        } else {
          plog(2, "We don't have any authenticators for this node; skipping this audit");
          haveEnoughAuthenticators = false;
        }
      }

      if (!authInStore->getMostRecentAuthenticator(buffer[i]->getIdentifier(), authTo)) {
        plog(2, "No recent authenticator; skipping this audit");
        haveEnoughAuthenticators = false;
      }
        
      if (haveEnoughAuthenticators && ((*(long long*)&authFrom)>(*(long long*)&authTo))) {
        plog(2, "authFrom>authTo; skipping this audit");
        haveEnoughAuthenticators = false; 
      }
        
      /* Add an entry to our table of ongoing audits. This entry will periodically
         be checked by cleanupAudits() */
        
      if (haveEnoughAuthenticators) 
        beginAudit(buffer[i], authFrom, authTo, needPrevCheckpoint, true);

    } else {
      warning("Node %s is already being audited; skipping", buffer[i]->render(buf1));
    }
  }
  
  /* Make sure that makeProgressOnAudits() is called regularly */
  
  if (!progressTimerActive) {
    progressTimerActive = true;
    transport->scheduleTimer(this, TI_MAKE_PROGRESS, peerreview->getTime() + PROGRESS_INTERVAL_MICROS);
  }
  
  free(buffer);
}

/* Called periodically to check if all audits have finished. An audit may not finish if either
   (a) the target does not respond, or (b) the target's response is discarded because it is
   malformed. In either case, we report the failed AUDIT challenge to the witnesses. */

void AuditProtocol::cleanupAudits()
{
  long long now = peerreview->getTime();
  
  for (int i=0; i<numActiveAudits; ) {
    if ((now >= activeAudit[i].currentTimeout) && !activeAudit[i].isReplaying) {
      int headerLen = 1 + peerreview->getIdentifierSizeBytes() + sizeof(long long);
          
      warning("No response to AUDIT request; filing as evidence %lld", activeAudit[i].evidenceSeq);
      infoStore->addEvidence(myHandle->getIdentifier(), activeAudit[i].target->getIdentifier(), activeAudit[i].evidenceSeq, &activeAudit[i].request[headerLen], activeAudit[i].requestLen - headerLen);
      peerreview->sendEvidenceToWitnesses(activeAudit[i].target->getIdentifier(), activeAudit[i].evidenceSeq, &activeAudit[i].request[headerLen], activeAudit[i].requestLen - headerLen);

      terminateAudit(i);
    } else {
      i++;
    }          
  }
}

void AuditProtocol::terminateAudit(int idx)
{
  assert((0<=idx) && (idx<numActiveAudits));

  free(activeAudit[idx].request);

  /* Delete all the state associated with this replay. The verifier will take care of the
     history and any registered event handlers */

  if (activeAudit[idx].verifier)
    delete activeAudit[idx].verifier;
  if (activeAudit[idx].target)
    delete activeAudit[idx].target;

  activeAudit[idx] = activeAudit[--numActiveAudits];
}

void AuditProtocol::terminateInvestigation(int idx)
{
  assert((0<=idx) && (idx<numActiveInvestigations));

  delete activeInvestigation[idx].target;
  if (activeInvestigation[idx].authFrom)
    free(activeInvestigation[idx].authFrom);
  if (activeInvestigation[idx].authTo)
    free(activeInvestigation[idx].authTo);
  
  activeInvestigation[idx] = activeInvestigation[--numActiveInvestigations];
}

void AuditProtocol::makeProgressOnInvestigations()
{
  long long now = peerreview->getTime();
  char buf1[256];
  
  for (int i=0; i<numActiveInvestigations; ) {
    if (activeInvestigation[i].currentTimeout < now) {
      long long authFromSeq = activeInvestigation[i].authFrom ? (*(long long*) activeInvestigation[i].authFrom) : -1;
      long long authToSeq = activeInvestigation[i].authTo ? (*(long long*) activeInvestigation[i].authTo) : -1;
      if ((0<=authFromSeq) && (authFromSeq <= activeInvestigation[i].since) && (activeInvestigation[i].since < authToSeq)) {
        plog(2, "Investigation of %s (since %lld) is proceeding with an audit", activeInvestigation[i].target->render(buf1), activeInvestigation[i].since);
        
#if 0
        unsigned char lastCheckedAuth[authenticatorSizeBytes];
        if (infoStore->getLastCheckedAuth(activeInvestigation[i].target->getIdentifier(), lastCheckedAuth)) {
          long long lastCheckedSeq = *(long long*)&lastCheckedAuth;
          if (lastCheckedSeq > authFromSeq) {
            plog(3, "We already have the log up to %lld; starting investigation from there", lastCheckedSeq);
            memcpy(activeInvestigation[i].authFrom, lastCheckedAuth, authenticatorSizeBytes);
            authFromSeq = lastCheckedSeq;
          }
        }
#endif
        
        if (authToSeq > authFromSeq) {
          plog(3, "Authenticators: %lld-%lld", *(long long*)activeInvestigation[i].authFrom, *(long long*)activeInvestigation[i].authTo);
          beginAudit(activeInvestigation[i].target, activeInvestigation[i].authFrom, activeInvestigation[i].authTo, FLAG_FULL_MESSAGES_SENDER, false);
          terminateInvestigation(i);
        } else {
          warning("Cannot start investigation; authTo<authFrom ?!? (since=%lld, authFrom=%lld, authTo=%lld)", activeInvestigation[i].since, authFromSeq, authToSeq);
          terminateInvestigation(i);
        }
      } else {
        plog(2, "Retransmitting investigation requests for %s at %lld", activeInvestigation[i].target->render(buf1), activeInvestigation[i].since);
        sendInvestigation(i);
        activeInvestigation[i].currentTimeout += INVESTIGATION_INTERVAL_MICROS;
        i++;
      }
    } else {
      i++;
    }
  }
}

void AuditProtocol::setAuditInterval(long long newIntervalMicros)
{
  auditIntervalMicros = newIntervalMicros;
  transport->cancelTimer(this, TI_START_AUDITS);
  long long nextTimeout = lastAuditStarted + (long long)((500+(random()%1000))*0.001*auditIntervalMicros);
  if (nextTimeout <= peerreview->getTime())
    nextTimeout = peerreview->getTime() + 1;
  transport->scheduleTimer(this, TI_START_AUDITS, nextTimeout);
}

void AuditProtocol::timerExpired(int timerID)
{
  switch (timerID) {
    case TI_START_AUDITS: /* A periodic timer to audit all nodes for which we are a witness */
      startAudits();
      lastAuditStarted = peerreview->getTime();
      transport->scheduleTimer(this, TI_START_AUDITS, lastAuditStarted + (long long)((500+(random()%1000))*0.001*auditIntervalMicros));
      break;
    case TI_MAKE_PROGRESS: /* While some audits haven't finished, we must call makeProgress() regularly */
      progressTimerActive = false;
      cleanupAudits();
      makeProgressOnInvestigations();
      if (!progressTimerActive && ((numActiveAudits > 0) || (numActiveInvestigations > 0))) {
        progressTimerActive = true;
        transport->scheduleTimer(this, TI_MAKE_PROGRESS, peerreview->getTime() + PROGRESS_INTERVAL_MICROS);
      }
      break;
    default:
      panic("Unknown timer #%d expired in AuditProtocol", timerID);
  }
}

/* Called by the challenge/response protocol if we have received a response to an AUDIT challenge. At this point,
   we already know that we have all the necessary certificates (because of the statement protocol). */

void AuditProtocol::processAuditResponse(Identifier *subject, long long timestamp, unsigned char *snippet, int snippetLen)
{
  int idx = findOngoingAudit(subject, timestamp);
  assert(idx >= 0);
  
  /* Read the header of the log snippet */
  
  int reqHdrSize = 1+peerreview->getIdentifierSizeBytes()+sizeof(long long);
  long long fromSeq = *(long long*)&activeAudit[idx].request[reqHdrSize+2];
  unsigned char *toAuthenticator = &activeAudit[idx].request[reqHdrSize+2+authenticatorSizeBytes];
  long long toSeq = *(long long*)&toAuthenticator[0];
  unsigned char currentNodeHash[hashSizeBytes];
  unsigned char initialNodeHash[hashSizeBytes];
  int readptr = 0;
  NodeHandle *subjectHandle = peerreview->readNodeHandle(snippet, (unsigned int*)&readptr, snippetLen);
  int posAfterNodeHandle = readptr;
  long long currentSeq = readLongLong(snippet, (unsigned int*)&readptr);
  int extInfoLen = snippet[readptr++];
  unsigned char *extInfo = &snippet[readptr];
  readptr += extInfoLen;
  
  long long initialCurrentSeq = currentSeq;
  memcpy(currentNodeHash, &snippet[readptr], hashSizeBytes);
  memcpy(initialNodeHash, &snippet[readptr], hashSizeBytes);
  readptr += hashSizeBytes;
  int initialReadPtr = readptr;
  char buf1[200];
  
  /* Retrieve all the authenticators we have for this node */
  
  unsigned char *auths = NULL;
  int numAuths = authInStore->numAuthenticatorsFor(subject, fromSeq, toSeq);
  if (numAuths > 0) {
    auths = (unsigned char*) malloc(numAuths * authenticatorSizeBytes);
    int ret = authInStore->getAuthenticators(subject, auths, numAuths * authenticatorSizeBytes, fromSeq, toSeq);
    assert(ret == (numAuths * authenticatorSizeBytes));
  }

  /* We have to keep a small fraction of the authenticators around so we can later
     answer AUTHREQ messages from other nodes. */

  plog(2, "Checking of AUDIT response against %d authenticators [%lld-%lld]", numAuths, fromSeq, toSeq);

  unsigned char mrauth[authenticatorSizeBytes];
  long long mostRecentAuthInCache = -1;
  if (authCacheStore->getMostRecentAuthenticator(subject, mrauth)) 
    mostRecentAuthInCache = *(long long*)&mrauth;
    
  for (int i=numAuths-1; i>=0; i--) {
    unsigned char *thisAuth = &auths[authenticatorSizeBytes * i];
    long long thisSeq = *(long long*)thisAuth;
    if (thisSeq > (mostRecentAuthInCache + (AUTH_CACHE_INTERVAL*1000LL))) {
      plog(3, "Caching auth %lld for %s", thisSeq, subject->render(buf1));
      authCacheStore->addAuthenticator(subject, thisAuth);
      mostRecentAuthInCache = thisSeq;
    }
  }

  /* We read the entries one by one, calculating the node hashes as we go, and we compare
     the node hashes to our (sorted) list of authenticators. If there is any divergence,
     we have proof that the node is misbehaving. */

  int authPtr = numAuths - 1;
  unsigned char *nextAuth = (authPtr<0) ? NULL : &auths[authPtr*authenticatorSizeBytes];
  long long nextAuthSeq = (authPtr<0) ? -1 : *(long long*)nextAuth;
  plog(3, "  NA #%d %lld", authPtr, nextAuthSeq);

  while (readptr < snippetLen) {
    unsigned char entryType = snippet[readptr++];
    unsigned char sizeCode = snippet[readptr++];
    unsigned int entrySize = sizeCode;
    bool entryIsHashed = (sizeCode == 0);

    if (sizeCode == 0xFF) {
      entrySize = *(unsigned short*)&snippet[readptr];
      readptr += 2;
    } else if (sizeCode == 0xFE) {
      entrySize = *(unsigned int*)&snippet[readptr];
      readptr += 4;
    } else if (sizeCode == 0) {
      entrySize = hashSizeBytes;
    }

    vlog(3, "[2] Entry type %d, size=%d, seq=%lld%s", entryType, entrySize, currentSeq, entryIsHashed ? " (hashed)" : "");

    const unsigned char *entry = &snippet[readptr];

    /* Calculate the node hash from the entry */

    unsigned char contentHash[hashSizeBytes];
    if (entryIsHashed)
      memcpy(contentHash, entry, hashSizeBytes);
    else
      transport->hash(contentHash, entry, entrySize);

    transport->hash(currentNodeHash, (const unsigned char*)&currentSeq, sizeof(currentSeq), &entryType, sizeof(entryType), currentNodeHash, hashSizeBytes, contentHash, hashSizeBytes);

    char buf1[256];
    vlog(4, "NH [%s]", renderBytes(currentNodeHash, hashSizeBytes, buf1));

    /* If we have an authenticator for this entry (matched by sequence number), the hash in the
       authenticator must match the node hash. If not, we have a proof of misbehavior. */

    if (authPtr >= 0) {
      bool foundMisbehavior = false;
      
      if (currentSeq == nextAuthSeq) {
        if (memcmp(currentNodeHash, &nextAuth[sizeof(long long)], hashSizeBytes)) {
          warning("Found a divergence for node <%08X>'s authenticator #%lld", subject, currentSeq);
          foundMisbehavior = true;
        } else {
          plog(4,"Authenticator verified OK");

          authPtr --;
          nextAuth = (authPtr<0) ? NULL : &auths[authPtr*authenticatorSizeBytes];
          nextAuthSeq = (authPtr<0) ? -1 : *(long long*)nextAuth;
          plog(4, "NA #%d %lld", authPtr, nextAuthSeq);
        }
      } else if (currentSeq > nextAuthSeq) {
        warning("Node %s is trying to hide authenticator #%lld", subject->render(buf1), nextAuthSeq);
        foundMisbehavior = true;
      }
      
      if (foundMisbehavior) {
        plog(2, "Extracting proof of misbehavior from audit response");
        
        unsigned char proof[1+authenticatorSizeBytes+1+authenticatorSizeBytes+(snippetLen-posAfterNodeHandle)];
        unsigned int pos = 0;
        writeByte(proof, &pos, PROOF_INCONSISTENT);
        writeBytes(proof, &pos, toAuthenticator, authenticatorSizeBytes);
        writeByte(proof, &pos, 1);
        writeBytes(proof, &pos, nextAuth, authenticatorSizeBytes);
        writeBytes(proof, &pos, &snippet[posAfterNodeHandle], snippetLen-posAfterNodeHandle);
        assert(pos <= sizeof(proof));

        long long evidenceSeq = peerreview->getEvidenceSeq();
        plog(2, "Filing proof against %s under evidence sequence number #%lld", subject->render(buf1), evidenceSeq);
        infoStore->addEvidence(transport->getLocalHandle()->getIdentifier(), subject, evidenceSeq, proof, pos);
        peerreview->sendEvidenceToWitnesses(subject, evidenceSeq, proof, pos);

        terminateAudit(idx);
        delete subjectHandle;
        return;
      }
    }

    readptr += entrySize;
    if (readptr == snippetLen) // legitimate end
      break;

    unsigned char dseqCode = snippet[readptr++];
    if (dseqCode == 0xFF) {
      currentSeq = *(long long*)&snippet[readptr];
      readptr += sizeof(long long);
    } else if (dseqCode == 0) {
      currentSeq ++;
    } else {
      currentSeq = currentSeq - (currentSeq%1000) + (dseqCode * 1000LL);
    }

    assert(readptr <= snippetLen);
  }

  /* All these authenticators for this segment checked out okay. We don't need them any more,
     so we can remove them from our local store. */

  plog(2, "All authenticators in range [%lld,%lld] check out OK; flushing", fromSeq, toSeq);
#warning must check the old auths; flush from fromSeq only!
  authInStore->flushAuthenticatorsFor(subject, LONG_LONG_MIN, toSeq);
  if (auths)
    free(auths);

  /* Find out if the log snipped is 'useful', i.e. if we can append it to our local history */

  char namebuf[200];
  infoStore->getHistoryName(subject, namebuf);
  SecureHistory *subjectHistory = SecureHistory::open(namebuf, "w", transport);
  
  bool logCanBeAppended = false;
  long long topSeq = 0;
  if (subjectHistory) {
    subjectHistory->getTopLevelEntry(NULL, &topSeq);
    if (topSeq >= fromSeq) 
      logCanBeAppended = true;
  } else {
    logCanBeAppended = true;
  }

  /* If it should not be replayed (e.g. because it was retrieved during an investigation), 
     we stop here */
  
  if (!activeAudit[idx].shouldBeReplayed/* && !logCanBeAppended*/) {
    plog(2, "This audit response does not need to be replayed; discarding");
    delete subjectHandle;
    if (subjectHistory)
      delete subjectHistory;
    terminateAudit(idx);
    return;
  }

  /* Add entries to our local copy of the subject's history */
  
  plog(2, "Adding entries in snippet to log '%s'", namebuf);
  if (!logCanBeAppended)
    panic("Cannot append snippet to local copy of node's history; there appears to be a gap (%lld-%lld)!", topSeq, fromSeq);
  
  if (!subjectHistory) {
    subjectHistory = SecureHistory::create(namebuf, initialCurrentSeq-1, initialNodeHash, transport);
    if (!subjectHistory)
      panic("Cannot create subject history: '%s'", namebuf);
  }
  
  long long firstNewSeq = currentSeq - (currentSeq%1000) + 1000;
  EvidenceTool::appendSnippetToHistory(&snippet[initialReadPtr], snippetLen - initialReadPtr, subjectHistory, peerreview, initialCurrentSeq, firstNewSeq);
#warning need to verify older authenticators against history

  if (replayEnabled) {

    /* We need to replay the log segment, so let's find the last checkpoint */

    unsigned char markerTypes[1] = { EVT_CHECKPOINT };
    int lastCheckpointIdx = subjectHistory->findLastEntry(markerTypes, 1, fromSeq);

    plog(4, "LastCheckpointIdx=%d (up to %lld)", lastCheckpointIdx, fromSeq);

    if (lastCheckpointIdx < 0) {
      warning("Cannot find last checkpoint in subject history %s", namebuf);
  //    if (subjectHistory->getNumEntries() >= MAX_ENTRIES_BETWEEN_CHECKPOINTS)
  //      panic("TODO: Must generate proof due to lack of checkpoints");

      delete subjectHistory;
      delete subjectHandle;
      terminateAudit(idx);
      return;
    }

    /* Create a Verifier instance and get a Replay instance from the application */

    Verifier *verifier = new Verifier(peerreview, subjectHistory, subjectHandle, signatureSizeBytes, hashSizeBytes, lastCheckpointIdx, fromSeq/1000, extInfo, extInfoLen);
    PeerReviewCallback *replayApp = app->getReplayInstance(verifier);
    if (!replayApp)
      panic("Application returned NULL when getReplayInstance() was called");

    verifier->setApplication(replayApp);

    activeAudit[idx].verifier = verifier;
    activeAudit[idx].isReplaying = true;

    plog(1, "REPLAY ============================================");
    plog(2, "Node being replayed: %s", subjectHandle->render(buf1));
    plog(2, "Range in log       : %lld-%lld", fromSeq, toSeq);

    /* Do the replay */

    while (verifier->makeProgress());

    bool verifiedOK = verifier->verifiedOK(); 
    plog(1, "END OF REPLAY: %s =================", verifiedOK ? "VERIFIED OK" : "VERIFICATION FAILED");

    /* If there was a divergence, we have a proof of misbehavior */

    if (!verifiedOK) {
      FILE *outfile = tmpfile();
      if (!subjectHistory->serializeRange(lastCheckpointIdx, subjectHistory->getNumEntries()-1, NULL, outfile))
        panic("Cannot serialize range for PROOF");

      int snippet2size = ftell(outfile);
      long long lastCheckpointSeq;
      if (!subjectHistory->statEntry(lastCheckpointIdx, &lastCheckpointSeq, NULL, NULL, NULL, NULL))
        panic("Cannot stat checkpoint entry");

      warning("Audit revealed a protocol violation; filing evidence (snippet from %lld)", lastCheckpointSeq);

      unsigned int maxProofLen = 1+authenticatorSizeBytes+MAX_HANDLE_SIZE+sizeof(long long)+snippet2size;
      unsigned char *proof = (unsigned char*)malloc(maxProofLen);
      unsigned int proofLen = 0;
      writeByte(proof, &proofLen, PROOF_NONCONFORMANT);
      writeBytes(proof, &proofLen, toAuthenticator, authenticatorSizeBytes);
      subjectHandle->write(proof, &proofLen, maxProofLen);
      writeLongLong(proof, &proofLen, lastCheckpointSeq);
      fseek(outfile, 0, SEEK_SET);
      fread(&proof[proofLen], snippet2size, 1, outfile);
      proofLen += snippet2size;
      assert(proofLen <= maxProofLen);

      long long evidenceSeq = peerreview->getEvidenceSeq();
      infoStore->addEvidence(transport->getLocalHandle()->getIdentifier(), subject, evidenceSeq, proof, proofLen);
      peerreview->sendEvidenceToWitnesses(subject, evidenceSeq, proof, proofLen);
    } 
  } else {
    delete subjectHandle;
    delete subjectHistory;
  }

  /* Terminate the audit, and remember the last authenticator for further reference */

  plog(2, "Audit completed; terminating");  
  infoStore->setLastCheckedAuth(activeAudit[idx].target->getIdentifier(), &activeAudit[idx].request[reqHdrSize+2+authenticatorSizeBytes]);
  terminateAudit(idx);
}

int AuditProtocol::findOngoingAudit(Identifier *subject, long long evidenceSeq)
{
  for (int i=0; i<numActiveAudits; i++) {
    if (!activeAudit[i].isReplaying && subject->equals(activeAudit[i].target->getIdentifier()) && (activeAudit[i].evidenceSeq == evidenceSeq)) 
      return i;
  }
  
  return -1;
}

bool AuditProtocol::statOngoingAudit(Identifier *subject, long long evidenceSeq, unsigned char **evidence, int *evidenceLen)
{
  int idx = findOngoingAudit(subject, evidenceSeq);
  if (idx < 0) {
    *evidence = NULL;
    *evidenceLen = 0;
    return false;
  }

  *evidence = &activeAudit[idx].request[1+peerreview->getIdentifierSizeBytes()+sizeof(long long)];
  *evidenceLen = 2+2*authenticatorSizeBytes;
  return true;
}

/* Handle an incoming datagram, which could be either a request for autheticators, or a response to such a request */

void AuditProtocol::handleIncomingDatagram(NodeHandle *handle, unsigned char *message, int msglen)
{
  char buf1[256], buf2[256];
  
  switch (message[0]) {
    case MSG_AUTHREQ: /* Request for authenticators */
      if (msglen == (int)(1+sizeof(long long)+peerreview->getIdentifierSizeBytes())) {

        /* The request contains a timestamp T; we're being asked to return two authenticators,
           one has to be older than T, and the other must be as recent as possible */
        
        unsigned int pos = 1;
        long long since = readLongLong(message, &pos);
        Identifier *id = peerreview->readIdentifier(message, &pos, msglen);
        plog(1, "Received authenticator request for %s (since %lld)", id->render(buf1), since);
        
        unsigned char response[1+peerreview->getIdentifierSizeBytes()+2*authenticatorSizeBytes];
        bool canRespond = true;
        pos = 0;
        writeByte(response, &pos, MSG_AUTHRESP);
        id->write(response, &pos, sizeof(response));
        
        /* There are several places we might find 'old' authenticators. Check all of them,
           and pick the authenticator that is closest to T */
        
        unsigned char a1[authenticatorSizeBytes];
        bool haveA1 = authInStore->getLastAuthenticatorBefore(id, since, a1);
        long long seq1 = *(long long*)&a1;
        unsigned char a2[authenticatorSizeBytes];
        bool haveA2 = authCacheStore->getLastAuthenticatorBefore(id, since, a2);
        long long seq2 = *(long long*)&a2;
        unsigned char a3[authenticatorSizeBytes];
        bool haveA3 = authInStore->getOldestAuthenticator(id, a3);
        long long seq3 = *(long long*)&a3;
        
        unsigned char best[authenticatorSizeBytes];
        bool haveBest = false;
        long long seqBest = -1;
        
        if (haveA1 && (!haveBest || (!(seqBest<since) && (seq1<since)) || ((seqBest<since) && (seq1<since) && (seqBest<seq1)))) {
          memcpy(best, a1, authenticatorSizeBytes);
          seqBest = seq1;
          haveBest = true;
        }

        if (haveA2 && (!haveBest || (!(seqBest<since) && (seq2<since)) || ((seqBest<since) && (seq2<since) && (seqBest<seq2)))) {
          memcpy(best, a2, authenticatorSizeBytes);
          seqBest = seq2;
          haveBest = true;
        }

        if (haveA3 && (!haveBest || (!(seqBest<since) && (seq3<since)) || ((seqBest<since) && (seq3<since) && (seqBest<seq3)))) {
          memcpy(best, a3, authenticatorSizeBytes);
          seqBest = seq3;
          haveBest = true;
        }
        
        if (haveBest) {
          memcpy(&response[pos], best, authenticatorSizeBytes);
        } else {
          canRespond = false;
        }
        
        /* Recent authenticators can be found in two places; check both */
        
        if (!authInStore->getMostRecentAuthenticator(id, &response[pos+authenticatorSizeBytes])) {
          if (!authCacheStore->getMostRecentAuthenticator(id, &response[pos+authenticatorSizeBytes]))
            canRespond = false;
        }
        
        pos += 2*authenticatorSizeBytes;
        assert(pos == sizeof(response));
        
        if (canRespond)
          peerreview->transmit(handle, true, response, pos);
        else
          warning("Cannot respond to this request; we don't have any authenticators for %s", id->render(buf1));
        
        delete id;
      } else {
        warning("AUTHREQ with incorrect length (%d bytes); discarding", msglen);
      }
      
      break;
    case MSG_AUTHRESP: /* Response to a request for authenticators */
      if (msglen == (int)(1+peerreview->getIdentifierSizeBytes()+2*authenticatorSizeBytes)) {
        unsigned int pos = 1;
        Identifier *id = peerreview->readIdentifier(message, &pos, msglen);
        unsigned char *authFrom = &message[pos];
        unsigned char *authTo = &message[pos+authenticatorSizeBytes];
        plog(2, "Received AUTHRESP(<%s>, %lld..%lld) from %s", id->render(buf1), *(long long*)authFrom, *(long long*)authTo, handle->render(buf2));

#warning must check signatures here        
        int idx = -1;
        for (int i=0; i<numActiveInvestigations; i++) {
          if (activeInvestigation[i].target->getIdentifier()->equals(id))
            idx = i;
        }
        
        if (idx >= 0) {
          long long authFromSeq = *(long long*)authFrom;
          if (!activeInvestigation[idx].authFrom || (authFromSeq<*(long long*)&activeInvestigation[idx].authFrom)) {
            if (!activeInvestigation[idx].authFrom)
              activeInvestigation[idx].authFrom = (unsigned char*) malloc(authenticatorSizeBytes);

            memcpy(activeInvestigation[idx].authFrom, authFrom, authenticatorSizeBytes);
          }
          
          long long authToSeq = *(long long*)authTo;
          if (!activeInvestigation[idx].authTo || (authToSeq>*(long long*)&activeInvestigation[idx].authTo)) {
            if (!activeInvestigation[idx].authTo)
              activeInvestigation[idx].authTo = (unsigned char*) malloc(authenticatorSizeBytes);

            memcpy(activeInvestigation[idx].authTo, authTo, authenticatorSizeBytes);
          }
        } else {
          warning("AUTH response does not match any ongoing investigations; ignoring");
        }
      } else {
        warning("AUTHRESP with incorrect length (%d bytes); discarding", msglen);
      }
      
      break;
    default:
      panic("AuditProtocol cannot handle incoming datagram type #%d", message[0]);
  }
}

/* Starts an investigation by sending authenticator requests to all the witnesses. Most of them are (hopefully)
   going to respond; we're going to pick the authenticators that work best for us. */

void AuditProtocol::sendInvestigation(int idx)
{
  assert((0<=idx) && (idx<numActiveInvestigations));

  unsigned char authenticatorRequest[1+sizeof(long long)+peerreview->getIdentifierSizeBytes()];
  unsigned int pos = 0;
  writeByte(authenticatorRequest, &pos, MSG_AUTHREQ);
  writeLongLong(authenticatorRequest, &pos, activeInvestigation[idx].since);
  activeInvestigation[idx].target->getIdentifier()->write(authenticatorRequest, &pos, sizeof(authenticatorRequest));

  evidenceTransferProtocol->sendMessageToWitnesses(activeInvestigation[idx].target->getIdentifier(), true, authenticatorRequest, pos);
}

/* Start an investigation */

void AuditProtocol::investigate(NodeHandle *target, long long since)
{
  char buf1[200];

  if (numActiveInvestigations >= MAX_ACTIVE_INVESTIGATIONS) {
    warning("Too many active investigations; refusing to investigate %s at this time", target->render(buf1));
    return;
  }
  
  int idx = -1;
  for (int i=0; i<numActiveInvestigations; i++) {
    if (activeInvestigation[i].target->equals(target))
      idx = i;
  }
  
  if (idx >= 0) {
    if (since > activeInvestigation[idx].since) {
      plog(2, "Skipping investigation request for %s at %lld, since an investigation at %lld is already ongoing", target->render(buf1), since, activeInvestigation[idx].since);
      return;
    }
    
    plog(2, "Extending existing investigation from %lld to %lld", activeInvestigation[idx].since, since * 1000ULL);
    activeInvestigation[idx].since = since * 1000ULL; /* log granularity */
  } else {
    idx = numActiveInvestigations ++;
    activeInvestigation[idx].target = target->clone();
    activeInvestigation[idx].since = since * 1000ULL; /* log granularity */
    activeInvestigation[idx].currentTimeout = peerreview->getTime() + INVESTIGATION_INTERVAL_MICROS;
    activeInvestigation[idx].authFrom = NULL;
    activeInvestigation[idx].authTo = NULL;
  }

  sendInvestigation(idx);

  if (!progressTimerActive) {
    progressTimerActive = true;
    transport->scheduleTimer(this, TI_MAKE_PROGRESS, peerreview->getTime() + PROGRESS_INTERVAL_MICROS);
  }
}
