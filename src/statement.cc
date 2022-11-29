#include <stdlib.h>
#include <string.h>

#include "peerreview.h"

#define SUBSYSTEM "peerreview"
#define VERBOSE

#ifdef VERBOSE
#define vlog(a...) plog(a)
#else
#define vlog(a...) do { } while (0)
#endif

StatementProtocol::StatementProtocol(PeerReview *peerreview, ChallengeResponseProtocol *challengeProtocol, PeerInfoStore *infoStore, IdentityTransport *transport, int hashSizeBytes, PeerReviewCallback *app)
{
  this->numIncompleteStatements = 0;
  this->challengeProtocol = challengeProtocol;
  this->transport = transport;
  this->infoStore = infoStore;
  this->signatureSizeBytes = transport->getSignatureSizeBytes();
  this->hashSizeBytes = hashSizeBytes;
  this->progressTimerActive = false;
  this->peerreview = peerreview;
  this->authenticatorSizeBytes = sizeof(long long) + hashSizeBytes + signatureSizeBytes;
  this->app = app;
}

StatementProtocol::~StatementProtocol()
{
  for (int i=0; i<numIncompleteStatements; i++)  {
    free(incompleteStatement[i].statement);
    if (incompleteStatement[i].isMissingCertificate)
      delete incompleteStatement[i].missingCertificateID;
    delete incompleteStatement[i].sender;
  }
}

/* Called if we have received a certificate for a new nodeID. If any messages in our queue were
   waiting for this certificate, we may be able to forward them now. */

void StatementProtocol::notifyCertificateAvailable(Identifier *id)
{
  for (int i=0; i<numIncompleteStatements; i++) {
    if (!incompleteStatement[i].finished && incompleteStatement[i].isMissingCertificate && id->equals(incompleteStatement[i].missingCertificateID)) 
      makeProgressOnStatement(i);
  }
}

/* If a message hangs around in our queue for too long, we discard it */

void StatementProtocol::cleanupIncompleteStatements()
{
  long long now = peerreview->getTime();
  char buf1[256];
  
  for (int i=0; i<numIncompleteStatements; ) {
    if (incompleteStatement[i].finished || (incompleteStatement[i].currentTimeout < now)) {
      if (!incompleteStatement[i].finished) {
        warning("Statement by %s is incomplete after the timeout; discarding", incompleteStatement[i].sender->render(buf1));
        if (incompleteStatement[i].statement)
          peerreview->dump(2, incompleteStatement[i].statement, incompleteStatement[i].statementLen);
      }
        
      if (incompleteStatement[i].statement)
        free(incompleteStatement[i].statement);
      if (incompleteStatement[i].isMissingCertificate)
        delete incompleteStatement[i].missingCertificateID;
      delete incompleteStatement[i].sender;
      
      incompleteStatement[i] = incompleteStatement[--numIncompleteStatements];
    } else {
      i++;
    }
  }
}

/* We use a periodic timer to throw out stale messages */

void StatementProtocol::timerExpired(int timerID)
{
  assert(timerID == TI_MAKE_PROGRESS);
  cleanupIncompleteStatements();
  if (numIncompleteStatements > 0)
    transport->scheduleTimer(this, TI_MAKE_PROGRESS, peerreview->getTime() + PROGRESS_INTERVAL_MICROS);
  else
    progressTimerActive = false;
}

/* Incoming ACCUSTION and RESPONSE messages come here first. We check whether we have all the necessary
   nodeID certificates; if not, we request them from the sender. */

void StatementProtocol::handleIncomingStatement(NodeHandle *source, const unsigned char *statement, int statementLen)
{
  assert((statementLen >= 1) && ((statement[0] == MSG_ACCUSATION) || (statement[0] == MSG_RESPONSE)));
  char buf1[256];

  plog(1, "Incoming %s from %s", (statement[0] == MSG_ACCUSATION) ? "accusation" : "response", source->render(buf1));

  /* Some sanity checks */

  if (statementLen < (int)(1+2*peerreview->getIdentifierSizeBytes()+sizeof(long long)+1)) {
peerreview->dump(2, statement, statementLen);  
    warning("Node %s sent a statement that is too short to be plausible; discarding", source->render(buf1));
    return;
  }

  /* Find an empty spot in our message buffer and store the message there */

  if (numIncompleteStatements >= MAX_INCOMPLETE_STATEMENTS) {
    warning("Too many incomplete statements; discarding");
    return;
  }
  
  int idx = numIncompleteStatements ++;
  incompleteStatement[idx].finished = false;
  incompleteStatement[idx].sender = source->clone();
  incompleteStatement[idx].currentTimeout = peerreview->getTime() + STATEMENT_COMPLETION_TIMEOUT_MICROS;
  incompleteStatement[idx].statement = (unsigned char*) malloc(statementLen);
  incompleteStatement[idx].statementLen = statementLen;
  memcpy(incompleteStatement[idx].statement, statement, statementLen);
  incompleteStatement[idx].isMissingCertificate = false;
  incompleteStatement[idx].missingCertificateID = NULL;
  
  /* Then call our central do-something-useful function */
  
  makeProgressOnStatement(idx);
  cleanupIncompleteStatements();
}

/* This reads a log snippet entry by entry, looks up all the nodeIDs that are mentioned, and 
   requests the first nodeID certificate we don't have locally. Also, it checks if the snipped 
   is malformed in any way. That way, the other protocols won't have to do all these sanity 
   checks later. */

int StatementProtocol::checkSnippetAndRequestCertificates(unsigned char *snippet, unsigned int snippetLen, int idx)
{
  char buf1[256];
  Identifier *missingCertID = NULL;

  int code = EvidenceTool::checkSnippet(snippet, snippetLen, &missingCertID, peerreview);

  if (code == EvidenceTool::CERT_MISSING) {
    assert(missingCertID != NULL);

    incompleteStatement[idx].isMissingCertificate = true;
    incompleteStatement[idx].missingCertificateID = missingCertID;
    plog(2, "AUDIT RESPONSE requires certificate for %s; requesting", missingCertID->render(buf1));
    transport->requestCertificate(incompleteStatement[idx].sender, missingCertID);  
  }

  return code;
}

/* Tries to make progress on some waiting message. We try to either (a) request a certificate
   we need but don't have, (b) forward the message to another protocol, or (c) discard
   the message because it's malformed. */

void StatementProtocol::makeProgressOnStatement(int idx)
{
  int identifierSizeBytes = peerreview->getIdentifierSizeBytes();
  char buf1[256];
  assert((0<=idx) && (idx<numIncompleteStatements) && !incompleteStatement[idx].finished);
  assert(incompleteStatement[idx].statementLen >= (int)(1+2*identifierSizeBytes+sizeof(long long)+1));

  /* Fetch the statement and reset all the 'missing' fields */

  unsigned char *statement = incompleteStatement[idx].statement;
  int statementLen = incompleteStatement[idx].statementLen;
  incompleteStatement[idx].isMissingCertificate = false;
  if (incompleteStatement[idx].missingCertificateID)
    delete incompleteStatement[idx].missingCertificateID;
  
  unsigned int pos = 1;
  Identifier *originator = peerreview->readIdentifier(statement, &pos, statementLen);
  Identifier *subject = peerreview->readIdentifier(statement, &pos, statementLen);
  long long timestamp = readLongLong(statement, &pos);
  unsigned char *payload = &statement[pos];
  int payloadLen = statementLen - pos;
  
#if 0
  /* Retrieve the originator's public key if we don't have it already */
  
  if (!transport->haveCertificate(originator)) {
    plog(2, "Need originator's certificate to verify statement; asking source for it");
    incompleteStatement[idx].isMissingCertificate = true;
    incompleteStatement[idx].missingCertificateID = originator->clone();
    transport->requestCertificate(incompleteStatement[idx].sender, originator);
    delete originator;
    delete subject;
    return;
  }
  
  delete originator;
  originator = NULL;
#endif
  
  /* Retrieve the subject's public key if we don't have it already */

  if (!transport->haveCertificate(subject)) {
    plog(2, "Need subject's certificate to verify statement; asking source for it");
    incompleteStatement[idx].isMissingCertificate = true;
    incompleteStatement[idx].missingCertificateID = subject->clone();
    transport->requestCertificate(incompleteStatement[idx].sender, subject);
    delete subject;
    return;
  }
  
  unsigned char subjectAsBytes[identifierSizeBytes];
  unsigned int subjectAsBytesLen = 0;
  subject->write(subjectAsBytes, &subjectAsBytesLen, sizeof(subjectAsBytes));
  
  /* Further checking depends on the type of the statement. At this point, we may still request
     additional material from the sender, if it becomes necessary. */
  
  if (statement[0] == MSG_ACCUSATION) {
  
    /* === CHECK ACCUSATIONS === */
  
    switch (payload[0]) {
      case CHAL_AUDIT :
      {
        if (payloadLen != (2+2*authenticatorSizeBytes)) {
          warning("AUDIT challenge has incorrect length; discarding");
          incompleteStatement[idx].finished = true;
          goto out;
        }

        unsigned char innerHash[hashSizeBytes];
        transport->hash(innerHash, &payload[2], authenticatorSizeBytes - signatureSizeBytes);
        if (transport->verify(subject, innerHash, hashSizeBytes, &payload[2+authenticatorSizeBytes-signatureSizeBytes]) != IdentityTransport::SIGNATURE_OK) {
          warning("AUDIT challenge's first authenticator has an invalid signature");
          incompleteStatement[idx].finished = true;
          goto out;
        }

        transport->hash(innerHash, &payload[2+authenticatorSizeBytes], authenticatorSizeBytes - signatureSizeBytes);
        if (transport->verify(subject, innerHash, hashSizeBytes, &payload[2+2*authenticatorSizeBytes-signatureSizeBytes]) != IdentityTransport::SIGNATURE_OK) {
          warning("AUDIT challenge's second authenticator has an invalid signature");
          incompleteStatement[idx].finished = true;
          goto out;
        }

        break;
      }
      case CHAL_SEND :
      {
        if (payloadLen <= (int)(1+identifierSizeBytes+sizeof(long long)+hashSizeBytes+signatureSizeBytes+sizeof(char))) {
          warning("SEND challenge has incorrect length; discarding");
          incompleteStatement[idx].finished = true;
          goto out;
        }
        
        unsigned int pos3 = 1;
        long long seq = readLongLong(payload, &pos3);
        NodeHandle *sender = peerreview->readNodeHandle(payload, &pos3, payloadLen);
        unsigned char *hTopMinusOne = &payload[pos3];
        pos3 += hashSizeBytes;
        unsigned char *signature = &payload[pos3];
        pos3 += signatureSizeBytes;
        unsigned char relevantCode = readByte(payload, &pos3);
        unsigned char *innerPayload = &payload[pos3];
        int innerPayloadLen = payloadLen - pos3;
        int relevantLen = (relevantCode == 0xFF) ? innerPayloadLen : relevantCode;
        assert(innerPayloadLen > 0);
        
        unsigned char innerHash[hashSizeBytes];
        if (relevantLen < innerPayloadLen) {
          unsigned char irrelevantHash[hashSizeBytes];
          unsigned char header[subjectAsBytesLen+1];
          memcpy(&header[0], &subjectAsBytes, subjectAsBytesLen);
          header[subjectAsBytesLen] = 1;
          transport->hash(irrelevantHash, &innerPayload[relevantLen], innerPayloadLen - relevantLen);
          transport->hash(innerHash, (const unsigned char*)&header, sizeof(header), (const unsigned char*)innerPayload, relevantLen, irrelevantHash, hashSizeBytes);
        } else {
          unsigned char header[subjectAsBytesLen+1];
          memcpy(&header[0], &subjectAsBytes, subjectAsBytesLen);
          header[subjectAsBytesLen] = 0;
          transport->hash(innerHash, (const unsigned char*)&header, sizeof(header), (const unsigned char*)innerPayload, innerPayloadLen);
        }
    
        // NOTE: This call puts the authenticator in our authInStore. This is intentional! Otherwise the bad guys
        // could fork their logs and send forked messages only as CHAL_SENDs.

        unsigned char authenticator[sizeof(seq) + hashSizeBytes + signatureSizeBytes];
        if (!peerreview->extractAuthenticator(sender->getIdentifier(), seq, EVT_SEND, innerHash, hTopMinusOne, signature, authenticator)) {
          warning("Message in SEND challenge is not properly signed; discarding");
          incompleteStatement[idx].finished = true;
          delete sender;
          goto out;
        }
        
        delete sender;
        break;
      }
      case PROOF_INCONSISTENT :
      {
        if (payloadLen < 2+2*authenticatorSizeBytes) {
          warning("INCONSISTENT proof is too short; discarding");
          incompleteStatement[idx].finished = true;
          goto out;
        }
        
        unsigned char *auth1 = &payload[1];
        unsigned char whichInconsistency = payload[1+authenticatorSizeBytes];
        unsigned char *auth2 = &payload[2+authenticatorSizeBytes];
        unsigned char signedHash[hashSizeBytes];
        
        transport->hash(signedHash, auth1, sizeof(long long)+hashSizeBytes);
        if (transport->verify(subject, signedHash, hashSizeBytes, &auth1[sizeof(long long)+hashSizeBytes]) != IdentityTransport::SIGNATURE_OK) {
          warning("INCONSISTENT proof's first authenticator has an invalid signature");
          incompleteStatement[idx].finished = true;
          goto out;
        }

        transport->hash(signedHash, auth2, sizeof(long long)+hashSizeBytes);
        if (transport->verify(subject, signedHash, hashSizeBytes, &auth2[sizeof(long long)+hashSizeBytes]) != IdentityTransport::SIGNATURE_OK) {
          warning("INCONSISTENT proof's second authenticator has an invalid signature");
          incompleteStatement[idx].finished = true;
          goto out;
        }

        switch (whichInconsistency) {
          case 0 :
          {
            long long seq1 = *(long long*)auth1;
            long long seq2 = *(long long*)auth2;
            
            if (seq1 != seq2) {
              warning("INCONSISTENT-0 proof's authenticators don't have matching sequence numbers (seq1=%lld, seq2=%lld) -- discarding", seq1, seq2);
              incompleteStatement[idx].finished = true;
              goto out;
            }
            
            unsigned char *hash1 = &auth1[sizeof(long long)];
            unsigned char *hash2 = &auth2[sizeof(long long)];
            if (!memcmp(hash1, hash2, hashSizeBytes)) {
              warning("INCONSISTENT-0 proof's authenticators have the same hash -- discarding", seq1, seq2);
              incompleteStatement[idx].finished = true;
              goto out;
            }
            
            break;
          }
          case 1 :
          {
            long long seq1 = *(long long*)auth1;
            long long seq2 = *(long long*)auth2;
            unsigned char *hash1 = &auth1[sizeof(long long)];
            unsigned char *hash2 = &auth2[sizeof(long long)];

            unsigned int xpos = 2+2*authenticatorSizeBytes;
            unsigned char extInfoLen = ((xpos+sizeof(long long))<payloadLen) ? payload[xpos+sizeof(long long)] : 0;

            if (payloadLen < (xpos + sizeof(long long) + 1 + extInfoLen + hashSizeBytes)) {
              warning("INCONSISTENT-1 proof is too short (case #2); discarding");
              incompleteStatement[idx].finished = true;
              goto out;
            }
            
            long long firstSeq = *(long long*)&payload[xpos];
            unsigned char *baseHash = &payload[xpos+sizeof(long long)+1+extInfoLen];
            unsigned char *snippet = &payload[xpos+sizeof(long long)+1+extInfoLen+hashSizeBytes];
            int snippetLen = payloadLen - (xpos+sizeof(long long)+1+extInfoLen+hashSizeBytes);
            
            assert(snippetLen >= 0);
            
            if (!((firstSeq<seq2) && (seq2<seq1))) {
              warning("INCONSISTENT-1 proof's sequence numbers do not make sense (first=%lld, seq2=%lld, seq1=%lld) -- discarding", firstSeq, seq2, seq1);
              incompleteStatement[idx].finished = true;
              goto out;
            }
            
            if (!EvidenceTool::checkHashChainContains(snippet, snippetLen, firstSeq, baseHash, hash1, seq1, transport)) {
              warning("Snippet in INCONSISTENT-1 proof cannot be authenticated using first authenticator (#%lld) -- discarding", seq1);
              incompleteStatement[idx].finished = true;
              goto out;
            }
            
            if (EvidenceTool::checkHashChainContains(snippet, snippetLen, firstSeq, baseHash, hash2, seq2, transport)) {
              warning("INCONSISTENT-1 proof claims that authenticator 2 (#%lld) is not in the snippet, but it is -- discarding", seq2);
              incompleteStatement[idx].finished = true;
              goto out;
            }

            break;
          }
          default:
          {
            warning("INCONSISTENT proof has an unknown inner type -- discarding");
            incompleteStatement[idx].finished = true;
            goto out;
          }
        }
        
        break;
      }
      case PROOF_NONCONFORMANT :
      {
        char buf1[200];
        unsigned int pos = 1;
        unsigned char *auth = &payload[pos];
        pos += authenticatorSizeBytes;
        NodeHandle *subjectHandle = peerreview->readNodeHandle(payload, &pos, payloadLen);
        long long firstSeq = readLongLong(payload, &pos);
        unsigned char *baseHash = &payload[pos];
        pos += hashSizeBytes;

        /* Is the authenticator properly signed? */

        unsigned char signedHash[hashSizeBytes];
        transport->hash(signedHash, auth, sizeof(long long)+hashSizeBytes);
        if (transport->verify(subject, signedHash, hashSizeBytes, &auth[sizeof(long long)+hashSizeBytes]) != IdentityTransport::SIGNATURE_OK) {
          warning("NONCONFORMANT proof's authenticator has an invalid signature");
          incompleteStatement[idx].finished = true;
          delete subjectHandle;
          goto out;
        }

        /* Is the snippet well-formed, and do we have all the certificates? */

        switch (checkSnippetAndRequestCertificates(&payload[pos], payloadLen - pos, idx)) {
          case EvidenceTool::INVALID:
            warning("PROOF NONCONFORMANT is not well-formed; discarding");
            incompleteStatement[idx].finished = true;
            delete subjectHandle;
            goto out;
          case EvidenceTool::CERT_MISSING:
            delete subjectHandle;
            goto out;
          default:
            break;
        }

        /* Are the signatures in the snippet okay, and does it contain the authenticated node? */
        
        if (!EvidenceTool::checkSnippetSignatures(&payload[pos], payloadLen - pos, firstSeq, baseHash, subjectHandle, NULL, FLAG_INCLUDE_CHECKPOINT, peerreview, peerreview, NULL, &auth[sizeof(long long)], *(long long*)&auth[0])) {
          warning("PROOF NONCONFORMANT cannot be validated (signatures or authenticator)");
          delete subjectHandle;
          goto out;
        }
        
        /* Now we are convinced that 
             - the authenticator is valid
             - the snippet is well-formed, and we have all the certificates
             - the snippet starts with a checkpoint and contains the authenticated node 
           We must now replay the log; if the proof is valid, it won't check out. */

        SecureHistory *subjectHistory = SecureHistory::createTemp(firstSeq-1, baseHash, transport);
        EvidenceTool::appendSnippetToHistory(&payload[pos], payloadLen - pos, subjectHistory, peerreview, firstSeq, -1);

#warning ext info missing
        Verifier *verifier = new Verifier(peerreview, subjectHistory, subjectHandle, signatureSizeBytes, hashSizeBytes, 1, firstSeq/1000, NULL, 0);
        PeerReviewCallback *replayApp = app->getReplayInstance(verifier);
        verifier->setApplication(replayApp);

        plog(1, "REPLAY ============================================");
        plog(2, "Node being replayed: %s", subjectHandle->render(buf1));
        plog(2, "Range in log       : %lld-?", firstSeq);

        while (verifier->makeProgress());
        bool verifiedOK = verifier->verifiedOK();
        delete verifier;
        delete subjectHandle;
        
        if (verifiedOK) {
          warning("PROOF NONCONFORMANT contains a log snippet that actually is conformant; discarding");
          goto out;
        }
        
        break;        
      }
      default :
      {
        warning("Unknown payload type #%d in accusation; discarding", payload[0]);
        incompleteStatement[idx].finished = true;
        goto out;
      }
    }
  } else {
  
    /* === CHECK RESPONSES === */
  
    switch (payload[0]) {
      
      /* To check an AUDIT RESPONSE, we need to verify that:
            - it is well-formed
            - we have certificates for all senders occurring in RECV entries 
         We do NOT check signatures, sequence numbers, or whether the content makes any
         sense at all. We also do NOT check whether this is a valid response to some
         specific challenge.
      */
    
      case CHAL_AUDIT :
      {
        if (payloadLen < (int)(sizeof(long long)+hashSizeBytes+1+1)) {
          warning("AUDIT RESPONSE is too short; discarding");
          incompleteStatement[idx].finished = true;
          goto out;
        }

        plog(2, "Checking AUDIT RESPONSE statement");
        
        int readptr = 0;
        readByte(payload, (unsigned int*)&readptr); /* RESP_AUDIT */
        NodeHandle *subjectHandle = peerreview->readNodeHandle(payload, (unsigned int*)&readptr, payloadLen);
        readptr += sizeof(long long);
        readptr += 1 + payload[readptr];
        readptr += hashSizeBytes;
        delete subjectHandle;

        switch (checkSnippetAndRequestCertificates(&payload[readptr], payloadLen - readptr, idx)) {
          case EvidenceTool::INVALID:
            warning("AUDIT RESPONSE is not well-formed; discarding");
            incompleteStatement[idx].finished = true;
            goto out;
          case EvidenceTool::CERT_MISSING:
            goto out;
          default:
            break;
        }

        break;
      }
      
      case CHAL_SEND:
      {
        if (payloadLen != (int)(1+identifierSizeBytes+2*sizeof(long long)+hashSizeBytes+signatureSizeBytes)) {
          warning("SEND RESPONSE does not have the correct length; discarding");
          incompleteStatement[idx].finished = true;
          goto out;
        }
        
        break;
      }
      
      default :
      {
        warning("Unknown payload type #%d in response; discarding", payload[0]);
        incompleteStatement[idx].finished = true;
        goto out;
      }
    }
  }
  
  /* At this point, we are convinced that the statement is valid, and we have all the 
     necessary supplemental material to be able to check it and any responses to it */

  challengeProtocol->handleStatement(incompleteStatement[idx].sender, statement, statementLen);
  incompleteStatement[idx].finished = true;

out:
  delete subject;
}

