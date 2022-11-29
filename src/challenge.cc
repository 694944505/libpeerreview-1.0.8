#include <stdlib.h>
#include <string.h>

#include "peerreview.h"

#define SUBSYSTEM "peerreview"

/* When a log segment is sent, not all entries need to be included; some can be replaced
   by their hashes. The following policy object makes this decision for each entry. */

class ChallengeHashPolicy : public HashPolicy {
protected:
  unsigned char flags;
  unsigned char *originatorAsBytes;
  int identifierSizeBytes;
  bool includeNextCheckpoint;
  bool includeNextSendSign;
  
public:
  ChallengeHashPolicy(unsigned char flags, unsigned char *originatorAsBytes, int identifierSizeBytes);
  virtual ~ChallengeHashPolicy();
  virtual bool hashEntry(unsigned int type, unsigned char *content, int contentLen);
};

ChallengeHashPolicy::ChallengeHashPolicy(unsigned char flags, unsigned char *originatorAsBytes, int identifierSizeBytes) : HashPolicy()
{
  this->includeNextCheckpoint = ((flags & FLAG_INCLUDE_CHECKPOINT)>0);
  this->includeNextSendSign = false;
  this->identifierSizeBytes = identifierSizeBytes;
  this->flags = flags;

  /* If FLAG_FULL_MESSAGES_SENDER is set, we must not hash SEND entries, and we must include
     SENDSIGN entries if they follow a SEND to the specified node */
  
  if (flags & FLAG_FULL_MESSAGES_SENDER) {
    assert(originatorAsBytes != NULL);
    this->originatorAsBytes = (unsigned char*) malloc(identifierSizeBytes); 
    memcpy(this->originatorAsBytes, originatorAsBytes, identifierSizeBytes);
  } else {
    this->originatorAsBytes = NULL;
  }
}

ChallengeHashPolicy::~ChallengeHashPolicy()
{
  if (originatorAsBytes)
    free(originatorAsBytes);
}

bool ChallengeHashPolicy::hashEntry(unsigned int type, unsigned char *content, int contentLen)
{
  switch (type) { 
    case EVT_CHECKPOINT : /* We include at most one checkpoint, and only if FLAG_INCLUDE_CHECKPOINT is set */
      if (includeNextCheckpoint) {
        includeNextCheckpoint = false;
        return false;
      }
      return true;
    case EVT_SEND : /* We include SEND entries only if FLAG_FULL_MESSAGES_{SENDER|ALL} is set */
      if (flags & FLAG_FULL_MESSAGES_ALL)
        return false;
        
      if (originatorAsBytes) {
        if ((contentLen>=identifierSizeBytes) && !memcmp(content, originatorAsBytes, identifierSizeBytes)) 
          includeNextSendSign = true;

        return false;
      }
      return true;
    case EVT_SENDSIGN : /* We only include SENDSIGN entries if they go to the specified target node */
      if (flags & FLAG_FULL_MESSAGES_ALL)
        return false;

      if (includeNextSendSign) {
        includeNextSendSign = false;
        return false;
      }
      return true;
    default :
      break;
  }
  
  return false;
}

ChallengeResponseProtocol::ChallengeResponseProtocol(PeerReview *peerreview, IdentityTransport *transport, PeerInfoStore *infoStore, SecureHistory *history, AuthenticatorStore *authOutStore, AuditProtocol *auditProtocol, CommitmentProtocol *commitmentProtocol, PeerReviewCallback *app)
{
  this->authOutStore = authOutStore;
  this->transport = transport;
  this->peerreview = peerreview;
  this->infoStore = infoStore;
  this->history = history;
  this->auditProtocol = auditProtocol;
  this->commitmentProtocol = commitmentProtocol;
  this->signatureSizeBytes = transport->getSignatureSizeBytes();
  this->hashSizeBytes = transport->getHashSizeBytes();
  this->authenticatorSizeBytes = signatureSizeBytes + hashSizeBytes + sizeof(long long);
  this->queueHead = NULL;
  this->app = app;
  this->extInfoPolicy = NULL;
}

ChallengeResponseProtocol::~ChallengeResponseProtocol()
{
  while (queueHead) {
    struct packetInfo *pi = queueHead;
    queueHead = queueHead->next;
    if (pi->isAccusation) {
      delete pi->subject;
      delete pi->originator;
    }
    free(pi->message);
    delete pi->source;
    free(pi);
  }
}

/* Enqueues a copy of a message */

void ChallengeResponseProtocol::copyAndEnqueueTail(NodeHandle *source, unsigned char *message, int msglen, bool isAccusation, Identifier *subject, Identifier *originator, long long evidenceSeq)
{
  struct packetInfo *pi = (struct packetInfo*) malloc(sizeof(struct packetInfo));
  pi->next = NULL;
  pi->source = source->clone();
  pi->message = (unsigned char*) malloc(msglen);
  memcpy(pi->message, message, msglen);
  pi->msglen = msglen;
  pi->isAccusation = isAccusation;
  pi->subject = subject ? subject->clone() : NULL;
  pi->originator = originator ? originator->clone() : NULL;
  pi->evidenceSeq = evidenceSeq;
  
  if (queueHead == NULL) {
    queueHead = pi;
    return;
  }
  
  struct packetInfo *iter = queueHead;
  while (iter->next)
    iter = iter->next;
    
  iter->next = pi;
}

void ChallengeResponseProtocol::deliver(struct packetInfo *pi)
{
  if (pi->isAccusation)
    infoStore->addEvidence(pi->originator, pi->subject, pi->evidenceSeq, pi->message, pi->msglen, pi->source);
  else
    commitmentProtocol->handleIncomingMessage(pi->source, pi->message, pi->msglen);
}

/* If a node goes back to TRUSTED, we deliver all pending messages. If it goes to EXPOSED, we throw them 
   all away because they won't ever be delivered. */

void ChallengeResponseProtocol::notifyStatusChange(Identifier *id, int newStatus)
{
  assert(!((newStatus == STATUS_SUSPECTED) && (queueHead != NULL)));

  while (queueHead && id->equals(queueHead->source->getIdentifier())) {
    struct packetInfo *pi = queueHead;
    queueHead = queueHead->next;
    if (newStatus == STATUS_TRUSTED)
      deliver(pi);
    delete pi->source;
    if (pi->isAccusation) {
      delete pi->subject;
      delete pi->originator;
    }
    free(pi->message);
    free(pi);
  }
   
  if (!queueHead)
    return;
    
  struct packetInfo *iter = queueHead;
  while (iter->next) {
    if (id->equals(iter->next->source->getIdentifier())) {
      struct packetInfo *pi = iter->next;
      iter->next = pi->next;
      if (newStatus == STATUS_TRUSTED)
        deliver(pi);
      delete pi->source;
      if (pi->isAccusation) {
        delete pi->subject;
        delete pi->originator;
      }
      free(pi->message);
      free(pi);
    } else {
      iter = iter->next;
    }
  }
}

/* Called when another node sends us a challenge. If the challenge is valid, we respond. */

void ChallengeResponseProtocol::handleChallenge(NodeHandle *source, unsigned char *challenge, int challengeLen)
{
  int identifierSizeBytes = peerreview->getIdentifierSizeBytes();
  char buf1[256];

  /* Sanity checks */

  if (challengeLen < (int)(1+identifierSizeBytes+sizeof(long long)+1)) {
    warning("Frivolous challenge from %s (len=%d)", source->render(buf1), challengeLen);
    return;
  }
   
  unsigned int pos = 1;
  unsigned char originatorAsBytes[identifierSizeBytes];
  readBytes(challenge, &pos, originatorAsBytes, identifierSizeBytes);
  long long evidenceSeq = readLongLong(challenge, &pos);
  unsigned char type = readByte(challenge, &pos);
  unsigned char *body = &challenge[pos];
  int bodyLen = challengeLen - pos;
  
  switch (type) {

    /* AUDIT challenges: We respond with a serialized log snippet */
      
    case CHAL_AUDIT:
    {
      /* Some sanity checking */
    
      if (bodyLen != (1+2*authenticatorSizeBytes)) {
        warning("Received an AUDIT challenge with an invalid length (%d)", bodyLen);
        return;
      }
      
      unsigned char flags = body[0];
      long long seqFrom = *(long long*)&body[1];
      long long seqTo = *(long long*)&body[1+authenticatorSizeBytes];
      plog(2, "Received an AUDIT challenge for [%lld,%lld] from %s (eseq=%lld, flags=%d)", seqFrom, seqTo, source->render(buf1), evidenceSeq, flags);
      
      if (seqTo < seqFrom) {
        warning("Received an AUDIT challenge with seqTo<seqFrom");
        return;
      }
      
      if ((seqFrom < history->getBaseSeq()) || (seqTo > history->getLastSeq())) {
        warning("Received an AUDIT whose range [%lld-%lld] is outside our history range [%lld-%lld]",
          seqFrom, seqTo, history->getBaseSeq(), history->getLastSeq()
        );
        return;
      }
       
      /* If the challenge asks for a snippet that starts with a checkpoint (FLAG_INCLUDE_CHECKPOINT set),
         we look up the last such entry; otherwise we start at the specified sequence number */
      
      unsigned char chkpointTypes[2] = { EVT_CHECKPOINT, EVT_INIT };
      int idxFrom = (flags&FLAG_INCLUDE_CHECKPOINT) ? history->findLastEntry(chkpointTypes, sizeof(chkpointTypes), seqFrom) : history->findSeq(seqFrom);
      int idxTo = history->findSeq(seqTo);

      if ((idxFrom >= 0) && (idxTo >= 0)) {
        unsigned char beginType;
        long long beginSeq;
        if (!history->statEntry(idxFrom, &beginSeq, &beginType, NULL, NULL, NULL))
          panic("Cannot get beginSeq during AUDIT challenge");
          
        /* Log entries with consecutive sequence numbers correspond to events that have happened
           'at the same time' (i.e. without updating the clock). In order to be able to replay
           this properly, we need to start at the first such event, which we locate by rounding
           down to the closest multiple of 1000. */
          
        if (((beginSeq % 1000) > 0) && !(flags & FLAG_INCLUDE_CHECKPOINT)) {
          beginSeq -= (beginSeq % 1000);
          idxFrom = history->findSeq(beginSeq);
          plog(4, "Moving beginSeq to %lld (idx=%d)", beginSeq, idxFrom);
          assert(idxFrom >= 0);
        }
        
        /* Similarly, we should always 'round up' to the next multiple of 1000 */
        
        long long followingSeq;
        while (history->statEntry(idxTo+1, &followingSeq, NULL, NULL, NULL, NULL)) {
          if ((followingSeq % 1000) == 0)
            break;
          
          idxTo ++;
          plog(4, "Advancing endSeq past %lld (idx=%d)", followingSeq, idxTo);
        }
        
        unsigned char endType;
        if (!history->statEntry(idxTo, NULL, &endType, NULL, NULL, NULL)) 
          panic("Cannot get endType during AUDIT challenge");
        if (endType == EVT_RECV)
          idxTo ++;

        /* Serialize the requested log snippet */
      
        HashPolicy *hashPolicy = new ChallengeHashPolicy(flags, originatorAsBytes, identifierSizeBytes);
        FILE *outfile = tmpfile();
        if (history->serializeRange(idxFrom, idxTo, hashPolicy, outfile)) {
          int size = ftell(outfile);
          
          unsigned char extInfo[255];
          unsigned int extInfoLen = extInfoPolicy ? extInfoPolicy->storeExtInfo(history, followingSeq, extInfo, sizeof(extInfo)) : 0;
          if (extInfoLen < 0)
            extInfoLen = 0;
          if (extInfoLen > sizeof(extInfo))
            extInfoLen = sizeof(extInfo);
          
          unsigned int maxHeaderLen = 1+2*MAX_ID_SIZE+sizeof(long long)+1+MAX_HANDLE_SIZE+sizeof(long long)+1+extInfoLen;
          unsigned char *buffer = (unsigned char*) malloc(maxHeaderLen+size);
          unsigned int headerLen = 0;
          
          /* Put together a RESPONSE message */
          
          writeByte(buffer, &headerLen, MSG_RESPONSE);
          writeBytes(buffer, &headerLen, originatorAsBytes, identifierSizeBytes);
          transport->getLocalHandle()->getIdentifier()->write(buffer, &headerLen, maxHeaderLen);
          writeLongLong(buffer, &headerLen, evidenceSeq);
          writeByte(buffer, &headerLen, type);
          peerreview->getLocalHandle()->write(buffer, &headerLen, maxHeaderLen);
          writeLongLong(buffer, &headerLen, beginSeq);
          writeByte(buffer, &headerLen, extInfoLen);
          if (extInfoLen>0)
            writeBytes(buffer, &headerLen, extInfo, extInfoLen);
          assert(headerLen <= maxHeaderLen);

          fseek(outfile, 0, SEEK_SET);
          fread(&buffer[headerLen], size, 1, outfile);

          /* ... and send it back to the challenger */

          plog(2, "Answering AUDIT challenge with %d-byte log snippet", size); 
          peerreview->transmit(source, false, buffer, headerLen+size);
          free(buffer);
        } else {
          warning("Error accessing history");
        }

        fclose(outfile);
        delete hashPolicy;
      } else {
        warning("Cannot respond to AUDIT challenge [%lld-%lld,flags=%d]; entries not found (iF=%d/iT=%d)", seqFrom, seqTo, flags, idxFrom, idxTo);
      }
      break;
    }
    
    /* SEND challenges: We accept the message if necessary and then respond with an ACK. At this point,
       the statement protocol has already checked the signature and filed the authenticator. */
    
    case CHAL_SEND:
    {
      int ackMsgLen = 17 + identifierSizeBytes + hashSizeBytes + signatureSizeBytes;
      int responseHeaderLen = 1 + 2*identifierSizeBytes + sizeof(long long);
      unsigned char response[responseHeaderLen + ackMsgLen];
      bool loggedPreviously;

      plog(1, "Received a SEND challenge");
      int alen = commitmentProtocol->logMessageIfNew(body, bodyLen, &response[responseHeaderLen], ackMsgLen, &loggedPreviously);
      assert(alen == ackMsgLen);

      /* We ONLY deliver the message to the application if we haven't done so
         already (i.e. if it was logged previously) */
        
      if (!loggedPreviously) {
        plog(2, "Delivering message in CHAL_SEND");
        unsigned int innerPos = 0;
        long long senderSeq = readLongLong(body, &innerPos);
        NodeHandle *sender = peerreview->readNodeHandle(body, &innerPos, bodyLen);
        innerPos += hashSizeBytes + signatureSizeBytes + 1;
        app->receive(sender, false, &body[innerPos], bodyLen - innerPos); 
        delete sender;
      }

      /* Put together a RESPONSE with an authenticator for the message in the challenge */

      unsigned int responsePos = 0;
      writeByte(response, &responsePos, MSG_RESPONSE);
      writeBytes(response, &responsePos, originatorAsBytes, identifierSizeBytes);
      peerreview->getLocalHandle()->getIdentifier()->write(response, &responsePos, sizeof(response));
      writeLongLong(response, &responsePos, evidenceSeq);
      writeByte(response, &responsePos, CHAL_SEND);
      
      /* ... and send it back to the challenger */
      
      plog(2, "Returning a %d-byte response", sizeof(response));
      peerreview->transmit(source, false, response, sizeof(response));
      
      break;
    }
    
    /* These are all the challenges we know */
    
    default:
    {
      warning("Unknown challenge #%d from %s", type, source->render(buf1));
      break;
    }
  }
}

/* Called when we've challenged another node, and it has sent us a response */

void ChallengeResponseProtocol::handleResponse(Identifier *originator, Identifier *subject, long long evidenceSeq, unsigned char *payload, int payloadLen)
{
  char buf1[256];

  /* If this is a response to an AUDIT, we let the AuditProtocol handle it */

  if (originator->equals(transport->getLocalHandle()->getIdentifier())) {
    unsigned char *auditEvidence;
    int auditEvidenceLen;
    if (auditProtocol->statOngoingAudit(subject, evidenceSeq, &auditEvidence, &auditEvidenceLen)) {
      if (isValidResponse(subject, auditEvidence, auditEvidenceLen, payload, payloadLen, true)) {
        plog(2, "Received response to ongoing AUDIT from %s", subject->render(buf1));
        auditProtocol->processAuditResponse(subject, evidenceSeq, &payload[1], payloadLen - 1);
      } else {
        warning("Invalid response to ongoing audit of %s", subject->render(buf1));
      }
      
      return;
    }
  }
  
  /* It's not an AUDIT, so let's see whether it matches any of our evidence (if not, the
     sender is responding to a challenge we haven't even made) */
  
  int evidenceLen = 0;
  bool isProof = false;
  bool haveResponse = false;
  NodeHandle *interestedParty = NULL;
  
  if (!infoStore->statEvidence(originator, subject, evidenceSeq, &evidenceLen, &isProof, &haveResponse, &interestedParty)) {
    warning("Received response, but matching request is missing; discarding");
    return;
  }
  
  /* The evidence has to be a CHALLENGE; for PROOFs there is no valid response */
  
  if (isProof) {
    warning("Received an alleged response to a proof; discarding");
    return;
  }
  
  /* If we get a duplicate response, discard it */
  
  if (haveResponse) {
    warning("Received duplicate response; discarding");
    return;
  }
  
  /* Retrieve the evidence */
  
  assert(evidenceLen > 0);
  unsigned char *evidence = (unsigned char*) malloc(evidenceLen);
  infoStore->getEvidence(originator, subject, evidenceSeq, evidence, evidenceLen);
  
  /* Check the response against the evidence; if it is valid, add it to our store */
  
  if (isValidResponse(subject, evidence, evidenceLen, payload, payloadLen)) {
    plog(2, "Received valid response (orig=%08X, subject=%08X, t=%lld); adding", originator, subject, evidenceSeq);
    infoStore->addResponse(originator, subject, evidenceSeq, payload, payloadLen);
    
    /* If we've only relayed this challenge for another node (probably in our
       capacity as a witness), we need to forward the response back to
       the original challenger. */
    
    if (interestedParty) {
      plog(2, "Relaying response to interested party %s", interestedParty->render(buf1));
      unsigned int bufMaxlen = 2+sizeof(long long)+2*MAX_ID_SIZE + payloadLen;
      unsigned char *buf = (unsigned char*)malloc(bufMaxlen);
      unsigned int len = 0;
      writeByte(buf, &len, MSG_RESPONSE);
      originator->write(buf, &len, bufMaxlen);
      subject->write(buf, &len, bufMaxlen);
      writeLongLong(buf, &len, evidenceSeq);
      writeBytes(buf, &len, payload, payloadLen);
      peerreview->transmit(interestedParty, false, buf, len);
      free(buf);
    }
  } else {
    warning("Invalid response; discarding");
  }
  
  free(evidence);
}

#define xlog(a, b...) do { peerreview->logText(SUBSYSTEM, a, b); } while (0)
#define xwarning(a...) do { peerreview->logText("warning", 0, "WARNING: " a); } while (0)

/* This method takes a challenge and a response, and it checks whether the response is valid,
   i.e. is well-formed and answers the challenge. */

bool ChallengeResponseProtocol::isValidResponse(Identifier *subject, unsigned char *evidence, int evidenceLen, unsigned char *response, int responseLen, bool extractAuthsFromResponse)
{
  const unsigned int identifierSizeBytes = peerreview->getIdentifierSizeBytes();
  char buf1[256];
  assert((evidenceLen > 0) && (responseLen > 0));
  
  if (evidence[0] != response[0])
    return false;
  
  switch (evidence[0]) {
    case CHAL_AUDIT :
    {
      long long requestedBeginSeq = *(long long*)&evidence[2];
      long long finalSeq = *(long long*)&evidence[2+authenticatorSizeBytes];
      unsigned char includePrevCheckpoint = ((evidence[1]&1)!=0);

      int readptr = 0;
      readByte(response, (unsigned int*)&readptr); /* RESP_AUDIT */
      NodeHandle *subjectHandle = peerreview->readNodeHandle(response, (unsigned int*)&readptr, responseLen);
      long long firstSeq = readLongLong(response, (unsigned int*)&readptr);
      readptr += 1 + response[readptr]; /* skip extInfo */
      unsigned char baseHash[hashSizeBytes];
      memcpy(baseHash, &response[readptr], hashSizeBytes);
      readptr += hashSizeBytes;

      unsigned char subjectHandleInBytes[MAX_HANDLE_SIZE];
      unsigned int subjectHandleInBytesLen = 0;
      subjectHandle->write(subjectHandleInBytes, &subjectHandleInBytesLen, sizeof(subjectHandleInBytes));

      if ((requestedBeginSeq % 1000) > 0)
        requestedBeginSeq -= requestedBeginSeq % 1000;

      long long fromNodeMaxSeq = requestedBeginSeq + 999;

      if ((firstSeq > requestedBeginSeq) || (!includePrevCheckpoint && (firstSeq < requestedBeginSeq))) {
        warning("Log snippet starts at %lld, but we asked for %lld (ilc=%s); flagging invalid", firstSeq, requestedBeginSeq, includePrevCheckpoint ? "yes" : "no");
        delete subjectHandle;
        return false;
      }

      bool snippetOK = EvidenceTool::checkSnippetSignatures(&response[readptr], responseLen - readptr, firstSeq, baseHash, subjectHandle, extractAuthsFromResponse ? authOutStore : NULL, includePrevCheckpoint, peerreview, peerreview, commitmentProtocol, &evidence[2+sizeof(long long)], fromNodeMaxSeq);
      delete subjectHandle;
      
      if (!snippetOK)
        return false;
      
      break;
    }
    case CHAL_SEND :
    {
      unsigned int pos = 0;
      readByte(evidence, &pos); // CHAL_SEND
      long long senderSeq = readLongLong(evidence, &pos);
      NodeHandle *senderHandle = peerreview->readNodeHandle(evidence, &pos, evidenceLen);
      unsigned char *senderHtopMinusOne = &evidence[pos];
      pos += hashSizeBytes;
      unsigned char *senderSignature = &evidence[pos];
      pos += signatureSizeBytes;
      unsigned char relevantCode = readByte(evidence, &pos);
      unsigned char *msgPayload = &evidence[pos];
      int msgPayloadLen = evidenceLen - pos;
      int relevantLen = (relevantCode == 0xFF) ? msgPayloadLen : relevantCode;
      
      unsigned int pos2 = 0;
      readByte(response, &pos2); // CHAL_SEND
      Identifier *receiverID = peerreview->readIdentifier(response, &pos2, responseLen);
      long long ackSenderSeq = readLongLong(response, &pos2);
      long long ackReceiverSeq = readLongLong(response, &pos2);
      unsigned char *receiverHtopMinusOne = &response[pos2];
      pos2 += hashSizeBytes;
      unsigned char *receiverSignature = &response[pos2];
      pos2 += signatureSizeBytes;
      
      bool okay = true;
      if (ackSenderSeq != senderSeq) {
        warning("RESP.SEND: ACK contains sender seq %lld, but challenge contains %lld; flagging invalid", ackSenderSeq, senderSeq);
        okay = false;
      }

      if (okay) {      
        unsigned char recvPrefix[MAX_HANDLE_SIZE + sizeof(long long) + 1];
        unsigned int pos3 = 0;
        senderHandle->write(recvPrefix, &pos3, sizeof(recvPrefix));
        writeLongLong(recvPrefix, &pos3, senderSeq);
        writeByte(recvPrefix, &pos3, (relevantLen < msgPayloadLen) ? 1 : 0);
      
        unsigned char innerHash[hashSizeBytes];
        if (relevantLen < msgPayloadLen) {
          unsigned char irrelevantHash[hashSizeBytes];
          peerreview->hash(irrelevantHash, &msgPayload[relevantLen], msgPayloadLen - relevantLen);
          peerreview->hash(innerHash, recvPrefix, pos3, msgPayload, relevantLen, irrelevantHash, hashSizeBytes);
        } else {
          peerreview->hash(innerHash, recvPrefix, pos3, msgPayload, msgPayloadLen);
        }
        
        unsigned char authenticator[sizeof(long long) + hashSizeBytes + signatureSizeBytes];
        if (peerreview->extractAuthenticator(receiverID, ackReceiverSeq, EVT_RECV, innerHash, receiverHtopMinusOne, receiverSignature, authenticator)) {
          xlog(2, "Auth OK");
        } else {
          warning("RESP.SEND: Signature on ACK is invalid");
          okay = false;
        }
      }
      
      delete senderHandle;
      delete receiverID;
      
      if (!okay)
        return false;

      break;
    }
    default :
    {
      warning("Cannot check whether response type #%d is valid; answering no", evidence[0]);
      panic("xx");
      break;
    }
  }

  return true;
}

/* Handle an incoming RESPONSE or ACCUSATION from another node */

void ChallengeResponseProtocol::handleStatement(NodeHandle *source, unsigned char *statement, int statementLen)
{
  char buf1[256], buf2[256];
  assert((statementLen>0) && ((statement[0] == MSG_ACCUSATION) || (statement[0] == MSG_RESPONSE)));

  unsigned int pos = 1;
  Identifier *originator = peerreview->readIdentifier(statement, &pos, statementLen);
  Identifier *subject = peerreview->readIdentifier(statement, &pos, statementLen);
  long long evidenceSeq = readLongLong(statement, &pos);
  unsigned char *payload = &statement[pos];
  int payloadLen = statementLen - pos;

  plog(2, "Statement completed: %s (orig=%s, subject=%s, ts=%lld, %d bytes)",
    (statement[0] == MSG_ACCUSATION) ? "ACCUSATION" : "RESPONSE",
    originator->render(buf1), subject->render(buf2), evidenceSeq, payloadLen
  );
  
  /* We get called from the StatementProtocol, so we already know that the statement
     is well-formed, and that we have acquired all the necessary supplementary material,
     such as certificates or hash maps */
     
  if (statement[0] == MSG_RESPONSE) {
    handleResponse(originator, subject, evidenceSeq, payload, payloadLen);
    if (infoStore->getStatus(source->getIdentifier()) == STATUS_SUSPECTED) {
      plog(2, "RECHALLENGE");
      challengeSuspectedNode(source);
    }
    delete originator;
    delete subject;
    return;
  }
     
  int status = infoStore->getStatus(source->getIdentifier());
  switch (status) {
    case STATUS_EXPOSED:
      plog(2, "Got an accusation from exposed node %s; discarding", source->render(buf1));
      break;
    case STATUS_TRUSTED:
      if (!infoStore->statEvidence(originator, subject, evidenceSeq, NULL, NULL, NULL, NULL))
        infoStore->addEvidence(originator, subject, evidenceSeq, payload, payloadLen, source);
      else
        plog(2, "We already have a copy of that challenge; discarding");
      break;
    case STATUS_SUSPECTED:
    {
      /* If the status is SUSPECTED, we queue the message for later delivery */

      warning("Incoming accusation from SUSPECTED node %s; queueing and challenging the node", source->render(buf1));
      copyAndEnqueueTail(source, payload, payloadLen, true, subject, originator, evidenceSeq);

      /* Furthermore, we must have an unanswered challenge, which we send to the remote node */

      challengeSuspectedNode(source);
      break;
    }
    default:
      panic("Unknown status: #%d", status);
  }
  
  delete originator;
  delete subject;
}

/* Looks up the first unanswered challenge to a SUSPECTED node, and sends it to that node */

void ChallengeResponseProtocol::challengeSuspectedNode(NodeHandle *target)
{
  char buf1[256];
  Identifier *originator;
  long long evidenceSeq;
  int evidenceLen;
  
  if (!infoStore->statFirstUnansweredChallenge(target->getIdentifier(), &originator, &evidenceSeq, &evidenceLen))
    panic("Node %s is SUSPECTED, but I cannot retrieve an unanswered challenge?!?", target->render(buf1));
    
  /* Construct a CHALLENGE message ... */
    
  int maxChallengeLen = 1+MAX_ID_SIZE+sizeof(evidenceSeq)+evidenceLen;
  unsigned char *challenge = (unsigned char*) malloc(maxChallengeLen);
  unsigned int challengeLen = 0;
  
  writeByte(challenge, &challengeLen, MSG_CHALLENGE);
  originator->write(challenge, &challengeLen, maxChallengeLen);
  writeLongLong(challenge, &challengeLen, evidenceSeq);
  infoStore->getEvidence(originator, target->getIdentifier(), evidenceSeq, &challenge[challengeLen], evidenceLen);
  challengeLen += evidenceLen;

  /* ... and send it */

  peerreview->transmit(target, false, challenge, challengeLen);
  free(challenge);
}

void ChallengeResponseProtocol::handleIncomingMessage(NodeHandle *source, unsigned char *message, int msglen)
{
  char buf1[256];
  assert(message && (msglen>0));

  int status = infoStore->getStatus(source->getIdentifier());
  switch (status) {
    case STATUS_EXPOSED:
      plog(2, "Got a user message from exposed node %s; discarding", source->render(buf1));
      return;
    case STATUS_TRUSTED:
      commitmentProtocol->handleIncomingMessage(source, message, msglen);
      return;
  }

  assert(status == STATUS_SUSPECTED);
  
  /* If the status is SUSPECTED, we queue the message for later delivery */

  warning("Incoming message from SUSPECTED node %s; queueing and challenging the node", source->render(buf1));
  copyAndEnqueueTail(source, message, msglen, false);

  /* Furthermore, we must have an unanswered challenge, which we send to the remote node */

  challengeSuspectedNode(source);
}
