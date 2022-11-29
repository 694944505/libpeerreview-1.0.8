#include <stdlib.h>
#include <string.h>

#include "peerreview.h"

#define SUBSYSTEM "peerreview"

AuthenticatorPushProtocol::AuthenticatorPushProtocol(PeerReview *peerreview, AuthenticatorStore *inStore, AuthenticatorStore *outStore, AuthenticatorStore *pendingStore, IdentityTransport *transport, PeerReviewCallback *app, PeerInfoStore *infoStore, int hashSizeBytes, EvidenceTransferProtocol *evidenceTransferProtocol)
{
  this->authInStore = inStore;
  this->authOutStore = outStore;
  this->authPendingStore = pendingStore;
  this->transport = transport;
  this->app = app;
  this->infoStore = infoStore;
  this->signatureSizeBytes = transport->getSignatureSizeBytes();
  this->hashSizeBytes = hashSizeBytes;
  this->peerreview = peerreview;
  this->authenticatorSizeBytes = sizeof(long long) + signatureSizeBytes + hashSizeBytes;
  this->evidenceTransferProtocol = evidenceTransferProtocol;
  this->probabilistic = false;
  this->pXmit = 1.0;
}

/* Start an authenticator push. We begin by determining the witness sets of all the nodes
   for which we have authenticators. */

void AuthenticatorPushProtocol::push()
{
  int subjectsTotal = authOutStore->getNumSubjects();  
  if (subjectsTotal < 1)
    return; 
    
  plog(2, "Authenticator push initiated with %d subjects", subjectsTotal);

  Identifier **subjects = (Identifier**) malloc(subjectsTotal * sizeof(Identifier*));
  for (int i=0; i<subjectsTotal; i++) {
    subjects[i] = authOutStore->getSubject(i);
    assert(subjects[i]);
  }
    
  evidenceTransferProtocol->requestWitnesses(subjects, subjectsTotal);
  
  free(subjects);
}

/* Once we have all the witness sets, we bundle up all of our authenticators in AUTHPUSH messages 
   and send them to the witnesses. */

void AuthenticatorPushProtocol::continuePush(int numSubjects, Identifier **subjects, int *witnessesPerSubject, NodeHandle **witnesses)
{
  char buf1[256];
  struct witnessRecord {
    NodeHandle *handle;
    int numSubjects;
    Identifier *subject[MAX_SUBJECTS_PER_WITNESS];
  };

  plog(2, "Continuing authenticator push with %d subjects", numSubjects);
    
  int maxWitnessesInList = numSubjects * MAX_WITNESSES_PER_SUBJECT;
  struct witnessRecord *list = (struct witnessRecord*) malloc(sizeof(struct witnessRecord) * maxWitnessesInList);
  int witnessesInList = 0;
  int witnessPtr = 0;
  
  /* We're given a list mapping subjects to witnesses, whereas what we really want is a list
     mapping witnesses to subjects (so, if a node is a witness for multiple subjects, we can
     put all of the subjects' authenticators into a single datagram). We invert the list here. */
  
  for (int i=0; i<numSubjects; i++) {
    Identifier *thisSubject = subjects[i];
    NodeHandle **theseWitnesses = &witnesses[witnessPtr];
    int witnessesHere = witnessesPerSubject[i];
    witnessPtr += witnessesHere;

    plog(3, "Subject #%d: %s (%d witnesses)", i, thisSubject->render(buf1), witnessesHere);

    for (int j=0; j<witnessesHere; j++) {
      plog(4, "Witness #%d: %s", j, theseWitnesses[j]->render(buf1));
    
      int idx = -1;
      for (int k=0; (idx<0) && (k<witnessesInList); k++) {
        if (list[k].handle->equals(theseWitnesses[j]))
          idx = k;
      }
      
      if (idx < 0) {
        if (witnessesInList >= maxWitnessesInList)
          panic("Witness list overflow");
        
        idx = witnessesInList ++;
        list[idx].handle = theseWitnesses[j];
        list[idx].numSubjects = 0;
      }
      
      if (list[idx].numSubjects >= MAX_SUBJECTS_PER_WITNESS)
        panic("Subject list overflow");
        
      list[idx].subject[list[idx].numSubjects++] = thisSubject;
    }
  }
  
  plog(3, "Found %d witnesses", witnessesInList);
  
  /* For each witness, create all the AUTHPUSH messages we need to send to it. The messages
     are datagrams, so we ask the transport layer for the MSS and split the messages
     where appropriate. */
  
  int mss = transport->getMSS();
  int authenticatorSizeBytes = authOutStore->getAuthenticatorSizeBytes();
  unsigned char *buffer = (unsigned char*)malloc(mss);
  int idSize = peerreview->getIdentifierSizeBytes();
  buffer[0] = MSG_AUTHPUSH;
  
  for (int i=0; i<witnessesInList; i++) {
    unsigned int bufWritePtr = 1;
    plog(3, "Gathering authenticators for witness #%d %s", i, list[i].handle->render(buf1));
    
    for (int j=0; j<list[i].numSubjects; j++) {
      int numHere = authOutStore->numAuthenticatorsFor(list[i].subject[j]);
      unsigned char *payload = (unsigned char*)malloc(numHere * authenticatorSizeBytes);
      authOutStore->getAuthenticators(list[i].subject[j], payload, numHere * authenticatorSizeBytes);
      
      /* If probabilistic checking is enabled, we can skip the authenticators with some probability */
      
      if (probabilistic) {
        int numActuallySent = 0;
        for (int k=0; k<numHere; k++) {
          if ((0.000001*(random()%1000000))<=pXmit) {
            for (int l=0; l<authenticatorSizeBytes; l++) 
              payload[numActuallySent*authenticatorSizeBytes+l] = payload[k*authenticatorSizeBytes+l];
            numActuallySent ++;
          }
        }
        
        numHere = numActuallySent;
      }
      
      int readPtr = 0;
      while (readPtr < numHere) {
        dlog(4, "==> readPtr=%d/%d at subject #%d, %d/%d bytes in buffer", readPtr, numHere, j, bufWritePtr, mss);      
        bool mustSend = false;
        if ((mss - bufWritePtr) >= (idSize + sizeof(char) + authenticatorSizeBytes)) {
          int numToCopy = (int)((mss - (bufWritePtr+idSize+sizeof(char))) / authenticatorSizeBytes);
          if (numToCopy > 255)
            numToCopy = 255;
          if (numToCopy > (numHere - readPtr))
            numToCopy = numHere - readPtr;
            
          list[i].subject[j]->write(buffer, &bufWritePtr, mss);
          writeByte(buffer, &bufWritePtr, numToCopy);
          writeBytes(buffer, &bufWritePtr, &payload[readPtr * authenticatorSizeBytes], numToCopy * authenticatorSizeBytes);
          readPtr += numToCopy;
          
          assert(((int)bufWritePtr <= mss) && (readPtr <= numHere));
        } else {
          mustSend = true;
        }
        
        if ((j == (list[i].numSubjects-1)) && (readPtr >= numHere))
          mustSend = true;
          
        if (mustSend) {
          dlog(4, "read %d/%d from subject %d; writing %d bytes", readPtr, numHere, j, bufWritePtr);
          plog(3, "Sending %d-byte authenticator message to %s", bufWritePtr, list[i].handle->render(buf1));
          peerreview->transmit(list[i].handle, true, buffer, bufWritePtr);
          bufWritePtr = 1;
        }
      }
      dlog(4, "Finishing subject #%d", j);
      
      /* Special case if, with probabilistic checking enabled, we've thrown away all the 
         authenticators for the last subject */
      
      if ((numHere == 0) && (j == (list[i].numSubjects-1)) && (bufWritePtr > 1)) {
        dlog(4, "special case; writing %d bytes", bufWritePtr);
        plog(3, "Sending %d-byte authenticator message to %s", bufWritePtr, list[i].handle->render(buf1));
        peerreview->transmit(list[i].handle, true, buffer, bufWritePtr);
        bufWritePtr = 1;
      }
      
      free(payload);
    }
    
    assert(bufWritePtr == 1);
  }
  
  /* Once all the messages are sent, we don't need the authenticators any more */
  
  plog(3, "Push completed; releasing authenticators");
  for (int i=0; i<numSubjects; i++)
    authOutStore->flush(subjects[i]);
    
  free(buffer);
  free(list);
}

void AuthenticatorPushProtocol::addAuthenticatorsIfValid(unsigned char *message, int numAuths, Identifier *id)
{
  for (int i=0; i<numAuths; i++) {
    unsigned char *thisAuth = &message[i*authenticatorSizeBytes];
    if (!peerreview->addAuthenticatorIfValid(authInStore, id, thisAuth)) 
      warning("Authenticator #%d has invalid signature; discarding", i);
  }
}

/* Called when some other node sends us an AUTHPUSH message. The message may contain authenticators
   from multiple nodes. If, for some node, we don't have a certificate, we store its auths in the
   authPendingStore and request the certificate from the sender, otherwise we check the auths'
   signatures and put them into the authInStore. */

void AuthenticatorPushProtocol::handleIncomingAuthenticators(NodeHandle *source, unsigned char *message, int msglen)
{
  char buf1[256];
  assert(message && (msglen>0) && (message[0] == MSG_AUTHPUSH));
  plog(1, "Received authenticators from %s (%d bytes)", source->render(buf1), msglen);
  unsigned int readptr = 1;
  while ((int)(readptr + peerreview->getIdentifierSizeBytes()) <= msglen) {
    Identifier *id = peerreview->readIdentifier(message, &readptr, msglen);
    int numAuths = readByte(message, &readptr);
    
    if ((int)(readptr + numAuths*authenticatorSizeBytes) <= msglen) {
      plog(2, "  Subject <%s>, %d authenticators", id->render(buf1), numAuths);
      if (transport->haveCertificate(id)) {
        addAuthenticatorsIfValid(&message[readptr], numAuths, id);
      } else {
        plog(2, "  Missing certificate for this subject; requesting from %s and recording auths as pending", source->render(buf1));
        for (int i=0; i<numAuths; i++)
          authPendingStore->addAuthenticator(id, &message[readptr + i*authenticatorSizeBytes]);
          
        transport->requestCertificate(source, id);
      }
            
      readptr += numAuths*authenticatorSizeBytes;
    } else {
      warning("Authenticator message truncated");
      delete id;
      break;
    }
    
    if (infoStore->getStatus(id) != STATUS_TRUSTED) 
      evidenceTransferProtocol->sendEvidence(source, id);
    
    delete id;
  }
}

/* When we receive a new certificate, we may be able to check some more signatures on auths in
   the authPendingStore */

void AuthenticatorPushProtocol::notifyCertificateAvailable(Identifier *id)
{
  char buf1[256];
  int numAuths = authPendingStore->numAuthenticatorsFor(id);
  if (numAuths > 0) {
    plog(2, "Found %d pending authenticators for <%s>; processing...", numAuths, id->render(buf1));
    
    unsigned char *buffer = (unsigned char*) malloc(numAuths * authenticatorSizeBytes);
    authPendingStore->getAuthenticators(id, buffer, numAuths * authenticatorSizeBytes);
    addAuthenticatorsIfValid(buffer, numAuths, id);
    authPendingStore->flushAuthenticatorsFor(id);
    free(buffer);
  }
}
