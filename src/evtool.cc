#include "peerreview.h"

#define SUBSYSTEM "evidencetool"

EvidenceTool::checkResult EvidenceTool::checkSnippet(unsigned char *snippet, unsigned int snippetLen, Identifier **missingCertID, IdentityTransport *transport)
{
  int hashSizeBytes = transport->getHashSizeBytes();
  int identifierSizeBytes = transport->getIdentifierSizeBytes();
  int signatureSizeBytes = transport->getSignatureSizeBytes();
  int entriesReadSoFar = 0;
  unsigned int readptr = 0;
  char buf1[256];

  /* Read the snippet entry by entry */

  while (readptr < snippetLen) {
    unsigned char entryType = ((readptr+1)<=snippetLen) ? snippet[readptr++] : 0;
    unsigned char sizeCode = ((readptr+1)<=snippetLen) ? snippet[readptr++] : 0;
    unsigned int entrySize = sizeCode;
    bool entryIsHashed = (sizeCode==0);

    /* Entry size is encoded as one byte (if below 255) or as two bytes
       preceded by 0xFF */
   
    if (sizeCode == 0xFF) {
      entrySize = ((readptr+2)<=snippetLen) ? *(unsigned short*)&snippet[readptr] : 0;
      readptr += 2;
    } else if (sizeCode == 0xFE) {
      entrySize = ((readptr+4)<=snippetLen) ? *(unsigned int*)&snippet[readptr] : 0;
      readptr += 4;
    } else if (sizeCode == 0) {
      entrySize = hashSizeBytes;
    }

    /* Only certain entry types may be hashed */

    if (entryIsHashed && ((entryType!=EVT_CHECKPOINT) && (entryType!=EVT_SENDSIGN) && (entryType!=EVT_SEND))) {
      warning("Malformed statement: Entry of type #%d is hashed", entryType);
      return INVALID;
    }

    /* Sanity check */

    if ((readptr+entrySize) > snippetLen) {
      warning("Malformed statement: Entry truncated");
      return INVALID;
    }

    /* Further processing depends on the entry type */

    plog(3, "Entry type %d, size=%d%s", entryType, entrySize, entryIsHashed ? " (hashed)" : "");

    unsigned char *entry = &snippet[readptr];
    switch (entryType) {
      case EVT_SEND : /* No certificates needed; just do syntax checking */
        if (!entryIsHashed) {
          if (entrySize >= (identifierSizeBytes + 1)) {
            unsigned char hashed = entry[identifierSizeBytes];
            int innerSize = entrySize - (identifierSizeBytes + 1);
            if ((hashed != 0) && (hashed != 1)) {
              warning("Malformed statement: SEND.hashed=%d", hashed);
              return INVALID;
            } else if (hashed && (innerSize < hashSizeBytes)) {
              warning("Malformed statement: SEND.innerSize=%d", innerSize);
              return INVALID;
            }
          } else {
            warning("Malformed statement: Truncated SEND entry");
            return INVALID;
          }
        }
        break;
      case EVT_RECV : /* We may need the certificate for the sender */
      {
        unsigned int pos4 = 0;
        NodeHandle *sender = transport->readNodeHandle(entry, &pos4, entrySize);
        long long seq = readLongLong(entry, &pos4);
        unsigned char hashed = readByte(entry, &pos4);
        int innerSize = entrySize - pos4;
        if (innerSize > 0) {
          if (!transport->haveCertificate(sender->getIdentifier())) {
            plog(2, "AUDIT RESPONSE contains RECV from %s; certificate needed", sender->getIdentifier()->render(buf1));
            *missingCertID = sender->getIdentifier()->clone();
            delete sender;
            return CERT_MISSING;
          }

          delete sender;

          if ((hashed != 0) && (hashed != 1)) {
            warning("Malformed statement: RECV.hashed=%d", hashed);
            return INVALID;
          } else if (hashed && (innerSize < hashSizeBytes)) {
            warning("Malformed statement: RECV.innerSize=%d", innerSize);
            return INVALID;
          }
        } else {
          warning("Malformed statement: Truncated RECV entry");
          delete sender;
          return INVALID;
        }
        break;
      }
      case EVT_SIGN : /* No certificates needed */
        if (entrySize != (signatureSizeBytes + hashSizeBytes)) {
          warning("Malformed statement: Truncated SIGN entry");
          return INVALID;
        }
        break;
      case EVT_ACK : /* We may need the certificate for the sender */
        if (entrySize == (identifierSizeBytes + 2*sizeof(long long) + hashSizeBytes + signatureSizeBytes)) {
          unsigned int pos5 = 0;
          Identifier *sender = transport->readIdentifier(entry, &pos5, entrySize);
          if (!transport->haveCertificate(sender)) {
            plog(2, "AUDIT RESPONSE contains ACK from %s; certificate needed", sender->render(buf1));
            *missingCertID = sender;
            return CERT_MISSING;
          }

          delete sender;
        } else {
          warning("Malformed statement: Truncated ACK entry");
          return INVALID;
        }
        break;
      case EVT_CHECKPOINT : /* No certificates needed */
      case EVT_VRF :
      case EVT_CHOOSE_Q :
      case EVT_CHOOSE_RAND :
        break;
      case EVT_INIT : /* No certificates needed */
      {
        unsigned int pos6 = 0;
        NodeHandle *handle = transport->readNodeHandle(entry, &pos6, entrySize);
        delete handle;

        if (entrySize != pos6) {
          warning("Malformed statement: INIT entry has incorrect size");
          return INVALID;
        }
        break;
      }
      case EVT_SENDSIGN : /* No certificates needed */
        break;
      default : /* No certificates needed */
        assert(entryType > EVT_MAX_RESERVED); 
        break;
    }

    readptr += entrySize;
    entriesReadSoFar ++;

    if (readptr == snippetLen) // legitimate end
      break;

    unsigned char dseqCode = ((readptr+1)<=snippetLen) ? snippet[readptr++] : 0;
    if (dseqCode == 0xFF)
      readptr += sizeof(long long);

    if (readptr >= snippetLen) {
      warning("Malformed statement: Cannot read dseqCode");
      return INVALID;
    }
  }

  if (entriesReadSoFar < 1) {
    warning("Malformed statement: No entries");
    return INVALID;
  }
  
  return VALID;
}

bool EvidenceTool::checkNoEntriesHashed(unsigned char *snippet, unsigned int snippetLen, unsigned char *typesToIgnore, int numTypesToIgnore, IdentityTransport *transport)
{
  int hashSizeBytes = transport->getHashSizeBytes();
  unsigned int readptr = 0;

  /* Read the snippet entry by entry */

  while (readptr < snippetLen) {
    unsigned char entryType = ((readptr+1)<=snippetLen) ? snippet[readptr++] : 0;
    unsigned char sizeCode = ((readptr+1)<=snippetLen) ? snippet[readptr++] : 0;
    unsigned int entrySize = sizeCode;
    bool entryIsHashed = (sizeCode==0);

    /* Entry size is encoded as one byte (if below 255) or as two bytes
       preceded by 0xFF */
   
    if (sizeCode == 0xFF) {
      entrySize = ((readptr+2)<=snippetLen) ? *(unsigned short*)&snippet[readptr] : 0;
      readptr += 2;
    } else if (sizeCode == 0xFE) {
      entrySize = ((readptr+4)<=snippetLen) ? *(unsigned int*)&snippet[readptr] : 0;
      readptr += 4;
    } else if (sizeCode == 0) {
      entrySize = hashSizeBytes;
    }

    readptr += entrySize;

    if (readptr == snippetLen) // legitimate end
      break;

    unsigned char dseqCode = ((readptr+1)<=snippetLen) ? snippet[readptr++] : 0;
    if (dseqCode == 0xFF)
      readptr += sizeof(long long);
  }

  return true;
}

EvidenceTool::checkResult EvidenceTool::isAuthenticatorValid(unsigned char *authenticator, Identifier *subject, IdentityTransport *transport)
{
  if (!transport->haveCertificate(subject))
    return CERT_MISSING;
    
  int hashSizeBytes = transport->getHashSizeBytes();
  unsigned char signedHash[hashSizeBytes];
  transport->hash(signedHash, authenticator, sizeof(long long)+hashSizeBytes);

  int sigResult = transport->verify(subject, signedHash, hashSizeBytes, &authenticator[sizeof(long long)+hashSizeBytes]);
  assert((sigResult == IdentityTransport::SIGNATURE_OK) || (sigResult == IdentityTransport::SIGNATURE_BAD));
  if (sigResult != IdentityTransport::SIGNATURE_OK)
    return INVALID;
    
  return VALID;
}

/* The following method does several things: It verifies all the signatures in a log snippet,
   it extracts all the authenticators for later forwarding to the corresponding witnesses,
   and it delivers any new messages to the local node that may be in the snippet (e.g. after
   an investigation) */

bool EvidenceTool::checkSnippetSignatures(unsigned char *snippet, int snippetLen, long long firstSeq, unsigned char *baseHash, NodeHandle *subjectHandle, AuthenticatorStore *authStoreOrNull, unsigned char flags, IdentityTransport *transport, PeerReview *peerreview, CommitmentProtocol *commitmentProtocol, unsigned char *keyNodeHash, long long keyNodeMaxSeq)
{
  bool startWithCheckpoint = (flags&FLAG_INCLUDE_CHECKPOINT);
  const int signatureSizeBytes = transport->getSignatureSizeBytes();
  const int hashSizeBytes = transport->getHashSizeBytes();
  unsigned int identifierSizeBytes = transport->getIdentifierSizeBytes();

  char buf1[256];
  unsigned char currentNodeHash[hashSizeBytes], prevNodeHash[hashSizeBytes], prevPrevNodeHash[hashSizeBytes];
  long long currentSeq = firstSeq;
  bool firstEntry = true;
  bool keyNodeFound = false;
  int lastEntryType = -1;
  int lastEntryPos = -1;
  int lastEntrySize = -1;
  long long lastEntrySeq = -1;
  memcpy(currentNodeHash, baseHash, hashSizeBytes);
  memset(prevNodeHash, 0, sizeof(prevNodeHash));
  memset(prevPrevNodeHash, 0, sizeof(prevNodeHash));
  
  unsigned char subjectHandleInBytes[MAX_HANDLE_SIZE];
  unsigned int subjectHandleInBytesLen = 0;
  subjectHandle->write(subjectHandleInBytes, &subjectHandleInBytesLen, sizeof(subjectHandleInBytes));

  /* If FLAG_FULL_MESSAGES_SENDER is set, we must get a list of all the messages we have received
     from this node, so we can later check whether it has sent any other ones */

  static const int maxPastSeqs = 100;
  long long seqBuf[maxPastSeqs];
#warning the size of this array should be unlimited
  int numSeqs = 0;
  if (commitmentProtocol && (flags & FLAG_FULL_MESSAGES_SENDER)) {
    assert(peerreview != NULL);
    SecureHistory *history = peerreview->getHistory();
    for (int i=history->getNumEntries()-1; (i>=1) && (numSeqs<maxPastSeqs); i--) {
#warning this loop should abort if we're past firstSeq-tolerance
      unsigned char type;
      history->statEntry(i, NULL, &type, NULL, NULL, NULL);
      if (type == EVT_RECV) {
        unsigned char buf[MAX_HANDLE_SIZE+sizeof(long long)];
        unsigned int pos = 0;

        history->getEntry(i, buf, sizeof(buf));
        NodeHandle *thisSender = transport->readNodeHandle(buf, &pos, sizeof(buf));
        if (thisSender->equals(subjectHandle)) 
          seqBuf[numSeqs++] = *(long long*)&buf[pos];
        delete thisSender;
      }
    }
  }

  /* We keep a cache of recent SEND entries. This is necessary because, when checking
     an ACK entry, we need to compute the message hash from the corresponding SEND entry */

  const int maxSendEntries = 80;
  struct sendEntryRecord {
    long long seq;
    int hashedPlusPayloadIndex;
    int hashedPlusPayloadLen;
  } secache[maxSendEntries];

  int numSendEntries = 0;

  plog(2, "Checking snippet (flags=%d)", flags);
#warning check for FLAG_FULL here?

  /* We read the snipped entry by entry and check the following:
         - Does the computed top-level hash value match the second authenticator in the challenge?
         - Do all the signatures in RECV/SIGN and ACK entries check out?
     If extractAuthsFromResponse is set, we also add all authenticators to the authOut store.
     Note that we do not do conformance/consistency checking here; all we care about is whether
     the snippet matches the two authenticators. */

  int readptr = 0;
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

    plog(3, "Entry type %d, size=%d, seq=%lld%s", entryType, entrySize, currentSeq, entryIsHashed ? " (hashed)" : "");

    if ((lastEntryType == EVT_RECV) && ((entryType != EVT_SIGN) || (currentSeq != (lastEntrySeq+1)))) {
      warning("Log snipped omits the mandatory EVT_SIGN after an EVT_RECV; flagging invalid");
      return false;
    }

    unsigned char *entry = &snippet[readptr];
    memcpy(prevPrevNodeHash, prevNodeHash, hashSizeBytes);
    memcpy(prevNodeHash, currentNodeHash, hashSizeBytes);

    /* Update the current node hash */

    unsigned char contentHash[hashSizeBytes];
    if (entryIsHashed)
      memcpy(contentHash, entry, hashSizeBytes);
    else
      transport->hash(contentHash, entry, entrySize);
      
    transport->hash(currentNodeHash, (const unsigned char*)&currentSeq, sizeof(currentSeq), &entryType, sizeof(entryType), currentNodeHash, hashSizeBytes, contentHash, hashSizeBytes);

    /* Check signatures */

    switch (entryType) {
      case EVT_SEND :
        if (!entryIsHashed) {
          if (numSendEntries >= maxSendEntries)
            panic("Too many pending SENDs without an ACK");

          /* Add an entry to the send-entry cache */

          secache[numSendEntries].seq = currentSeq;
          secache[numSendEntries].hashedPlusPayloadIndex = readptr + identifierSizeBytes;
          secache[numSendEntries].hashedPlusPayloadLen = entrySize - identifierSizeBytes;
          numSendEntries ++;
        }
        break;
      case EVT_RECV :

        /* Do nothing. The processing for RECV will be done when we find the SIGN entry */

        break;
      case EVT_SENDSIGN :
        if (!entryIsHashed) {
          assert(entrySize >= signatureSizeBytes);
          if (!firstEntry) {
            if (lastEntryType != EVT_SEND) {
              warning("Spurious EVT_SENDSIGN in snippet; flagging invalid");
              return false;
            }

            bool sendWasHashed = (snippet[lastEntryPos+identifierSizeBytes]>0);
            if (sendWasHashed) {
              unsigned char actualHash[hashSizeBytes];
              transport->hash(actualHash, &entry[signatureSizeBytes], entrySize - signatureSizeBytes);
              if (memcmp(actualHash, &snippet[lastEntryPos+lastEntrySize-hashSizeBytes], hashSizeBytes)) {
                warning("EVT_SENDSIGN content does not match hash in EVT_SEND");
                return false;
              }
            } else {
              if (entrySize > signatureSizeBytes) {
                warning("EVT_SENDSIGN contains extra bytes, but preceding EVT_SEND was not hashed");
                return false;
              }
            }

            unsigned char authPrefix[sizeof(long long)+hashSizeBytes];
            *(long long*)&authPrefix[0] = lastEntrySeq;
            memcpy(&authPrefix[sizeof(long long)], prevNodeHash, hashSizeBytes);

            unsigned char signedHash[hashSizeBytes];
            transport->hash(signedHash, authPrefix, sizeof(authPrefix));

            int verifyResult = transport->verify(subjectHandle->getIdentifier(), signedHash, hashSizeBytes, &entry[0]);
            assert((verifyResult == IdentityTransport::SIGNATURE_OK) || (verifyResult == IdentityTransport::SIGNATURE_BAD));
            if (verifyResult != IdentityTransport::SIGNATURE_OK) {
              warning("Signature in EVT_SENDSIGN does not match node hash of EVT_SEND");
              return false;
            }

            /* If the message in the SEND entry was for the local node, we check whether we 
               have previously delivered that message. If not, we deliver it now. */

            if (commitmentProtocol && (flags & FLAG_FULL_MESSAGES_SENDER)) {
              unsigned int pos = 0;
              Identifier *dest = transport->readIdentifier(&snippet[lastEntryPos], &pos, snippetLen);
              if (dest->equals(transport->getLocalHandle()->getIdentifier())) {
                bool previouslyReceived = false;
                for (int i=0; i<numSeqs; i++) {
                  if (seqBuf[i] == lastEntrySeq)
                    previouslyReceived = true;
                }

                if (!previouslyReceived) {
                  transport->logText(SUBSYSTEM, 3, "XXX accepting new message %lld", lastEntrySeq);

                  /* We're cheating a little bit here... essentially we reconstruct the original
                     USERDATA message as feed it to the commitment protocol, pretending that
                     it has just arrived from the network. This causes all the right things to happen. */

                  int relevantBytes = lastEntrySize-(identifierSizeBytes+1+(sendWasHashed ? hashSizeBytes : 0));
                  int irrelevantBytes = entrySize - signatureSizeBytes;
                  unsigned int messageMaxlen = 1+sizeof(long long)+MAX_HANDLE_SIZE+hashSizeBytes+signatureSizeBytes+1+relevantBytes+irrelevantBytes;
                  unsigned char message[messageMaxlen];
                  unsigned int pos = 0;
                  writeByte(message, &pos, MSG_USERDATA);
                  writeLongLong(message, &pos, lastEntrySeq);
                  subjectHandle->write(message, &pos, messageMaxlen);
                  writeBytes(message, &pos, prevPrevNodeHash, hashSizeBytes);
                  writeBytes(message, &pos, entry, signatureSizeBytes);
                  writeByte(message, &pos, (irrelevantBytes>0) ? relevantBytes : 0xFF);
                  if (relevantBytes)
                    writeBytes(message, &pos, &snippet[lastEntryPos+identifierSizeBytes+1], relevantBytes);
                  if (irrelevantBytes)
                    writeBytes(message, &pos, &entry[signatureSizeBytes], irrelevantBytes);
                  assert(pos <= sizeof(message));

                  commitmentProtocol->handleIncomingMessage(subjectHandle, message, pos);
                }
              }

              delete dest;
            }
          }
        }
        break;
      case EVT_SIGN :
        assert(entrySize == (hashSizeBytes + signatureSizeBytes));
        if (!firstEntry) {

          /* RECV entries must ALWAYS be followed by a SIGN */

          if (lastEntryType != EVT_RECV) {
            warning("Spurious EVT_SIGN in snippet; flagging invalid");
            return false;
          }

          /* Decode all the values */

          unsigned int pos = lastEntryPos;
          NodeHandle *senderHandle = transport->readNodeHandle(snippet, &pos, snippetLen);
          long long senderSeq = readLongLong(snippet, &pos);
          unsigned char *hashedPlusPayload = &snippet[pos];
          int hashedPlusPayloadLen = lastEntrySize - (pos - lastEntryPos);

          unsigned int pos2 = 0;
          unsigned char receiverAsBytes[identifierSizeBytes];
          subjectHandle->getIdentifier()->write(receiverAsBytes, &pos2, sizeof(receiverAsBytes));
          assert(pos2 == identifierSizeBytes);

          const unsigned char *senderHtopMinusOne = entry;
          const unsigned char *senderSignature = &entry[hashSizeBytes];

          /* Extract the authenticator and check it */

          unsigned char senderContentHash[hashSizeBytes];
          transport->hash(senderContentHash, receiverAsBytes, identifierSizeBytes, hashedPlusPayload, hashedPlusPayloadLen);

          unsigned char senderAuth[sizeof(long long)+hashSizeBytes+signatureSizeBytes];
          unsigned char senderType = EVT_SEND;
          *(long long*)&senderAuth[0] = senderSeq;
          transport->hash(&senderAuth[sizeof(long long)], (const unsigned char*)&senderSeq, sizeof(senderSeq), &senderType, sizeof(senderType), senderHtopMinusOne, hashSizeBytes, senderContentHash, hashSizeBytes);
          memcpy(&senderAuth[sizeof(long long)+hashSizeBytes], senderSignature, signatureSizeBytes);

          bool isGoodAuth = peerreview ? peerreview->addAuthenticatorIfValid(authStoreOrNull, senderHandle->getIdentifier(), senderAuth) : (isAuthenticatorValid(senderAuth, senderHandle->getIdentifier(), transport) == VALID);
          if (!isGoodAuth) {
            warning("Snippet contains a RECV from %s whose signature does not match; flagging invalid", senderHandle->render(buf1));
            delete senderHandle;
            return false;
          }

          delete senderHandle;
        }

        break;
      case EVT_ACK :
      {
        /* Decode all the values */

        assert(entrySize == (identifierSizeBytes + 2*sizeof(long long) + hashSizeBytes + signatureSizeBytes));
        unsigned int pos = 0;
        Identifier *receiverID = transport->readIdentifier(entry, &pos, entrySize);
        long long senderSeq = readLongLong(entry, &pos);
        long long receiverSeq = readLongLong(entry, &pos);
        const unsigned char *receiverHtopMinusOne = &entry[pos];
        pos += hashSizeBytes;
        const unsigned char *receiverSignature = &entry[pos];
        pos += signatureSizeBytes;

        unsigned int pos2 = 0;
        unsigned char senderAsBytes[identifierSizeBytes];
        subjectHandle->getIdentifier()->write(senderAsBytes, &pos2, sizeof(senderAsBytes));

        /* Look up the entry in the send-entry cache */

        int seidx = -1;
        for (int i=0; (seidx<0) && (i<numSendEntries); i++) {
          if (secache[i].seq == senderSeq)
            seidx = i;
        }

        if (seidx < 0) {
#if 0
          warning("Snippet contains an ACK but not a SEND; maybe look in the log?");
#endif          
//              return false;
#warning here we should probably return false
        } else {
          /* Extract the authenticator and check it */

          const unsigned char *hashedPlusPayload = &snippet[secache[seidx].hashedPlusPayloadIndex];
          int hashedPlusPayloadLen = secache[seidx].hashedPlusPayloadLen;
          secache[seidx] = secache[--numSendEntries];

          unsigned char receiverContentHash[hashSizeBytes];
          transport->hash(receiverContentHash, subjectHandleInBytes, subjectHandleInBytesLen, (const unsigned char*)&senderSeq, sizeof(senderSeq), hashedPlusPayload, hashedPlusPayloadLen);

          unsigned char receiverAuth[sizeof(long long)+hashSizeBytes+signatureSizeBytes];
          unsigned char receiverType = EVT_RECV;
          *(long long*)&receiverAuth[0] = receiverSeq;
          transport->hash(&receiverAuth[sizeof(long long)], (const unsigned char*)&receiverSeq, sizeof(receiverSeq), &receiverType, sizeof(receiverType), receiverHtopMinusOne, hashSizeBytes, receiverContentHash, hashSizeBytes);
          memcpy(&receiverAuth[sizeof(long long)+hashSizeBytes], receiverSignature, signatureSizeBytes);

          bool isGoodAuth = peerreview ? peerreview->addAuthenticatorIfValid(authStoreOrNull, receiverID, receiverAuth) : (isAuthenticatorValid(receiverAuth, receiverID, transport) == VALID);
          if (!isGoodAuth) {
            warning("Snippet contains an ACK from %08X whose signature does not match; flagging invalid", receiverID);
            delete receiverID;
            return false;
          }
        }

        delete receiverID;
        break;
      }
      case EVT_CHECKPOINT :
      case EVT_VRF :
      case EVT_INIT :
      case EVT_CHOOSE_Q :
      case EVT_CHOOSE_RAND :
        break;
      default :
        assert(entryType > EVT_MAX_RESERVED); 
        break;
    }

    /* Remember where the last RECV entry was */

    lastEntryType = entryType;
    lastEntryPos = readptr;
    lastEntrySeq = currentSeq;
    lastEntrySize = entrySize;

    /* If this is the first entry, its hash must match the first authenticator in the challenge */

    if (keyNodeHash && !keyNodeFound) {
      if (!memcmp(currentNodeHash, keyNodeHash, hashSizeBytes))  
        keyNodeFound = true;
    }

    if (firstEntry) {
      if (startWithCheckpoint) {
        if ((entryType != EVT_CHECKPOINT) && (entryType != EVT_INIT)) {
          warning("Previous checkpoint requested, but not included; flagging invalid");
          return false;
        }
        if (entryIsHashed) {
          warning("Previous checkpoint requested, but only hash is included; flagging invalid");
          return false;
        }
      } else {
      }

      firstEntry = false;
    }

    /* Skip ahead to the next entry in the snippet */

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

    if (currentSeq <= lastEntrySeq) {
      warning("Log snippet attempts to roll back the sequence number from %lld to %lld; flagging invalid", lastEntrySeq, currentSeq);
      return false;
    }

    if (keyNodeHash && !keyNodeFound && (currentSeq > keyNodeMaxSeq)) {
      warning("Hash of keyNode does not appear in [%lld,%lld]; flagging invalid", firstSeq, keyNodeMaxSeq);
      return false;
    }

    assert(readptr <= snippetLen);
  }

  if (lastEntryType == EVT_RECV) {
    warning("Log snippet ends with a RECV event; missing mandatory SIGN");
    return false;
  }

  if (lastEntryType == EVT_SEND) {
    warning("Log snippet ends with a SEND event; missing mandatory SENDSIGN");
    return false;
  }

  if (keyNodeHash && !keyNodeFound) {
    warning("Key node not found in log snippet; flagging invalid");
    return false;
  }
  
  return true;
}

/* This is called when (a) we have obtained a new log segment from some node, and (b) we are convinced
   that the log segment is genuine. We append any new entries to our local copy of the node's log. 
   Note that sometimes AUDIT responses overlap (e.g. because a checkpoint has been requested), so it's
   perfectly legitimate to sometimes receive certain entries twice. Also, it's okay if some of the
   entries are hashed. */
   
void EvidenceTool::appendSnippetToHistory(unsigned char *snippet, int snippetLen, SecureHistory *history, IdentityTransport *transport, long long firstSeq, long long skipEverythingBeforeSeq)
{
  long long currentSeq = firstSeq;
  int readptr = 0;

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
      entrySize = transport->getHashSizeBytes();
    }

#ifdef VERBOSE
    plog(3, "Entry type %d, size=%d, seq=%lld", entryType, entrySize, currentSeq);
#endif

    if (currentSeq > history->getLastSeq()) {
      if (!history->setNextSeq(currentSeq))
        panic("Audit: Cannot set history sequence number?!?");
        
      if (!entryIsHashed)
        history->appendEntry(entryType, true, &snippet[readptr], entrySize);
      else
        history->appendHash(entryType, &snippet[readptr]);
    } else {
#ifdef VERBOSE
      if (currentSeq >= skipEverythingBeforeSeq)
        warning("Skipped entry because it is already present (top=%lld)", history->getLastSeq());
#endif
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
}

bool EvidenceTool::checkHashChainContains(unsigned char *snippet, int snippetLen, long long firstSeq, unsigned char *baseHash, unsigned char *keyNodeHash, long long keyNodeSeq, IdentityTransport *transport)
{
  assert(keyNodeHash && (keyNodeSeq >= 0));

  const int hashSizeBytes = transport->getHashSizeBytes();
  unsigned char currentNodeHash[hashSizeBytes];
  long long currentSeq = firstSeq;
  memcpy(currentNodeHash, baseHash, hashSizeBytes);
  
  plog(2, "Checking whether hash chain in snippet contains node #%lld", keyNodeSeq);

  int readptr = 0;
  while ((readptr < snippetLen) && (currentSeq <= keyNodeSeq)) {
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

    plog(3, "Entry type %d, size=%d, seq=%lld%s", entryType, entrySize, currentSeq, entryIsHashed ? " (hashed)" : "");

    unsigned char *entry = &snippet[readptr];
    unsigned char contentHash[hashSizeBytes];
    if (entryIsHashed)
      memcpy(contentHash, entry, hashSizeBytes);
    else
      transport->hash(contentHash, entry, entrySize);
      
    transport->hash(currentNodeHash, (const unsigned char*)&currentSeq, sizeof(currentSeq), &entryType, sizeof(entryType), currentNodeHash, hashSizeBytes, contentHash, hashSizeBytes);

    /* If this is the first entry, its hash must match the first authenticator in the challenge */

    if (currentSeq == keyNodeSeq) {
      if (!memcmp(currentNodeHash, keyNodeHash, hashSizeBytes)) {
        plog(3, "Yes, the node was found and has the specified hash");
        return true;
      } else {
        plog(3, "No, the node was found but has a different hash");
        return false;
      }
    }

    /* Skip ahead to the next entry in the snippet */

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

  plog(3, "No, a node with this sequence number was not found");
  return false;
}
