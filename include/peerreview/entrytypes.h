#ifndef __peerreview_entrytypes_h__
#define __peerreview_entrytypes_h__

/* Event types in the log */

#define EVT_SEND         0   /* Outgoing message (followed by SENDSIGN entry) */
#define EVT_RECV         1       /* Incoming message (followed by SIGN entry) */
#define EVT_SIGN         2                   /* Signature on incoming message */
#define EVT_ACK          3                                  /* Acknowledgment */
#define EVT_CHECKPOINT   4                 /* Checkpoint of the state machine */
#define EVT_INIT         5                    /* State machine is (re)started */
#define EVT_SENDSIGN     6                   /* Signature on outgoing message */
#define EVT_VRF          7                         /* New Si value in the VRF */
#define EVT_CHOOSE_Q     8                           /* Choose Q array in VRF */
#define EVT_CHOOSE_RAND  9                        /* Choose randomness in VRF */
#define EVT_MAX_RESERVED EVT_CHOOSE_RAND    /* User defined events start here */

#endif /* defined(__peerreview_entrytypes_h__) */
