//
//  pmpptypes.h
//  pmpp_test
//
//  Created on 3/5/16.
//
//

#ifndef pmpptypes_h
#define pmpptypes_h

#include <netdb.h>

#define PMPP_BOOT                       "bootr"
#define PMPP_HEARTBEAT_INTERVAL         3 * 1000 // 3 seconds
#define PMPP_PROP_DELIMETER             "\f"
#define PMPP_REACH_ATTEMPT_THRESHOLD    3
#define PMPP_VERSION                    "1.0"

typedef enum pmppentity_t {
        PMPP_E_ANY,
        PMPP_E_MESSAGE,
        PMPP_E_SERVER,
        PMPP_E_SERVER_SENDER,
        PMPP_E_SERVER_RECIPIENT,
        PMPP_E_SERVICE,
        PMPP_E_RVP
} PmppEntityType;

typedef enum pmpplabel_t {
        PMPP_L_UNKNOWN,
        PMPP_L_CRYPTO_IV,
        PMPP_L_CRYPTO_KEY,
        PMPP_L_CRYPTO_RSA,
        PMPP_L_ENCODE_SIZE,
        PMPP_L_HASH,
        PMPP_L_HISTORY_RECV,
        PMPP_L_HISTORY_SENT,
        PMPP_L_INET_LADDR,   // Local address
        PMPP_L_INET_LPORT,   // Local port
        PMPP_L_INET_PADDR,   // Public address
        PMPP_L_INET_PPORT,   // Public port
        PMPP_L_INET_RADDR,   // Requested address
        PMPP_L_INET_RPORT,   // Requested port
        PMPP_L_MESSAGE_SEQ,
        PMPP_L_MESSAGE_TYPE,
        PMPP_L_PAYLOAD,
        PMPP_L_REACHABILITY,
        PMPP_L_REF_HASH,     // Use of this label is reserved for acknowledgments.
        PMPP_L_RUUID,
        PMPP_L_TIME,
        PMPP_L_UUID,
        PMPP_L_UUIDTYPE,
        PMPP_L_VERSION
} PmppLabelType;

typedef enum pmppmessagestat_t {
        PMPP_MS_UNKNWON,
        PMPP_MS_DELIVERED_SERVER,
        PMPP_MS_DELIVERED_SERVICE
} PmppMessageStatus;

typedef enum pmppmessage_t {
        PMPP_MT_UNKNOWN,
        
        /**
         * Upon receiving this type of message, a server, X, will
         * completely remove the sender from its list because it
         * means no more services on the sender's side are using X.
         * Any services on X that are still registered with the sender
         * should be notified that the sender is now offline.
         */
        PMPP_MT_BYE,
        
        /**
         * Service->local
         * Server->server
         * Used only when connecting to other correspondent for the
         * first time.
         */
        PMPP_MT_GREET,
        PMPP_MT_HAND_EXTEND,
        PMPP_MT_HAND_SHAKE,
        PMPP_MT_HAND_SHAKE_OK,
        
        /**
         * The following 2 types are used for requesting
         * the public key of a server from a 3rd party
         * in order to verify them.
         */
        PMPP_MT_ID_REQ,
        PMPP_MT_ID_RES,
        
        /**
         * Service->local (with recipient UUID): send given message to given remote server.
         */
        PMPP_MT_MESSAGE,
        
        /**
         * Message being delivered by a rendezvous point.
         */
        PMPP_MT_MESSAGE_FWD,
        
        /**
         * Local->service: message status updates (i.e. delivered to server/service).
         */
        PMPP_MT_MESSAGE_STAT,
        
        /**
         * Local->service: local/remote server IP address changed.
         */
        PMPP_MT_NOTIF_PRES,
        
        /**
         * Initiates hearbeats.
         */
        PMPP_MT_PING,
        
        /**
         * Server->server: looking for a specific server.
         */
        PMPP_MT_PROBE,
        
        /**
         * Server->server: probe response.
         */
        PMPP_MT_PROBE_RES,
        
        /**
         * Service->local (with recipient UUID): request to register with the remote server.
         */
        PMPP_MT_REGISTER,
        
        /**
         * Server->server: sending info about a rendezvous point.
         */
        PMPP_MT_RVP,
        
        /**
         * Stops heartbeats.
         */
        PMPP_MT_SLEEP,
        
        /**
         * Service->local (with recipient UUID): request to unregister with remote server.
         */
        PMPP_MT_UNREGISTER
} PmppMessageType;

typedef enum pmppreach_t {
        PMPP_R_UNKNOWN, // A wildcard that matches any reachability status.
        PMPP_R_OFFLINE,
        PMPP_R_ONLINE,
        PMPP_R_SERVICE_OFFLINE,
        PMPP_R_SERVICE_ONLINE
} PmppReachability;

struct pmppcorres_t; // Forward declaration.

/**
 * A message is in essence just a list of properties.
 */
struct pmppmsg_t {
        char *cipherblock;              // - For storing the original, ciphertext block of the message.
        char *m_hash;                   // - For saving the original hash of a message before any successive modifications.
        char *pkg;                      // - For holding the serialized representation of the message.
        int critical;                   // - For indicating whether the message should be held onto until the recipient is reachable.
        struct pmppproplist_t *plist;   // - This property list is what defines the actual message.
        struct pmppcorres_t *recipient; // - The recipient, which can be either a server or a service (may be different from the final recipient).
        struct pmppcorres_t *sender;    // - The sender (may be different from the original sender).
        unsigned int attempts;          // - The number of sending attempts.
};

/**
 * Properties are combined in property lists in order
 * to describe entities.
 */
struct pmppprop_t {
        char *val;
        enum pmpplabel_t label;
        unsigned int secure; // Flag for determining whether contents are encrypted or not.
        unsigned int domain;
};

struct pmppcorreslist_t {
        struct pmppcorres_t *corres;
        struct pmppcorreslist_t *next;
};

struct pmppmsglist_t {
        struct pmppmsg_t *msg;
        struct pmppmsglist_t *next;
};

struct pmppproplist_t {
        struct pmppprop_t *prop;
        struct pmppproplist_t *next;
};

/**
 * A correspondent is a common name for both servers
 * & services. How can you tell which one you're dealing
 * with? You query the UUID type property.
 */
struct pmppcorres_t {
        enum pmppreach_t reachability;  // - For indicating whether the correspondent is online or not.
        int verified;                   // - A flag. Only set to true if a shared key exists with this correspondent.
        struct sockaddr_in laddr;       // - Holds the local IP address & port associated with this correspondent.
        struct sockaddr_in paddr;       // - Holds the public IP address & port associated with this correspondent.
        struct pmppcorreslist_t *clist; // - Holds a list of other correspondents associated with this correspondent (servers & services).
        struct pmppmsglist_t *mlist;    // - Holds a list of messages associated with this correspondent.
        struct pmppproplist_t *plist;   // - Holds a list of properties that describe this correspondent.
};

#endif /* pmpptypes_h */
