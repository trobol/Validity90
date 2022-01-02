/*
    Encapsulation of TLS 1.2 fuctions / data

    
    some things might not line up with the spec because validity devices don't always
    NON SPEC COMPLIANCE SHOULD BE MARKED

    

    some of this probably could be done through openssl but because of the spec non compliance and how sparse openssl documentation this is easier for the time being

*/
#include <stdint.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>

#define max(a,b) (a > b ? a : b)
#define min(a,b) (a > b ? b : a)

typedef struct {
    uint8_t data[32];
} __attribute__((packed)) HASH_SHA256;


#define TLS_PLAINTEXT_TYPE_CHANGE_CIPHER 20
#define TLS_PLAINTEXT_TYPE_ALERT 0x15
#define TLS_PLAINTEXT_TYPE_HANDSHAKE 0x16
#define TLS_PLAINTEXT_TYPE_APP_DATA 23

typedef struct _TLS_KEY32 {
    uint8_t data[32];
} __attribute__((packed)) TLS_KEY32;

typedef struct _TLS_MSG TLS_MSG;
typedef struct _TLS_HNDSHK TLS_HNDSHK;

typedef struct _TLS_CTX {

} _TLS_CTX;

typedef struct {
    uint8_t major;
    uint8_t minor;
} __attribute__((packed)) ProtocolVersion;

typedef struct {
    uint8_t type; // TLS_PLAINTEXT_TYPE
    ProtocolVersion version;
    uint16_t length;
    uint8_t fragment[]; 
} __attribute__((packed)) TLSPlaintext;


enum TLS_HANDSHAKE_TYPE {
 TLS_HANDSHAKE_TYPE_HELLO_REQ = 0,
 TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 1,
 TLS_HANDSHAKE_TYPE_SERVER_HELLO = 2,
 TLS_HANDSHAKE_TYPE_CERT = 11,
 TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12,
 TLS_HANDSHAKE_TYPE_CERT_REQ = 13,
 TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14,
 TLS_HANDSHAKE_TYPE_CERT_VERIFY = 15,
 TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16,
 TLS_HANDSHAKE_TYPE_FINISHED = 20
};



const char* tls_handshake_type_name(uint8_t type);

typedef struct {
    uint8_t msg_type;
    uint8_t length[3];
    uint8_t body[];
    /*
    body is one of  
    HelloRequest - empty
    ClientHello
    ServerHello
    Certificate
    ServerKeyExchange
    CertificateRequest
    ServerHelloDone
    CertificateVerify
    ClientKeyExchange
    Finished
    */
} __attribute__((packed)) Handshake;


typedef struct {
    uint8_t level;
    uint8_t description;
} __attribute__((packed)) Alert;

#define TLS_EXTENSION_TYPE_TRUNC_HMAC 0x0400
#define TLS_EXTENSION_TYPE_EC_POINTS_FORMAT 0x0b00

typedef struct {
    uint16_t extension_type;
    uint16_t length; // 2 
    uint8_t  data[2];
} __attribute__((packed)) Extension;

typedef struct {
    uint8_t len; // 7
    uint8_t data[7];
} __attribute__((packed)) SessionID;

typedef struct {
    ProtocolVersion client_version;
    TLS_KEY32 random;
    SessionID session_id;

    // everything after this is normally dynamic
    uint16_t cipher_suites_len;
    uint16_t cipher_suites[3];
    
    uint8_t compression_methods_len; // zero
    uint8_t compression_methods[0]; 
   
    uint16_t extensions_len; // 10 for some reason (number of bytes - 2)
    
    Extension extensions[2];

} __attribute__((packed)) ClientHello;


typedef struct {
    ProtocolVersion server_version;
    TLS_KEY32 random;
    SessionID session_id;
    uint16_t cipher_suite;
    uint8_t compression_method;
    // shouldn't be any more data, extensions not supported
} __attribute__((packed)) ServerHello;

// not in spec
typedef struct {
    uint8_t len0[3];
    uint8_t len1[3];
    uint8_t client_random[2];  
    uint8_t cert_data[];
} __attribute__((packed)) ClientCertificate;

typedef struct {
    uint8_t prefix; // always 0x04
    TLS_KEY32 x;
    TLS_KEY32 y;
} __attribute__((packed)) ClientKeyExchange;

#define TLS_HASH_ALGORITHM_NONE 0
#define TLS_HASH_ALGORITHM_MD5  1
#define TLS_HASH_ALGORITHM_SHA1 2
#define TLS_HASH_ALGORITHM_SHA224 3
#define TLS_HASH_ALGORITHM_SHA256 4
#define TLS_HASH_ALGORITHM_SHA384 5
#define TLS_HASH_ALGORITHM_SHA512 6

#define TLS_SIGNATURE_ALGORITHM_ANONYMOUS 0
#define TLS_SIGNATURE_ALGORITHM_RSA 1
#define TLS_SIGNATURE_ALGORITHM_DSA 2
#define TLS_SIGNATURE_ALGORITHM_ECDSA 3

typedef struct {
    uint8_t hash;
    uint8_t signature;
} __attribute__((packed)) SignatureAndHashAlgorithm;

// digitally signed struct
typedef struct {
    SignatureAndHashAlgorithm algorithm;
    uint8_t handshake_messages[];
} __attribute__((packed)) CertificateVerify;

typedef struct {
    uint8_t type;
} __attribute__((packed)) ChangeCipherSpec;

/*
typedef struct {
    uint8_t verify_data[];
} Finished;
*/

typedef struct {
    uint16_t certificate_types_cout; // 1
    uint8_t certificate_type;
    uint16_t certificate_authorities_len;
    uint8_t certificate_authorities[];
} __attribute__((packed)) CertificateRequest;



/*

 Client                                               Server

    ClientHello                  -------->
                                                    ServerHello
                                                    Certificate*
                                              ServerKeyExchange*
                                             CertificateRequest*
                                <--------        ServerHelloDone
    Certificate*
    ClientKeyExchange
    CertificateVerify*
    [ChangeCipherSpec]
    Finished                     -------->
                                              [ChangeCipherSpec]
                                <--------               Finished
    Application Data             <------->     Application Data


*/

void TLS_MSG_init(TLS_MSG** msg);
TLS_HNDSHK* TLS_MSG_get_handshake(TLS_MSG** msg, uint8_t index);
int TLS_MSG_get_handshake_count(TLS_MSG** msg);
void TLS_MSG_add_handshake(TLS_MSG** msg, TLS_HNDSHK* hand);

void TLS_HNDSHK_init(TLS_HNDSHK** hndshk, int length);
void TLS_HNDSHK_set_data(TLS_HNDSHK** hndshk, uint8_t* data, uint32_t length);
void TLS_HNDSHK_set_type(TLS_HNDSHK** hndshk, uint8_t type);
uint16_t TLS_HNDSHK_get_length(TLS_HNDSHK* hndshk);

TLS_HNDSHK* TLS_HNDSHK_new(uint8_t type, uint8_t* data, uint32_t length);

#define TLS_CLIENT_HELLO_SIZE 4 + sizeof(TLSPlaintext) + sizeof(Handshake) + sizeof(ClientHello)


// inner_contents must be at least 64 + msg_len bytes long, out must be at least 32 bytes long
void hmac_sha256_raw(uint8_t* key, int key_len, uint8_t* msg, int msg_len, uint8_t* inner_contents, uint8_t* out);

/*
pseudorandom function

takes as input a secret, a seed, and
   an identifying label and produces an output of arbitrary length.
*/
void prf(uint8_t* secret, int secret_len, const char* label, uint8_t* seed, int seed_len, uint8_t* out, int len);

HASH_SHA256 hmac_sha256(uint8_t* key, int key_len, uint8_t* msg, int msg_len);


void add_msg_prefix(uint8_t* out);
void TLSPlaintext_init(TLSPlaintext* msg, uint8_t type, uint16_t length);
void Handshake_init(Handshake* out, uint8_t msg_type, uint32_t len);
void build_client_hello(uint8_t* out, TLS_KEY32 client_random);
void urandom(uint8_t* out, int len);

void build_client_handshake(SHA256_CTX* ctx, SHA256_CTX* ctx_dupe, uint8_t** out, uint32_t* out_len, uint8_t* cert, uint8_t cert_len, TLS_KEY32 pub_x, TLS_KEY32 pub_y, EC_KEY* priv_key, uint8_t* master_secret, TLS_KEY32 sign_key, TLS_KEY32 encryption_key);