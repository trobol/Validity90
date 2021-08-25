/*
    Encapsulation of TLS 1.2 fuctions / data

    
    some things might not line up with the spec because validity devices don't always
    NON SPEC COMPLICENCE SHOULD BE MARKED


    some of this probably could be done through openssl but because of the spec non compliance and how sparse openssl documentation this is easier for the time being

*/
#include <stdint.h>
#include <string.h>


#define TLS_PLAINTEXT_TYPE_CHANGE_CIPHER 20
#define TLS_PLAINTEXT_TYPE_ALERT 0x15
#define TLS_PLAINTEXT_TYPE_HANDSHAKE 0x16
#define TLS_PLAINTEXT_TYPE_APP_DATA 23


typedef struct {
    uint8_t major;
    uint8_t minor;
} __attribute__((packed)) ProtocolVersion;

typedef struct {
    uint32_t prefix; // specific to validity 
    uint8_t type; // TLS_PLAINTEXT_TYPE
    ProtocolVersion version;
    uint16_t length;
    uint8_t fragment[]; 
} __attribute__((packed)) TLSPlaintext;

#define TLS_HANDSHAKE_TYPE_HELLO_REQ 0
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 1
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO 2
#define TLS_HANDSHAKE_TYPE_CERT 11
#define TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE 12
#define TLS_HANDSHAKE_TYPE_CERT_REQ 13
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE 14
#define TLS_HANDSHAKE_TYPE_CERT_VERIFY 15
#define TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE 16
#define TLS_HANDSHAKE_TYPE_FINISHED 20


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
    uint8_t random[32];
    SessionID session_id;

    // everything after this is normally dynamic
    uint16_t cipher_suites_len;
    uint16_t cipher_suites[2]; 
    
    uint8_t compression_methods_len; // zero
    uint8_t compression_methods[0]; 
   
    uint16_t extensions_len; // 10 for some reason (number of bytes - 2)
    
    Extension extensions[2];

} __attribute__((packed)) ClientHello;


typedef struct {
    ProtocolVersion server_version;
    uint8_t random[32];
    SessionID session_id[32];
    uint16_t cipher_suite;
    uint8_t compression_method;
    // shouldn't be any more data, extensions not supported
} __attribute__((packed)) ServerHello;

/*
typedef struct {
    uint8_t certificate_list[];
} Certificate;
*/
/*
typedef struct {
    uint8_t dh_public[];
} ClientKeyExchange;
*/

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

#define TLS_CLIENT_HELLO_SIZE sizeof(TLSPlaintext) + sizeof(Handshake) + sizeof(ClientHello)

void TLSPlaintext_init(TLSPlaintext* msg, uint8_t type, uint16_t length) {
    msg->prefix = 0x00000044;
    msg->type = type;
    msg->version = (ProtocolVersion){ 0x03, 0x03 };
    msg->length = (length >> 8) | (length << 8);
}
void Handshake_init(Handshake* out, uint8_t msg_type, uint32_t len) {
    out->msg_type = msg_type;
    out->length[0] = len >> 16;
    out->length[1] = len >> 8;
    out->length[2] = len;
}

void build_client_hello(TLSPlaintext* out, uint8_t* client_random) {
    Handshake* handshake = (Handshake*)out->fragment;
    ClientHello* hello = (ClientHello*)handshake->body;

    TLSPlaintext_init(out, TLS_PLAINTEXT_TYPE_HANDSHAKE, sizeof(ClientHello) + sizeof(Handshake));
    Handshake_init(handshake, TLS_HANDSHAKE_TYPE_CLIENT_HELLO, sizeof(ClientHello));

    hello->client_version = (ProtocolVersion){ 0x03, 0x03 };
    hello->session_id = (SessionID){ 7, {} };
    hello->cipher_suites_len = 0x0400; // 4 little endian
    hello->cipher_suites[0] = 0x05c0;
    hello->cipher_suites[1] = 0x3d00;
    hello->compression_methods_len = 0;
    hello->extensions_len = 0x0a00;
    
    Extension* hmac = hello->extensions;
    hmac->length = 0x0200;
    hmac->extension_type = TLS_EXTENSION_TYPE_TRUNC_HMAC;
    hmac->data[0] = 0x00;
    hmac->data[1] = 0x17;

    Extension* ec_formats = hello->extensions + 1;
    ec_formats->length = 0x0200;
    ec_formats->extension_type = TLS_EXTENSION_TYPE_EC_POINTS_FORMAT;
    ec_formats->data[0] = 0x01;
    ec_formats->data[1] = 0x00;
    
    memcpy(hello->random, client_random, 32);
}

/*
    ProtocolVersion client_version;
    uint8_t random[32];
    SessionID session_id;

    // everything after this is normally dynamic
    uint8_t cipher_suites_len[2];
    uint16_t cipher_suites[2]; 
    
    uint8_t compression_methods_len; // zero
    uint8_t compression_methods[0]; 
   
    uint8_t extensions_len[2]; // 10 for some reason (number of bytes - 2)
    
    Extension extensions[2];


*/