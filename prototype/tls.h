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
    uint8_t type; // TLS_PLAINTEXT_TYPE
    ProtocolVersion version;
    uint16_t length;
    uint8_t fragment[]; 
} __attribute__((packed)) TLSPlaintext;

#define TLS_HANDSHAKE_TYPE_HELLO_REQ 0
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 1
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO 2
#define TLS_HANDSHAKE_TYPE_CERT 0x0b
#define TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE 12
#define TLS_HANDSHAKE_TYPE_CERT_REQ 13
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE 14
#define TLS_HANDSHAKE_TYPE_CERT_VERIFY 15
#define TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE 0x10
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

// not in spec
typedef struct {
    uint8_t len0[3];
    uint8_t len1[3];
    uint8_t client_random[2];  
    uint8_t cert_data[];
} __attribute__((packed)) ClientCertificate;



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

#define TLS_CLIENT_HELLO_SIZE 4 + sizeof(TLSPlaintext) + sizeof(Handshake) + sizeof(ClientHello)

// key and out are 32 bytes
void hmac_sha256_compute(uint8_t* key, int key_len, uint8_t* data, int data_len, uint8_t* out) {
    HMAC(EVP_sha256(), key, key_len, data, data_len, out, NULL);
}

// out must be out_len bytes long
void prf(uint8_t* secret, int secret_len, uint8_t* seed, int seed_len, uint8_t* out, int len) {

    
    uint32_t a_len = 32 + seed_len; 
    uint8_t* a = (uint8_t*)malloc(a_len); 
    memcpy(a + 32, seed, seed_len); 

    hmac_sha256_compute(secret, secret_len, seed, seed_len, a);
    
    for (uint8_t* res = out; res < out+len; res += 32) {
        hmac_sha256_compute(secret, secret_len, a, a_len, res); // seed is a + seed
        hmac_sha256_compute(secret, secret_len, a, 32, a); // seed is a, replace a in "a + seed" buffer
    }
}

void add_msg_prefix(uint8_t* out) {
    *(uint32_t*)out = 0x00000044;
}

void TLSPlaintext_init(TLSPlaintext* msg, uint8_t type, uint16_t length) {
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

void build_client_hello(uint8_t* out, uint8_t* client_random) {
    
   
    TLSPlaintext* msg = out+4;
    Handshake* handshake = (Handshake*)msg->fragment;
    ClientHello* hello = (ClientHello*)handshake->body;

    add_msg_prefix(out);
    TLSPlaintext_init(msg, TLS_PLAINTEXT_TYPE_HANDSHAKE, sizeof(ClientHello) + sizeof(Handshake));
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


void build_client_handshake(SHA256_CTX* ctx, byte** out, uint32_t* out_len, uint8_t* cert, uint8_t cert_len, uint8_t* client_params, uint8_t client_params_len, uint8_t* master_secret) {

    uint32_t total_cert_len = cert_len;

    const int first_msg_len = (sizeof(Handshake) * 3) + sizeof(ClientCertificate) + total_cert_len + client_params_len + sizeof(CertificateVerify) + SHA256_DIGEST_LENGTH; 
    const int buf_len = 4 +
                        sizeof(TLSPlaintext) + first_msg_len +
                        sizeof(TLSPlaintext) + sizeof(ChangeCipherSpec) +
                        sizeof(TLSPlaintext) + sizeof(Handshake) + 80;
    uint8_t* buf = malloc(buf_len);

    add_msg_prefix(buf);
    TLSPlaintext* msg0 = buf + 4;
    TLSPlaintext_init(msg0, TLS_PLAINTEXT_TYPE_HANDSHAKE, first_msg_len);

    Handshake* hnd_cert = msg0->fragment;
    ClientCertificate* msg_client_cert = hnd_cert->body;
    int msg_cert_len = sizeof(ClientCertificate) + total_cert_len;
    Handshake_init(hnd_cert, TLS_HANDSHAKE_TYPE_CERT, msg_cert_len);
    msg_client_cert->len0[0] = msg_client_cert->len1[0] = total_cert_len >> 16;
    msg_client_cert->len0[1] = msg_client_cert->len1[1] = total_cert_len >> 8;
    msg_client_cert->len0[2] = msg_client_cert->len1[2] = total_cert_len;
    msg_client_cert->client_random[0] = 0xac;
    msg_client_cert->client_random[1] = 0x16; // TODO: randomize this
    memcpy(msg_client_cert->cert_data, cert, cert_len);



    Handshake* hnd_key_exchange = hnd_cert->body + msg_cert_len;
    int msg_key_exchange_len = client_params_len;
    Handshake_init(hnd_key_exchange, TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, msg_key_exchange_len);
    memcpy(hnd_key_exchange->body, client_params, client_params_len);

    puts("handshake");
    print_hex(client_params, client_params_len);
    
    uint8_t cert_verify[SHA256_DIGEST_LENGTH];

    SHA256_Update(ctx, hnd_cert, msg_cert_len + sizeof(Handshake));
    SHA256_Update(ctx, hnd_key_exchange, msg_key_exchange_len + sizeof(Handshake));
    SHA256_Final(cert_verify, ctx);

    Handshake* hnd_cert_verify = hnd_key_exchange->body + msg_key_exchange_len;
    CertificateVerify* msg_cert_verify = hnd_cert_verify;
    int msg_cert_verify_len = sizeof(CertificateVerify) + SHA256_DIGEST_LENGTH;
    Handshake_init(hnd_cert_verify, TLS_HANDSHAKE_TYPE_CERT_VERIFY, msg_cert_verify_len);
    msg_cert_verify->algorithm = (SignatureAndHashAlgorithm){ 48, 70 };
    memcpy(msg_cert_verify->handshake_messages, cert_verify, SHA256_DIGEST_LENGTH);

    *out = buf;
    *out_len = buf_len;
    //*out_len = 4 + sizeof(TLSPlaintext) + first_msg_len;

    
    TLSPlaintext* msg1 = hnd_cert_verify->body + msg_cert_verify_len;
    TLSPlaintext_init(msg1, TLS_PLAINTEXT_TYPE_CHANGE_CIPHER, sizeof(ChangeCipherSpec));
    ChangeCipherSpec* cng_cipher = msg1->fragment;
    cng_cipher->type = 0x01;

   
    uint8_t verify_seed[15 + SHA256_DIGEST_LENGTH];
    uint8_t verify_data[80];

    memcpy(verify_seed, "client finished", 15);
    memcpy(verify_seed + 15, cert_verify, SHA256_DIGEST_LENGTH);
    prf(master_secret, 48, verify_seed, 15 + SHA256_DIGEST_LENGTH, verify_data, 80);


    TLSPlaintext* msg2 = msg1->fragment + 1;
    TLSPlaintext_init(msg2, TLS_PLAINTEXT_TYPE_HANDSHAKE, sizeof(Handshake) + 80);
    Handshake* hnd_final = msg2->fragment;
    Handshake_init(hnd_final, TLS_HANDSHAKE_TYPE_FINISHED, 80);
    memcpy(verify_data, hnd_final->body, 80);

}