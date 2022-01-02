#include "tls.h"
#include <openssl/sha.h>

struct _TLS_MSG {
    uint8_t type; // TLS_PLAINTEXT_TYPE
    ProtocolVersion version;
    uint8_t len_bytes[2];
    uint8_t fragment[]; 
};

struct _TLS_HNDSHK {
    uint8_t msg_type;
    uint8_t len_bytes[3];
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
};

/*

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

 */

const char* tls_handshake_type_name(uint8_t type) {
    switch(type) {
        case TLS_HANDSHAKE_TYPE_HELLO_REQ:
            return "HELLO REQ";
        case TLS_HANDSHAKE_TYPE_CLIENT_HELLO:
            return "CLIENT HELLO";
        case TLS_HANDSHAKE_TYPE_SERVER_HELLO:
            return "SERVER HELLO";
        case TLS_HANDSHAKE_TYPE_CERT:
            return "CERT";
        case TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
            return "SERVER KEY EXCHANGE";
        case TLS_HANDSHAKE_TYPE_CERT_REQ:
            return "CERT REQ";
        case TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE:
            return "CLIENT KEY EXCHANGE";

        default:
        return "unknown";
    }
}


void TLS_MSG_init(TLS_MSG** msg) {
    *msg = (TLS_MSG*)malloc(sizeof(TLS_MSG));
    TLS_MSG_set_length(msg, 0);
}

uint16_t TLS_MSG_get_length(TLS_MSG** msg) {
    return ((*msg)->len_bytes[0] >> 8) | ((*msg)->len_bytes[1] << 8);
}

void TLS_MSG_set_length(TLS_MSG** msg, uint16_t len) {
    (*msg)->len_bytes[0] = len << 8;
    (*msg)->len_bytes[1] = len >> 8;
}

void TLS_MSG_set_type(TLS_MSG** msg, uint8_t type) {
    (*msg)->type = type;
}

TLS_HNDSHK* TLS_MSG_get_handshake(TLS_MSG** msg, uint8_t index);
int TLS_MSG_get_handshake_count(TLS_MSG** msg);
void TLS_MSG_add_handshake(TLS_MSG** msg, TLS_HNDSHK* hnd) {
    uint16_t frag_len = sizeof(TLS_MSG) + TLS_MSG_get_length(msg);
    uint16_t hand_len = sizeof(TLS_HNDSHK) + TLS_HNDSHK_get_length(hnd);
    *msg = (TLS_MSG*)realloc(*msg, frag_len + hand_len);
    memcpy(*msg + frag_len, hnd, hand_len);
}


void TLS_HNDSHK_init(TLS_HNDSHK** hndshk, int length);
void TLS_HNDSHK_set_data(TLS_HNDSHK** hndshk, uint8_t* data, uint32_t length);
void TLS_HNDSHK_set_type(TLS_HNDSHK** hndshk, uint8_t type);
uint16_t TLS_HNDSHK_get_length(TLS_HNDSHK* hndshk) {

}

// inner_contents must be at least 64 + msg_len bytes long, out must be at 32 bytes long
void hmac_sha256_raw(uint8_t* key, int key_len, uint8_t* msg, int msg_len, uint8_t* inner_contents, uint8_t* out) {
    uint8_t padded_key[64] = {};
    uint8_t outer_contents[96] = {};
    const int blocksize = 64;
    

    // inner_contents is inner key + msg
    // outer_contents is outer key + hash(inner_contents)

    if ( key_len > blocksize )
        SHA256(key, key_len, padded_key);
    else
        memcpy(padded_key, key, key_len);

    for (int i = 0; i < 64; i++) {
        outer_contents[i] = padded_key[i] ^ 0x5c;
        inner_contents[i] = padded_key[i] ^ 0x36;
    }


    memcpy(inner_contents + 64, msg, msg_len);
    

    SHA256(inner_contents, 64 + msg_len, outer_contents + 64);
    SHA256(outer_contents, 96, out);
}


/*
pseudorandom function

takes as input a secret, a seed, and
   an identifying label and produces an output of arbitrary length.
*/
void prf(uint8_t* secret, int secret_len, const char* label, uint8_t* seed, int seed_len, uint8_t* out, int len) {
    /*
    A(0) = seed
    A(i) = HMAC_hash(secret, A(i-1))

    prf(secret, seed) =     HMAC_hash(secret, A(1) + seed) +
                            HMAC_hash(secret, A(2) + seed) +
                            HMAC_hash(secret, A(3) + seed) + ...
    */
    int label_len = strlen(label);
    int a_len = 32 + label_len + seed_len; 
    uint8_t *a = (uint8_t*)malloc(a_len);
    uint8_t *hash_buf = (uint8_t*)malloc(64 + a_len);
    uint8_t out_buf[32];

   

    memcpy(a + 32, label, label_len);
    memcpy(a + 32 + label_len, seed, seed_len);

    //a[a_len-1] = 0;
    //puts(a + 32);

    hmac_sha256_raw(secret, secret_len, a + 32, label_len + seed_len, hash_buf, a);
    puts("hashed secret");
    print_hex(a, 32);
    
    for (uint32_t i = 0; i < len; i += 32) {
        
        hmac_sha256_raw(secret, secret_len, a, a_len, hash_buf, out_buf); // seed is a + seed
        hmac_sha256_raw(secret, secret_len, a, 32, hash_buf, a); // seed is a, replace a in "a + seed" buffer
        memcpy(out + i, out_buf, min(32, len-i));
    }

    free(a);
    free(hash_buf);
}



HASH_SHA256 hmac_sha256(uint8_t* key, int key_len, uint8_t* msg, int msg_len) {

    uint8_t* inner_buf = (uint8_t*)malloc(64 + msg_len);
    HASH_SHA256 ret;
    hmac_sha256_raw(key, key_len, msg, msg_len, inner_buf, ret.data);
    free(inner_buf);
    return ret;
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

void build_client_hello(uint8_t* out, TLS_KEY32 client_random) {
    
   
    TLSPlaintext* msg = out+4;
    Handshake* handshake = (Handshake*)msg->fragment;
    ClientHello* hello = (ClientHello*)handshake->body;

    add_msg_prefix(out);
    TLSPlaintext_init(msg, TLS_PLAINTEXT_TYPE_HANDSHAKE, sizeof(ClientHello) + sizeof(Handshake));
    Handshake_init(handshake, TLS_HANDSHAKE_TYPE_CLIENT_HELLO, sizeof(ClientHello));

    hello->client_version = (ProtocolVersion){ 0x03, 0x03 };
    hello->session_id = (SessionID){ 7, {} };
    hello->cipher_suites_len = 0x0600; // 4 little endian
    hello->cipher_suites[0] = 0x05c0;
    hello->cipher_suites[1] = 0x3d00;
    hello->cipher_suites[2] = 0x8d00;
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

    hello->random = client_random;
    
}

void urandom(uint8_t* out, int len) {
    if (RAND_load_file("/dev/random", 32) != 32) { puts("RAND_load_file failed"); exit(1); };
    if (RAND_bytes(out, len) != 1) { puts("RAND_bytes failed"); exit(1); };
}


void build_client_handshake(SHA256_CTX* ctx, SHA256_CTX* ctx_dupe, uint8_t** out, uint32_t* out_len, uint8_t* cert, uint8_t cert_len, TLS_KEY32 pub_x, TLS_KEY32 pub_y, EC_KEY* priv_key, uint8_t* master_secret, TLS_KEY32 sign_key, TLS_KEY32 encryption_key) {

    uint32_t total_cert_len = cert_len;
    int ecda_size = ECDSA_size(priv_key);

    const int first_msg_len = (sizeof(Handshake) * 3) + sizeof(ClientCertificate) + total_cert_len + sizeof(ClientKeyExchange) + ecda_size;
    const int max_buf_len = 4 +
                        sizeof(TLSPlaintext) + first_msg_len +
                        sizeof(TLSPlaintext) + sizeof(ChangeCipherSpec) +
                        sizeof(TLSPlaintext) + 80;
    uint8_t* buf = malloc(max_buf_len);

    add_msg_prefix(buf);
    TLSPlaintext* msg0 = buf + 4;
    

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

    printf("client cert len: %u\n", total_cert_len);

    Handshake* hnd_key_exchange = hnd_cert->body + msg_cert_len;
    ClientKeyExchange* msg_key_exchange = hnd_key_exchange->body;
    int msg_key_exchange_len = sizeof(ClientKeyExchange);
    Handshake_init(hnd_key_exchange, TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, msg_key_exchange_len);
    msg_key_exchange->prefix = 0x04;
    //reverse(pub_x.data, 32);
    //reverse(pub_y.data, 32);
    msg_key_exchange->x = pub_x;
    msg_key_exchange->y = pub_y;
    
    uint8_t cert_verify[SHA256_DIGEST_LENGTH];

    SHA256_Update(ctx, hnd_cert, msg_cert_len + sizeof(Handshake));
    SHA256_Update(ctx, hnd_key_exchange, msg_key_exchange_len + sizeof(Handshake));
    SHA256_Final(cert_verify, ctx);

    SHA256_Update(ctx_dupe, hnd_cert, msg_cert_len + sizeof(Handshake));
    SHA256_Update(ctx_dupe, hnd_key_exchange, msg_key_exchange_len + sizeof(Handshake));

    Handshake* hnd_cert_verify = hnd_key_exchange->body + msg_key_exchange_len;
   
    int sig_len;
    if ( ECDSA_sign(0, cert_verify, SHA256_DIGEST_LENGTH, hnd_cert_verify->body, &sig_len, priv_key) != 1 ) { puts("failed to sign"); exit(1); }
    Handshake_init(hnd_cert_verify, TLS_HANDSHAKE_TYPE_CERT_VERIFY, sig_len);


    TLSPlaintext_init(msg0, TLS_PLAINTEXT_TYPE_HANDSHAKE, first_msg_len - (ecda_size-sig_len));
    printf("sig len: %i total sig: %i\n ", sig_len, ecda_size);

    SHA256_Update(ctx_dupe, hnd_cert_verify, sig_len + sizeof(Handshake));
    SHA256_Final(cert_verify, ctx_dupe);
    
    TLSPlaintext* msg1 = hnd_cert_verify->body + sig_len;
    TLSPlaintext_init(msg1, TLS_PLAINTEXT_TYPE_CHANGE_CIPHER, sizeof(ChangeCipherSpec));
    ChangeCipherSpec* cng_cipher = msg1->fragment;
    cng_cipher->type = 0x01;


    *out = buf;
    *out_len = max_buf_len;
    *out_len = max_buf_len - (ecda_size-sig_len);

    //*out_len = 4 + sizeof(TLSPlaintext) + first_msg_len + sizeof(TLSPlaintext) + sizeof(ChangeCipherSpec) - (ecda_size-sig_len);
   

    uint8_t verify_data[12];

    prf(master_secret, 0x30, "client finished", cert_verify, SHA256_DIGEST_LENGTH, verify_data, 12);


    uint8_t final_data_buf[64];
    

    TLSPlaintext* buf_msg2 = final_data_buf;
    Handshake* buf_hnd_final = buf_msg2->fragment;
    TLSPlaintext_init(buf_msg2, TLS_PLAINTEXT_TYPE_HANDSHAKE, 12 + sizeof(Handshake));
    Handshake_init(buf_hnd_final, TLS_HANDSHAKE_TYPE_FINISHED, 12);
    memcpy(verify_data, buf_hnd_final->body, 12);

    //reverse(sign_key.data, 32);
    HASH_SHA256 sign_hmac = hmac_sha256(sign_key.data, 32, buf_msg2, sizeof(TLSPlaintext) + sizeof(Handshake) + 12);
    memcpy(buf_hnd_final->body + 12, sign_hmac.data, 32);

    uint8_t* i = final_data_buf + 53;
    uint8_t* end = i + 11;
    for (; i < end; i++) {
        *i = 10;
    }
    print_hex(final_data_buf, 64);

    
    TLSPlaintext* msg2 = msg1->fragment + 1;
    TLSPlaintext_init(msg2, TLS_PLAINTEXT_TYPE_HANDSHAKE, 80);
    
    uint8_t rand_vec[16];
    urandom(rand_vec, 16);
    memcpy(msg2->fragment, rand_vec, 16);
    //reverse(msg2->fragment, 16);

    EVP_CIPHER_CTX* ci_ctx = EVP_CIPHER_CTX_new();
    if ( EVP_EncryptInit(ci_ctx, EVP_aes_256_cbc(), encryption_key.data, rand_vec) != 1) {puts("faild to encrpt"); exit(1);}
    int outlenA, outlenB;
    if ( EVP_EncryptUpdate(ci_ctx, msg2->fragment + 16, &outlenA, buf_msg2, 64) != 1) {puts("faild to encrpt"); exit(1);}
    //EVP_EncryptFinal(ci_ctx, msg2->fragment + 16 + outlenA, &outlenB);
    
    printf("outlenA : %i, outlenB: %i \n", outlenA, outlenB);
    
    EVP_CIPHER_CTX_free(ci_ctx);
}


