
#include <stdio.h>
#include <stdbool.h>
#include <libusb.h>
#include <stdlib.h>
#include <string.h>
#include <nss.h>
#include <keyhi.h>
#include <keythi.h>
#include <secoid.h>
#include <secmodt.h>
#include <sechash.h>
#include <pk11pub.h>
#include <err.h>
#include <errno.h>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/aes.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/ecdh.h>
#include "constants.h"


#define xstr(a) str(a)
#define str(a) #a

#define max(a,b) (a > b ? a : b)
#define min(a,b) (a > b ? b : a)

#define err(x) res_err(x, xstr(x))
#define errb(x) res_errb(x, xstr(x))

typedef struct DeviceInfo {
    guint16 vid;
    guint16 pid;

    guint hasLed;
    guint hasBios;
    guint requiresReset;
    guint hasRawOutput;
    gboolean unsupported;

    gchar *description;
} DeviceInfo;

DeviceInfo all_devices[] = {
    { .vid = 0x138a, .pid = 0x0090, .hasLed = 1, .hasBios = 1, .requiresReset = 0, .hasRawOutput = 1 },
    { .vid = 0x138a, .pid = 0x0097, .hasLed = 1, .hasBios = 1, .requiresReset = 0, .hasRawOutput = 0 },
    { .vid = 0x138a, .pid = 0x0094, .hasLed = 0, .hasBios = 0, .requiresReset = 1, .hasRawOutput = 1, .unsupported = 1, .description = "Support would be available soon" },
    { .vid = 0x06cb, .pid = 0x0081, .hasLed = -1, .hasBios = -1, .requiresReset = 1, .hasRawOutput = -1, .unsupported = 1, .description = "Support would be available soon" },
    { .vid = 0x06cb, .pid = 0x009a, .hasLed = 1, .hasBios = -1, .requiresReset = 0, .hasRawOutput = -1 },
    { .vid = 0x138a, .pid = 0x0091, .unsupported = 1, .description = "Won't be supported, check README" },
};


static libusb_device_handle * dev;

int idProduct = 0;

/*
 * UTILITIES
 */

#define throw_error(msg) throw_err_impl(msg, __LINE__)

void throw_err_impl(const char* msg, unsigned int line) {
    printf("threw error on line %u: \n \"%s\"\n", line, msg);
    exit(EXIT_FAILURE);
}

void print_hex_gn(byte* data, int len, int sz) {
    for (int i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0) {
                printf("\n");
            }
            printf("%04x ", i);
        } else if ((i % 8) == 0) {
            printf(" ");
        }
        printf("%02x ", data[i * sz]);
    }
    puts("");
}

void print_hex(byte* data, int len) {
    print_hex_gn(data, len, 1);
}

void print_hex_dw(dword* data, int len) {
    print_hex_gn(data, len, 4);
}

void res_err(int result, char* where) {
    if (result != 0) {
        printf("Failed '%s': %d - %s\n", where, result, libusb_error_name(result));
        exit(0);
    }
}

void res_errb(int result, char* where) {
    if (result != 1) {
        printf("Failed '%s': %d - %s\n", where, result, libusb_error_name(result));
        ERR_print_errors_fp(stderr);
        exit(0);
    }
}

void qwrite(byte * data, int len) {
    int send;
    err(libusb_bulk_transfer(dev, 0x01, data, len, &send, 10000));

    printf("usb write (%u bytes):\n", len);
    print_hex(data, len);
}

void qread(byte * data, int len, int *out_len) {
    err(libusb_bulk_transfer(dev, 0x81, data, len, out_len, 10000));

    printf("usb read (%u bytes):\n", *out_len);
    print_hex(data, *out_len);
}


// returns status
word usb_cmd(byte* cmd, int len, byte* rsp, int max_rsp, int *rsp_len) {
    int out_len;

    qwrite(cmd, len);
    qread(rsp, max_rsp, &out_len);

    if (out_len < 2) {
        throw_error("usb command response was too short");
    }
    if (rsp_len) *rsp_len = out_len;
    return *(word*)rsp;
}

word usb_cmd_byte(byte cmd, byte* rsp, int max_rsp, int *rsp_len) {
    return usb_cmd(&cmd, 1, rsp , max_rsp, rsp_len);
}

void assert_status(word status) {
    if (status != 0) {
        printf("signature=%u\n", status);
        // what signature?
        if (status == 0x44f) throw_error("usb cmd failed signature validation");
        else throw_error("usb cmd returned error status");
    }
}

void reverse(byte* data, int len) {
    for( byte *end = data+len-1; data < end; data++, end--) {
        byte tmp = *data;
        *data = *end;
        *end = tmp;
    }
}

byte system_serial[1024];
int system_serial_len;

void loadBiosData() {
    char name[1024], serial[1024];
    FILE *nameFile, *serialFile;
    if (!(nameFile = fopen("/sys/class/dmi/id/product_name", "r"))) {
        perror("Can't open /sys/class/dmi/id/product_name");
        exit(EXIT_FAILURE);
    }
    if (!(serialFile = fopen("/sys/class/dmi/id/product_serial", "r"))) {
        perror("Can't open /sys/class/dmi/id/product_serial");
        exit(EXIT_FAILURE);
    }

    fscanf(nameFile, "%s", name);
    fscanf(serialFile, "%s", serial);

    int len1 = strlen(name), len2 = strlen(serial);
    memcpy(system_serial, name, len1 + 1);
    memcpy(system_serial + len1 + 1, serial, len2 + 1);
    system_serial_len = len1 + len2 + 2;

    fclose(nameFile);
    fclose(serialFile);

    set_hwkey(name, serial);
}

// key and out are 32 bytes
void hmac_sha256_compute(byte* key, byte* data, int data_len, byte* out) {
    HMAC(EVP_sha256(), key, 32, data, data_len, out, NULL);
}

byte psk_encryption_key[32];
byte psk_validation_key[32];



// out must be out_len bytes long
void prf(byte* secret, byte* seed, int seed_len, byte* out, int len) {

    
    byte* a_len = 32 + seed_len; 
    byte* a = (byte*)malloc(a_len); 
    memcpy(a + 32, seed, seed_len); 

    hmac_sha256_compute(secret, seed, seed_len, a);
    
    for (byte* res = out; res < out+len; res += 32) {
        hmac_sha256_compute(secret, a, a_len, res); // seed is a + seed
        hmac_sha256_compute(secret, a, 32, a); // seed is a, replace a in "a + seed" buffer
    }
}

void set_hwkey(char* name, char* serial) {
    // null terminators are included
    int name_len   = strlen(name)   + 1;
    int serial_len = strlen(serial) + 1;
    int hwkey_len  = name_len + serial_len; 

    byte* hwkey = (byte*)malloc(hwkey_len);
    memcpy(hwkey, name, name_len);
    memcpy(hwkey + name_len, serial, serial_len);

    int seed_len = 3 + hwkey_len;
    byte* seed = (byte*)malloc(seed_len);
    memcpy(seed + 3, hwkey, hwkey_len);
    seed[0] = 'G';
    seed[1] = 'W';
    seed[2] = 'K';

    prf(password_hardcoded, seed, seed_len, psk_encryption_key, 32);
    prf(psk_encryption_key, gwk_sign_hardcoded, sizeof(gwk_sign_hardcoded), psk_validation_key, 32);
    
    print_hex(psk_encryption_key, 32);
    print_hex(psk_validation_key, 32);

}
/*
 * READING DATA OFF DEVICE
 */ 
typedef struct flash_read_cmd {
    byte cmd; // 0x40
    byte partition;
    byte unknown0; // 1
    word unknown1; // 0
    dword addr;
    dword size;
} __attribute__((packed)) flash_read_cmd ;



void read_flash(byte* rsp, int max_rsp, int* rsp_size, byte partition, dword addr, dword size) {
    byte rsp_buf[1024 * 1024]; // TODO: find real size
    int rsp_len;
    flash_read_cmd cmd = { 0x40, partition, 1, 0, addr, size};
    // TODO if tls is active use that
    int status = usb_cmd(&cmd, sizeof(flash_read_cmd), rsp_buf, 1024 * 1024, &rsp_len);
    assert_status(status);

    dword data_size = (*(dword*)(rsp_buf + 2));
    
    memcpy(rsp, rsp_buf + 8, data_size);
    
    *rsp_size = data_size;
}


void read_tls_flash(byte* rsp, int max_rsp, int* rsp_size) {
    return read_flash(rsp, max_rsp, rsp_size, 1, 0, 0x1000);
}


typedef struct _firmware_module_info {
    word type;
    word subtype;
    word major;
    word minor;
    dword size;
} firmware_module_info;

typedef struct _firmware_info {
    word major;
    word minor;
    word module_count;
    dword buildtime;
    firmware_module_info modules[];
} firmware_info;

bool has_firmware() {
    const byte cmd[2] = { CMD_ID_READ_PARTITION, 0x02 }; // read partition, second partition
    byte rsp[1024 * 1024];
    int rsp_len;
    // status + 10
    
    qwrite(cmd, 2);
    qread(rsp, 1024 * 1024, &rsp_len);

    word status = *(word*)rsp;

    // what is this constant?
    if (status == 0x04b0) return false;
    else if (status == 0) return true;
    else {
        throw_error("unexpected status from firmware partition");
    }
}

// firmware_info must be freed
firmware_info* get_firmware_info() {
    const byte cmd[2] = { CMD_ID_READ_PARTITION, 0x02 }; // read partition, second partition
    byte rsp[1024 * 1024];
    int rsp_len;
    // status + 10
    
    qwrite(cmd, 2);
    qread(rsp, 1024 * 1024, &rsp_len);
    word status = usb_cmd(cmd, 2, rsp, 1024 * 1024, &rsp_len);
    
    // no firmware yet
    if (rsp_len == 2 && status == 0x04b0)
        return NULL;

    assert_status(rsp);
    
    if (rsp_len-2 < sizeof(firmware_info)) {
        puts("firmware info response wasn't large enough"); exit(1);
    }

    firmware_info *tmp_info = (firmware_info*)(rsp + 2);
    const firm_size = sizeof(firmware_info) + ( sizeof(firmware_module_info) * tmp_info->module_count );

    if (rsp_len-2 < firm_size) {
        throw_error("firmware info response wasn't large enough");
    }

    firmware_info *info = (firmware_info*)malloc(firm_size);
    memcpy(info, tmp_info, firm_size);

    return info;
}

void send_init() {
    byte rsp[1024 * 1024] = {};
    // these have something to do with hardware
    assert_status(usb_cmd_byte(0x00, rsp, 1024*1024, NULL));
    assert_status(usb_cmd_byte(0x19, rsp, 1024*1024, NULL));

    bool fw = has_firmware();

    assert_status(usb_cmd(init_sequence_msg4_alt, sizeof(init_sequence_msg4_alt), rsp, 1024*1024, NULL));
    
    // if there is no firmware upload clean slate
    if ( !fw ) {
        // TODO: upload init_hardcoded_clean_slate
        puts("REQUIRED CLEAN SLATE");
        exit(1);
    }
}


typedef struct _flash_partition_info {
    byte id;
    byte type;
    word access_lvl;
    dword offset;
    dword size;
} flash_partition_info;

typedef struct _flash_ic_info {
    const char* name;
    int size;
    int f18;
    int jid0;
    int jid1;
    int f1b;
    int f1c;
} flash_ic_info;



typedef struct _flash_info {
    word jid0;
    word jid1;
    word blocks;
    word unknown0;
    word blocksize;
    word unknown1;
    word partition_count;
    flash_partition_info partitions[];
} flash_info;



// flash_info must be freed
flash_info* get_flash_info() {
    static const byte get_flash_info_data[1] = { 0x3e };
    byte buf[ 1024 * 1024 ];
    int bytes_read;
    qwrite(get_flash_info_data, 1);
    qread(buf, 1024 * 1024, &bytes_read);

    if ( bytes_read < (2 + sizeof(flash_info))) {
        // error
    }

    flash_info* buf_info = (flash_info*)(buf+2);

    int part_size = buf_info->partition_count * sizeof(flash_partition_info);
    int info_size = sizeof(flash_info) + part_size;
    flash_info* info = (flash_info*)malloc(info_size);
    memcpy(info, buf_info, info_size);

 
    return info;
}

void init_flash() {
     // init flash
    flash_info* flash_info = get_flash_info();
    word part_count = flash_info->partition_count;
    free(flash_info);

    if (part_count > 0) {
        printf("flash has %hu partitions\n", part_count);
        return;
    }
    
    puts("flash is not initialized. formatting...");
    

    // TODO: init flash
}

typedef struct _rom_info {
    unsigned int timestamp;
    unsigned int build;
    byte major;
    byte minor;
    byte pad0;
    byte product;
    byte pad1;
    byte pad2;
    byte pad3;
    byte u1;
} rom_info;


rom_info get_rom_info() {
    static const byte get_rom_info_data[1] = { 0x01 };
    byte buf[1024 * 1024];
    int bytes_read;
    //tls_write(get_rom_info_data, 1);
    //tls_read(buf, &bytes_read);
    throw_error("get_rom_info requires tls");

    if (bytes_read < (sizeof(rom_info) + 2)) {
        // error
    }
    
    rom_info info;
    memcpy(&info, buf + 2, sizeof(rom_info));
    return info;
}


/*
 * TLS STUFF
 *
 */

BIGNUM* make_bignum(byte* n) {
    return BN_lebin2bn( n, 32, NULL);
}


// output is "SHA256_DIGEST_LENGTH" bytes
void hash_sha256(byte *in, int len, byte* out) {
    SHA256_CTX context;
    if(!SHA256_Init(&context))
        throw_error("failed to init sha256 hash context");
    if(!SHA256_Update(&context, in, len))
        throw_error("failed to update sha256 hash");
    if(!SHA256_Final(out, &context))
        throw_error("failed to output sha256 hash");
}


EC_KEY* derive_private_key(BIGNUM* bn_d) {
    // "Note that in [PKI-ALG] ... the secp256r1 curve was referred to as prime256v1." https://www.ietf.org/rfc/rfc5480.txt
    const EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_GROUP* group = EC_KEY_get0_group(key);
    const EC_POINT* point = EC_POINT_new(group);

    const BN_CTX* bn_ctx = BN_CTX_new();


    BN_CTX_start(bn_ctx);
    EC_POINT_mul(group, point, bn_d, NULL, NULL, bn_ctx);

    const BIGNUM* bn_x = BN_CTX_get(bn_ctx);
    const BIGNUM* bn_y = BN_CTX_get(bn_ctx);

    EC_POINT_get_affine_coordinates(group, point, bn_x, bn_y, bn_ctx);

    BN_CTX_end(bn_ctx);


    EC_KEY_set_public_key(key, point);
    EC_KEY_set_private_key(key, bn_d);

    return key;
} 


struct tls_priv_info {
    byte prefix;
union {
    struct {
        byte iv[16];
        byte keys[112];
    };
    byte data[128];
};
    
    byte hash[32];
} __attribute__((packed));


void parse_tls_priv(byte* body, int len) {
    puts("found priv block");
    
    struct tls_priv_info* info = body;
    if ( info->prefix != 2 ) throw_error("unknown private key prefix");

    byte sig[32];
    hmac_sha256_compute(psk_validation_key, info->data, 128, sig);

    if ( memcmp(info->hash, sig, 32) != 0 )
        throw_error("signature verification failed. this device was probably paired with another computer");
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    byte keys_decrypt[112 + 128];
    int keys_decrypt_len0;
    int keys_decrypt_len1;

    EVP_DecryptInit(ctx, EVP_aes_256_cbc(), psk_encryption_key, info->iv);
    EVP_DecryptUpdate(ctx, keys_decrypt, &keys_decrypt_len0, info->keys, 112);
    EVP_DecryptFinal(ctx, keys_decrypt + keys_decrypt_len0, &keys_decrypt_len1);

    int keys_decrypt_len_total = keys_decrypt_len0 + keys_decrypt_len1;

    byte* x = keys_decrypt;
    byte* y = keys_decrypt + 32;
    byte* d = keys_decrypt + 64;
    
    puts("private key:");
    puts(" x:");
    print_hex(x, 32);
    puts(" y:");
    print_hex(y, 32);
    puts(" d:");
    print_hex(d, 32);

    // "Someone has reported that x and y are 0 after pairing with the latest windows driver."
    //pub_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    //elf.priv_key = ec.EllipticCurvePrivateNumbers(d, pub_key).private_key(crypto_backend)



    EC_KEY* key = derive_private_key(d);
}

struct tls_ecdh_info {
union {
    struct {
    byte unknown0[8];
    byte x[32];
    byte unknown1[36];
    byte y[32];
    byte unknown2[36];
    };
    byte key[0x90];
};
    dword sig_len;
    byte sig[];
} __attribute__((packed));




void parse_tls_ecdh(byte* body, int len) {
    puts("ecdh");
    print_hex(body, len);
   
    struct tls_ecdh_info* info = body;
    byte* zeros = info->sig + info->sig_len;
    
    BIGNUM* x = make_bignum(info->x);
    BIGNUM* y = make_bignum(info->y);

    printf("x: %s\ny: %s\n", BN_bn2hex(x), BN_bn2hex(y));
    

    // "Note that in [PKI-ALG] ... the secp256r1 curve was referred to as prime256v1." https://www.ietf.org/rfc/rfc5480.txt
    EC_KEY* pubkey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (pubkey == NULL) {
        puts("FAILED TO CREATE KEY");
        exit(1);
    }
    if (! EC_KEY_set_public_key_affine_coordinates(pubkey, x, y)) {
        puts("FAILED TO SET KEY pubkey");
        exit(1);
    }

    puts("key");
    print_hex(info->key, 0x90); 
    puts("sig");
    print_hex(info->sig, info->sig_len);
    puts("zeros");
    print_hex(zeros, len-info->sig_len);
    

    for(byte* end = body + len; zeros < end; zeros++) {
        if (*zeros != 0) {
            puts("ZEROS EXPECTED");
            exit(1);
        }
    }

    // "The following pub key is hardcoded for each fw revision in the synaWudfBioUsb.dll.
    //      Corresponding private key should only be known to a genuine Synaptic device."
    EC_KEY* fwpub = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (fwpub == NULL) {
        puts("FAILED TO CREATE KEY");
        exit(1);
    }

    byte fw_x_raw[32] = { 0xf7, 0x27, 0x65, 0x3b, 0x4e, 0x16, 0xce, 0x06, 0x65, 0xa6, 0x89, 0x4d, 0x7f, 0x3a, 0x30, 0xd7, 0xd0, 0xa0, 0xbe, 0x31, 0x0d, 0x12, 0x92, 0xa7, 0x43, 0x67, 0x1f, 0xdf, 0x69, 0xf6, 0xa8, 0xd3 };
    byte fw_y_raw[32] = { 0xa8, 0x55, 0x38, 0xf8, 0xb6, 0xbe, 0xc5, 0x0d, 0x6e, 0xef, 0x8b, 0xd5, 0xf4, 0xd0, 0x7a, 0x88, 0x62, 0x43, 0xc5, 0x8b, 0x23, 0x93, 0x94, 0x8d, 0xf7, 0x61, 0xa8, 0x47, 0x21, 0xa6, 0xca, 0x94 };

    // these are already in big-endian format so dont use make_bignum
    BIGNUM* fw_x = BN_bin2bn( fw_x_raw, 32, NULL);  
    BIGNUM* fw_y = BN_bin2bn( fw_y_raw, 32, NULL);  
    

    if (! EC_KEY_set_public_key_affine_coordinates(fwpub, fw_x, fw_y))  {
        puts("FAILED TO SET KEY fwpub");
        exit(1);
    }
    
    byte key_hash[SHA256_DIGEST_LENGTH];
    hash_sha256(info->key, 0x90, key_hash);

    int verify = ECDSA_verify(0, key_hash, SHA256_DIGEST_LENGTH, info->sig, info->sig_len, fwpub);
    if ( verify == 1 ) puts("verified signature");
    else if (verify == 0) throw_error("invalid signature");
    else throw_error("ERROR while verifying signature");
    
    puts("parsed ecdh block");
}

void parse_tls_cert(byte* body, int len) {
    puts("found cert block");
}

void parse_tls_empty(byte* body, int len) {
    for (byte* end = body + len; body < end; body++) 
    if (*body != 0) {
        puts("EXPECTED EMPTY BLOCK");
        exit(1);
    }
}



void parse_tls_flash() {
    byte tls_flash[1024 * 1024];
    
    int rsp_size;
    read_tls_flash(tls_flash, 1024 * 1024, &rsp_size);
    
    SHA256_CTX context;
    byte* end = tls_flash + rsp_size;
    byte* itr = tls_flash;
    // TODO: error checking on data amount
    while(itr < end) {
        byte hashed_body[SHA256_DIGEST_LENGTH];
        word id = *(word*)itr;
        word len = *(word*)(itr+2);
        byte* hash = itr + 4;
        itr += 4 + SHA256_DIGEST_LENGTH; // hash is 32 bytes
        byte* body = itr;
        itr += len;

        if (id == 0xffff) break;

        hash_sha256(body, len, hashed_body);
        if (memcmp(hashed_body, hash, SHA256_DIGEST_LENGTH) != 0) {
            printf("block id %hu\n", id);
            throw_error("tls section hash did not match hash of body");
        }

        switch(id) {
            case 0:
            case 1:
            case 2:
                parse_tls_empty(body, len);
                break;
            case 3:
                parse_tls_cert(body, len);
                break;
            case 4:
                parse_tls_priv(body, len);
                break;
            case 6:
                parse_tls_ecdh(body, len);
                break;
            default:
                printf("unhandled block id %04x\n", id);
        }

           
       
    }
}



void open_usb_device() {
    // find and then load usb
    struct libusb_config_descriptor descr;
    libusb_device ** dev_list;

    int dev_cnt = libusb_get_device_list(NULL, &dev_list);
    for (int i = 0; i < dev_cnt; i++) {
        struct libusb_device_descriptor descriptor;
        libusb_get_device_descriptor(dev_list[i], &descriptor);

        for (int j = 0; j < sizeof(all_devices) / sizeof(DeviceInfo); j++) {
            if (all_devices[j].vid == descriptor.idVendor && all_devices[j].pid == descriptor.idProduct) {
                printf("Found device %04x:%04x\n", descriptor.idVendor, descriptor.idProduct);

                if (all_devices[j].description != NULL) {
                    puts(all_devices[j].description);
                }

                if (all_devices[j].unsupported) {
                    exit(-1);
                }

                idProduct = descriptor.idProduct;

                err(libusb_get_device_descriptor(dev_list[i], &descr));
                err(libusb_open(dev_list[i], &dev));


                break;
            }
        }
        
    }
}

int main(int argc, char *argv[]) {
    puts("Prototype version 15");
        loadBiosData();

    libusb_init(NULL);
    libusb_set_debug(NULL, 3);

    open_usb_device();
  
    if (dev == NULL) {
        puts("No devices found");
        return -1;
    }


    // is this needed?
    err(libusb_reset_device(dev));
    // there seems to only be one config, this might mess things up
    err(libusb_set_configuration(dev, 1));
    err(libusb_claim_interface(dev, 0));



    init_flash();
    
    

    puts("");

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    send_init();

    parse_tls_flash();
    //init();
    //handshake();

    rom_info info = get_rom_info();
    printf("timestamp: %u, build: %u, major: %hhu minor: %hhu product: %hhu u1: %hhu\n", 
    info.timestamp, info.build, info.major, info.minor, info.product, info.u1);


    //printf("IN: "); print_hex_string(key_block + 0x60, 0x20);
    //printf("OUT: "); print_hex_string(key_block + 0x40, 0x20);

    fflush(stdout);
    /*
    while(true) {
        puts("");
        puts("1 - Scan fingerprint");
        puts("2 - Test leds");
        puts("3 - Entroll fingerprint");
        puts("0 - Exit");

        char x[1024];
        scanf("%s", x);

        if (x[0] == '1') {
            fingerprint();
        } else if (x[0] == '2') {
            led_test();
        } else if (x[0] == '3') {
            enroll();
        } else if (x[0] == '0') {
            exit(EXIT_SUCCESS);
        }
    }
    */

    return 0;
}
