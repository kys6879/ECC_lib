#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <memory.h>

#include "header/ecc.h"
#include "header/content.h"
#include "header/sha256.h"

void hash_sha256(uint8_t p_secret[ECC_BYTES],uint8_t p_hash[ECC_BYTES]);

int main()
{

    uint8_t a_pub[ECC_BYTES+1];
    uint8_t a_pri[ECC_BYTES];

    uint8_t b_pub[ECC_BYTES+1];
    uint8_t b_pri[ECC_BYTES];

    uint8_t a_secret[ECC_BYTES];
    uint8_t b_secret[ECC_BYTES];

    uint8_t p_signature[ECC_BYTES*2];

    uint8_t a_hash[SHA256_BLOCK_SIZE];
    uint8_t b_hash[SHA256_BLOCK_SIZE];

    SHA256_CTX ctx;

    int errid = 0;
    int i=0;

    /* print ECC_CURVE parameter */
    print_parameter(ECC_CURVE);

    /* make key */
    errid = ecc_make_key(a_pub,a_pri);
    if(errid != 1){
        printf("[ecc_make _key] error!!!");
        return -1;
    }
    printf("A key pair generation completed...\n");


    errid = ecc_make_key(b_pub,b_pri);
    if(errid != 1){
        printf("[ecc_make _key] error!!!");
        return -1;
    }
    printf("B key pair generation completed...\n");

    /* compute shared secret */
    errid = ecdh_shared_secret(b_pub,a_pri,a_secret);
    if(errid != 1){
        printf("[ecdh_sharedS_secret]error!!!");
        return -1;
    }
    printf("A shared_secret generation completed...\n");

    errid = ecdh_shared_secret(a_pub,b_pri,b_secret);
    if(errid != 1){
        printf("[ecdh_sharedS_secret]error!!!");
        return -1;
    }
    printf("B shared_secret generation completed...\n");

    hash_sha256(a_secret,a_hash);
    if(errid != 1){
        printf("[hash_sha256]error!!!");
        return -1;
    }
    printf("A shared_secret hash completed...\n");

    hash_sha256(b_secret,b_hash);
    if(errid != 1){
        printf("[hash_sha256]error!!!");
        return -1;
    }
    printf("B shared_secret hash completed...\n");


    /* sign */
    errid = ecdsa_sign(a_pri,a_hash,p_signature);
    if(errid != 1){
        printf("[ecdsa_sign]error!!!");
        return -1;
    }

    /* verify */
    errid = ecdsa_verify(a_pub,a_hash,p_signature);
    if(errid != 1){
        printf("[ecdsa_verify]error!!!");
        return -1;
    }else{
        printf("success \n");
    }

    errid = ecdsa_sign(b_pri,b_hash,p_signature);
    if(errid != 1){
        printf("[ecdsa_sign]error!!!");
        return -1;
    }

    /* verify */
    errid = ecdsa_verify(b_pub,b_hash,p_signature);
    if(errid != 1){
        printf("[ecdsa_verify]error!!!");
        return -1;
    }else{
        printf("success \n");
    }

    return 0;
}

void hash_sha256(uint8_t p_secret[ECC_BYTES],uint8_t p_hash[ECC_BYTES]){
    int pass =1;
	BYTE hash1[SHA256_BLOCK_SIZE] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
	                                 0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, p_secret, strlen(p_secret));
    sha256_final(&ctx, p_hash);

    pass = pass && !memcmp(hash1, p_hash, SHA256_BLOCK_SIZE);

    return pass;

}




