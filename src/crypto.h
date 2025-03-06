//
//  crypto.h
//  pmppd
//
//  Created on 3/4/16.
//
//

#ifndef crypto_h
#define crypto_h

#include <stdio.h>

#include <openssl/evp.h>

#include "pmpptypes.h"

#define AES256_KEY_SIZE         16 // 256-bit key.
#define AES256_IV_SIZE          8  // 128-bit IV.

EVP_PKEY *crypto_ctok(unsigned char **c, size_t len);
EVP_PKEY *rsa_fetch_key(const char *identifier, int type);
EVP_PKEY *rsa_make_key(RSA *pRSA);

int aes_gen(char **key, const unsigned int bit_size);
int crypto_req(const enum pmppmessage_t msg_type);
int rsa_dump_key(EVP_PKEY *key, const char *identifier, int type);
int rsa_gen(const char *identifier);
int rsa_passwd_callback(char *passphrase_buff, int size, int rwflag, void *pass);
int rsa_remove_keys(const char *identifier);

size_t aes_decrypt(const unsigned char *ciphertext, size_t ciphertext_len, const char *key, const char *iv, char **plaintext);
size_t aes_encrypt(const char *plaintext, const char *key, const char *iv, unsigned char **ciphertext);
size_t base64_decode(const char *src, size_t len, unsigned char **dest);
size_t base64_encode(const unsigned char *src, size_t len, char **dest);
size_t crypto_ktoc(EVP_PKEY *key, unsigned char **dest);
size_t rsa_decrypt(EVP_PKEY *priv_key, const unsigned char *data, size_t data_len, char **decrypted);
size_t rsa_encrypt(EVP_PKEY *pub_key, const char *data, unsigned char **encrypted);

void crypto_cleanup(void);
void crypto_error(void);
void crypto_init(void);
void rsa_gen_callback(int what, int in_prime, void *param);
void sha(const char *str, char **hash);

#endif /* crypto_h */
