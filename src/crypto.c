//
//  crypto.c
//  pmppd
//
//  Created on 3/4/16.
//
//

#include "crypto.h"

#include <ctype.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <string.h>

#include "io.h"
#include "util.h"

#define PEM_POSTFIX_PRIVATE     "_priv"
#define PEM_POSTFIX_PUBLIC      "_pub"

const unsigned char base64_table[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Converts a binary representation into an RSA public key.
 * @return The key.
 */
EVP_PKEY *crypto_ctok(unsigned char **c, size_t len)
{
        EVP_PKEY *key;
        const unsigned char *q;
        q = *c;
        
        key = d2i_PUBKEY(NULL, &q, len);
        
        return key;
}

/**
 * Reads a .pem file with the given name. Pass in
 * 1 for a private key, or 2 if it is a public key.
 * @return The key.
 */
EVP_PKEY *rsa_fetch_key(const char *identifier, int type)
{
        char *postfix  = NULL;
        char *filename = NULL;
        EVP_PKEY *key = NULL;
        FILE *file = NULL;
        
        if ( type == 1 ) {
                postfix = PEM_POSTFIX_PRIVATE;
                filename = malloc(strlen(identifier) + strlen(postfix) + 1);
                
                strcpy(filename, identifier);
                strcat(filename, postfix);
                
                file  = io_file(filename, 's');
                
                if ( file && (key = PEM_read_PrivateKey(file, NULL, rsa_passwd_callback, (void *)identifier))) {
                        printf("Private key read.\n");
                } else {
                        wtf(0, "Could not read private key.", 0);
                        crypto_error();
                }
        } else if ( type == 2 ) {
                postfix = PEM_POSTFIX_PUBLIC;
                filename = malloc(strlen(identifier) + strlen(postfix) + 1);
                
                strcpy(filename, identifier);
                strcat(filename, postfix);
                
                file  = io_file(filename, 's');
                
                if ( file && (key = PEM_read_PUBKEY(file, NULL, NULL, NULL)) )
                {
                        printf("Public key read.\n");
                } else {
                        wtf(0, "Could not read public key.", 0);
                        crypto_error();
                }
        }
        
        if ( filename ) {
                free(filename);
                
                filename = NULL;
        }
        
        if ( file )
        {
                fclose(file);
                
                file = NULL;
        }
        
        return key;
}

/**
 * Generates a key for an RSA key pair. Make sure to
 * pass in the same RSA parameter.
 * @return The key.
 */
EVP_PKEY *rsa_make_key(RSA *rsa)
{
        EVP_PKEY *key = EVP_PKEY_new();
        
        if ( rsa && key && EVP_PKEY_assign_RSA(key, rsa) ) {
                // pKey owns pRSA from now.
                if ( RSA_check_key(rsa) <= 0 ) {
                        fprintf(stderr, "RSA_check_key failed.\n");
                        crypto_error();
                        EVP_PKEY_free(key);
                        
                        key = NULL;
                }
        } else {
                crypto_error();
                
                if ( rsa )
                {
                        RSA_free(rsa);
                        
                        rsa = NULL;
                }
                
                if ( key )
                {
                        EVP_PKEY_free(key);
                        
                        key = NULL;
                }
        }
        
        return key;
}

/**
 * Generates a random string that is 8n-bits in size.
 * @return 0 on success.
 */
int aes_gen(char **key, const unsigned int n)
{
        unsigned char buf[n];
        int r = RAND_bytes(buf, n);
        
        if ( !r )
                return r;
        
        *key = malloc(sizeof(buf) * 2 + 1);
        
        for ( int i = 0; i < n; i++ )
                sprintf(&(*key)[i * 2], "%02x", buf[i]);
        
        return 0;
}

/**
 * @return Whether encryption is mandatory or not for
 * the given message type.
 */
int crypto_req(const enum pmppmessage_t msg_type)
{
        int ee = 1; // Yes by default.
        
        // The exceptions.
        switch ( msg_type ) {
                case PMPP_MT_UNKNOWN:
                case PMPP_MT_GREET:
                case PMPP_MT_HAND_EXTEND:
                case PMPP_MT_HAND_SHAKE:
                case PMPP_MT_PROBE:
                case PMPP_MT_PROBE_RES:
                        ee = 0;
                        
                        break;
                        
                default:
                        break;
        }
        
        return ee;
}

/**
 * Saves the given key. The identifier is used as the filename as well as the
 * passphrase.
 * @param type 1 = private key being passed in, 2 = public key being passed in.
 */
int rsa_dump_key(EVP_PKEY *key, const char *identifier, int type)
{
        char *postfix  = NULL;
        char *filename = NULL;
        const EVP_CIPHER *cipher = NULL;
        FILE *file = NULL;
        int ret_val = EXIT_SUCCESS;
        
        if ( type == 1 ) {
                postfix = PEM_POSTFIX_PRIVATE;
                filename = malloc(strlen(identifier) + strlen(postfix) + 1);
                
                strcpy(filename, identifier);
                strcat(filename, postfix);
                
                file  = io_make_file(filename, 's');
                
                if ( file && (cipher = EVP_aes_256_cbc()) ) {
                        if ( !PEM_write_PrivateKey(file, key, cipher,
                                                   (unsigned char *)identifier,
                                                   (int)strlen(identifier), NULL, NULL) ) {
                                wtf(0, "PEM_write_PrivateKey failed", 0);
                                crypto_error();
                                
                                ret_val = EXIT_FAILURE;
                        }
                } else {
                        wtf(0, "Cannot save private key file", 0);
                        crypto_error();
                        
                        ret_val = EXIT_FAILURE;
                        
                        
                }
        } else if ( type == 2 ) {
                postfix = PEM_POSTFIX_PUBLIC;
                filename = malloc(strlen(identifier) + strlen(postfix) + 1);
                
                strcpy(filename, identifier);
                strcat(filename, postfix);
                
                file  = io_make_file(filename, 's');
                
                if ( file ) {
                        if ( !PEM_write_PUBKEY(file, key) ) {
                                wtf(0, "PEM_write_PUBKEY failed", 0);
                                crypto_error();
                                
                                ret_val = EXIT_FAILURE;
                        }
                } else {
                        wtf(0, "Cannot save public key file", 0);
                        crypto_error();
                        
                        ret_val = EXIT_FAILURE;
                }
        }
        
        if ( filename )
        {
                free(filename);
                
                filename = NULL;
        }
        if ( file )
        {
                fclose(file);
                
                file = NULL;
        }
        
        return ret_val;
}

/**
 * Generates & saves an RSA public-private key pair for the local
 * server. The passed identifier is used as the passphrase.
 * @attention Use this only for generating keys for the local server.
 */
int rsa_gen(const char *identifier)
{
        printf("Generating RSA keys…\n");
        
        EVP_PKEY *key_private = NULL;
        EVP_PKEY *key_public  = NULL;
        int ret_val = EXIT_SUCCESS;
        RSA *rsa = NULL;
        
        rsa = RSA_generate_key(2048, RSA_3, rsa_gen_callback, NULL);
        key_private = rsa_make_key(rsa);
        key_public  = rsa_make_key(rsa);
        
        if ( key_private && key_public ) // Save the keys.
        {
                int ret_priv_key = rsa_dump_key(key_private, identifier, 1);
                int ret_pub_key  = rsa_dump_key(key_public, identifier, 2);
                
                if ( ret_priv_key != EXIT_SUCCESS )
                        ret_val = ret_priv_key;
                else if ( ret_pub_key != EXIT_SUCCESS )
                        ret_val = ret_pub_key;
        }
        
        // Freeing the public key causes a crash for some reason.
        if ( key_private )
        {
                EVP_PKEY_free(key_private);
                
                key_private = NULL;
        }
        
        return ret_val;
}

int rsa_passwd_callback(char *passphrase_buff, int size, int rwflag, void *pass)
{
        size_t unpass = strlen((char *)pass);
        
        if ( unpass > (size_t)size )
                unpass = (size_t)size;
        
        memcpy(passphrase_buff, pass, unpass);
        
        return (int)unpass;
}

/**
 * Removes the public & private keys associated with the given identifier.
 * @return 0 on success, -1 otherwise.
 */
int rsa_remove_keys(const char *identifier)
{
        char *postfix_priv   = PEM_POSTFIX_PRIVATE;
        char *postfix_public = PEM_POSTFIX_PUBLIC;
        char *filename_priv  = malloc(strlen(identifier) + strlen(postfix_priv) + 1);
        char *filename_pub   = malloc(strlen(identifier) + strlen(postfix_priv) + 1);
        
        strcpy(filename_priv, identifier);
        strcpy(filename_pub, identifier);
        strcat(filename_priv, postfix_priv);
        strcat(filename_pub, postfix_public);
        
        int ret_priv = io_remove(filename_priv, 's');
        int ret_pub  = io_remove(filename_pub, 's');
        
        if ( ret_priv != 0 )
                return ret_priv;
        
        if ( ret_pub != 0 )
                return ret_pub;
        
        return 0;
}

/**
 * AES algorithms courtesy of the
 * <a href="https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption">OpenSSL wiki</a>.
 * @return The length of the plaintext.
 */
size_t aes_decrypt(const unsigned char *ciphertext, size_t ciphertext_len, const char *key, const char *iv, char **plaintext)
{
        if ( !ciphertext ) {
                wtf(0, "aes_decrypt: ciphertext is null", 0);
                
                return -1;
        }
        
        if ( !iv ||
             !key ) {
                wtf(0, "aes_encrypt: null key/IV", 0);
                
                return -1;
        }
        
        EVP_CIPHER_CTX *ctx;
        int len = 0;
        size_t plaintext_len = 0;
        *plaintext = malloc(ciphertext_len);
        
        // Create and initialise the context.
        if ( !(ctx = EVP_CIPHER_CTX_new()) )
                crypto_error();
        
        /* 
         * Initialise the decryption operation. IMPORTANT - ensure you use a key
         * and IV size appropriate for your cipher.
         * In this example we are using 256 bit AES (i.e. a 256 bit key). The
         * IV size for *most* modes is the same as the block size. For AES this
         * is 128 bits.
         */
        if ( 1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv) ) {
                *plaintext = NULL;
                
                crypto_error();
                
                return -1;
        }
        
        /* 
         * Provide the message to be decrypted, and obtain the plaintext output.
         * EVP_DecryptUpdate can be called multiple times if necessary.
         */
        if ( 1 != EVP_DecryptUpdate(ctx, (unsigned char *)*plaintext, &len, ciphertext, (int)ciphertext_len) ) {
                *plaintext = NULL;
                
                crypto_error();
                
                return -1;
        }
        
        plaintext_len = len;
        
        /* 
         * Finalise the decryption. Further plaintext bytes may be written at
         * this stage.
         */
        if ( 1 != EVP_DecryptFinal_ex(ctx, (unsigned char *)*plaintext + len, &len) ) {
                *plaintext = NULL;
                
                crypto_error();
                
                return -1;
        }
        
        plaintext_len += len;
        
        /*
         * Ciphertext is almost always longer than the plaintext.
         * realloc to free up any unused space.
         */
        *plaintext = realloc(*plaintext, plaintext_len);
        
        // Clean up.
        EVP_CIPHER_CTX_free(ctx);
        
        // Show the decrypted text.
        /*printf("Decrypted text is:\n");
        printf("%s\n", *plaintext);*/
        
        return plaintext_len;
}

/**
 * AES algorithms courtesy of the
 * <a href="https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption">OpenSSL wiki</a>.
 * @return The length of the cyphertext.
 */
size_t aes_encrypt(const char *plaintext, const char *key, const char *iv, unsigned char **ciphertext)
{
        if ( !plaintext ) {
                wtf(0, "aes_encrypt: plaintext is null", 0);
                
                return -1;
        }
        
        if ( !iv ||
             !key ) {
                wtf(0, "aes_encrypt: null key/IV", 0);
                
                return -1;
        }
        
        EVP_CIPHER_CTX *ctx;
        int len;
        size_t ciphertext_len;
        size_t plaintext_len = strlen(plaintext) + 1; // +1 to account for the '\0';
        *ciphertext = malloc(plaintext_len + 16 - (plaintext_len % 16));
        
        // Create and initialise the context.
        if ( !(ctx = EVP_CIPHER_CTX_new()) )
                crypto_error();
        
        /* 
         * Initialise the encryption operation. IMPORTANT - ensure you use a key
         * and IV size appropriate for your cipher.
         * In this example we are using 256 bit AES (i.e. a 256 bit key). The
         * IV size for *most* modes is the same as the block size. For AES this
         * is 128 bits. 
         */
        if ( 1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv) )
                crypto_error();
        
        /* 
         * Provide the message to be encrypted, and obtain the encrypted output.
         * EVP_EncryptUpdate can be called multiple times if necessary.
         */
        if ( 1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, (unsigned char *)plaintext, (int)plaintext_len) )
                crypto_error();
        
        ciphertext_len = len;
        
        /* 
         * Finalise the encryption. Further ciphertext bytes may be written at
         * this stage.
         */
        if ( 1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len) )
                crypto_error();
        
        ciphertext_len += len;
        
        // Clean up.
        EVP_CIPHER_CTX_free(ctx);
        
        // Show the ciphertext.
        /*printf("(%zu) Ciphertext is:\n", ciphertext_len);
        BIO_dump_fp(stdout, (const char *)*ciphertext, (int)ciphertext_len);
        printf("(%zu) Plaintext was:\n%s\n", plaintext_len, plaintext);*/
        
        return ciphertext_len;
}

/**
 * Returns an allocated buffer of decoded base64 data, or NULL on failure.
 *
 * Caller is responsible for freeing the returned buffer.
 * Source: http://src.gnu-darwin.org/src/contrib/wpa_supplicant/base64.c.html
 */
size_t base64_decode(const char *src, size_t len, unsigned char **dest)
{
        size_t count;
        size_t i;
        size_t olen;
        unsigned char  block[4];
        unsigned char  dtable[256];
        unsigned char  in[4];
        unsigned char *pos;
        unsigned char  tmp;
        
        memset(dtable, 0x80, 256);
        
        for ( i = 0; i < sizeof(base64_table); i++ )
                dtable[base64_table[i]] = i;
        
        dtable['='] = 0;
        count = 0;
        
        for ( i = 0; i < len; i++ ) {
                if ( dtable[src[i]] != 0x80 )
                        count++;
        }
        
        if ( count % 4 )
                return -1;
        
        olen = count / 4 * 3;
        pos = *dest = malloc(count);
        
        if ( !*dest )
                return -1;
        
        count = 0;
        
        for ( i = 0; i < len; i++ ) {
                tmp = dtable[src[i]];
                
                if ( tmp == 0x80 )
                        continue;
                
                in[count] = src[i];
                block[count] = tmp;
                count++;
                
                if ( count == 4 ) {
                        *pos++ = (block[0] << 2) | (block[1] >> 4);
                        *pos++ = (block[1] << 4) | (block[2] >> 2);
                        *pos++ = (block[2] << 6) | block[3];
                        count = 0;
                }
        }
        
        if ( pos > *dest ) {
                if ( in[2] == '=' )
                        pos -= 2;
                else if ( in[3] == '=' )
                        pos--;
        }
        
        olen = pos - *dest;
        
        return olen;
}

/**
 * Returns an allocated buffer of base64-encoded data, or NULL on failure.
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string.
 * Source: http://src.gnu-darwin.org/src/contrib/wpa_supplicant/base64.c.html
 */
size_t base64_encode(const unsigned char *src, size_t len, char **dest)
{
        unsigned char *pos;
        const unsigned char *end;
        const unsigned char *in;
        int line_len;
        size_t olen;
        
        olen = len * 4 / 3 + 4; // 3-byte blocks to 4-byte.
        olen += olen / 72;      // Line feeds.
        olen++;                 // Null termination.
        *dest = malloc(olen);
        
        if ( !*dest )
                return -1;
        
        end = src + len;
        in = src;
        pos = (unsigned char *)*dest;
        line_len = 0;
        
        while ( end - in >= 3 ) {
                *pos++ = base64_table[in[0] >> 2];
                *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
                *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
                *pos++ = base64_table[in[2] & 0x3f];
                in += 3;
                line_len += 4;
                
                if ( line_len >= 72 ) {
                        *pos++ = '\n';
                        line_len = 0;
                }
        }
        
        if ( end - in ) {
                *pos++ = base64_table[in[0] >> 2];
                
                if ( end - in == 1 ) {
                        *pos++ = base64_table[(in[0] & 0x03) << 4];
                        *pos++ = '=';
                } else {
                        *pos++ = base64_table[((in[0] & 0x03) << 4) |
                                              (in[1] >> 4)];
                        *pos++ = base64_table[(in[1] & 0x0f) << 2];
                }
                
                *pos++ = '=';
                line_len += 4;
        }
        
        if ( line_len )
                *pos++ = '\n';
        
        *pos = '\0';
        olen = pos - (unsigned char *)*dest;
        
        return olen;
}

/**
 * Converts an RSA public key into its binary representation.
 * @return The length of the data.
 */
size_t crypto_ktoc(EVP_PKEY *key, unsigned char **dest)
{
        int key_len = i2d_PUBKEY(key, NULL);
        unsigned char *uctempBuf;
        
        *dest = malloc(key_len);
        uctempBuf = *dest;
        
        return i2d_PUBKEY(key, &uctempBuf);
}

/**
 * Decrypts the given data using the given private key.
 * @return The size of the decrypted data.
 */
size_t rsa_decrypt(EVP_PKEY *priv_key, const unsigned char *data, size_t data_len, char **decrypted)
{
        RSA *rsa = EVP_PKEY_get1_RSA(priv_key);
        
        *decrypted = malloc(data_len);
        
        size_t result = RSA_private_decrypt((int)data_len, data, (unsigned char *)*decrypted, rsa, RSA_PKCS1_OAEP_PADDING);
        
        return result;
}

/**
 * Encrypts the given data using the given public key.
 * @return The length of the encrypted data.
 */
size_t rsa_encrypt(EVP_PKEY *pub_key, const char *data, unsigned char **encrypted)
{
        size_t data_len = strlen(data) + 1; // Account for '\0'.
        RSA *rsa = EVP_PKEY_get1_RSA(pub_key);
        
        *encrypted = malloc(RSA_size(rsa));
        
        size_t result = RSA_public_encrypt((int)data_len, (const unsigned char *)data, *encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
        
        return result;
}

void crypto_cleanup(void)
{
        CRYPTO_cleanup_all_ex_data();
        ERR_free_strings();
        ERR_remove_thread_state(0);
        EVP_cleanup();
}

/**
 * Prints out all the errors generated by OpenSSL.
 */
void crypto_error(void)
{
        ERR_print_errors_fp(stderr);
}

/**
 * Initialise the OpenSSL library.
 */
void crypto_init(void)
{
        if ( SSL_library_init() ) {
                ERR_load_crypto_strings();
                OpenSSL_add_all_algorithms();
                OPENSSL_config(NULL);
        } else {
                exit(EXIT_FAILURE);
        }
}

void rsa_gen_callback(int what, int in_prime, void *param)
{
        char c = '*';
        
        switch ( what ) {
                case 0: c = '.';  break;
                case 1: c = '+';  break;
                case 2: c = '*';  break;
                case 3: c = '\n'; break;
        }
        
        fprintf(stderr, "%c", c);
}

/** 
 * Creates the SHA-256 hash of a string.
 */
void sha(const char *str, char **hash)
{
        if ( hash ) {
                if ( !str ) {
                        *hash = NULL;
                        
                        return;
                }
                
                unsigned char digest[SHA256_DIGEST_LENGTH];
                
                SHA256((unsigned char *)str, strlen(str), digest);
                
                *hash = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
                
                if ( *hash ) {
                        for ( int i = 0; i < SHA256_DIGEST_LENGTH; i++ )
                                sprintf(&(*hash)[i * 2], "%02x", digest[i]);
                }
        }
}
