#include <openssl/aes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <Windows.h>

#define KEY_BIT 128

typedef unsigned char U8;


char* base64_encode(const U8* input, int length)
{
    BIO* bmem, * b64;
    BUF_MEM* bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char* buff = (char*)malloc(bptr->length);
    memcpy(buff, bptr->data, bptr->length - 1);
    buff[bptr->length - 1] = 0;

    BIO_free_all(b64);

    return buff;
}


int aes_encrypt(U8* p_in, U8* p_out, U8* cipher_key, U8* iv_enc, int size)
{
    AES_KEY aes_key;
    AES_set_encrypt_key(cipher_key, KEY_BIT, &aes_key);
    AES_cbc_encrypt(p_in, p_out, size, &aes_key, iv_enc, AES_ENCRYPT);

    return 0;
}

int aes_decrypt(U8* p_in, U8* p_out, U8* cipher_key, U8* iv_dec, int size)
{
    AES_KEY aes_key;
    AES_set_decrypt_key(cipher_key, KEY_BIT, &aes_key);
    AES_cbc_encrypt(p_in, p_out, size, &aes_key, iv_dec, AES_DECRYPT);
    
    return 0;
}

int main() {
    int i;
    int encrypt_size;
    U8 p_text[1024];
    U8 p_encrypt[1024];
    U8 p_decrypt[1024];
    U8 p_temp[1024];
    U8 iv_enc[AES_BLOCK_SIZE];
    U8 iv_dec[AES_BLOCK_SIZE];
    U8 iv_temp[AES_BLOCK_SIZE];
    U8 cipher_key_enc[AES_BLOCK_SIZE];
    U8 cipher_key_dec[AES_BLOCK_SIZE];
    U8 cipher_key_temp[AES_BLOCK_SIZE];
    RAND_bytes(cipher_key_enc, AES_BLOCK_SIZE);
    memcpy(cipher_key_dec, cipher_key_enc, AES_BLOCK_SIZE);
    memcpy(cipher_key_temp, cipher_key_enc, AES_BLOCK_SIZE);

    RAND_bytes(iv_enc, AES_BLOCK_SIZE);
    memcpy(iv_dec, iv_enc, AES_BLOCK_SIZE);
    memcpy(iv_temp, iv_enc, AES_BLOCK_SIZE);
    
    printf("text: ");
    scanf("%s", p_text);

    size_t text_len = strlen((const char*)p_text);

    aes_encrypt(p_text, p_encrypt, iv_enc, cipher_key_enc, text_len);
    encrypt_size = (text_len + AES_BLOCK_SIZE) / 16 * 16;
    memcpy(p_temp, p_encrypt, encrypt_size);
    aes_decrypt(p_temp, p_decrypt, iv_dec, cipher_key_dec, encrypt_size);


    printf("chpher_key(base 64): %s\n", base64_encode(cipher_key_temp, AES_BLOCK_SIZE));
    printf("iv(base 64): %s\n", base64_encode(iv_temp, AES_BLOCK_SIZE));
    printf("encrypt aes(base 64): %s\n", base64_encode(p_encrypt, encrypt_size));
    printf("decrypt aes: %s\n", p_decrypt);

    system("pause");
    return 0;
}