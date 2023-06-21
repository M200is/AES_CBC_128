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

void base64_decode(const U8* input, U8* output) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new_mem_buf(input, -1);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    int decoded_length = BIO_read(bio, output, strlen((const char*)input));
    decoded_length = ((decoded_length + 2) / 3) * 3;
    output[decoded_length] = '\0';

    BIO_free_all(bio);
}


int aes_encrypt(U8* p_in, U8* p_out, U8* iv_enc, U8* cipher_key, int size)
{
    AES_KEY aes_key;
    if (AES_set_encrypt_key(cipher_key, KEY_BIT, &aes_key) < 0) {
        printf("Failed to set encryption key.\n");
        return -1;
    }

    int padded_size = ((size + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE; // 패딩된 크기 계산
    int padding = padded_size - size; // 패딩할 바이트 수

    // 패딩 추가
    memcpy(p_out, p_in, size);
    memset(p_out + size, padding, padding);

    AES_cbc_encrypt(p_out, p_out, padded_size, &aes_key, iv_enc, AES_ENCRYPT);

    return padded_size;
}

int aes_decrypt(U8* p_in, U8* p_out, U8* iv_dec, U8* cipher_key, int size)
{
    AES_KEY aes_key;
    if (AES_set_decrypt_key(cipher_key, KEY_BIT, &aes_key) < 0) {
        printf("Failed to set decryption key.\n");
        return -1;
    }

    AES_cbc_encrypt(p_in, p_out, size, &aes_key, iv_dec, AES_DECRYPT);

    int padding = p_out[size - 1];
    int decrypted_size = size - padding;

    return decrypted_size;
}



int main() {
    int i;
    char check;

    while (1)
    {
        printf("encrypt=e/decrypt=d/exit=q : ");
        scanf(" %c", &check);


        switch (check)
        {
        case 'e':
        {
            U8 p_text[173];
            U8 p_encrypt[1024];
            U8 p_temp[1024];
            U8 iv_enc[AES_BLOCK_SIZE];
            U8 iv_temp[AES_BLOCK_SIZE];
            U8 cipher_key_enc[AES_BLOCK_SIZE];
            U8 cipher_key_temp[AES_BLOCK_SIZE];

            RAND_bytes(cipher_key_enc, AES_BLOCK_SIZE);
            memcpy(cipher_key_temp, cipher_key_enc, AES_BLOCK_SIZE);

            RAND_bytes(iv_enc, AES_BLOCK_SIZE);
            memcpy(iv_temp, iv_enc, AES_BLOCK_SIZE);

            printf("text: ");
            scanf(" %[^\n]s", p_text);

            size_t text_len = strlen((const char*)p_text);
            aes_encrypt(p_text, p_encrypt, iv_enc, cipher_key_enc, text_len);
            size_t encrypt_size = (text_len + 16) / 16 * 16;

            printf("chpher_key(base 64): %s\n", base64_encode(cipher_key_temp, AES_BLOCK_SIZE));
            printf("iv(base 64): %s\n", base64_encode(iv_temp, AES_BLOCK_SIZE));
            printf("encrypted_text(base 64): %s\n", base64_encode(p_encrypt, encrypt_size));
            while (getchar() != '\n');
            break;
        }
        case 'd':
        {
            int encrypt_size;
            U8 b64encoded_data[24];
            U8 iv_dec[AES_BLOCK_SIZE];
            U8 cipher_key_dec[AES_BLOCK_SIZE];
            U8 p_encrypt[10000];
            U8 p_decrypt[10000];

            printf("chiper_key(base64): ");
            scanf("%s", b64encoded_data);
            base64_decode(b64encoded_data, cipher_key_dec);

            printf("iv(base64): ");
            scanf("%s", b64encoded_data);
            base64_decode(b64encoded_data, iv_dec);

            printf("encrypted_data(base64): ");
            scanf("%s", b64encoded_data);
            base64_decode(b64encoded_data, p_encrypt);

            size_t decoded_length = (strlen((const char*)b64encoded_data) * 3) / 4;

            aes_decrypt(p_encrypt, p_decrypt, iv_dec, cipher_key_dec, decoded_length);

            p_decrypt[decoded_length] = '\0';

            printf("decrypt_text: %s  (The strange characters are due to padding)\n", p_decrypt);
            memset(p_decrypt, 0, decoded_length);

            while (getchar() != '\n');
            break;
        }
        case 'q':
        {
            system("pause");
            return 0;
        }
        default:
            printf("Please provide the correct arguments\n");
            break;
        }
    }
}