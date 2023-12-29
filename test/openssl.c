#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#define BLOCK_SIZE 2048


char* encrypt(const char *plaintext, const char *key, const unsigned char *iv) {
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const int key_len = EVP_CIPHER_key_length(cipher);
    const int iv_len = EVP_CIPHER_iv_length(cipher);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, NULL, (unsigned char *)key, iv);

    int in_size = strlen(plaintext);
    int out_size = in_size + EVP_CIPHER_block_size(cipher);
    unsigned char *ciphertext = (unsigned char *)malloc(out_size);

    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext, in_size);
    int final_len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
    out_size = len + final_len;

    EVP_CIPHER_CTX_free(ctx);

    // Combine IV and ciphertext into a single buffer
    char *result = (char *)malloc(iv_len + out_size);
    memcpy(result, iv, iv_len);
    memcpy(result + iv_len, ciphertext, out_size);

    free(ciphertext);

    return result;
}


char* decrypt(const char *ciphertext, const char *key, const unsigned char *iv) {
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const int key_len = EVP_CIPHER_key_length(cipher);
    const int iv_len = EVP_CIPHER_iv_length(cipher);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, cipher, NULL, (unsigned char *)key, iv);

    const unsigned char *ciphertext_data = (const unsigned char *)(ciphertext + iv_len);
    int ciphertext_len = strlen(ciphertext + iv_len);

    unsigned char plaintext_block[BLOCK_SIZE + EVP_CIPHER_block_size(cipher)];

    int len;
    int final_len;
    int total_len = 0;
    int buffer_size = 1024;  // Initial buffer size, adjust as needed
    char *decrypted_text = (char *)malloc(buffer_size);

    EVP_DecryptUpdate(ctx, plaintext_block, &len, ciphertext_data, ciphertext_len);
    final_len = 0;
    EVP_DecryptFinal_ex(ctx, plaintext_block + len, &final_len);

    len += final_len;

    // Resize the buffer if needed
    if (total_len + len > buffer_size) {
        buffer_size *= 2;
        decrypted_text = (char *)realloc(decrypted_text, buffer_size);
    }

    // Copy the decrypted block to the result buffer
    memcpy(decrypted_text + total_len, plaintext_block, len);
    total_len += len;

    decrypted_text[total_len] = '\0';  // Null-terminate the string

    EVP_CIPHER_CTX_free(ctx);

    return decrypted_text;
}


void generateRandomIV(unsigned char *iv, size_t ivSize) {
    if (RAND_bytes(iv, ivSize) != 1) {
        fprintf(stderr, "Error generating random IV.\n");
        exit(EXIT_FAILURE);
    }
}

int main() {
    const char *plaintext = "Bonjour test";
    const char *key = "I7pGzM96PhZ0BHshb04BDWrO3ilRKFYA";

    char iv[32];
    generateRandomIV(iv, 32);

    

    char *encrypted_content = encrypt(plaintext, key, iv);
    printf("encrypted : %s\n", encrypted_content);
    
    char *decrypted = decrypt(encrypted_content, key, iv);
    printf("decrypted : %s\n", decrypted);

    return 0;
}
