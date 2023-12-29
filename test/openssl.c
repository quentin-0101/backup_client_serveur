#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <unistd.h>

#define BLOCK_SIZE 4096



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

    //free(ciphertext);

    return result;
}

char* decrypt(const char *ciphertext, const char *key, const unsigned char *iv) {
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const int key_len = EVP_CIPHER_key_length(cipher);
    const int iv_len = EVP_CIPHER_iv_length(cipher);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, cipher, NULL, (unsigned char *)key, iv);

    const unsigned char *ciphertext_data = (const unsigned char *)(ciphertext + iv_len);
    int ciphertext_len = /* Use the correct length here */299;

    int len;
    int final_len;
    int buffer_size = ciphertext_len + EVP_CIPHER_block_size(cipher);
    char *decrypted_text = (char *)malloc(buffer_size + 1); // Add space for the null terminator

    if (!decrypted_text) {
        fprintf(stderr, "Memory allocation error.\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    EVP_DecryptUpdate(ctx, (unsigned char *)decrypted_text, &len, ciphertext_data, ciphertext_len);
    final_len = 0;
    EVP_DecryptFinal_ex(ctx, (unsigned char *)decrypted_text + len, &final_len);

    len += final_len;

    decrypted_text[len] = '\0';  // Null-terminate the string

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
    const char *plaintext = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdeg";
    const char *key = "I7pGzM96PhZ0BHshb04BDWrO3ilRKFYA";

    char iv[32];
    generateRandomIV(iv, 32);
    
  
    char *encrypted_content = encrypt(plaintext, key, iv);
    
    printf("encrypted : ");
    for (int i = 0; i < strlen(encrypted_content); i++) {
        printf("%02X", (unsigned char)encrypted_content[i]);
    }
    printf("\n");
   
    char *decrypted = decrypt(encrypted_content, key, iv);
    
    printf("decrypted : %s\n", decrypted);

    free(decrypted);
    free(encrypted_content);

    return 0;
}
