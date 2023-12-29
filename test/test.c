#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

void handleErrors(void) {
    fprintf(stderr, "Error in OpenSSL operation.\n");
    exit(EXIT_FAILURE);
}

void encryptAES256(const unsigned char *plaintext, size_t plaintext_len, const unsigned char *key,
                   const unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    int len;
    int ciphertext_len;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

void decryptAES256(const unsigned char *ciphertext, size_t ciphertext_len, const unsigned char *key,
                   const unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    int len;
    int plaintext_len;

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

void generateRandomIV(unsigned char *iv, size_t ivSize) {
    if (RAND_bytes(iv, ivSize) != 1) {
        fprintf(stderr, "Error generating random IV.\n");
        exit(EXIT_FAILURE);
    }
}


int main() {
    // Example key and plaintext
    const unsigned char key[] = "01234567890123456789012345678901";
    const char *plaintext = "abcdeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabeabcdeabcdeabcdeabcdeabcdeabcdeabcaaaaaaaaaaaaaaaaaaaaaaaaaadeabcdeabcdeabcdeabcdeabcdeabcdeabe";
    size_t plaintext_len = strlen(plaintext);

    // Allocate memory for ciphertext and IV
    size_t ciphertext_len = AES_BLOCK_SIZE * ((plaintext_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE);
    unsigned char *ciphertext = (unsigned char *)malloc(ciphertext_len);
    unsigned char iv[AES_BLOCK_SIZE];

    // Generate random IV
    generateRandomIV(iv, sizeof(iv));

    // Encrypt
    encryptAES256((unsigned char *)plaintext, plaintext_len, key, iv, ciphertext);

    // Print ciphertext
    printf("Ciphertext: ");
    for (size_t i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Decrypt
    unsigned char *decrypted_text = (unsigned char *)malloc(ciphertext_len);
    decryptAES256(ciphertext, ciphertext_len, key, iv, decrypted_text);

    // Print decrypted text
    printf("Decrypted Text: %s\n", decrypted_text);

    // Clean up
    free(ciphertext);
    free(decrypted_text);

    return 0;
}
