#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include "tiny-AES-c/aes.h"

#define AES256 1

void generateRandomIV(uint8_t *iv, size_t ivSize) {
    if (RAND_bytes(iv, ivSize) != 1) {
        fprintf(stderr, "Error generating random IV.\n");
        exit(EXIT_FAILURE);
    }
}

int main() {
    struct AES_ctx ctx;

    uint8_t key[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

    // Allocate memory for the IV
    size_t ivSize = AES_BLOCKLEN;
    uint8_t *iv = (uint8_t *)malloc(ivSize);
    if (iv == NULL) {
        fprintf(stderr, "Error allocating memory for IV.\n");
        return EXIT_FAILURE;
    }

    // Generate a random IV
    generateRandomIV(iv, ivSize);

    uint8_t str[] = "This a sample text, Length eq 32This a sample text, Length eq 32";
    size_t textSize = strlen((char *)str);

    printf("\n Raw buffer:\n");
    for (size_t i = 0; i < textSize; ++i) {
        printf("%.2x", str[i]);
    }

    printf("\nText: %s\n", str);

    // Encryption
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, str, textSize);

    // Display the encrypted buffer in hex
    printf("\n Encrypted buffer:\n");
    for (size_t i = 0; i < textSize; ++i) {
        printf("%.2x", str[i]);
    }
    printf("\n");

    // Save the IV for later use in decryption
    uint8_t savedIV[AES_BLOCKLEN];
    memcpy(savedIV, iv, AES_BLOCKLEN);

    // Decryption
    // Use the saved IV for decryption
    AES_init_ctx_iv(&ctx, key, savedIV);
    AES_CBC_decrypt_buffer(&ctx, str, textSize);

    // Display the decrypted buffer in hex
    printf("\n Decrypted buffer:\n");
    for (size_t i = 0; i < textSize; ++i) {
        printf("%.2x", str[i]);
    }
    printf("\n");

    // Display the decrypted text
    printf("Text (Decrypted): %s\n", str);

    // Free the allocated memory for the IV
    free(iv);

    return 0;
}
