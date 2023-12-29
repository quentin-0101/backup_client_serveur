#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include "../lib/tiny-AES-c/aes.h"

#define AES256 1
#define BUFFER_SIZE 4096

uint8_t buffer[BUFFER_SIZE];  // Declare buffer globally

static const uint8_t commonIV[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};


void generateRandomIV(uint8_t *iv, size_t ivSize) {
    if (RAND_bytes(iv, ivSize) != 1) {
        fprintf(stderr, "Error generating random IV.\n");
        exit(EXIT_FAILURE);
    }
}

void encryptFile(const char *inputFilename, const char *outputFilename, const uint8_t *key) {
    struct AES_ctx ctx;
    size_t ivSize = AES_BLOCKLEN;
    uint8_t *iv = (uint8_t *)malloc(ivSize);
    if (iv == NULL) {
        fprintf(stderr, "Error allocating memory for IV.\n");
        exit(EXIT_FAILURE);
    }

    FILE *inputFile = fopen(inputFilename, "rb");
    if (inputFile == NULL) {
        perror("Error opening input file");
        exit(EXIT_FAILURE);
    }

    FILE *outputFile = fopen(outputFilename, "wb");
    if (outputFile == NULL) {
        perror("Error opening output file");
        fclose(inputFile);
        exit(EXIT_FAILURE);
    }

    generateRandomIV(iv, ivSize);
    fwrite(iv, 1, ivSize, outputFile); // Write IV to the beginning of the output file

    AES_init_ctx_iv(&ctx, key, iv);

    uint8_t buffer[BUFFER_SIZE];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), inputFile)) > 0) {
        AES_CBC_encrypt_buffer(&ctx, buffer, bytesRead);
        fwrite(buffer, 1, bytesRead, outputFile);
    }

    fclose(inputFile);
    fclose(outputFile);
    free(iv);
}

void decryptFile(const char *inputFilename, const char *outputFilename, const uint8_t *key) {
    struct AES_ctx ctx;
    size_t ivSize = AES_BLOCKLEN;
    uint8_t *iv = (uint8_t *)malloc(ivSize);
    if (iv == NULL) {
        fprintf(stderr, "Error allocating memory for IV.\n");
        exit(EXIT_FAILURE);
    }

    FILE *inputFile = fopen(inputFilename, "rb");
    if (inputFile == NULL) {
        perror("Error opening input file");
        exit(EXIT_FAILURE);
    }

    FILE *outputFile = fopen(outputFilename, "wb");
    if (outputFile == NULL) {
        perror("Error opening output file");
        fclose(inputFile);
        exit(EXIT_FAILURE);
    }

    fread(iv, 1, ivSize, inputFile); // Read IV from the beginning of the input file
    AES_init_ctx_iv(&ctx, key, iv);

    uint8_t buffer[BUFFER_SIZE];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), inputFile)) > 0) {
        AES_CBC_decrypt_buffer(&ctx, buffer, bytesRead);
        fwrite(buffer, 1, bytesRead, outputFile);
    }

    fclose(inputFile);
    fclose(outputFile);
    free(iv);
}




void encryptData(const char *inputData, size_t dataSize, char *outputData, uint8_t key[]) {
    struct AES_ctx ctx;
    size_t ivSize = AES_BLOCKLEN;

    AES_init_ctx_iv(&ctx, key, commonIV);

    // Copy IV to the beginning of the output buffer
    memcpy(outputData, commonIV, ivSize);

    size_t remainingData = dataSize;
    size_t offset = 0;

    while (remainingData > 0) {
        size_t blockSize = (remainingData < BUFFER_SIZE) ? remainingData : BUFFER_SIZE;
        memcpy(buffer, inputData + offset, blockSize);
        AES_CBC_encrypt_buffer(&ctx, buffer, blockSize);
        memcpy(outputData + offset + ivSize, buffer, blockSize);

        remainingData -= blockSize;
        offset += blockSize;
    }
}

void decryptData(const char *inputData, size_t dataSize, char *outputData, uint8_t key[]) {
    struct AES_ctx ctx;
    size_t ivSize = AES_BLOCKLEN;

    AES_init_ctx_iv(&ctx, key, commonIV);

    size_t remainingData = dataSize - ivSize;
    size_t offset = 0;

    while (remainingData > 0) {
        size_t blockSize = (remainingData < BUFFER_SIZE) ? remainingData : BUFFER_SIZE;
        memcpy(buffer, inputData + offset + ivSize, blockSize);
        AES_CBC_decrypt_buffer(&ctx, buffer, blockSize);
        memcpy(outputData + offset, buffer, blockSize);

        remainingData -= blockSize;
        offset += blockSize;
    }
}


int main() {
    uint8_t key[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
                      0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};


    char *data = "mon super texte";

    char encrypted[BUFFER_SIZE];
    encryptData(data, strlen(data), encrypted, key);

    printf("chiffré : %s\n", encrypted);

    char decrypted[BUFFER_SIZE];
    decryptData(encrypted, strlen(encrypted), decrypted, key);

    printf("déchiffré : %s\n", decrypted);
/*
    const char *inputFilename = "gentoo_root.img";
    const char *encryptedFilename = "encrypted.bin";
    const char *decryptedFilename = "decrypted.img";

    encryptFile(inputFilename, encryptedFilename, key);
    printf("File encrypted successfully. Output filename: %s\n", encryptedFilename);

    decryptFile(encryptedFilename, decryptedFilename, key);
    printf("File decrypted successfully. Output filename: %s\n", decryptedFilename);
*/
    return 0;
}
