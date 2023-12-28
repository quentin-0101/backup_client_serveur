#include "aes.h"

uint8_t content[BUFFER_SIZE];
const uint8_t commonIV[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
const uint8_t commonKey[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};


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

void generateKey(const char *input, uint8_t key[]) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, strlen(input));
    SHA256_Final(key, &sha256);
}

void encryptData(const char *inputData, size_t dataSize, char *outputData, const uint8_t *key) {
    struct AES_ctx ctx;
    size_t ivSize = AES_BLOCKLEN;

    AES_init_ctx_iv(&ctx, commonKey, commonIV);

    // Copy IV to the beginning of the output buffer
    memcpy(outputData, commonIV, ivSize);

    size_t remainingData = dataSize;
    size_t offset = 0;

    while (remainingData > 0) {
        size_t blockSize = (remainingData < BUFFER_SIZE) ? remainingData : BUFFER_SIZE;
        memcpy(content, inputData + offset, blockSize);
        AES_CBC_encrypt_buffer(&ctx, content, blockSize);
        memcpy(outputData + offset + ivSize, content, blockSize);

        remainingData -= blockSize;
        offset += blockSize;
    }
}

void decryptData(const char *inputData, size_t dataSize, char *outputData, const uint8_t *key) {
    struct AES_ctx ctx;
    size_t ivSize = AES_BLOCKLEN;

    AES_init_ctx_iv(&ctx, commonKey, commonIV);

    size_t remainingData = dataSize - ivSize;
    size_t offset = 0;

    while (remainingData > 0) {
        size_t blockSize = (remainingData < BUFFER_SIZE) ? remainingData : BUFFER_SIZE;
        memcpy(content, inputData + offset + ivSize, blockSize);
        AES_CBC_decrypt_buffer(&ctx, content, blockSize);
        memcpy(outputData + offset, content, blockSize);

        remainingData -= blockSize;
        offset += blockSize;
    }
}

/*
int main() {
    const char *input1 = "wT3NBAglxIJyUKMYC4o9NEB1J14HtFcV";
    const char *input2 = "VotreDeuxiemeChaine";

    uint8_t key1[32];
    uint8_t key2[32];

    generateKey(input1, key1);
    generateKey(input2, key2);

    printf("Clé pour la première chaîne : ");
    for (int i = 0; i < 32; ++i) {
        printf("%02x", key1[i]);
    }
    printf("\n");

    printf("Clé pour la deuxième chaîne : ");
    for (int i = 0; i < 32; ++i) {
        printf("%02x", key2[i]);
    }
    printf("\n");

    return 0;
}
*/