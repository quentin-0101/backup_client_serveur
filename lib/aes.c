#include "aes.h"


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
    uint8_t buffer[BUFFER_SIZE];
    struct AES_ctx ctx;
    size_t ivSize = AES_BLOCKLEN;
    uint8_t *iv = (uint8_t *)malloc(ivSize);
    if (iv == NULL) {
        fprintf(stderr, "Error allocating memory for IV.\n");
        exit(EXIT_FAILURE);
    }

    generateRandomIV(iv, ivSize);
    memcpy(outputData, iv, ivSize); // Copy IV to the beginning of the output buffer

    AES_init_ctx_iv(&ctx, key, iv);

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

    free(iv);
}

void decryptData(const char *inputData, size_t dataSize, char *outputData, const uint8_t *key) {
    uint8_t buffer[BUFFER_SIZE];
    struct AES_ctx ctx;
    size_t ivSize = AES_BLOCKLEN;
    uint8_t *iv = (uint8_t *)malloc(ivSize);
    if (iv == NULL) {
        fprintf(stderr, "Error allocating memory for IV.\n");
        exit(EXIT_FAILURE);
    }

    // Extract IV from the input data
    memcpy(iv, inputData, ivSize);

    AES_init_ctx_iv(&ctx, key, iv);

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

    free(iv);
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