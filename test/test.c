#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include "base64.h"
#define CHUNK_SIZE 200000
#define DECRYPT_MAX_SIZE 200000
#define PACKET_SIZE 2048

void handleErrors(void) {
    fprintf(stderr, "Error in OpenSSL operation.\n");
    exit(EXIT_FAILURE);
}


void encryptFileAES256(const char *inputFilePath, const char *outputFilePath, const unsigned char *key, const unsigned char *iv) {
    FILE *inputFile = fopen(inputFilePath, "rb");
    if (!inputFile) {
        perror("Erreur lors de l'ouverture du fichier en lecture");
        exit(EXIT_FAILURE);
    }

    fseek(inputFile, 0, SEEK_END);
    size_t fileSize = ftell(inputFile);
    rewind(inputFile);

    unsigned char *plaintext = (unsigned char *)malloc(fileSize);
    if (!plaintext) {
        perror("Erreur lors de l'allocation de mémoire");
        fclose(inputFile);
        exit(EXIT_FAILURE);
    }

    if (fread(plaintext, 1, fileSize, inputFile) != fileSize) {
        perror("Erreur lors de la lecture du fichier");
        fclose(inputFile);
        free(plaintext);
        exit(EXIT_FAILURE);
    }

    fclose(inputFile);

    unsigned char *ciphertext = (unsigned char *)malloc(fileSize + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    if (!ciphertext) {
        perror("Erreur lors de l'allocation de mémoire");
        free(plaintext);
        exit(EXIT_FAILURE);
    }

    encryptAES256(plaintext, fileSize, key, iv, ciphertext);

    FILE *outputFile = fopen(outputFilePath, "wb");
    if (!outputFile) {
        perror("Erreur lors de l'ouverture du fichier en écriture");
        free(plaintext);
        free(ciphertext);
        exit(EXIT_FAILURE);
    }

    if (fwrite(ciphertext, 1, fileSize + EVP_CIPHER_block_size(EVP_aes_256_cbc()), outputFile) != fileSize + EVP_CIPHER_block_size(EVP_aes_256_cbc())) {
        perror("Erreur lors de l'écriture du fichier");
        fclose(outputFile);
        free(plaintext);
        free(ciphertext);
        exit(EXIT_FAILURE);
    }

    fclose(outputFile);
    free(plaintext);
    free(ciphertext);
}
void decryptFileAES256(const char *inputFile, const char *outputFile, const unsigned char *key,
                        const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    FILE *input = fopen(inputFile, "rb");
    FILE *output = fopen(outputFile, "wb");

    if (!input || !output) {
        // Handle file opening errors
        handleErrors();
    }

    int len;
    size_t plaintext_len = 0;
    unsigned char ciphertext[CHUNK_SIZE];
    unsigned char plaintext[CHUNK_SIZE + EVP_CIPHER_block_size(EVP_aes_256_cbc())];

    while (1) {
        size_t bytesRead = fread(ciphertext, 1, CHUNK_SIZE, input);
        if (bytesRead <= 0) {
            // End of the encrypted file
            break;
        }

        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();

        if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, bytesRead))
            handleErrors();

        plaintext_len += len;

        if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
            // Handle errors, if necessary
        }
        plaintext_len += len;

        // Write only the decrypted part to the output file
        fwrite(plaintext, 1, plaintext_len, output);

        // Print the decrypted content
        for (size_t i = 0; i < len; ++i) {
            printf("%c", plaintext[i]);
        }

        // Reset the decrypted text size for the next loop iteration
        plaintext_len = 0;
    }

    size_t stringLength = strlen(plaintext);
    size_t currentPosition = 0;

    while (currentPosition < stringLength) {
        size_t currentBufferSize = (stringLength - currentPosition < PACKET_SIZE)
                                      ? (stringLength - currentPosition)
                                      : PACKET_SIZE;

        // Utilisez la fonction processBuffer avec le morceau de la chaîne
        

        // Déplacez la position actuelle pour la prochaine itération
        currentPosition += currentBufferSize;
    }

    printf("\n");
    fclose(input);
    fclose(output);
    EVP_CIPHER_CTX_free(ctx);
}

void decryptFileAES256_2(const char *inputFile, const unsigned char *key,
                        const unsigned char *iv) {
     EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    FILE *input = fopen(inputFile, "rb");

    if (!input) {
        // Handle file opening errors
        handleErrors();
    }

    int len;
    size_t plaintext_len = 0;
    unsigned char ciphertext[DECRYPT_MAX_SIZE];
    unsigned char plaintext[DECRYPT_MAX_SIZE + EVP_CIPHER_block_size(EVP_aes_256_cbc())];

    while (1) {
        size_t bytesRead = fread(ciphertext, 1, DECRYPT_MAX_SIZE, input);
        if (bytesRead <= 0) {
            // End of the encrypted file
            break;
        }

        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();

        if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, bytesRead))
            handleErrors();

        plaintext_len += len;

        if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
            // Handle errors, if necessary
        }
        plaintext_len += len;

        // Reset the decrypted text size for the next loop iteration
        plaintext_len = 0;
    }

    size_t stringLength = strlen(plaintext);
    size_t currentPosition = 0;

    while (currentPosition < stringLength) {
        size_t currentBufferSize = (stringLength - currentPosition < 2048)
                                      ? (stringLength - currentPosition)
                                      : 2048;
        printf("text : %s\n", plaintext);
       // memcpy(packet.fileContent.content, plaintext, currentBufferSize);
       // packet.fileContent.size = currentBufferSize;
        //packet.flag = CONTENT_FILE;
       // SSL_write(ssl, &packet , sizeof(packet));

        currentPosition += currentBufferSize;
    }

    printf("\n");
    fclose(input);
    EVP_CIPHER_CTX_free(ctx);
}



void generateRandomIV(unsigned char *iv, size_t ivSize) {
    if (RAND_bytes(iv, ivSize) != 1) {
        fprintf(stderr, "Error generating random IV.\n");
        exit(EXIT_FAILURE);
    }
}

void writeToFile(const char *filename, const unsigned char *data, size_t data_len) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        // Gérer les erreurs d'ouverture de fichier
        perror("Erreur lors de l'ouverture du fichier");
        exit(EXIT_FAILURE);
    }

    fwrite(data, 1, data_len, file);

    fclose(file);
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




int main() {
    const unsigned char key[] = "DFfKeb8jcXjYIArhdbB4904cTpJFupfm";


    char *encoded_iv = "pE8rijaXhXnPNsv9KX7kRBtrK1aDpjLzHysCnoOXc54=";
    int out_len = b64_decoded_size(encoded_iv)+1;
    char *out = malloc(out_len);
    b64_decode(encoded_iv, (unsigned char *)out, out_len);
    out[out_len] = '\0';
    printf("decode iv        :%s\n", out);


      char cipher[20000];
      decryptFileAES256_2("mEH263gJ12WZcMmfD2mbC0Hz3MGa8bQm", key, out);


/*
    char *data = "abcde";

    unsigned char iv[AES_BLOCK_SIZE];
    generateRandomIV(iv, sizeof(iv));

    char cipher[20000];


    encryptAES256(data, strlen(data), key, iv, cipher);
    writeToFile("encrypted_file2.bin", cipher, strlen(cipher));

   // encryptFileAES256("config.txt", "encrypted_file.bin", key, iv);
    //decryptFileAES256("encrypted_file.bin", "decrypt.txt", key, iv);
    decryptFileAES256_2("encrypted_file2.bin", key, iv);

   // free(decrypted_text);
*/
    return 0;
}
