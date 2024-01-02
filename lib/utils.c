#include "utils.h"

char* replace(const char *str, char last, char new) {
    char *result = (char *)malloc(strlen(str) + 1);

    // Check if memory allocation is successful
    if (result == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    // Copy the contents of str into result
    strcpy(result, str);

    for(size_t i = 0; i < strlen(result); i++){
        if(result[i] == last){
            result[i] = new;
        }
    }
    return result;
}

void deleteAfterLastSlash(char *path) {
    // Recherche du dernier '/'
    char *lastSlash = strrchr(path, '/');
    
    // Si un '/' est trouvé, tronquer la chaîne après ce point
    if (lastSlash != NULL) {
        *lastSlash = '\0';
    }
}

void createBackupDirectory() {
    struct stat st = {0};
    
    if (stat("/var/log/backup", &st) == -1) {
        if (mkdir("/var/log/backup", 0700) != 0) {
            fprintf(stderr, "Error: Unable to create the backup directory.\n");
            exit(EXIT_FAILURE);
        }
    }
}

void writeToLog(const char *message) {
    FILE *logFile;
    time_t currentTime;
    struct tm *timeInfo;
    char logFileName[50];  // Adjust the size based on your needs
    char timestamp[20];

    createBackupDirectory();  // Create the backup directory if it doesn't exist

    time(&currentTime);
    timeInfo = localtime(&currentTime);

    // Specify the full path for the log file in /var/log/backup
    strftime(logFileName, sizeof(logFileName), "/var/log/backup/logfile_%Y-%m-%d.txt", timeInfo);

    logFile = fopen(logFileName, "a");

    if (logFile == NULL) {
        fprintf(stderr, "Error: Unable to open the log file.\n");
        return;
    }

    strftime(timestamp, sizeof(timestamp), "[%H:%M:%S] ", timeInfo);

    fprintf(logFile, "%s%s\n", timestamp, message);

    fclose(logFile);
}


void generateRandomKey(char *apiKey, size_t length) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const size_t charsetSize = sizeof(charset) - 1;

    for (size_t i = 0; i < length; ++i) {
        RAND_bytes((unsigned char *)&apiKey[i], 1);
        apiKey[i] = charset[apiKey[i] % charsetSize];
    }
}

char* calculateMD5(const char *filename) {
    int BUFFER_SIZE = 1024;
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    MD5_CTX mdContext;
    MD5_Init(&mdContext);

    unsigned char data[BUFFER_SIZE];
    size_t bytesRead;

    while ((bytesRead = fread(data, 1, BUFFER_SIZE, file)) != 0) {
        MD5_Update(&mdContext, data, bytesRead);
    }

    MD5_Final(data, &mdContext);

    fclose(file);

    // Allouer dynamiquement de la mémoire pour la chaîne de caractères
    char *md5sum = (char *)malloc(2 * MD5_DIGEST_LENGTH + 1);

    // Convertir le hash en chaîne hexadécimale
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(md5sum + 2 * i, "%02x", data[i]);
    }

    return md5sum;
}



void generateRandomIV(char *iv, size_t ivSize) {
    if (RAND_bytes(iv, ivSize) != 1) {
        fprintf(stderr, "Error generating random IV.\n");
        exit(EXIT_FAILURE);
    }
}
void handleErrors(void) {
    fprintf(stderr, "Error in OpenSSL operation.\n");
    exit(EXIT_FAILURE);
}


void decryptAES256(const unsigned char *ciphertext, size_t ciphertext_len, const unsigned char *key,
                   const unsigned char *iv, char *plaintext) {
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

char* decrypt(const char *ciphertext, const char *key, const unsigned char *iv) {
    int MAX_TEXT_SIZE = 8192;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const int key_len = EVP_CIPHER_key_length(cipher);
    const int iv_len = EVP_CIPHER_iv_length(cipher);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, cipher, NULL, (unsigned char *)key, iv);

    const unsigned char *ciphertext_data = (const unsigned char *)(ciphertext + iv_len);
    int ciphertext_len = strlen(ciphertext + iv_len);

    int len;
    int final_len;
    int buffer_size = MAX_TEXT_SIZE + EVP_CIPHER_block_size(cipher);
    char *decrypted_text = (char *)malloc(buffer_size);

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


void decryptFileAES256(char *inputFile, unsigned char *key,
                        char *iv, SSL *ssl, Packet packet) {
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
        size_t currentBufferSize = (stringLength - currentPosition < BLOCK_SIZE)
                                      ? (stringLength - currentPosition)
                                      : BLOCK_SIZE;
        printf("\ntext : %s\n", plaintext);
        
        memcpy(packet.fileContent.content, plaintext, currentBufferSize);
        packet.fileContent.size = currentBufferSize;
        packet.flag = CONTENT_FILE;
        SSL_write(ssl, &packet , sizeof(packet));
        

        currentPosition += currentBufferSize;
    }

    printf("\n");
    fclose(input);
    EVP_CIPHER_CTX_free(ctx);
}