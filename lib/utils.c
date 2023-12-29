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



void generateRandomIV(char *iv, size_t ivSize) {
    if (RAND_bytes(iv, ivSize) != 1) {
        fprintf(stderr, "Error generating random IV.\n");
        exit(EXIT_FAILURE);
    }
}