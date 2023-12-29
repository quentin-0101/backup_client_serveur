#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <openssl/md5.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define BLOCK_SIZE 2048

char* replace(const char *str, char last, char new);
void deleteAfterLastSlash(char *chaine);
void createBackupDirectory();
void writeToLog(const char *message);
void generateRandomKey(char *apiKey, size_t length);
char* calculateMD5(const char *filename);

char* encrypt(const char *plaintext, const char *key, const unsigned char *iv) ;
char* decrypt(const char *ciphertext, const char *key, const unsigned char *iv) ;
void generateRandomIV(char *iv, size_t ivSize);

void decryptAES256(const unsigned char *ciphertext, size_t ciphertext_len, const unsigned char *key,
                   const unsigned char *iv, unsigned char *plaintext);
void encryptAES256(const unsigned char *plaintext, size_t plaintext_len, const unsigned char *key,
                   const unsigned char *iv, unsigned char *ciphertext);
void handleErrors(void);

#endif