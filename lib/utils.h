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
#include <openssl/ssl.h>
#include "../objects/packet.h"

#define BLOCK_SIZE 2048


#define CHUNK_SIZE_PLAINTEXT 4096
#define CHUNK_SIZE_CRYPTED 4112


char* replace(const char *str, char last, char new);
void deleteAfterLastSlash(char *chaine);
void createBackupDirectory();
void writeToLog(const char *message);
void generateRandomKey(char *apiKey, size_t length);
char* calculateMD5(const char *filename);

void generateRandomIV(unsigned char *iv, size_t ivSize);
void handleErrors(void);
int encryptAES(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);

#endif