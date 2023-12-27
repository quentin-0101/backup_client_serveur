#ifndef _MY_AES_H
#define _MY_AES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include "tiny-AES-c/aes.h"
#include <openssl/sha.h>

#define AES256 1

#define BUFFER_SIZE 4096

void generateRandomIV(uint8_t *iv, size_t ivSize);
void generateKey(const char *input, uint8_t key[]);
void encryptFile(const char *inputFilename, const char *outputFilename, const uint8_t *key);
void decryptFile(const char *inputFilename, const char *outputFilename, const uint8_t *key);
void decryptData(const char *inputData, size_t dataSize, char *outputData, const uint8_t *key);
void encryptData(const char *inputData, size_t dataSize, char *outputData, const uint8_t *key);

#endif