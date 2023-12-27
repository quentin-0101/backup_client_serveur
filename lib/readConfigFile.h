#ifndef READCONFIGFFILE_H
#define READCONFIGFFILE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../objects/apiPacket.h"

#define MAX_LINE_LENGTH 1024

typedef struct DatabaseConfig {
    char host[MAX_LINE_LENGTH];
    int port;
    char user[MAX_LINE_LENGTH];
    char password[MAX_LINE_LENGTH];
    char dbname[MAX_LINE_LENGTH];
} DatabaseConfig;

typedef struct ConfigClient {
    int numRepositories;
    char **repositories;
    int numExtensions;
    char **extensions;
    char serverIP[2048];
    int port;
    char action[2048];
} ConfigClient;

int readDatabaseConfig(const char *filename, DatabaseConfig *config);
const char* buildDatabaseConnectionString(const struct DatabaseConfig *config);

int readConfigClientFile(const char *filename, ConfigClient *config);
void freeConfigClient(ConfigClient *config);

#endif