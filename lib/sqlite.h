#ifndef SQLITE_H
#define SQLITE_H

#include <stdio.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>
#include "../objects/packet.h"
#include "../objects/restore.h"
#include "utils.h"

int createDatabase(sqlite3 *db, int rc);
const char *selectLastModificationFromFileByPath(sqlite3 *db, const char *path);
int insertNewFile(sqlite3 *db, Packet *packet, const char *user_api);
int updateFile(sqlite3 *db, Packet *packet);
int deleteFileWithFilePath(sqlite3 *db, const char *filePath, const char *user_api);
char** selectAllPathFromFile(sqlite3* db, int* rowCount, char *user_api);
const char *selectSlugByPath(sqlite3 *db, const char *path, const char *user_api);

int selectCountFile(sqlite3 *db);
int selectAllPath(sqlite3 *db, Restore *restore, const char *user_api);

int authenticateUser(sqlite3 *db, const char *user_api);
char* getIPByUserAPI(sqlite3 *db, const char *user_api);
int insertUser(sqlite3 *db, const char *api, const char *ip);
int updateIPByAPI(sqlite3 *db, const char *api, const char *newIP);


#endif