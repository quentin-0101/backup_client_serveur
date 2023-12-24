#ifndef SQLITE_H
#define SQLITE_H

#include <stdio.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>
#include "../objects/packet.h"
#include "../objects/restore.h"

int createDatabase(sqlite3 *db, int rc);
const char *selectLastModificationFromFileByPath(sqlite3 *db, const char *path);
int insertNewFile(sqlite3 *db, struct Packet *packet);
int deleteFileWithFilePath(sqlite3 *db, const char *filePath);
char** selectAllPathFromFile(sqlite3* db, int* rowCount);
const char* selectSlugByPath(sqlite3* db, const char* path);

int selectCountFile(sqlite3 *db);
int selectAllPath(sqlite3 *db, Restore *restore);


#endif