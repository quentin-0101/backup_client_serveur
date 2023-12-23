#ifndef SQLITE_H
#define SQLITE_H

#include <stdio.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>
#include "../objects/packet.h"

int createDatabase(sqlite3 *db, int rc);
const char *selectLastModificationFromFileByPath(sqlite3 *db, const char *path);
int insertNewFile(sqlite3 *db, struct Packet *packet);
int selectCountFileExtension(sqlite3 *db, const char* extension);
//int selectAllPathFromExtension(sqlite3 *db, const char* extension, struct Restore *restore);
int deleteFileWithFilePath(sqlite3 *db, const char *filePath);

#endif