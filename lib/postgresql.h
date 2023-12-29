#ifndef POSTGRESQL_H
#define POSTGRESQL_H

#include <stdio.h>
#include <stdlib.h>
#include <libpq-fe.h>
#include <string.h>
#include "../objects/packet.h"
#include "../objects/restore.h"
#include "utils.h"
#include <stdint.h>


int createDatabase(PGconn *conn);
const char *selectLastModificationFromFileByPath(PGconn *conn, const char *path, const char *api);
int insertNewFile(PGconn *conn, Packet *packet, const char *user_api, char *iv);
int updateFile(PGconn *conn, Packet *packet, char *iv);
int selectCountFile(PGconn *conn, const char *user_api);
int deleteFileWithFilePath(PGconn *conn, const char *filePath, const char *user_api);
char **selectAllPathFromFile(PGconn *conn, int *rowCount, const char *user_api);
const char *selectSlugByPath(PGconn *conn, const char *path, const char *user_api);
int selectAllPath(PGconn *conn, Restore *restore, const char *user_api);
char* getSecret(PGconn *conn, const char *user_api);
char *getIPByUserAPI(PGconn *conn, const char *user_api);
int insertUser(PGconn *conn, const char *api, const char *ip, const char *secret);
int updateIPByAPI(PGconn *conn, const char *api, const char *newIP);
char *getIVFromFile(PGconn *conn, const char *path, const char *user_api);

#endif