#include "postgresql.h"

int createDatabase(PGconn *conn) {
    char *createUsersTableSQL = "CREATE TABLE IF NOT EXISTS users ("
                                "api TEXT PRIMARY KEY,"
                                "secret TEXT,"
                                "ip TEXT UNIQUE"
                                ");";

    PGresult *result = PQexec(conn, createUsersTableSQL);

    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Error creating table: %s\n", PQerrorMessage(conn));
        PQclear(result);
        return 1;
    }

    PQclear(result);

    char *createFileTableSQL = "CREATE TABLE IF NOT EXISTS file ("
                               "path TEXT, "
                               "lastModification TEXT, "
                               "slug TEXT, "
                               "user_api TEXT, "
                               "iv TEXT,"
                               "PRIMARY KEY (path, user_api), "
                               "FOREIGN KEY (user_api) REFERENCES users(api)"
                               ");";

    result = PQexec(conn, createFileTableSQL);

    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Error creating table: %s\n", PQerrorMessage(conn));
        PQclear(result);
        return 1;
    }

    PQclear(result);

    printf("The database has been successfully created.\n");
    writeToLog("The database has been successfully created.");
    return 0;
}

const char *selectLastModificationFromFileByPath(PGconn *conn, const char *path, const char *api) {
    const char *select_sql = "SELECT lastModification FROM file WHERE path = $1 AND user_api = $2;";
    
    // Set up parameter values
    const char *paramValues[2] = {path, api};
    const int paramLengths[2] = {-1, -1};  // Use -1 for null-terminated strings
    const int paramFormats[2] = {0, 0};    // 0 means text format

    PGresult *result = PQexecParams(conn, select_sql, 2, NULL, paramValues, paramLengths, paramFormats, 0);

    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Error executing SELECT statement: %s\n", PQerrorMessage(conn));
        PQclear(result);
        return NULL;
    }

    if (PQntuples(result) > 0) {
        const char *resultLastDateUpdate = PQgetvalue(result, 0, 0);
        PQclear(result);
        return resultLastDateUpdate;
    }

    PQclear(result);
    return NULL;
}


int insertNewFile(PGconn *conn, Packet *packet, const char *user_api, char *iv) {
    PGresult *result = PQexec(conn, "BEGIN TRANSACTION");

    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Error beginning transaction: %s\n", PQerrorMessage(conn));
        PQclear(result);
        return 1;
    }

    PQclear(result);

    printf("postgre : %s\n", iv);

    const char *insert_sql = "INSERT INTO file (path, lastModification, slug, user_api, iv) VALUES ($1, $2, $3, $4, $5)";
    const char *paramValues[5] = {packet->fileInfo.path, packet->fileInfo.lastModification, packet->fileInfo.slug, user_api, iv};
    const int paramLengths[5] = {-1, -1, -1, -1, -1};
    const int paramFormats[5] = {0, 0, 0, 0, 0};

    result = PQexecParams(conn, insert_sql, 5, NULL, paramValues, paramLengths, paramFormats, 0);

    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Error executing INSERT statement: %s\n", PQerrorMessage(conn));
        PQclear(result);

        result = PQexec(conn, "ROLLBACK");
        if (PQresultStatus(result) != PGRES_COMMAND_OK) {
            fprintf(stderr, "Error rolling back transaction: %s\n", PQerrorMessage(conn));
            PQclear(result);
        }

        return 1;
    }

    PQclear(result);

    result = PQexec(conn, "COMMIT");

    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Error committing transaction: %s\n", PQerrorMessage(conn));
        PQclear(result);
        return 1;
    }

    PQclear(result);

    return 0;
}

int updateFile(PGconn *conn, Packet *packet, char *iv) {
    printf("update : %s\n", packet->fileInfo.lastModification);

    PGresult *result = PQexec(conn, "BEGIN TRANSACTION");

    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Error beginning transaction: %s\n", PQerrorMessage(conn));
        PQclear(result);
        return 1;
    }

    PQclear(result);

    const char *update_sql = "UPDATE file SET lastModification = $1, iv = $2 WHERE path = $3";
    const char *paramValues[3] = {packet->fileInfo.lastModification, iv, packet->fileInfo.path};
    const int paramLengths[3] = {-1, -1, -1};
    const int paramFormats[3] = {0, 0, 0};

    result = PQexecParams(conn, update_sql, 3, NULL, paramValues, paramLengths, paramFormats, 0);

    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Error executing UPDATE statement: %s\n", PQerrorMessage(conn));
        PQclear(result);

        result = PQexec(conn, "ROLLBACK");
        if (PQresultStatus(result) != PGRES_COMMAND_OK) {
            fprintf(stderr, "Error rolling back transaction: %s\n", PQerrorMessage(conn));
            PQclear(result);
        }

        return 1;
    }

    PQclear(result);

    result = PQexec(conn, "COMMIT");

    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Error committing transaction: %s\n", PQerrorMessage(conn));
        PQclear(result);
        return 1;
    }

    PQclear(result);

    printf("update fin\n");
    return 0;
}

int selectCountFile(PGconn *conn, const char *user_api) {
    const char *select_sql = "SELECT COUNT(*) FROM file WHERE user_api = $1;";
    
    const char *paramValues[1] = {user_api};
    int paramLengths[1] = {(int)strlen(user_api)};
    int paramFormats[1] = {1};  // 1 for text format

    PGresult *result = PQexecParams(conn, select_sql, 1, NULL,
                                    paramValues, paramLengths, paramFormats, 0);

    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Error executing SELECT statement: %s\n", PQerrorMessage(conn));
        PQclear(result);
        return -1;
    }

    int count = atoi(PQgetvalue(result, 0, 0));

    PQclear(result);

    return count;
}


int deleteFileWithFilePath(PGconn *conn, const char *filePath, const char *user_api) {
    PGresult *result = PQexec(conn, "BEGIN TRANSACTION");

    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Error beginning transaction: %s\n", PQerrorMessage(conn));
        PQclear(result);
        return 1;
    }

    PQclear(result);

    const char *delete_sql = "DELETE FROM file WHERE path = $1 AND user_api = $2";
    const char *paramValues[2] = {filePath, user_api};
    const int paramLengths[2] = {-1, -1};
    const int paramFormats[2] = {0, 0};

    result = PQexecParams(conn, delete_sql, 2, NULL, paramValues, paramLengths, paramFormats, 0);

    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Error executing DELETE statement: %s\n", PQerrorMessage(conn));
        PQclear(result);

        result = PQexec(conn, "ROLLBACK");
        if (PQresultStatus(result) != PGRES_COMMAND_OK) {
            fprintf(stderr, "Error rolling back transaction: %s\n", PQerrorMessage(conn));
            PQclear(result);
        }

        return 1;
    }

    PQclear(result);

    result = PQexec(conn, "COMMIT");

    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Error committing transaction: %s\n", PQerrorMessage(conn));
        PQclear(result);
        return 1;
    }

    PQclear(result);

    return 0;
}

char **selectAllPathFromFile(PGconn *conn, int *rowCount, const char *user_api) {
    const char *select_sql = "SELECT path FROM file WHERE user_api = $1";
    const char *paramValues[1] = {user_api};
    const int paramLengths[1] = {-1};
    const int paramFormats[1] = {0};

    PGresult *result = PQexecParams(conn, select_sql, 1, NULL, paramValues, paramLengths, paramFormats, 0);

    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Error executing SELECT statement: %s\n", PQerrorMessage(conn));
        PQclear(result);
        return NULL;
    }

    *rowCount = PQntuples(result);

    char **paths = (char **)malloc(*rowCount * sizeof(char *));

    for (int i = 0; i < *rowCount; i++) {
        const char *path = PQgetvalue(result, i, 0);
        paths[i] = strdup(path);
    }

    PQclear(result);

    return paths;
}

const char *selectSlugByPath(PGconn *conn, const char *path, const char *user_api) {
    const char *select_sql = "SELECT slug FROM file WHERE path = $1 AND user_api = $2";
    const char *paramValues[2] = {path, user_api};
    const int paramLengths[2] = {-1, -1};
    const int paramFormats[2] = {0, 0};

    PGresult *result = PQexecParams(conn, select_sql, 2, NULL, paramValues, paramLengths, paramFormats, 0);

    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Error executing SELECT statement: %s\n", PQerrorMessage(conn));
        PQclear(result);
        return NULL;
    }

    const char *slug = PQgetvalue(result, 0, 0);

    PQclear(result);

    return slug;
}

int selectAllPath(PGconn *conn, Restore *restore, const char *user_api) {
    const char *select_sql = "SELECT path, slug, lastModification FROM file WHERE user_api = $1";
    const char *paramValues[1] = {user_api};
    const int paramLengths[1] = {-1};
    const int paramFormats[1] = {0};

    PGresult *result = PQexecParams(conn, select_sql, 1, NULL, paramValues, paramLengths, paramFormats, 0);

    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Error executing SELECT statement: %s\n", PQerrorMessage(conn));
        PQclear(result);
        return 1;
    }

    int rowCount = PQntuples(result);

    for (int i = 0; i < rowCount; i++) {
        const char *resultPath = PQgetvalue(result, i, 0);
        const char *resultSlug = PQgetvalue(result, i, 1);
        const char *resultLastModification = PQgetvalue(result, i, 2);

        strncpy(restore->restorePath[i].path, resultPath, sizeof(restore->restorePath[i].path));
        strncpy(restore->restorePath[i].slug, resultSlug, sizeof(restore->restorePath[i].slug));
        strncpy(restore->restorePath[i].lastModification, resultLastModification, sizeof(restore->restorePath[i].lastModification));
    }

    PQclear(result);

    return 0;
}

char* getSecret(PGconn *conn, const char *user_api) {
    const char *select_sql = "SELECT secret FROM users WHERE api = $1";
    const char *paramValues[1] = {user_api};
    const int paramLengths[1] = {-1};
    const int paramFormats[1] = {0};

    PGresult *result = PQexecParams(conn, select_sql, 1, NULL, paramValues, paramLengths, paramFormats, 0);

    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Error executing SELECT statement: %s\n", PQerrorMessage(conn));
        PQclear(result);
        return NULL;  // Retournez NULL en cas d'erreur
    }

    int rowCount = PQntuples(result);

    if (rowCount > 0) {
        const char *hashedApi = PQgetvalue(result, 0, 0);
        char *hashedApiCopy = strdup(hashedApi);

        PQclear(result);
        return hashedApiCopy;
    } else {
        printf("L'authentification a échoué. Aucun utilisateur trouvé avec API : %s\n", user_api);
        PQclear(result);
        return NULL;
    }
}

char *getIPByUserAPI(PGconn *conn, const char *user_api) {
    const char *select_sql = "SELECT ip FROM users WHERE api = $1";
    const char *paramValues[1] = {user_api};
    const int paramLengths[1] = {-1};
    const int paramFormats[1] = {0};

    PGresult *result = PQexecParams(conn, select_sql, 1, NULL, paramValues, paramLengths, paramFormats, 0);

    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Error executing SELECT statement: %s\n", PQerrorMessage(conn));
        PQclear(result);
        return NULL;
    }

    int rowCount = PQntuples(result);

    if (rowCount > 0) {
        const char *ip_result = PQgetvalue(result, 0, 0);
        printf("L'IP pour l'utilisateur avec API %s est : %s\n", user_api, ip_result);

        char *ip = strdup(ip_result);
        PQclear(result);
        return ip;
    } else {
        printf("Aucun utilisateur trouvé avec API : %s\n", user_api);
        PQclear(result);
        return NULL;
    }
}

int insertUser(PGconn *conn, const char *api, const char *ip, const char *secret) {
    const char *insert_sql = "INSERT INTO users (api, ip, secret) VALUES ($1, $2, $3)";
    const char *paramValues[3] = {api, ip, secret};
    const int paramLengths[3] = {-1, -1, -1};
    const int paramFormats[3] = {0, 0, 0};

    PGresult *result = PQexecParams(conn, insert_sql, 3, NULL, paramValues, paramLengths, paramFormats, 0);

    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Error executing INSERT statement: %s\n", PQerrorMessage(conn));
        PQclear(result);
        return 1;
    }

    PQclear(result);

    return 0;
}

int updateIPByAPI(PGconn *conn, const char *api, const char *newIP) {
    PGresult *res;
    const char *update_sql = "UPDATE users SET ip = $1 WHERE api = $2;";
    
    res = PQexecParams(conn, update_sql, 2, NULL, 
                       (const char * const []){newIP, api}, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Error executing UPDATE statement: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    return 0;
}



char *getIVFromFile(PGconn *conn, const char *path, const char *user_api) {
    const char *select_sql = "SELECT iv FROM file WHERE path = $1 AND user_api = $2";

    const char *paramValues[2] = {path, user_api};
    const int paramLengths[2] = {-1, -1};
    const int paramFormats[2] = {0, 0};

    PGresult *result = PQexecParams(conn, select_sql, 2, NULL, paramValues, paramLengths, paramFormats, 0);

    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Error executing SELECT statement: %s\n", PQerrorMessage(conn));
        PQclear(result);
        return NULL;
    }

    if (PQntuples(result) > 0) {
        char *iv = PQgetvalue(result, 0, 0);
        PQclear(result);
        return iv;
    } else {
        fprintf(stderr, "No results found for the specified path and user_api.\n");

        PQclear(result);

        return NULL;
    }
}

/*
int main() {
    // Remplacez les informations de connexion par les vôtres
    const char *conninfo = "dbname=mydatabase user=myuser password=mypassword host=127.0.0.1";

    PGconn *conn = PQconnectdb(conninfo);

    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "La connexion a échoué : %s", PQerrorMessage(conn));
        PQfinish(conn);
        return 1;
    }

    int rc = createDatabase(conn);
    if (rc != 0) {
        fprintf(stderr, "Erreur lors de la création de la base de données.\n");
        PQfinish(conn);
        return 1;
    }

    // Vous pouvez maintenant appeler d'autres fonctions ici pour tester.
    Packet packet;
    strcpy(packet.fileInfo.path, "testh");
    strcpy(packet.fileInfo.lastModification, "bonjour");
    strcpy(packet.apiPacket.api, "rsedhtfjygk");

   // insertUser(conn, packet.apiPacket.api, "1.1.1.8");
    insertNewFile(conn, &packet, packet.apiPacket.api);
    printf("test : %d\n", selectCountFile(conn, packet.apiPacket.api));
    PQfinish(conn);

    return 0;
}
*/