#include "sqlite.h"



int createDatabase(sqlite3 *db, int rc){
    // Création d'une table de test
    const char *createFileTableSQL = "CREATE TABLE IF NOT EXISTS file (path TEXT PRIMARY KEY, lastModification TEXT, slug TEXT );";
    rc = sqlite3_exec(db, createFileTableSQL, 0, 0, 0);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error creating table: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return rc;
    }
    return rc;
}


const char *selectLastModificationFromFileByPath(sqlite3 *db, const char *path) {
    const char *select_sql = "SELECT * FROM file WHERE path = ?;";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error preparing SELECT statement: %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }

    // Lier le nom comme paramètre de la requête préparée
    rc = sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error binding path parameter: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        exit(EXIT_FAILURE);
    }

    // Exécution de la requête SELECT
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        // Lire les résultats de la requête ici
       // const char *resultPath = (const char *)sqlite3_column_text(stmt, 0);
        const char *resultLastDateUpdate = (const char *)sqlite3_column_text(stmt, 1);
        return resultLastDateUpdate;
    }

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Error executing SELECT statement: %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }

    sqlite3_finalize(stmt);

    return NULL;
}


int insertNewFile(sqlite3 *db, Packet *packet) {
   
    sqlite3_exec(db, "BEGIN TRANSACTION", 0, 0, 0);
    const char *insert_sql = "INSERT INTO file (path, lastModification, slug) VALUES (?, ?, ?);";
    sqlite3_stmt *stmt;
     int rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error preparing INSERT statement: %s\n", sqlite3_errmsg(db));
        return rc;
    }

    // Lier les valeurs aux paramètres de la requête préparée
    rc = sqlite3_bind_text(stmt, 1, packet->fileInfo.path, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error binding path parameter: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return rc;
    }
    // --------

    rc = sqlite3_bind_text(stmt, 2, packet->fileInfo.lastModification, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error binding lastModification parameter: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return rc;
    }
     // --------

    rc = sqlite3_bind_text(stmt, 3, packet->fileInfo.slug, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error binding slug parameter: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return rc;
    }
     // --------

    // Exécution de la requête INSERT
    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Error executing INSERT statement: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);

    sqlite3_exec(db, "COMMIT", 0, 0, 0);

    return rc;
}

int updateFile(sqlite3 *db, Packet *packet) {
    printf("update : %s\n", packet->fileInfo.lastModification);

    sqlite3_exec(db, "BEGIN TRANSACTION", 0, 0, 0);

    const char *update_sql = "UPDATE file SET lastModification = ? WHERE path = ?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, update_sql, -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error preparing UPDATE statement: %s\n", sqlite3_errmsg(db));
        return rc;
    }

    // Bind values to prepared statement parameters
    rc = sqlite3_bind_text(stmt, 1, packet->fileInfo.lastModification, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error binding lastModification parameter: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return rc;
    }

    rc = sqlite3_bind_text(stmt, 2, packet->fileInfo.path, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error binding path parameter: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return rc;
    }

    // Execute the UPDATE statement
    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Error executing UPDATE statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return rc;
    }

    // Finalize the statement before committing the transaction
    sqlite3_finalize(stmt);

    sqlite3_exec(db, "COMMIT", 0, 0, 0);

    printf("update fin\n");
    return rc;
}

int selectCountFile(sqlite3 *db){
    const char *select_sql = "SELECT COUNT(*) FROM file;";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error preparing SELECT statement: %s\n", sqlite3_errmsg(db));
        return rc;
    }

    // Exécution de la requête SELECT
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        // Lire les résultats de la requête ici
        return sqlite3_column_int(stmt, 0);
    }

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Error executing SELECT statement: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);

    return NULL;
}


int deleteFileWithFilePath(sqlite3 *db, const char *filePath) {

    sqlite3_exec(db, "BEGIN TRANSACTION", 0, 0, 0);

   
    sqlite3_stmt *stmt;

    // Préparer la requête DELETE
    const char *delete_sql = "DELETE FROM file WHERE path = ?";

    int rc = sqlite3_prepare_v2(db, delete_sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Erreur de préparation de la requête DELETE : %s\n", sqlite3_errmsg(db));
        return rc;
    }

    // Lier la valeur de filePath au paramètre dans la requête
    rc = sqlite3_bind_text(stmt, 1, filePath, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Erreur de liaison du paramètre : %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return rc;
    }

    // Exécuter la requête DELETE
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Erreur lors de l'exécution de la requête DELETE : %s\n", sqlite3_errmsg(db));
    }

    // Finaliser l'instruction
    sqlite3_finalize(stmt);

    sqlite3_exec(db, "COMMIT", 0, 0, 0);

    return rc;
}

char** selectAllPathFromFile(sqlite3* db, int* rowCount) {
    const char* select_sql = "SELECT path FROM file;";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error preparing SELECT statement: %s\n", sqlite3_errmsg(db));
        return NULL;
    }

    // Exécution de la requête SELECT
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        fprintf(stderr, "Error executing SELECT statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return NULL;
    }

    // Allocation dynamique d'un tableau de chaînes de caractères
    char** paths = NULL;
    int index = 0;
    *rowCount = 0;

    while (rc == SQLITE_ROW) {
        const char* path = (const char*)sqlite3_column_text(stmt, 0);

        // Allocation mémoire pour la nouvelle chaîne de caractères
        char* newPath = strdup(path);

        // Réallocation du tableau de chaînes de caractères
        paths = (char**)realloc(paths, (index + 1) * sizeof(char*));
        paths[index++] = newPath;
        (*rowCount)++;

        // Passage à la prochaine ligne du résultat
        rc = sqlite3_step(stmt);
    }

    // Finalisation
    sqlite3_finalize(stmt);

    return paths;
}

const char *selectSlugByPath(sqlite3 *db, const char *path) {
    const char *select_sql = "SELECT slug FROM file WHERE path = ?;";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error preparing SELECT statement: %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }

    // Lier le nom comme paramètre de la requête préparée
    rc = sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error binding path parameter: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        exit(EXIT_FAILURE);
    }

    // Exécution de la requête SELECT
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *slug = (const char *)sqlite3_column_text(stmt, 0);
        printf("result : %s\n", slug);
        return slug;
    }

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Error executing SELECT statement: %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }

    sqlite3_finalize(stmt);

    return NULL;
}


int selectAllPath(sqlite3 *db, Restore *restore) {
    const char *select_sql = "SELECT path,slug,lastModification FROM file;";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error preparing SELECT statement: %s\n", sqlite3_errmsg(db));
        return rc;
    }

    // Exécution de la requête SELECT
    int i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        // Lire les résultats de la requête ici
        char *resultPath = (const char *)sqlite3_column_text(stmt, 0);
        char *resultSlug = (const char *)sqlite3_column_text(stmt, 1);
        char *resultLastModification = (const char *)sqlite3_column_text(stmt, 2);
        
        strncpy(restore->restorePath[i].path, resultPath, sizeof(restore->restorePath[i].path));
        strncpy(restore->restorePath[i].slug, resultSlug, sizeof(restore->restorePath[i].slug));
        strncpy(restore->restorePath[i].lastModification, resultLastModification, sizeof(restore->restorePath[i].lastModification));
        i++;
    }

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Error executing SELECT statement: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
    return 0;
}


/*
int main(){

    sqlite3 *db;
    int rc = sqlite3_open("/Users/quentingauny/Documents/cours-semestre5/client-server-tls/sqlite/database.db", &db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Impossible d'ouvrir la base de données: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return rc;
    }

    // creation de la base si elle n'existe pas
    createDatabase(db, rc);

    Packet packet;
    strcpy(packet.fileInfo.path, "dhcfjgvh");
    strcpy(packet.fileInfo.lastModification, "dtfcgjvhk");
    strcpy(packet.fileInfo.slug, "fcjgvhkb;");

    insertNewFile(db, &packet);

}

*/