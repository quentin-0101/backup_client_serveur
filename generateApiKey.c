#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include "lib/sqlite.h"

#define API_KEY_LENGTH 32

void generateApiKey(char *apiKey, size_t length) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const size_t charsetSize = sizeof(charset) - 1;

    for (size_t i = 0; i < length; ++i) {
        RAND_bytes((unsigned char *)&apiKey[i], 1);
        apiKey[i] = charset[apiKey[i] % charsetSize];
    }
}

int main() {

     sqlite3 *db;
    int rc = sqlite3_open("sqlite/database.db", &db);

    createDatabase(db, &rc);

    if (RAND_poll() != 1) {
        fprintf(stderr, "Erreur lors de l'initialisation du générateur de nombres aléatoires.\n");
        return EXIT_FAILURE;
    }

    char apiKey[API_KEY_LENGTH + 1];  

    // Generate API key
    generateApiKey(apiKey, API_KEY_LENGTH);
    apiKey[API_KEY_LENGTH] = '\0';  

    // Print the generated API key
    printf("Clé API générée : %s\n", apiKey);

    char ip[2048];
    printf("taper une ip : ");
    scanf("%s", ip);

    insertUser(db, apiKey, ip);

    sqlite3_close(db);

    return EXIT_SUCCESS;
}
