#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include "lib/postgresql.h"
#include "lib/utils.h"

#include "lib/libbcrypt/bcrypt.h"


#define API_SECRET_LENGTH 32

int main() {

    const char *conninfo = "dbname=backup user=postgres password=password host=127.0.0.1 port=5431";

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

    printf("choix 1 : créer un nouveau client\n");
    printf("choix 2 : modifier l'ip d'un client\n");

    int choix = -1;
    printf("votre choix : ");
    scanf("%d", &choix);

    switch (choix)
    {
    case 1:
        if (RAND_poll() != 1) {
            fprintf(stderr, "Erreur lors de l'initialisation du générateur de nombres aléatoires.\n");
            return EXIT_FAILURE;
        }

        char api[2048];
        printf("entrer un identifiant : ");
        scanf("%s", api);

        char secret[API_SECRET_LENGTH + 1];

        // Generate API key
        generateRandomKey(secret, API_SECRET_LENGTH);
        secret[API_SECRET_LENGTH] = '\0';  

        // hash api key
        char salt[BCRYPT_HASHSIZE];
        char hash[BCRYPT_HASHSIZE];
        int ret;
        ret = bcrypt_gensalt(10, salt);
        ret = bcrypt_hashpw(secret, salt, hash);

        // Print the generated API key
        char ip[2048];
        printf("taper une ip : ");
        scanf("%s", ip);

        
        insertUser(conn, api, ip, hash);

        printf("Clé API générée : %s\n", secret);

        break;

    case 2:
        if(1 == 1){
            char api[2048];
            printf("entrer une clé api valide : ");
            scanf("%s", api);

            char *hash = getSecret(conn, api);
            if (hash == NULL) {
                printf("\nmauvaise api : veuillez réésayer\n");
                break;
            }
            
            char pass[2048];
            printf("entrer votre mot de passe : ");
            scanf("%s", pass);

            if(bcrypt_checkpw(pass, hash) == 0){
                printf("entrer une nouvelle ip : ");
                char ip[2048];
                scanf("%s", ip);
                updateIPByAPI(conn, api, ip);
            } else {
                printf("\nmauvaise api : veuillez réésayer\n");
            }
        }
        
        break;
    
    default:
        break;
    }



    
     PQfinish(conn);

    return EXIT_SUCCESS;
}
