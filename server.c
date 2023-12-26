#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "objects/packet.h"

#include "lib/sqlite.h"
#include "lib/utils.h"

#define PORT 12347




void handle_client(SSL *ssl) {
    // Fonction pour gérer la communication avec le client
    Packet packet;
    packet.flag = NEW_CLIENT_HELLO;
    SSL_write(ssl, &packet, sizeof(packet));

    sqlite3 *db;
    int rc = sqlite3_open("sqlite/database.db", &db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Impossible d'ouvrir la base de données: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
    }
    

    while (1) {
        // Recevoir un message du client
        Packet packetReceive;
        Packet packetResponse;
        int bytes_received = SSL_read(ssl, &packetReceive, sizeof(packetReceive));

        
        FILE *fichier;
        char slug[1024];


        if (bytes_received > 0) {
            

            switch (packetReceive.flag)
            {
                case CONFIRM_RECEPTION:
                    printf("Le paquet à bien été reçu par le client \n");
                    break;
                
                case EXIT:
                    printf("un client vient de se déconnecter\n");
                    sqlite3_close(db);
                    exit(EXIT_SUCCESS);
                    break;
                
                case FILE_INFO:
                
                    printf("FILE_INFO requested : %d\n", packetReceive.flag);
                    printf("path : %s\n", packetReceive.fileInfo.path);
                    printf("last modification : %s\n", packetReceive.fileInfo.lastModification);
                    printf("\n");

                    const char *lastDateUpdate =  selectLastModificationFromFileByPath(db, packetReceive.fileInfo.path);

                    // le fichier n'est pas connu de la base : il faut le sauvegarder
                    if(lastDateUpdate == NULL){
                        packetResponse.flag = REQUEST_FILE;
                        memcpy(packetResponse.fileInfo.path, packetReceive.fileInfo.path, strlen(packetReceive.fileInfo.path) + 1);
                        SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                    } else { // le fichier est connu
                        if(strcmp(lastDateUpdate, packetReceive.fileInfo.lastModification) == 0){ // le fichier est à la même version que la sauvegarde : ne rien faire
                            printf("le fichier est déja sauvegardé à la dernière version\n");
                        } else { // le fichier à changé : il faut le resauvegarder
                            packetResponse.flag = REQUEST_FILE;
                            memcpy(packetResponse.fileInfo.path, packetReceive.fileInfo.path, strlen(packetReceive.fileInfo.path) + 1);
                            SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                        }
                    }
                    break;

                case HEADER_FILE:
                    memcpy(packetReceive.fileInfo.slug, replace(packetReceive.fileInfo.path, '/', '_'), strlen(replace(packetReceive.fileInfo.path, '/', '_')) + 1);
                    insertNewFile(db, &packetReceive);
                    updateFile(db, &packetReceive);
                    printf("open file\n");
                    snprintf(slug, sizeof(slug), "server_data/%s", packetReceive.fileInfo.slug);
                    fichier = fopen(slug, "wb");
                    break;
                case CONTENT_FILE:
                    // Écrire les données dans le fichier
                    fwrite(packetReceive.fileContent.content, 1, packetReceive.fileContent.size, fichier);
                    break;
                case FINISH_FILE:
                    fclose(fichier);
                    printf("close file");
                    break;


                case REQUEST_ALL_PATH:
                    if(1 == 1){
                        int rowCount = 0;
                        char **results = selectAllPathFromFile(db, &rowCount);
                        for(int i = 0; i < rowCount; i++){
                            packetResponse.flag = RESPONSE_PATH;
                            memcpy(packetResponse.fileInfo.path, results[i], strlen(results[i]) + 1);
                            SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                            memset(packetResponse.fileInfo.path, 0, sizeof(packetResponse.fileInfo.path));
                        }
                        packetResponse.flag = RESPONSE_PATH_FINISH;
                        SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                    }

                    break;

                case REQUEST_FILE:  
                    printf("REQUEST_FILE received\n");

                    // envoi de l'entête
                    packetResponse.flag = HEADER_FILE;
                    memcpy(packetResponse.fileInfo.path, packetReceive.fileInfo.path, strlen(packetReceive.fileInfo.path) + 1);
                    SSL_write(ssl, &packetResponse, sizeof(packetResponse));

                    const char *slug = selectSlugByPath(db, packetReceive.fileInfo.path);
                    memcpy(packetResponse.fileInfo.slug, slug, strlen(slug) + 1);
                    // envoi du contenu

                    char filePath[1024];
                    snprintf(filePath, sizeof(filePath), "server_data/%s", packetResponse.fileInfo.slug);

                    fichier = fopen(filePath, "rb");
                    if (fichier == NULL) {
                        perror("Erreur lors de l'ouverture du fichier");
                    }
                    unsigned char *buffer = (unsigned char *)malloc(SIZE_BLOCK_FILE * sizeof(unsigned char));

                    if (buffer == NULL) {
                        perror("Erreur d'allocation mémoire");
                        fclose(fichier);
                    }

                    size_t octetsLus;
                    while ((octetsLus = fread(buffer, 1, SIZE_BLOCK_FILE, fichier)) > 0) {
                        for (size_t i = 0; i < octetsLus; i++) {
                            packetResponse.fileContent.content[i] = buffer[i];
                        }
                        packetResponse.flag = CONTENT_FILE;
                        packetResponse.fileContent.size = octetsLus;
                        SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                        memset(packetResponse.fileContent.content, 0, SIZE_BLOCK_FILE);
                    }

                    free(buffer); // Libérer la mémoire du tampon
                    fclose(fichier);

                    // envoi d'un flag pour signaler la fin du fichier
                    packetResponse.flag = FINISH_FILE;
                    SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                    printf("envoi fini\n");
                    break;

                case REQUEST_RESTORE:
                    if(1 == 1){
                        int count = selectCountFile(db);
                        Restore restore;
                        restore.restorePath = malloc(sizeof(RestorePath) * count);
                        selectAllPath(db, &restore);
                        for(int i = 0; i < count; i++){
                            packetResponse.flag = REQUEST_FILE_RESTORE;
                            memcpy(packetResponse.fileInfo.path, restore.restorePath[i].path, strlen(restore.restorePath[i].path) + 1);
                            memcpy(packetResponse.fileInfo.lastModification, restore.restorePath[i].lastModification, strlen(restore.restorePath[i].lastModification) + 1);
                            SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                            printf("envoi : %s\n", packetResponse.fileInfo.path);
                        }
                        free(restore.restorePath);
                    }
                    break;

                case FILE_INFO_RESTORE:
                    break;
                    
                case FILE_INFO_RESTORE_FINISH:
                    break;
                
                default:
                    printf("paquet non reconnu !!\n");
                    break;
            }
        } else {
            ERR_print_errors_fp(stderr);
        //    sqlite3_close(db);
            break;
        }
        //sqlite3_close(db);
            
       // free(packetReceive);
    }

    // Fermer la connexion SSL
    SSL_shutdown(ssl);
    SSL_free(ssl);
}


int main() {
    sqlite3 *db;
    int rc = sqlite3_open("sqlite/database.db", &db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Impossible d'ouvrir la base de données: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
    }

    // creation de la base si elle n'existe pas
    createDatabase(db, rc);
    sqlite3_close(db);


    SSL_CTX *ctx;
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Initialiser la bibliothèque SSL
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    // Créer un contexte SSL avec TLS 1.3
    ctx = SSL_CTX_new(TLS_server_method());

    if (!ctx) {
        fprintf(stderr, "Erreur lors de la création du contexte SSL.\n");
        return EXIT_FAILURE;
    }

    // Configurer le contexte pour utiliser TLS 1.3
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2);

    // Charger le certificat et la clé privée
    if (SSL_CTX_use_certificate_file(ctx, "certificats/server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "certificats/server.key", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Erreur lors du chargement du certificat/clave privée.\n");
        return EXIT_FAILURE;
    }

    // Créer la socket du serveur
    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (server_socket == -1) {
        perror("Erreur lors de la création de la socket du serveur");
        return EXIT_FAILURE;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Lier la socket du serveur à l'adresse et au port
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Erreur lors de la liaison de la socket du serveur");
        close(server_socket);
        return EXIT_FAILURE;
    }

    // Mettre en écoute la socket du serveur
    if (listen(server_socket, 10) == -1) {
        perror("Erreur lors de la mise en écoute de la socket du serveur");
        close(server_socket);
        return EXIT_FAILURE;
    }

    printf("Le serveur écoute sur le port %d...\n", PORT);

    while (1) {
        // Accepter la connexion d'un client
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);

        if (client_socket == -1) {
            perror("Erreur lors de l'acceptation de la connexion client");
            close(server_socket);
            SSL_CTX_free(ctx);
            return EXIT_FAILURE;
        }

        // Créer une nouvelle structure SSL pour la connexion avec le client
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_socket);

        // Effectuer la poignée de main SSL
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            // Créer un processus fils pour gérer la communication avec le client
            pid_t pid = fork();

            if (pid == -1) {
                perror("Erreur lors de la création du processus fils");
                close(client_socket);
            } else if (pid == 0) {
                // Processus fils
                close(server_socket); // Fermer la socket du serveur dans le processus fils
                handle_client(ssl);
                exit(EXIT_SUCCESS);
            } else {
                // Processus parent
                close(client_socket); // Fermer la socket du client dans le processus parent
            }
        }
    }

    // Fermer la socket du serveur et libérer le contexte SSL (le code ne parvient jamais ici dans la boucle infinie)
    close(server_socket);
    SSL_CTX_free(ctx);

    return EXIT_SUCCESS;
}
