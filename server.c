#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "objects/packet.h"
#include "objects/apiPacket.h"

#include "lib/postgresql.h"
#include "lib/utils.h"

#define PORT 12347




void handle_client(SSL *ssl) {

    
    struct sockaddr_in peer_addr;
    socklen_t addr_len = sizeof(peer_addr);
    
    char ip_str[INET_ADDRSTRLEN];
    if (getpeername(SSL_get_fd(ssl), (struct sockaddr *)&peer_addr, &addr_len) == 0) {
        if (inet_ntop(AF_INET, &peer_addr.sin_addr, ip_str, sizeof(ip_str)) != NULL) {
            writeToLog("new client connected");
            writeToLog(ip_str);
        }
    }

    const char *conninfo = "dbname=backup user=postgres password=password host=127.0.0.1 port=5431";
    PGconn *conn = PQconnectdb(conninfo);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "La connexion a échoué : %s", PQerrorMessage(conn));
        writeToLog("database connexion failed");
        writeToLog(PQerrorMessage(conn));
        PQfinish(conn);
        return 1;
    }
    writeToLog("connected to the database");

    Packet packet;
    packet.flag = REQUEST_USER_API;
    SSL_write(ssl, &packet, sizeof(packet));

    Packet authPacket;
    int bytes_received = SSL_read(ssl, &authPacket, sizeof(authPacket));
    if(bytes_received > 0){
        if(authPacket.flag == API_RESPONSE){

            char *hash = getSecret(conn, authPacket.apiPacket.api);
            if(hash == NULL){
                writeToLog("API key not found. Closing the connection.");
                exit(EXIT_SUCCESS);
            } else {
                int ret = bcrypt_checkpw(authPacket.apiPacket.secret, hash);
                if(ret == 0 && strcmp(ip_str, getIPByUserAPI(conn, authPacket.apiPacket.api)) == 0){ // si l'api est correcte, on vérifie l'ip associé afin d'éviter un potentiel vol d'api
                    Packet packet;
                    packet.flag = AUTH_SUCCESS;
                    SSL_write(ssl, &packet, sizeof(packet));
                } else {
                    writeToLog("Connection from unauthorized api. Closing the connection.");
                    exit(EXIT_SUCCESS);
                }
            }

        } else {
            writeToLog("Connection from unauthorized api. Closing the connection.");
            exit(EXIT_SUCCESS);
        }
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
                    writeToLog("Client disconnected");
                    writeToLog(ip_str);
                    PQfinish(conn);
                    exit(EXIT_SUCCESS);
                    break;
                
                case FILE_INFO:
                
                    printf("FILE_INFO requested : %d\n", packetReceive.flag);
                    printf("path : %s\n", packetReceive.fileInfo.path);
                    printf("last modification : %s\n", packetReceive.fileInfo.lastModification);
                    printf("\n");

                    const char *lastDateUpdate =  selectLastModificationFromFileByPath(conn, packetReceive.fileInfo.path);

                    // le fichier n'est pas connu de la base : il faut le sauvegarder
                    if(lastDateUpdate == NULL){
                        packetResponse.flag = REQUEST_FILE;
                        memcpy(packetResponse.fileInfo.path, packetReceive.fileInfo.path, strlen(packetReceive.fileInfo.path) + 1);
                        writeToLog("REQUEST FILE");
                        SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                    } else { // le fichier est connu
                        if(strcmp(lastDateUpdate, packetReceive.fileInfo.lastModification) == 0){ // le fichier est à la même version que la sauvegarde : ne rien faire
                            printf("le fichier est déja sauvegardé à la dernière version\n");
                            writeToLog("the file requested is already save to the last version");
                        } else { // le fichier à changé : il faut le resauvegarder
                            packetResponse.flag = REQUEST_FILE;
                            memcpy(packetResponse.fileInfo.path, packetReceive.fileInfo.path, strlen(packetReceive.fileInfo.path) + 1);
                            writeToLog("REQUEST FILE");
                            SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                        }
                    }
                    break;

                case HEADER_FILE:
                    generateRandomKey(packetReceive.fileInfo.slug, 32);
                    insertNewFile(conn, &packetReceive, authPacket.apiPacket.api);
                    updateFile(conn, &packetReceive);
                    printf("open file\n");
                    writeToLog("FILE RECEIVE");
                    writeToLog(packetReceive.fileInfo.path);

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
                    writeToLog("CLOSE FILE");
                    break;


                case REQUEST_ALL_PATH:
                    if(1 == 1){
                        writeToLog("REQUEST_ALL_PATH received");
                        int rowCount = 0;
                        char **results = selectAllPathFromFile(conn, &rowCount, authPacket.apiPacket.api);
                        for(int i = 0; i < rowCount; i++){
                            packetResponse.flag = RESPONSE_PATH;
                            memcpy(packetResponse.fileInfo.path, results[i], strlen(results[i]) + 1);
                            SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                            memset(packetResponse.fileInfo.path, 0, sizeof(packetResponse.fileInfo.path));
                        }
                        packetResponse.flag = RESPONSE_PATH_FINISH;
                        writeToLog("send RESPONSE_PATH_FINISH");
                        SSL_write(ssl, &packetResponse, sizeof(packetResponse));

                    }

                    break;

                case REQUEST_FILE:  
                    printf("REQUEST_FILE received\n");
                    writeToLog("REQUEST_FILE received");
                    // envoi de l'entête
                    packetResponse.flag = HEADER_FILE;
                    memcpy(packetResponse.fileInfo.path, packetReceive.fileInfo.path, strlen(packetReceive.fileInfo.path) + 1);
                    SSL_write(ssl, &packetResponse, sizeof(packetResponse));


                    writeToLog("send HEADER_FILE");
                    writeToLog(packetResponse.fileInfo.path);

                    const char *slug = selectSlugByPath(conn, packetReceive.fileInfo.path, authPacket.apiPacket.api);
                    memcpy(packetResponse.fileInfo.slug, slug, strlen(slug) + 1);
                    // envoi du contenu

                    char filePath[1024];
                    snprintf(filePath, sizeof(filePath), "server_data/%s", packetResponse.fileInfo.slug);

                    fichier = fopen(filePath, "rb");
                    writeToLog("open file");
                    writeToLog(filePath);
                    if (fichier == NULL) {
                        writeToLog("Erreur lors de l'ouverture du fichier");
                        perror("Erreur lors de l'ouverture du fichier");
                    }
                    unsigned char *buffer = (unsigned char *)malloc(SIZE_BLOCK_FILE * sizeof(unsigned char));

                    if (buffer == NULL) {
                        writeToLog("Erreur d'allocation mémoire");
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
                        writeToLog("send CONTENT_FILE");
                    }

                    free(buffer); // Libérer la mémoire du tampon
                    fclose(fichier);

                    // envoi d'un flag pour signaler la fin du fichier
                    packetResponse.flag = FINISH_FILE;
                    SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                    printf("envoi fini\n");
                    writeToLog("send FINISH_FILE");
                    break;

                case REQUEST_RESTORE:
                    writeToLog("received REQUEST_RESTORE");
                    if(1 == 1){
                        int count = selectCountFile(conn, authPacket.apiPacket.api);
                        Restore restore;
                        restore.restorePath = malloc(sizeof(RestorePath) * count);
                        selectAllPath(conn, &restore, authPacket.apiPacket.api);
                        for(int i = 0; i < count; i++){
                            packetResponse.flag = REQUEST_FILE_RESTORE;
                            memcpy(packetResponse.fileInfo.path, restore.restorePath[i].path, strlen(restore.restorePath[i].path) + 1);
                            memcpy(packetResponse.fileInfo.lastModification, restore.restorePath[i].lastModification, strlen(restore.restorePath[i].lastModification) + 1);
                            SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                            printf("envoi : %s\n", packetResponse.fileInfo.path);
                            writeToLog("send REQUEST_FILE_RESTORE");
                            writeToLog(packetResponse.fileInfo.path);
                        }
                        free(restore.restorePath);
                    }
                    break;

                case FILE_INFO_RESTORE:
                    break;
                    
                case FILE_INFO_RESTORE_FINISH:
                    break;
                
                default:
                    writeToLog("PACKET RECEIVE NOT FOUND");
                    printf("paquet non reconnu !!\n");
                    break;
            }
        } else {
            ERR_print_errors_fp(stderr);
        //    sqlite3_close(db);
            break;
        }
            
       // free(packetReceive);
    }

    // Fermer la connexion SSL
    SSL_shutdown(ssl);
    SSL_free(ssl);
}


int main() {

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
            writeToLog("Error loading certificate/private key");
            fprintf(stderr, "Erreur lors du chargement du certificat/clave privée.\n");
            return EXIT_FAILURE;
    }

    // Créer la socket du serveur
    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (server_socket == -1) {
        perror("Erreur lors de la création de la socket du serveur");
        writeToLog("Error creating the server socket");
        return EXIT_FAILURE;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Lier la socket du serveur à l'adresse et au port
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Erreur lors de la liaison de la socket du serveur");
        writeToLog("Error linking server socket");
        close(server_socket);
        return EXIT_FAILURE;
    }

    // Mettre en écoute la socket du serveur
    if (listen(server_socket, 10) == -1) {
        perror("Erreur lors de la mise en écoute de la socket du serveur");
        writeToLog("Error listening to the server socket");
        close(server_socket);
        return EXIT_FAILURE;
    }

    printf("Le serveur écoute sur le port %d...\n", PORT);
    writeToLog("The server is listening on port");
    //writeToLog(PORT);
    while (1) {
        // Accepter la connexion d'un client
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);

        if (client_socket == -1) {
            perror("Erreur lors de l'acceptation de la connexion client");
            writeToLog("Error accepting client connection");
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
                writeToLog("Error creating child process");
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
