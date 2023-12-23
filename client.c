#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "objects/packet.h"
#include "enum/flag.h"

#include "lib/find.h"


// global variables
SSL *ssl;
//Packet *packetReceive = NULL;

// mode => SYNCHRONIZE | RESTORE 
char mod[1024];
char repository[4096];
char extensionsFile[4096];

void onPacketReceive(Packet packetReceive){
    

    char **extensions = NULL;
    int numExtensions;
    char *paths[1000];
    int count;
    Packet packetResponse;
    FILE *fichier;


    switch (packetReceive.flag)
    {
        case NEW_CLIENT_HELLO:

            // Lit les extensions depuis le fichier
            readExtensionsFromFile(extensionsFile, &extensions, &numExtensions);
            for(int i = 0; i < numExtensions; i++){
                printf("extension : %s\n", extensions[i]);
            }
         
            findFiles(repository, paths, &count);
            for(int i = 0; i < count; i++){
                printf("%s\n", paths[i]);
            }
            // Appelle la fonction de recherche
           // searchFilesRecursive(repository, extensions, numExtensions, &results, &count);

            // Envois des résultats au serveur
            for (int i = 0; i < count; i++) {
                if(paths[i] != NULL){
                    printf("envoi : %s\n", paths[i]);

                    char *lastModification = getLastUpdated(paths[i]);
                    packetResponse.flag = FILE_INFO;
                    memcpy(packetResponse.fileInfo.path, paths[i], strlen(paths[i]) + 1);
                    memcpy(packetResponse.fileInfo.lastModification, lastModification, strlen(lastModification) + 1);
                    SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                }
            }

            break;

            case REQUEST_FILE:
                // envoi de l'entête du fichier (path, date de modification)
                packetResponse.flag = HEADER_FILE;
                memcpy(packetResponse.fileInfo.path, packetReceive.fileInfo.path, strlen(packetReceive.fileInfo.path) + 1);
                char *lastModification = getLastUpdated(packetResponse.fileInfo.path);
                memcpy(packetResponse.fileInfo.lastModification, lastModification, strlen(lastModification) + 1);
                SSL_write(ssl, &packetResponse, sizeof(packetResponse));


                // envoi du contenu par paquet de 2048 bits en binaire
                packetResponse.flag = CONTENT_FILE;

                printf("receive REQUEST_FILE\n");
                printf("le serveur demande le fichier %s\n\n", packetReceive.fileInfo.path);
                fichier = fopen(packetReceive.fileInfo.path, "rb");
                if (fichier == NULL) {
                    perror("Erreur lors de l'ouverture du fichier");
                   // return 1;
                }
                unsigned char *buffer = (unsigned char *)malloc(SIZE_BLOCK_FILE * sizeof(unsigned char));

                if (buffer == NULL) {
                    perror("Erreur d'allocation mémoire");
                    fclose(fichier);
                   // return 1;
                }

                

                size_t octetsLus;
                while ((octetsLus = fread(buffer, 1, SIZE_BLOCK_FILE, fichier)) > 0) {
                    for (size_t i = 0; i < octetsLus; i++) {
                        packetResponse.fileContent.content[i] = buffer[i];
                    }
                    printf("data : %s\n", packetResponse.fileContent.content);
                    packetResponse.flag = CONTENT_FILE;

                    for(int i = 0; i < 2048; i++){
                        printf("%02X ", packetResponse.fileContent.content[i]);
                    }
                    
                    packetResponse.fileContent.size = octetsLus;
                    SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                    memset(packetResponse.fileContent.content, 0, SIZE_BLOCK_FILE);
                }

                free(buffer); // Libérer la mémoire du tampon
                fclose(fichier);

                packetResponse.flag = FINISH_FILE;
                SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                printf("envoi finish\n");




                break;
            
        default:
            break;
    }

    //packetResponse.flag = EXIT;
    //SSL_write(ssl, &packetResponse, sizeof(packetResponse));
    //exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {

    if (argc != 6) {
        printf("Usage: %s <server IP> <port> <SYNCHRONIZE|RESTORE> <repository> <config extension file>\n", argv[0]);
        return 1;
    }

    char *serverIP = argv[1];
    int port = atoi(argv[2]);

    if(strcmp(argv[3], "SYNCHRONIZE") && strcmp(argv[3], "RESTORE")){
        printf("Usage: %s <server IP> <port> <SYNCHRONIZE|RESTORE> <repository> <config extension file>\n", argv[0]);
        return 1;
    }

    strcpy(mod, argv[3]);
    strcpy(repository, argv[4]);
    strcpy(extensionsFile, argv[5]);

    int client_socket;
    struct sockaddr_in server_addr;
    SSL_CTX *ctx;


    // Initialiser la bibliothèque SSL
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    // Créer un contexte SSL avec TLS 1.3
    ctx = SSL_CTX_new(TLS_client_method());

    if (!ctx) {
        fprintf(stderr, "Erreur lors de la création du contexte SSL.\n");
        return EXIT_FAILURE;
    }

    // Configurer le contexte pour utiliser uniquement TLS 1.3
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2);

    // Créer la socket du client
    client_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (client_socket == -1) {
        perror("Erreur lors de la création de la socket du client");
        return EXIT_FAILURE;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(serverIP);
    server_addr.sin_port = htons(port);

    // Connecter la socket du client au serveur
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Erreur lors de la connexion au serveur");
        close(client_socket);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    // Créer une nouvelle structure SSL pour la connexion avec le serveur
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_socket);

    // Effectuer la poignée de main SSL
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        

        while (1) {

            // allocation mémoire pour packetReceive
        //    packetReceive = (Packet *)malloc(sizeof(Packet));
        //    if (packetReceive == NULL) {
        //        fprintf(stderr, "Memory allocation failed\n");
        //        break;
        //    }

            // Recevoir un message initial du serveur
            Packet packetReceive;
            int bytes_received = SSL_read(ssl, &packetReceive, sizeof(packetReceive));
            if (bytes_received > 0) {
                printf("--------- bytes received\n");
                onPacketReceive(packetReceive);
            } else {
                ERR_print_errors_fp(stderr);
                break;
            }
        }
    }

    // Fermer la connexion SSL
    SSL_shutdown(ssl);
    SSL_free(ssl);

    // Fermer la socket du client et libérer le contexte SSL
    close(client_socket);
    SSL_CTX_free(ctx);

    return EXIT_SUCCESS;
}


