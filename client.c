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
#include "lib/readConfigFile.h"

#include "lib/utils.h"
#include "libgen.h"

#include <signal.h>

// global variables
SSL *ssl;
//Packet *packetReceive = NULL;

// mode => SYNCHRONIZE | RESTORE 
ConfigClient configClient;

FILE *fichier;



void handle_ctrl_c() {
    printf("Vous avez appuyé sur Ctrl + C !\n");
    Packet packet;
    packet.flag = EXIT;
    SSL_write(ssl, &packet, sizeof(packet));
    exit(EXIT_SUCCESS);
}

void onPacketReceive(Packet packetReceive){
    Packet packetResponse;
    FILE *fichier;

    switch (packetReceive.flag)
    {

        case REQUEST_USER_API:
            readClientCredentials(".api", &packetResponse.apiPacket);
            printf("API : %s\n", packetResponse.apiPacket.api);
            printf("Secret : %s\n", packetResponse.apiPacket.secret);

            packetResponse.flag = API_RESPONSE;
            SSL_write(ssl, &packetResponse, sizeof(packetResponse));
            break;

        case AUTH_SUCCESS:
            if(strcmp(configClient.action, "SYNCHRONIZE") == 0){
                  
                for(int i = 0; i < configClient.numExtensions; i++){
                    printf("extension : %s\n", configClient.extensions[i]);
                }

                for(int i = 0; i < configClient.numRepositories; i++){
                    char *paths[1000];
                     int count = 0;
                    printf("scan du répertoire %s\n", configClient.repositories[i]);
                    findFiles(configClient.repositories[i], paths, &count, configClient.extensions, configClient.numExtensions);
                    printf("count : %d\n", count);
                    for(int i = 0; i < count; i++){
                        printf("ok\n");
                        printf("%s\n", paths[i]);
                    }

                    // Envois des résultats au serveur
                    printf("count : %d ----------------\n", count);
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
                }
            
                
            } else {
                printf("mode restauration activé : Que voulez-vous faire ?\n");
                printf("option 1 : restaurer un seul fichier uniquement\n");
                printf("option 2 : restaurer tous les fichiers manquants et modifiés\n");

                int choix;
                printf("votre choix : ");
                scanf("%d", &choix);
                
                switch (choix) 
                {
                case 1:
                    // demander au serveur tous les paths sauvegardés
                    packetResponse.flag = REQUEST_ALL_PATH;
                    SSL_write(ssl, &packetResponse, sizeof(packetResponse)); // pas fini
                    break;

                case 2:
                    packetResponse.flag = REQUEST_RESTORE;            
                    SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                    break;
                
                default:
                    break;
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
                    packetResponse.flag = CONTENT_FILE;
                    packetResponse.fileContent.size = octetsLus;
                    SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                    memset(packetResponse.fileContent.content, 0, SIZE_BLOCK_FILE);
                }

                free(buffer); // Libérer la mémoire du tampon
                fclose(fichier);

                packetResponse.flag = FINISH_FILE;
                SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                printf("envoi fini\n");

                break;

            case RESPONSE_PATH:
                printf("%s\n", packetReceive.fileInfo.path);
                break;
            

            case RESPONSE_PATH_FINISH:
                printf("RESPONSE_PATH_FINISH received\n");
                if(1 == 1){
                    printf("votre choix : ");
                    fflush(stdin);
                    scanf("%s", packetResponse.fileInfo.path);      

                    printf("choix : %s\n", packetResponse.fileInfo.path);

                    packetResponse.flag = REQUEST_FILE;
                    SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                    printf("envoi de %s", packetResponse.fileInfo.path);
                }
                break;
            
            case REQUEST_FILE_RESTORE:
                printf("packet reçu : %s\n", packetReceive.fileInfo.path);
                
                if (access(packetReceive.fileInfo.path, F_OK) != -1) {
                    char *lastUpdate = getLastUpdated(packetReceive.fileInfo.path);
                    if(strcmp(lastUpdate, packetReceive.fileInfo.lastModification) == 0){
                        // le fichier est à jour
                    } else {
                        packetReceive.flag = REQUEST_FILE;
                        SSL_write(ssl, &packetReceive, sizeof(packetReceive));
                        printf("je demande le fichier : %s\n", packetResponse.fileInfo.path);
                    }
                } else {
                    printf("Le fichier n'existe pas.\n");
                    packetReceive.flag = REQUEST_FILE;
                    SSL_write(ssl, &packetReceive, sizeof(packetReceive));
                }
                break;

            case HEADER_FILE:
                char dirpath[2048];
                char command[4096];
                memcpy(dirpath, packetReceive.fileInfo.path, strlen(packetReceive.fileInfo.path) + 1);
                deleteAfterLastSlash(dirpath);
                
                snprintf(command, sizeof(command), "mkdir -p %s", dirpath);

                system(command);
                printf("création de %s\n", dirpath);

                if (access(packetReceive.fileInfo.path, F_OK) != -1) { // si le fichier existe
                     remove(packetReceive.fileInfo.path);
                }
               
                fichier = fopen(packetReceive.fileInfo.path, "wb");
                break;
            
            case CONTENT_FILE:
                // Écrire les données dans le fichier
                fwrite(packetReceive.fileContent.content, 1, packetReceive.fileContent.size, fichier);
                break;
            
            case FINISH_FILE:
                fclose(fichier);
                printf("close file\n");
                break;
            
        default:
            break;
    }

    //packetResponse.flag = EXIT;
    //SSL_write(ssl, &packetResponse, sizeof(packetResponse));
    //exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {

    if (argc != 2) {
        printf("Usage: %s <path/to/client.conf>\n", argv[0]);
        return 1;
    }

    readConfigClientFile(argv[1], &configClient);

    for(int i = 0; i < configClient.numExtensions; i++){
        printf("new extension : %s\n", configClient.extensions[i]);
    }

    for(int i = 0; i < configClient.numRepositories; i++){
        printf("new repository : %s\n", configClient.repositories[i]);
    }

    printf("ip serveur : %s\n", configClient.serverIP);
    printf("port serveur : %d\n", configClient.port);

    if (signal(SIGINT, handle_ctrl_c) == SIG_ERR) {
        fprintf(stderr, "Impossible de capturer SIGINT\n");
        return 1;
    }
    

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
    server_addr.sin_addr.s_addr = inet_addr(configClient.serverIP);
    server_addr.sin_port = htons(configClient.port);

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


