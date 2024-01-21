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
#include "lib/readConfigFile.h"

#include "lib/libbcrypt/bcrypt.h"

#include "lib/base64.h"

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

    DatabaseConfig databaseConfig;
    readDatabaseConfig("database.conf", &databaseConfig);

    const char *conninfo = buildDatabaseConnectionString(&databaseConfig);
    PGconn *conn = PQconnectdb(conninfo);    


    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "La connexion a échoué : %s", PQerrorMessage(conn));
        writeToLog("database connexion failed");
        writeToLog(PQerrorMessage(conn));
        PQfinish(conn);
       // return 1;
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

    char savePath[1024];
    char hashReceivedCurrentFile[1024];

    char iv[32];


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

                    const char *lastDateUpdate =  selectLastModificationFromFileByPath(conn, packetReceive.fileInfo.path, authPacket.apiPacket.api);

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
                            printf("REQUEST_FILE\n");
                            SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                            
                        }
                    }
                    break;

                case HEADER_FILE:
                    
                    // récupérer le nom de l'ancien fichier, et le supprimer
                    

                   
                //    generateRandomIV(packetReceive.fileInfo.iv, 16);
                    if(1 == 1){
                        const char *exist = selectLastModificationFromFileByPath(conn, packetReceive.fileInfo.path, authPacket.apiPacket.api);
                        generateRandomIV(iv, 32);
                        char *enc = b64_encode((const unsigned char *)iv, strlen(iv));
                     //   printf("iv              :%s\n", iv);
                     //   printf("iv encoded      :%s\n", enc);
                        memset(packetReceive.fileInfo.iv, enc, strlen(enc) + 1);

                        

                        if(exist == NULL){
                            generateRandomKey(packetReceive.fileInfo.slug, 32);
                            printf("insertion en base : \n");
                            printf("hash : %s\n", packetReceive.fileInfo.lastModification);
                            insertNewFile(conn, &packetReceive, authPacket.apiPacket.api, enc);
                        } else {
                            char *slug = selectSlugByPath(conn, packetReceive.fileInfo.path, authPacket.apiPacket.api);
                            char fullPathServer[2048];
                            snprintf(fullPathServer, sizeof(fullPathServer), "server_data/%s", slug);
                            remove(fullPathServer);
                            memcpy(packetReceive.fileInfo.slug, slug, strlen(slug) + 1);
                            updateFile(conn, &packetReceive, enc);
                        }
                        memcpy(hashReceivedCurrentFile, packetReceive.fileInfo.lastModification, strlen(packetReceive.fileInfo.lastModification) + 1);
                    
                        printf("open file\n");
                        writeToLog("FILE RECEIVE");
                        writeToLog(packetReceive.fileInfo.path);
                        memcpy(savePath, packetReceive.fileInfo.path, strlen(packetReceive.fileInfo.path) + 1);

                        snprintf(slug, sizeof(slug), "server_data/%s", packetReceive.fileInfo.slug);

                        fichier = fopen(slug, "wb");
                    }
                    
                    break;
                case CONTENT_FILE:
                    // Écrire les données dans le fichier
                  //  char crypted[2048];
                  //  uint8_t key[32];
                  //  generateKey(authPacket.apiPacket.secret, key);
                  if(1 == 1){
                    unsigned char ciphertext[CHUNK_SIZE_CRYPTED];
                    int size = encryptAES(packetReceive.fileContent.content, packetReceive.fileContent.size, authPacket.apiPacket.secret, iv, ciphertext);
                    fwrite(ciphertext, 1, size, fichier);
                  }
                    
                    break;
                
                case FINISH_FILE:
                    fclose(fichier);
                    printf("close file");
                    writeToLog("CLOSE FILE");


                    char *slug = selectSlugByPath(conn, savePath, authPacket.apiPacket.api);
                    char fullPathServer[2048];
                    snprintf(fullPathServer, sizeof(fullPathServer), "server_data/%s", slug);

                    /*
                    char *hash = calculateMD5(fullPathServer);

                    if(strcmp(hash, hashReceivedCurrentFile) == 0){
                        printf("le fichier reçu est complet\n");
                        writeToLog("the file received is complete");
                    } else {
                        printf("il y a eu une erreur lors du trasnfert pour le fichier %s\n", savePath);
                        writeToLog("error : file not completly received");
                    }
                    */
                    writeToLog("the file received is complete");
                    writeToLog(savePath);


                    char *my_iv = getIVFromFile(conn, savePath, authPacket.apiPacket.api);
                    int out_len = b64_decoded_size(my_iv)+1;
                    char *out = malloc(out_len);
                    b64_decode(my_iv, (unsigned char *)out, out_len);
                    out[out_len] = '\0';
             //     printf("decode iv        :%s\n", out);

                  //  decryptFileAES256(fullPathServer, authPacket.apiPacket.secret, out);
                   
                  //  printf("\niv encoded used : %s\n",  b64_encode(out, strlen(out)));
                  //  printf("\niv used : %s\n",  out);
                  //  printf("\nsecret used : %s\n", authPacket.apiPacket.secret);


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
                    if(1 == 1){
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


                    
                        writeToLog("send CONTENT_FILE start");
                        size_t octetsLus;

                        char *iv_base64encode =  getIVFromFile(conn, packetResponse.fileInfo.path, authPacket.apiPacket.api);
             //           printf("iv database : %s\n", iv_base64encode);
                       
                       
                        	/* +1 for the NULL terminator. */
                        int out_len = b64_decoded_size(iv_base64encode)+1;
                        char *out = malloc(out_len);
                        


                        if (!b64_decode(iv_base64encode, (unsigned char *)out, out_len)) {
                        }
                        out[out_len] = '\0';

           //             printf("decode iv        :%s\n", out);

                        FILE *input = fopen(filePath, "rb");
                         if (!input) {
                            handleErrors();
                        }

                        int len;
                        size_t plaintext_len = 0;
                        unsigned char ciphertext[CHUNK_SIZE_CRYPTED];
                        unsigned char plaintext[CHUNK_SIZE_PLAINTEXT];

                        packetResponse.flag = CONTENT_FILE;

                        while (1) {
                            size_t bytesRead = fread(ciphertext, 1, CHUNK_SIZE_CRYPTED, input);
                            if (bytesRead <= 0) {
                                // End of the encrypted file
                                break;
                            }
                            int size = decrypt(ciphertext, bytesRead, authPacket.apiPacket.secret, out, plaintext);
                            memcpy(packetResponse.fileContent.content, plaintext, size + 1);
                            packetResponse.fileContent.size = size;
                            SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                        }
                        
                        writeToLog("send CONTENT_FILE end");

                        fclose(fichier);

                        // envoi d'un flag pour signaler la fin du fichier
                        packetResponse.flag = FINISH_FILE;
                        SSL_write(ssl, &packetResponse, sizeof(packetResponse));
                        printf("envoi fini\n");
                        writeToLog("send FINISH_FILE");
                    }
                    
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
