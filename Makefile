# Makefile

# Nom des fichiers exécutables
SERVER_TARGET = server
CLIENT_TARGET = client
API_TARGET = apikey

# Dossier de compilation
BUILD_DIR = build

# Compilateur
CC = gcc

# Options de compilation
CFLAGS = -Wall -Wextra

# Bibliothèques nécessaires
LIBS_SERVER =  lib/find.c lib/utils.c lib/libbcrypt/bcrypt.a lib/readConfigFile.c -lssl -lcrypto -I/usr/include/postgresql -lpq lib/postgresql.c lib/base64.c
LIBS_CLIENT =   lib/readConfigFile.c lib/find.c lib/utils.c  -lssl -lcrypto
LIBS_API = -lssl -lcrypto -I/usr/include/postgresql -lpq lib/postgresql.c lib/utils.c lib/libbcrypt/bcrypt.a lib/readConfigFile.c

# Sources pour le serveur
SERVER_SRCS = server.c

# Sources pour le client
CLIENT_SRCS = client.c

API_SRCS = generateApiKey.c

# Chemin complet des fichiers exécutables dans le dossier build
SERVER_EXEC = $(BUILD_DIR)/$(SERVER_TARGET)
CLIENT_EXEC = $(BUILD_DIR)/$(CLIENT_TARGET)
API_EXEC = $(BUILD_DIR)/$(API_TARGET)

# Options de compilation pour les fichiers source du serveur et du client
SERVER_CFLAGS = $(CFLAGS) -DUSE_PACKED_STRUCT
CLIENT_CFLAGS = $(CFLAGS) -DUSE_PACKED_STRUCT

# Commande de compilation pour le serveur
$(SERVER_EXEC): $(SERVER_SRCS)
	$(CC) $(SERVER_CFLAGS) $(SERVER_SRCS) $(LIBS_SERVER) -o $(SERVER_EXEC)

# Commande de compilation pour le client
$(CLIENT_EXEC): $(CLIENT_SRCS)
	$(CC) $(CLIENT_CFLAGS) $(CLIENT_SRCS) $(LIBS_CLIENT) -o $(CLIENT_EXEC)

$(API_EXEC): $(API_SRCS)
	$(CC) $(API_SRCS) $(LIBS_API) -o $(API_EXEC)

# Cible pour nettoyer les fichiers générés
clean:
	rm -f $(SERVER_EXEC) $(CLIENT_EXEC) $(API_EXEC) 

# Cible par défaut
all: $(SERVER_EXEC) $(CLIENT_EXEC) $(API_EXEC) 
