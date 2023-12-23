# Makefile

# Nom des fichiers exécutables
SERVER_TARGET = server
CLIENT_TARGET = client

# Dossier de compilation
BUILD_DIR = build

# Compilateur
CC = gcc

# Options de compilation
CFLAGS = -Wall -Wextra

# Bibliothèques nécessaires
LIBS_SERVER = -lssl -lcrypto -lsqlite3 lib/find.c lib/sqlite.c lib/utils.c
LIBS_CLIENT =  -lssl -lcrypto lib/find.c lib/utils.c

# Sources pour le serveur
SERVER_SRCS = server.c

# Sources pour le client
CLIENT_SRCS = client.c

# Chemin complet des fichiers exécutables dans le dossier build
SERVER_EXEC = $(BUILD_DIR)/$(SERVER_TARGET)
CLIENT_EXEC = $(BUILD_DIR)/$(CLIENT_TARGET)

# Options de compilation pour les fichiers source du serveur et du client
SERVER_CFLAGS = $(CFLAGS) -DUSE_PACKED_STRUCT
CLIENT_CFLAGS = $(CFLAGS) -DUSE_PACKED_STRUCT

# Commande de compilation pour le serveur
$(SERVER_EXEC): $(SERVER_SRCS)
	$(CC) $(SERVER_CFLAGS) $(SERVER_SRCS) $(LIBS_SERVER) -o $(SERVER_EXEC)

# Commande de compilation pour le client
$(CLIENT_EXEC): $(CLIENT_SRCS)
	$(CC) $(CLIENT_CFLAGS) $(CLIENT_SRCS) $(LIBS_CLIENT) -o $(CLIENT_EXEC)

# Cible pour nettoyer les fichiers générés
clean:
	rm -f $(SERVER_EXEC) $(CLIENT_EXEC)

# Cible par défaut
all: $(SERVER_EXEC) $(CLIENT_EXEC)
