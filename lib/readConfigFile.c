#include "readConfigFile.h"


int readDatabaseConfig(const char *filename, DatabaseConfig *config) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Erreur lors de l'ouverture du fichier");
        return 0;
    }

    char key[MAX_LINE_LENGTH];
    char value[MAX_LINE_LENGTH];

    while (fscanf(file, "%2047[^=]=%2047[^\n]\n", key, value) == 2) {
        if (strcmp(key, "HOST") == 0) {
            strcpy(config->host, value);
        } else if (strcmp(key, "PORT") == 0) {
            config->port = atoi(value);
        } else if (strcmp(key, "USER") == 0) {
            strcpy(config->user, value);
        } else if (strcmp(key, "PASSWORD") == 0) {
            strcpy(config->password, value);
        } else if (strcmp(key, "DBNAME") == 0) {
            strcpy(config->dbname, value);
        }
    }

    fclose(file);
    return 1;
}

int readClientCredentials(const char *filename, ApiPacket *apiPacket){
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Erreur lors de l'ouverture du fichier");
        return 0;
    }

    char key[MAX_LINE_LENGTH];
    char value[MAX_LINE_LENGTH];

    while (fscanf(file, "%2047[^=]=%2047[^\n]\n", key, value) == 2) {
        if (strcmp(key, "API") == 0) {
            strcpy(apiPacket->api, value);
        } else if (strcmp(key, "SECRET") == 0) {
            strcpy(apiPacket->secret, value);
        }
    }

    fclose(file);
    return 1;
}

const char* buildDatabaseConnectionString(const struct DatabaseConfig *config) {
    static char conninfo[MAX_LINE_LENGTH * 5]; // Assez grand pour contenir la chaîne de connexion
    snprintf(conninfo, sizeof(conninfo), "dbname=%s user=%s password=%s host=%s port=%d",
             config->dbname, config->user, config->password, config->host, config->port);
    return conninfo;
}

int readConfigClientFile(const char *filename, ConfigClient *config) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Erreur lors de l'ouverture du fichier de configuration");
        exit(EXIT_FAILURE);
    }

    char *line = NULL;
    size_t len = 0;
    size_t read;

    while ((read = getline(&line, &len, file)) != -1) {
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "\n");

        if (key != NULL && value != NULL) {
            if (strcmp(key, "REPOSITORY") == 0) {
                char *token = strtok(value, ",");
                int count = 0;

                while (token != NULL) {
                    config->repositories = realloc(config->repositories, (count + 1) * sizeof(char *));
                    config->repositories[count] = strdup(token);
                    token = strtok(NULL, ",");
                    count++;
                }

                config->numRepositories = count;
            } else if (strcmp(key, "EXTENSION") == 0) {
                char *token = strtok(value, ",");
                int count = 0;

                while (token != NULL) {
                    config->extensions = realloc(config->extensions, (count + 1) * sizeof(char *));
                    config->extensions[count] = strdup(token);
                    token = strtok(NULL, ",");
                    count++;
                }

                config->numExtensions = count;
            } else if (strcmp(key, "SERVER_IP") == 0) {
                strcpy(config->serverIP, value);
            } else if (strcmp(key, "SERVER_PORT") == 0) {
                config->port = atoi(value);
            } else if (strcmp(key, "MODE") == 0) {
                strcpy(config->action, value);
            } 
        }
    }

    free(line);
    fclose(file);
    return 1;
}

void freeConfigClient(ConfigClient *config) {
    for (int i = 0; i < config->numRepositories; i++) {
        free(config->repositories[i]);
    }
    free(config->repositories);

    for (int i = 0; i < config->numExtensions; i++) {
        free(config->extensions[i]);
    }
    free(config->extensions);
}