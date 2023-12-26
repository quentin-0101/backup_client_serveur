#include "utils.h"

char* replace(const char *str, char last, char new) {
    char *result = (char *)malloc(strlen(str) + 1);

    // Check if memory allocation is successful
    if (result == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    // Copy the contents of str into result
    strcpy(result, str);

    for(size_t i = 0; i < strlen(result); i++){
        if(result[i] == last){
            result[i] = new;
        }
    }
    return result;
}

void deleteAfterLastSlash(char *path) {
    // Recherche du dernier '/'
    char *lastSlash = strrchr(path, '/');
    
    // Si un '/' est trouvé, tronquer la chaîne après ce point
    if (lastSlash != NULL) {
        *lastSlash = '\0';
    }
}

void createBackupDirectory() {
    struct stat st = {0};
    
    if (stat("/var/log/backup", &st) == -1) {
        if (mkdir("/var/log/backup", 0700) != 0) {
            fprintf(stderr, "Error: Unable to create the backup directory.\n");
            exit(EXIT_FAILURE);
        }
    }
}

void writeToLog(const char *message) {
    FILE *logFile;
    time_t currentTime;
    struct tm *timeInfo;
    char logFileName[50];  // Adjust the size based on your needs
    char timestamp[20];

    createBackupDirectory();  // Create the backup directory if it doesn't exist

    time(&currentTime);
    timeInfo = localtime(&currentTime);

    // Specify the full path for the log file in /var/log/backup
    strftime(logFileName, sizeof(logFileName), "/var/log/backup/logfile_%Y-%m-%d.txt", timeInfo);

    logFile = fopen(logFileName, "a");

    if (logFile == NULL) {
        fprintf(stderr, "Error: Unable to open the log file.\n");
        return;
    }

    strftime(timestamp, sizeof(timestamp), "[%H:%M:%S] ", timeInfo);

    fprintf(logFile, "%s%s\n", timestamp, message);

    fclose(logFile);
}


int isIPAllowed(const char *ip) {
    FILE *file = fopen("ip_allow.conf", "r");
    if (file == NULL) {
        perror("Erreur lors de l'ouverture du fichier ip_allow.conf");
        return 0;  // Assume denied on file error
    }

    char line[16 + 1];
    int allowed = 0;

    while (fgets(line, sizeof(line), file) != NULL) {
        // Remove newline character
        line[strcspn(line, "\n")] = '\0';

        if (strcmp(line, ip) == 0) {
            allowed = 1;
            break;
        }
    }

    fclose(file);

    return allowed;
}