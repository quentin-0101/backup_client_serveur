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