#include "find.h"

#define TAILLE_CHAINE_DATE 80

void freeResults(char ***results, int count) {
    for (int i = 0; i < count; i++) {
        free((*results)[i]);
    }
    free(*results);
    *results = NULL;
}

/**
 * cette fonction va chercher certains fichiers dans un path précis (récursif). Elle stocke les résultats dans la variable results
*/
void searchFilesRecursive(const char *dirPath, char **extensions, int numExtensions, char ***results, int *count) {
    DIR *dir;
    struct dirent *entry;

    // Ouvre le répertoire
    if ((dir = opendir(dirPath)) == NULL) {
        perror("Erreur lors de l'ouverture du répertoire");
        exit(EXIT_FAILURE);
    }

    // Parcourt les fichiers du répertoire
    while ((entry = readdir(dir)) != NULL) {
        // Ignore les entrées "." et ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // Construit le chemin complet du fichier ou sous-répertoire
        char fullPath[PATH_MAX];
        snprintf(fullPath, sizeof(fullPath), "%s/%s", dirPath, entry->d_name);

        // Obtenir les informations détaillées sur le fichier
        struct stat fileStat;
        if (stat(fullPath, &fileStat) == -1) {
            perror("Erreur lors de l'obtention des informations sur le fichier");
            exit(EXIT_FAILURE);
        }

        // Vérifie si c'est un répertoire
        if (S_ISDIR(fileStat.st_mode)) {
            // Appelle récursivement la fonction pour le sous-répertoire
            searchFilesRecursive(fullPath, extensions, numExtensions, results, count);
        } else {
            // Vérifie si le fichier a l'une des extensions recherchées
            for (int i = 0; i < numExtensions; i++) {
                if (strstr(entry->d_name, extensions[i]) != NULL) {
                    // Incrémente le compteur
                    (*count)++;

                    // Alloue de l'espace pour stocker le chemin du fichier
                //    *results = realloc(*results, sizeof(char *) * (*count));
                    if (*results == NULL) {
                        perror("Erreur d'allocation de mémoire");
                        freeResults(results, *count - 1);
                        exit(EXIT_FAILURE);
                    }

                    // Alloue de l'espace pour stocker le chemin du fichier
                    (*results)[(*count) - 1] = strdup(fullPath);
                    if ((*results)[(*count) - 1] == NULL) {
                        perror("Erreur d'allocation de mémoire");
                        freeResults(results, *count - 1);
                        exit(EXIT_FAILURE);
                    }
                    break;  // Sort de la boucle si une extension correspond
                }
            }

            // Si aucune extension correspondante n'est trouvée, ne pas ajouter au résultat
            // No need for additional print statements here
        }
    }

    // Ferme le répertoire
    closedir(dir);
}

/**
 * cette fonction prend un path en paramètre, et retourne la date de modification du fichier
*/
char *getLastUpdated(const char *path) {
    static char lastUpdated[TAILLE_CHAINE_DATE];

    struct stat stat_info;

    if (stat(path, &stat_info) != 0) {
        perror("Erreur lors de la récupération des informations sur le fichier");
        return NULL;
    }

    // Utiliser strftime pour formater le timestamp dans la chaîne de caractères
    strftime(lastUpdated, TAILLE_CHAINE_DATE, "%d/%m/%Y %H:%M", localtime(&stat_info.st_mtime));

    return lastUpdated;
}


void findFiles(char *basePath, char **paths, int *numPaths, char **extensions, int numberExtension) {
  char path[1000];
  struct dirent *dp;
  DIR *dir = opendir(basePath);

  if (!dir)
      return;

  while ((dp = readdir(dir)) != NULL) {
      if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0) {
          strcpy(path, basePath);
          strcat(path, "/");
          strcat(path, dp->d_name);

          // Vérifie si l'entrée est un répertoire ou un fichier
          DIR *childDir = opendir(path);
          if (childDir) {
              // C'est un répertoire, donc nous devons le parcourir récursivement
              closedir(childDir);
              findFiles(path, paths, numPaths, extensions, numberExtension);
          } else {
              // C'est un fichier, donc nous ajoutons le chemin au tableau de chemins

                if(numberExtension > 0){
                    int verification = 0;
                    for(int i = 0; i < numberExtension; i++){
                        if (strstr(dp->d_name, extensions[i]) != NULL) {
                            verification = 1;
                            break;
                        }
                    }
                    if(verification == 1){
                        paths[(*numPaths)++] = strdup(path);
                    }
                } else {
                    paths[(*numPaths)++] = strdup(path);
                }
          }
      }
  }

  closedir(dir);
}
