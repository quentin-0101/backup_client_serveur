#ifndef FIND_H
#define FIND_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <time.h>
#include <openssl/md5.h>

#include "../objects/packet.h"


void searchFilesRecursive(const char *dirPath, char **extensions, int numExtensions, char ***results, int *count);
void readExtensionsFromFile(const char *filename, char ***extensions, int *numExtensions);
void freeExtensions(char **extensions, int numExtensions);
char *getLastUpdated(const char *nom_fichier);

void findFiles(char *basePath, char **paths, int *numPaths, char **extensions, int numberExtension) ;

#endif
