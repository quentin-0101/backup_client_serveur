#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

char* replace(const char *str, char last, char new);
void deleteAfterLastSlash(char *chaine);
void createBackupDirectory();
void writeToLog(const char *message);


#endif