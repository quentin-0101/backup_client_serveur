#ifndef RESTOREPATH_H
#define RESTOREPATH_H

typedef struct RestorePath {
    char path[1024];
    char slug[1024];
    char lastModification[1024];
} RestorePath;

#endif