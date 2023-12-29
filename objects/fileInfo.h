#ifndef FILEINFO_H
#define FILEINFO_H

#include <stdint.h>

typedef struct FileInfo {
    char path[2048];
    char slug[2048];
    char lastModification[512];
    char iv[2048];
} __attribute__((packed)) FileInfo;

#endif