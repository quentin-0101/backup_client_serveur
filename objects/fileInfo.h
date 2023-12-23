#ifndef FILEINFO_H
#define FILEINFO_H

typedef struct FileInfo {
    char path[2048];
    char slug[2048];
    char lastModification[512];
} __attribute__((packed)) FileInfo;

#endif