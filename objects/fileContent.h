#ifndef FILECONTENT_H
#define FILECONTENT_H

#define SIZE_BLOCK_FILE 2048

typedef struct FileContent {
    char content[2048];
    int size;
} __attribute__((packed)) FileContent;

#endif