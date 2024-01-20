#ifndef FILECONTENT_H
#define FILECONTENT_H

#define BLOCK_CONTENT_SIZE 4096

typedef struct FileContent {
    char content[BLOCK_CONTENT_SIZE];
    int size;
} __attribute__((packed)) FileContent;

#endif