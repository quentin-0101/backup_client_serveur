#ifndef RESTORE_H
#define RESTORE_H

#include "restorePath.h"

typedef struct Restore {
    int number;
    char extention[1024];
    struct RestorePath *restorePath;
} Restore;

#endif