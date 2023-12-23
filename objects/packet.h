#ifndef PACKET_H
#define PACKET_H

#include "../enum/flag.h"
#include "fileInfo.h"
#include "fileContent.h"

typedef struct Packet {
    enum Flag flag;
    FileInfo fileInfo;
    FileContent fileContent;
} __attribute__((packed)) Packet;

#endif // PACKET_H