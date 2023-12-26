#ifndef PACKET_H
#define PACKET_H

#include "../enum/flag.h"
#include "fileInfo.h"
#include "fileContent.h"
#include "apiPacket.h"

typedef struct Packet {
    enum Flag flag;
    FileInfo fileInfo;
    FileContent fileContent;
    ApiPacket apiPacket;
} __attribute__((packed)) Packet;

#endif // PACKET_H