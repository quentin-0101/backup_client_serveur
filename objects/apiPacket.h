#ifndef APIPACKET_H
#define APIPACKET_H

#include "../enum/flag.h"

typedef struct ApiPacket {
    char api[2048];
} __attribute__((packed)) ApiPacket;

#endif // PACKET_H