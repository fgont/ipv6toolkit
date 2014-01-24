#ifndef PCAP_WITH_BSDTYPES__H
#define PCAP_WITH_BSDTYPES__H

#define u_int unsigned int
#define u_char unsigned char
#define u_short unsigned short

#include <pcap.h>

#undef u_int
#undef u_char
#undef u_short

#endif
