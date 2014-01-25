#ifndef ETHER_ADDR__H
#define ETHER_ADDR__H

#include <inttypes.h>

#define ETH_ALEN        6          /* Octets in one ethernet addr */
#define ETH_HLEN        14         /* Total octets in header. */
#define ETH_DATA_LEN    1500       /* Max. octets in payload */
#define ETHERTYPE_IPV6  0x86dd     /* IP protocol version 6 */
#define ETHER_ADDR_LEN  ETH_ALEN   /* size of ethernet addr */
#define ETHER_HDR_LEN   ETH_HLEN   /* total octets in header */

#define ETHER_ADDR_PLEN 18                /* Includes termination byte */

#define ETHER_ALLNODES_LINK_ADDR    "33:33:00:00:00:01"
#define ETHER_ALLROUTERS_LINK_ADDR  "33:33:00:00:00:02"

struct ether_addr{
	uint8_t a[ETHER_ADDR_LEN];
} __attribute__ ((__packed__));

#endif
