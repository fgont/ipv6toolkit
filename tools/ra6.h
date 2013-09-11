/*
 * Header file for the ra6 tool
 *
 */


#define	MAX_IPV6_PAYLOAD	65535
#define	MTU_OPT_LEN		1
#define	SLLA_OPT_LEN		1
#define	PREFIX_OPT_LEN		4

#ifndef ND_OPT_ROUTE_INFORMATION
#define ND_OPT_ROUTE_INFORMATION 24
#endif

#ifndef ND_OPT_RDNSS
#define ND_OPT_RDNSS 		25
#endif

#ifndef ND_OPT_PI_FLAG_RADDR
#define ND_OPT_PI_FLAG_RADDR	0x20
#endif

#define MAX_ROUTE_OPT_LEN 0x03

#ifndef ND_RA_FLAG_ND_PROXY
#define ND_RA_FLAG_ND_PROXY	0x04
#endif

#ifndef ND_RA_FLAG_HOME_AGENT
#define ND_RA_FLAG_HOME_AGENT	0x20
#endif

#define IFACE_LENGTH	255




