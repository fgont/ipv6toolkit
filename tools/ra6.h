/*
 * Header file for the ra6 tool
 *
 */

#define LUI		long unsigned int

#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define ETH_HLEN	14		/* Total octets in header.	 */
#define ETH_DATA_LEN	1500		/* Max. octets in payload	 */
#define	ETHERTYPE_IPV6	0x86dd		/* IP protocol version 6 */
#define	ETHER_ADDR_LEN	ETH_ALEN	/* size of ethernet addr */
#define	ETHER_HDR_LEN	ETH_HLEN	/* total octets in header */

#define ETHER_ALLNODES_LINK_ADDR	"33:33:00:00:00:01"

#define	ETHERMTU	ETH_DATA_LEN

#define ETHER_ADDR_PLEN	18 /* Includes termination (null) byte */

#define	MIN_IPV6_HLEN		40
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

#define MAX_PREFIX_OPTION	256
#define	MAX_ROUTE_OPTION	MAX_PREFIX_OPTION
#define MAX_MTU_OPTION		MAX_PREFIX_OPTION
#define MAX_SLLA_OPTION		MAX_PREFIX_OPTION
#define	MAX_RDNSS_OPTION	MAX_PREFIX_OPTION
#define	MAX_RDNSS_OPT_ADDRS	127
#define DEFAULT_PREFIX_PREFERRED	0xffffffff
#define DEFAULT_PREFIX_VALID		0xffffffff
#define DEFAULT_CURHOP			255
#define DEFAULT_ROUTER_LIFETIME		9000
#define DEFAULT_ROUTER_REACHABLE	0Xffffffff
#define	DEFAULT_ROUTER_RETRANS		4000
#define DEFAULT_ROUTER_PREFERENCE	0x08
#define	DEFAULT_RDNSS_LIFETIME		9000
#define DEFAULT_ROUTE_OPT_LIFE		0xffffffff
#define DEFAULT_ROUTE_OPT_PREF		0x08
#define ALL_NODES_MULTICAST_ADDR	"FF02::1"
#define ALL_ROUTERS_MULTICAST_ADDR	"FF02::2"

/* Support for IPv6 extension headers */
#define FRAG_HDR_SIZE	8
#define MAX_DST_OPT_HDR		256
#define MAX_DST_OPT_U_HDR	MAX_DST_OPT_HDR
#define MAX_HBH_OPT_HDR		MAX_DST_OPT_HDR

/* Filter Constants */
#define MAX_BLOCK_SRC			50
#define MAX_BLOCK_DST			50
#define MAX_BLOCK_TARGET		50
#define MAX_BLOCK_LINK_SRC		50
#define MAX_BLOCK_LINK_DST		50

#define MAX_ACCEPT_SRC			50
#define MAX_ACCEPT_DST			50
#define MAX_ACCEPT_TARGET		50
#define MAX_ACCEPT_LINK_SRC		50
#define MAX_ACCEPT_LINK_DST		50

#define ACCEPTED			1
#define BLOCKED				0

/* Functions used with the libpcap functions */
#define PCAP_ICMPV6_RS_FILTER	"icmp6 and ip6[7]==255 and ip6[40]==133 and ip6[41]==0"
#define PCAP_SNAP_LEN		65535
#define	PCAP_TIMEOUT		1
#define PCAP_PROMISC		1
#define	PCAP_OPT		1
#ifndef PCAP_NETMASK_UNKNOWN
	#define PCAP_NETMASK_UNKNOWN	0xffffffff
#endif

struct ether_addr{
  u_int8_t a[ETHER_ADDR_LEN];
} __attribute__ ((__packed__));


struct	nd_opt_slla{
    u_int8_t	type;
    u_int8_t	length;
    u_int8_t	address[6];
} __attribute__ ((__packed__));

struct nd_opt_route_info_l{
    u_int8_t	nd_opt_ri_type;
    u_int8_t	nd_opt_ri_len;
    u_int8_t	nd_opt_ri_prefix_len;
    u_int8_t	nd_opt_ri_rsvd_pref_rsvd;
    u_int32_t	nd_opt_ri_lifetime;
    struct in6_addr	nd_opt_ri_prefix;
} __attribute__ ((__packed__));
    
struct nd_opt_rdnss_l{
    u_int8_t	nd_opt_rdnss_type;
    u_int8_t	nd_opt_rdnss_len;
    u_int16_t	nd_opt_rdnss_rsvd;
    u_int32_t	nd_opt_rdnss_lifetime;
    struct in6_addr	nd_opt_rdnss_addr[];
} __attribute__ ((__packed__));

struct ipv6pseudohdr{
    struct in6_addr srcaddr;
    struct in6_addr dstaddr;
    u_int32_t	len;
    u_int8_t zero[3];
    u_int8_t	nh;
} __attribute__ ((__packed__));


/* 10Mb/s ethernet header */
struct ether_header
{
  struct ether_addr dst;	/* destination eth addr	*/
  struct ether_addr src;	/* source ether addr	*/
  u_int16_t ether_type;		/* packet type ID field	*/
} __attribute__ ((__packed__));



/* These members of struct in6_addr are not defined in the KAME IPv6 implementation */

#if defined (__FreeBSD__) || defined (__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
    #ifndef s6_addr16
    #define s6_addr16	__u6_addr.__u6_addr16
    #endif

    #ifndef s6_addr8
    #define s6_addr8	__u6_addr.__u6_addr8
    #endif

    #ifndef s6_addr32
    #define s6_addr32	__u6_addr.__u6_addr32
    #endif
#endif
