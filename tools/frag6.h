/*
 * Header file for the frag6 tool
 *
 */

#define LUI		long unsigned int

#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define ETH_HLEN	14		/* Total octets in header.	 */
#define ETH_DATA_LEN	1500		/* Max. octets in payload	 */
#define	ETHERTYPE_IPV6	0x86dd		/* IP protocol version 6 */
#define	ETHER_ADDR_LEN	ETH_ALEN	/* size of ethernet addr */
#define	ETHER_HDR_LEN	ETH_HLEN	/* total octets in header */

#define ETHER_ADDR_PLEN	18		/* Includes termination byte */

#define ETHER_ALLNODES_LINK_ADDR	"33:33:00:00:00:01"
#define ETHER_ALLROUTERS_LINK_ADDR	"33:33:00:00:00:02"

#define	MIN_IPV6_HLEN		40
#define MIN_IPV6_MTU		1280
#define MIN_TCP_HLEN		20
#define MIN_UDP_HLEN		20
#define MIN_ICMP6_HLEN		8
#define	SLLA_OPT_LEN		1
#define	TLLA_OPT_LEN		1
#define MAX_TLLA_OPTION		256
#define IFACE_LENGTH	255
#define ALL_NODES_MULTICAST_ADDR	"FF02::1"
#define ALL_ROUTERS_MULTICAST_ADDR	"FF02::2"
#define SOLICITED_NODE_MULTICAST_PREFIX "FF02:0:0:0:0:1:FF00::"


/* Support for IPv6 extension headers */
#define FRAG_HDR_SIZE		8
#define	MAX_IPV6_PAYLOAD	65535
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

#define	QUERY_TIMEOUT			70

#define MIN_HBH_LEN			8

/* For discovering the fragment reassembly policy */
#define	TIMED_OUT			1
#define FIRST_COPY			2
#define LAST_COPY			3
#define TIME_EXCEEDED			4
#define UNKNOWN_COPY			5
#define MIN_FRAG_SIZE			104


/* Constants used with the libpcap functions */
#define PCAP_ICMPV6_NA_FILTER "icmp6 and ip6[7]==255 and ip6[40]==136 and ip6[41]==0"


#define PCAP_ICMPV6NSEXCEEDED_FILTER  "icmp6 and ((ip6[40]==3 and ip6[41]==1) or (ip6[40]==129 and ip6[41]==0))"

#define PCAP_ICMPV6_NSECHOEXCEEDED_FILTER  "icmp6 and ((ip6[40]==3 and ip6[41]==1) or (ip6[40]==129 and ip6[41]==0) or (ip6[7]==255 and ip6[40]==135 and ip6[41]==0))"

/* Filter to receive Neighbor Solicitations and Fragmented packets */
#define PCAP_ICMPV6NSFRAG_FILTER "(ip6[7]==255 and icmp6 and ip6[40]==135 and ip6[41]==0) or (ip6 and ip6[6]==44)"
/*
#define PCAP_ICMPV6NSEXCEEDED_FILTER  "icmp6 and ((ip6[7]==255 and ip6[40]==135 and ip6[41]==0) or (ip6[40]==3 and ip6[41]==1) or (ip6[40]==129 and ip6[41]==0))"
*/
#define PCAP_ICMPV6_RANS_FILTER		"icmp6 and ip6[7]==255 and ((ip6[40]==134 and ip6[41]==0) or (ip6[40]==135 and ip6[41]==0))"
#define PCAP_ICMPV6_NA_FILTER "icmp6 and ip6[7]==255 and ip6[40]==136 and ip6[41]==0"
#define PCAP_TCPIPV6_FILTER "ip6 and tcp"
#define PCAP_IPV6_FILTER "ip6"

/* Constants used for Router Discovery */
#define MAX_PREFIXES_ONLINK		100
#define MAX_PREFIXES_AUTO		100
#define MAX_LOCAL_ADDRESSES		256


/* Constants for the send_fragment() function */
#define	FIRST_FRAGMENT			1
#define LAST_FRAGMENT			2
#define ATOMIC_FRAGMENT			3
#define MIDDLE_FRAGMENT			4
#define TIMESTAMP				1
#define NO_TIMESTAMP			0

#define MAX_FRAG_OFFSET			0xfff8

/* For Fragment ID assessment */
#define ID_ASSESS_TIMEOUT		(NBATCHES+4)
#define NBATCHES				3
#define NSAMPLES				40
#define FIXED_ORIGIN			1
#define MULTI_ORIGIN			2

/* Size of the fragmentation buffer (including link-layer headers) for FID probes */
#define FRAG_BUFFER_SIZE		(MIN_IPV6_HLEN + FRAG_HDR_SIZE + MAX_IPV6_PAYLOAD)

/* For limiting strncmp */
#define MAX_STRING_SIZE			10

struct ether_addr{
  u_int8_t a[ETHER_ADDR_LEN];
} __attribute__ ((__packed__));

/* For DLT_NULL encapsulation */
struct dlt_null
{
  u_int32_t	family;	/* Protocol Family	*/
} __attribute__ ((__packed__));


struct	nd_opt_slla{
    u_int8_t	type;
    u_int8_t	length;
    u_int8_t	address[6];
} __attribute__ ((__packed__));

struct	nd_opt_tlla{
    u_int8_t	type;
    u_int8_t	length;
    u_int8_t	address[6];
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


struct prefix_entry{
	struct in6_addr		ip6;
	unsigned char		len;
};

struct prefix_list{
	struct prefix_entry	**prefix;
	unsigned int		nprefix;
	unsigned int		maxprefix;
};

struct iface_data{
	char			iface[IFACE_LENGTH];
	int			type;
	int			flags;
	int			fd;
	pcap_t			*pd;
	struct ether_addr	ether;
	unsigned int		ether_flag;
	struct in6_addr		ip6_local;
	unsigned int		ip6_local_flag;
	struct prefix_list	ip6_global;
	unsigned int		ip6_global_flag;
	struct in6_addr		router_ip6;
	struct ether_addr	router_ether;
	struct prefix_list	prefix_ac;
	struct prefix_list	prefix_ol;
	unsigned int		local_retrans;
	unsigned int		local_timeout;
	unsigned int		mtu;
};

#if defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
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


/* This causes Linux to use the BSD definition of the TCP and UDP header fields */
#ifndef __FAVOR_BSD
	#define __FAVOR_BSD
#endif

