/*
 * Header file for the scan6 tool
 *
 */

#define LUI		long unsigned int
#define LINE_BUFFER_SIZE	80
#define BUFFER_SIZE		65556

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
#define MIN_DST_OPT_HDR_SIZE	8
#define	SLLA_OPT_LEN		1
#define	TLLA_OPT_LEN		1
#define MAX_TLLA_OPTION		256
#define IFACE_LENGTH	255

/* Constants used with the multi_scan_local() function */
#define	PROBE_ICMP6_ECHO	1
#define PROBE_UNREC_OPT		2
#define PROBE_TCP		3
#define	LOCAL_SRC		1
#define GLOBAL_SRC		2

#define ICMPV6_ECHO_PAYLOAD_SIZE	56

#define MAX_PREFIXES_ONLINK		100
#define MAX_PREFIXES_AUTO		100
#define	MAX_IPV6_ENTRIES		65000
#define MAX_LOCAL_ADDRESSES		256

/* Constant for the host-scanning functions */
#define	PRINT_ETHER_ADDR		1
#define NOT_PRINT_ETHER_ADDR		0


#define	VALID_MAPPING			1
#define INVALID_MAPPING			0
 
#define ALL_NODES_MULTICAST_ADDR	"FF02::1"
#define ALL_ROUTERS_MULTICAST_ADDR	"FF02::2"
#define SOLICITED_NODE_MULTICAST_PREFIX "FF02:0:0:0:0:1:FF00::"

/* ICMPv6 Types/Codes not defined in some OSes */
#ifndef ICMP6_DST_UNREACH_FAILEDPOLICY
	#define ICMP6_DST_UNREACH_FAILEDPOLICY	5
#endif

#ifndef ICMP6_DST_UNREACH_REJECTROUTE
	#define ICMP6_DST_UNREACH_REJECTROUTE	6
#endif


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

/* Constants used with the libcap functions */
#define PCAP_SNAP_LEN			65535
#define PCAP_TCPV6_FILTER		"ip6 and tcp"
#define PCAP_UDPV6_FILTER		"ip6 and udp"
#define PCAP_ICMPV6_FILTER		"icmp6"
#define PCAP_ICMPV6_NA_FILTER		"icmp6 and ip6[7]==255 and ip6[40]==136 and ip6[41]==0"
#define PCAP_ICMPV6_RANS_FILTER		"icmp6 and ip6[7]==255 and ((ip6[40]==134 and ip6[41]==0) or (ip6[40]==135 and ip6[41]==0))"
#define PCAP_ICMPV6_ERNS_FILTER		"icmp6 and ((ip6[40]==129 and ip6[41]==0) or (ip6[40]==135 and ip6[41]==0))"
#define PCAP_ICMPV6_ERRORNS_FILTER	"icmp6 and ((ip6[40]==4) or (ip6[40]==135 and ip6[41]==0))"

#define PCAP_ICMPV6_ERQNSNA_FILTER	"icmp6 and ((ip6[40]==129 and ip6[41]==0) or ((ip6[40]==135 or ip6[40]==136) and ip6[41]==0 and ip6[7]==255))"
#define PCAP_ICMPV6_ERRORNSNA_FILTER	"icmp6 and ((ip6[40]==4) or ((ip6[7]==255 and ip6[41]==0) and (ip6[40]==135 or ip6[40]==136)))"
#define PCAP_TCP_NSNA_FILTER		"(ip6 and tcp) or (icmp6 and ip6[7]==255 and ip6[41]==0 and (ip6[40]==135 or ip6[40]==136))"
#define	PCAP_TIMEOUT			100
#define	PCAP_PROMISC			1
#define	PCAP_OPT			1
#ifndef PCAP_NETMASK_UNKNOWN
	#define PCAP_NETMASK_UNKNOWN	0xffffffff
#endif

/* Remote scans */
#define LOW_BYTE_1ST_WORD_UPPER		800
#define LOW_BYTE_2ND_WORD_UPPER		100
#define	MAX_IEEE_OUIS_LINE_SIZE		160
#define	OUI_HEX_STRING_SIZE		5
#define	MAX_IEEE_OUIS			1000
#define MAX_SCAN_ENTRIES		8192
#define	SELECT_TIMEOUT			4
#define MAX_RANGE_STR_LEN		79
#define MIN_INC_RANGE			1000
#define ND_RETRIES			0

/* Constants for config file processing */
#define MAX_LINE_SIZE			250
#define MAX_VAR_NAME_LEN		100
#define MAX_FILENAME_SIZE		250

struct ether_addr{
  u_int8_t a[ETHER_ADDR_LEN];
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


/* For DLT_NULL encapsulation */
struct dlt_null
{
  u_int32_t	family;	/* Protocol Family	*/
} __attribute__ ((__packed__));

/* IPv6 options

   Most stacks define "struct ip_opt" for this purpose. But ias has proved to be painful to use this 
   structure in Mac OS, since its definition seems to depend on the Xcode version, which is hard 
   (if at all possible) to check at compile time. As a workaround, we define our own data type for 
   IPv6 options
*/
struct ip6_option{
	uint8_t  ip6o_type;
	uint8_t  ip6o_len;
} __attribute__ ((__packed__));



struct host_entry{
	struct in6_addr		ip6;
	struct ether_addr	ether;
	unsigned char		flag;
	struct host_entry	*next;
};

struct host_list{
	struct host_entry	**host;
	unsigned int		nhosts;
	unsigned int		maxhosts;
};


struct prefix_entry{
	struct in6_addr		ip6;
	unsigned char		len;
};

struct prefix4_entry{
	struct in_addr		ip;
	unsigned char		len;
};

struct prefix_list{
	struct prefix_entry	**prefix;
	unsigned int		nprefix;
	unsigned int		maxprefix;
};


struct address_list{
	struct in6_addr		*addr;
	unsigned int		naddr;
	unsigned int		maxaddr;
};


/* Stores one remote target to scan */
struct scan_entry{
	struct in6_addr		start;
	struct in6_addr		end;
	struct in6_addr		cur;
};


/* Store the list of remote targets to scan */
struct scan_list{
	struct scan_entry	**target;
	unsigned int		ctarget;
	unsigned int		ntarget;
	unsigned int		maxtarget;
	unsigned int		inc;
};

struct iface_data{
	char			iface[IFACE_LENGTH];
	char			loopback_f;
	int			type;
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
	unsigned int		pending_write_f;
	void			*pending_write_data;
	unsigned int		pending_write_size;
	int			fd;
	pcap_t			*pd;
	fd_set			*rset;
	fd_set			*wset;
	fd_set			*eset;
	unsigned int		write_errors;
};


#if defined(__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
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

