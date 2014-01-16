/* General constants */
#define SUCCESS	1
#define FAILURE 0
#define TRUE 1
#define FALSE 0

#define LUI		long unsigned int
#define	CHAR_CR			0x0d
#define CHAR_LF			0x0a
#define	DATA_BUFFER_LEN		1000
#define LINE_BUFFER_SIZE	80
#define MAX_STRING_SIZE			10 /* For limiting strncmp */
#define MAX_RANGE_STR_LEN		79 /* For function that check for address ranges in string */
#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define ETH_HLEN	14		/* Total octets in header.	 */
#define ETH_DATA_LEN	1500		/* Max. octets in payload	 */
#define	ETHERTYPE_IPV6	0x86dd		/* IP protocol version 6 */
#define	ETHER_ADDR_LEN	ETH_ALEN	/* size of ethernet addr */
#define	ETHER_HDR_LEN	ETH_HLEN	/* total octets in header */

#define ETHER_ADDR_PLEN	18		/* Includes termination byte */

#define ETHER_ALLNODES_LINK_ADDR	"33:33:00:00:00:01"
#define ETHER_ALLROUTERS_LINK_ADDR	"33:33:00:00:00:02"

#define	MIN_IPV6_HLEN			40
#define MIN_IPV6_MTU			1280
#define MIN_TCP_HLEN			20
#define MIN_UDP_HLEN			20
#define MIN_ICMP6_HLEN			8
#define MIN_HBH_LEN				8
#define	SLLA_OPT_LEN			1
#define	TLLA_OPT_LEN			1
#define MIN_DST_OPT_HDR_SIZE	8
#define MAX_SLLA_OPTION			100
#define MAX_TLLA_OPTION			256
#define IFACE_LENGTH			255
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

struct filters{
	/* Block Filters */
	struct in6_addr		*blocksrc;
	struct in6_addr		*blockdst;
	struct in6_addr		*blocktarget;

	u_int8_t		*blocksrclen;
	u_int8_t		*blockdstlen;
	u_int8_t		*blocktargetlen;

	struct ether_addr	*blocklinksrc;
	struct ether_addr	*blocklinkdst;

	unsigned int		nblocksrc;
	unsigned int		nblockdst;
	unsigned int		nblocktarget;
	unsigned int		nblocklinksrc;
	unsigned int		nblocklinkdst;

	/* Accept Filters */
	struct in6_addr		*acceptsrc;
	struct in6_addr		*acceptdst;
	struct in6_addr		*accepttarget;

	u_int8_t		*acceptsrclen;
	u_int8_t		*acceptdstlen;
	u_int8_t		*accepttargetlen;
	unsigned char	acceptfilters_f;

	struct ether_addr	*acceptlinksrc;
	struct ether_addr	*acceptlinkdst;

	unsigned int		nacceptsrc;
	unsigned int		nacceptdst;
	unsigned int		naccepttarget;
	unsigned int		nacceptlinksrc;
	unsigned int		nacceptlinkdst;
};

#define MAX_ACCEPT_SRC			50
#define MAX_ACCEPT_DST			50
#define MAX_ACCEPT_TARGET		50
#define MAX_ACCEPT_LINK_SRC		50
#define MAX_ACCEPT_LINK_DST		50

#define ACCEPTED				1
#define BLOCKED					0


/* Constants used with the libcap functions */
#define PCAP_IPV6_FILTER		"ip6"
#define PCAP_TCPV6_FILTER		"ip6 and tcp"
#define PCAP_UDPV6_FILTER		"ip6 and udp"
#define PCAP_ICMPV6_FILTER		"icmp6"
#define PCAP_ICMPV6_NA_FILTER	"icmp6 and ip6[7]==255 and ip6[40]==136 and ip6[41]==0"
#define PCAP_ICMPV6_NS_FILTER  "icmp6 and ((ip6[7]==255 and ip6[40]==135 and ip6[41]==0) or ip6[40]==4)"
#define PCAP_ICMPV6_RA_FILTER "icmp6 and ip6[7]==255 and ip6[40]==134 and ip6[41]==0"
#define PCAP_ICMPV6_RANS_FILTER	"icmp6 and ip6[7]==255 and ((ip6[40]==134 and ip6[41]==0) or (ip6[40]==135 and ip6[41]==0))"
#define PCAP_TCPIPV6_NS_FILTER	"ip6 and (tcp or (icmp6 and ip6[7]==255 and ip6[40]==135 and ip6[41]==0))"
#define PCAP_ICMPV6_NI_QUERY	"icmp6 and ip6[40]==139"
#define PCAP_ICMPV6_NI_REPLY	"icmp6 and ip6[40]==140"
#define PCAP_NOPACKETS_FILTER	"not ip and not ip6 and not arp"
#define PCAP_ICMPV6NSEXCEEDED_FILTER  "icmp6 and ((ip6[40]==3 and ip6[41]==1) or (ip6[40]==129 and ip6[41]==0))"
#define PCAP_ICMPV6_RS_FILTER	"icmp6 and ip6[7]==255 and ip6[40]==133 and ip6[41]==0"
#define PCAP_ICMPV6_NSECHOEXCEEDED_FILTER  "icmp6 and ((ip6[40]==3 and ip6[41]==1) or (ip6[40]==129 and ip6[41]==0) or (ip6[7]==255 and ip6[40]==135 and ip6[41]==0))"

/* Filter to receive Neighbor Solicitations and Fragmented packets */
#define PCAP_ICMPV6NSFRAG_FILTER "(ip6[7]==255 and icmp6 and ip6[40]==135 and ip6[41]==0) or (ip6 and ip6[6]==44)"
#define PCAP_NSTCP_FILTER "(ip6[7]==255 and icmp6 and ip6[40]==135 and ip6[41]==0) or (ip6 and ip6[6]==6)"


/* Filter to receive Neighbor Solicitations and Fragmented packets */
#define PCAP_ICMPV6NSFRAG_FILTER "(ip6[7]==255 and icmp6 and ip6[40]==135 and ip6[41]==0) or (ip6 and ip6[6]==44)"
/*
#define PCAP_ICMPV6NSEXCEEDED_FILTER  "icmp6 and ((ip6[7]==255 and ip6[40]==135 and ip6[41]==0) or (ip6[40]==3 and ip6[41]==1) or (ip6[40]==129 and ip6[41]==0))"
*/

#define PCAP_TCPIPV6_FILTER "ip6 and tcp"



/* Constants used for Router Discovery */
#define MAX_PREFIXES_ONLINK		100
#define MAX_PREFIXES_AUTO		100
#define MAX_LOCAL_ADDRESSES		256


/* Constants used for sending Router Advertisements */
#define MAX_PREFIX_OPTION	256
#define	MAX_ROUTE_OPTION	MAX_PREFIX_OPTION
#define MAX_MTU_OPTION		MAX_PREFIX_OPTION
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



/* For Fragment ID or Flow Label assessment */
#define ID_ASSESS_TIMEOUT		5
#define NSAMPLES				40
#define FIXED_ORIGIN			1
#define MULTI_ORIGIN			2


struct ether_addr{
  u_int8_t a[ETHER_ADDR_LEN];
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


typedef	u_int32_t tcp_seq;


#if defined(__linux__) || ( !defined(__FreeBSD__) && defined(__FreeBSD_kernel__))
/* Linux definition */

/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcp_hdr{
    u_int16_t th_sport;		/* source port */
    u_int16_t th_dport;		/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4;		/* (unused) */
    u_int8_t th_off:4;		/* data offset */
#  endif
#  if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4;		/* data offset */
    u_int8_t th_x2:4;		/* (unused) */
#  endif
    u_int8_t th_flags;
#  define TH_FIN	0x01
#  define TH_SYN	0x02
#  define TH_RST	0x04
#  define TH_PUSH	0x08
#  define TH_ACK	0x10
#  define TH_URG	0x20
    u_int16_t th_win;		/* window */
    u_int16_t th_sum;		/* checksum */
    u_int16_t th_urp;		/* urgent pointer */
} __attribute__ ((__packed__));
#elif defined(__APPLE__)
/* Mac OS definition */

/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcp_hdr{
    u_int16_t th_sport;		/* source port */
    u_int16_t th_dport;		/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
#  if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    u_int8_t th_x2:4;		/* (unused) */
    u_int8_t th_off:4;		/* data offset */
#  endif
#  if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    u_int8_t th_off:4;		/* data offset */
    u_int8_t th_x2:4;		/* (unused) */
#  endif
    u_int8_t th_flags;
#  define TH_FIN	0x01
#  define TH_SYN	0x02
#  define TH_RST	0x04
#  define TH_PUSH	0x08
#  define TH_ACK	0x10
#  define TH_URG	0x20
    u_int16_t th_win;		/* window */
    u_int16_t th_sum;		/* checksum */
    u_int16_t th_urp;		/* urgent pointer */
} __attribute__ ((__packed__));
#else
/* BSD definition */

/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcp_hdr {
	u_int16_t th_sport;		/* source port */
	u_int16_t th_dport;		/* destination port */
	tcp_seq	  th_seq;		/* sequence number */
	tcp_seq	  th_ack;		/* acknowledgement number */
#if _BYTE_ORDER == _LITTLE_ENDIAN
	u_int32_t th_x2:4,		/* (unused) */
		  th_off:4;		/* data offset */
#endif
#if _BYTE_ORDER == _BIG_ENDIAN
	u_int32_t th_off:4,		/* data offset */
		  th_x2:4;		/* (unused) */
#endif
	u_int8_t  th_flags;
#define	TH_FIN	  0x01
#define	TH_SYN	  0x02
#define	TH_RST	  0x04
#define	TH_PUSH	  0x08
#define	TH_ACK	  0x10
#define	TH_URG	  0x20
#define	TH_ECE	  0x40
#define	TH_CWR	  0x80
	u_int16_t th_win;			/* window */
	u_int16_t th_sum;			/* checksum */
	u_int16_t th_urp;			/* urgent pointer */
};
#endif

struct udp_hdr{
  u_int16_t uh_sport;		/* source port */
  u_int16_t uh_dport;		/* destination port */
  u_int16_t uh_ulen;		/* udp length */
  u_int16_t uh_sum;		/* udp checksum */
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

struct prefix4_entry{
	struct in_addr		ip;
	unsigned char		len;
};

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

struct address_list{
	struct in6_addr		*addr;
	unsigned int		naddr;
	unsigned int		maxaddr;
};


#define MAX_IFACES 10
struct iface_entry{
	int					ifindex;
	char				iface[IFACE_LENGTH];	
	struct ether_addr	ether;
	struct prefix_list	ip6_global;
	struct prefix_list  ip6_local;
	int					flags;	
};

struct iface_list{
	struct iface_entry	*ifaces;
	unsigned int		nifaces;
	unsigned int		maxifaces;
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


/* Names (DNS, NI) related constants and definitions */
#define MAX_DOMAIN_LEN			512
#define MAX_DNS_LABELS			50
#define MAX_DNS_CLABELS         5


/* ICMPv6 Types/Codes not defined in some OSes */
#ifndef ICMP6_DST_UNREACH_FAILEDPOLICY
	#define ICMP6_DST_UNREACH_FAILEDPOLICY	5
#endif

#ifndef ICMP6_DST_UNREACH_REJECTROUTE
	#define ICMP6_DST_UNREACH_REJECTROUTE	6
#endif


#if !(defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__))
/* Definitions for Linux */

	#define ICMP6_NI_QUERY			139	/* node information request */
	#define ICMP6_NI_REPLY			140	/* node information reply */
	/*
	 * icmp6 namelookup
	 */

	struct icmp6_namelookup {
		struct icmp6_hdr 	icmp6_nl_hdr;
		u_int8_t	icmp6_nl_nonce[8];
		int32_t		icmp6_nl_ttl;
	#if 0
		u_int8_t	icmp6_nl_len;
		u_int8_t	icmp6_nl_name[3];
	#endif
		/* could be followed by options */
	} __attribute__ ((__packed__));

	/*
	 * icmp6 node information
	 */
	struct icmp6_nodeinfo {
		struct icmp6_hdr icmp6_ni_hdr;
		u_int8_t icmp6_ni_nonce[8];
		/* could be followed by reply data */
	} __attribute__ ((__packed__));

	#define ni_type		icmp6_ni_hdr.icmp6_type
	#define ni_code		icmp6_ni_hdr.icmp6_code
	#define ni_cksum	icmp6_ni_hdr.icmp6_cksum
	#define ni_qtype	icmp6_ni_hdr.icmp6_data16[0]
	#define ni_flags	icmp6_ni_hdr.icmp6_data16[1]

	#define NI_QTYPE_NOOP		0 /* NOOP  */
	#define NI_QTYPE_SUPTYPES	1 /* Supported Qtypes */
	#define NI_QTYPE_FQDN		2 /* FQDN (draft 04) */
	#define NI_QTYPE_DNSNAME	2 /* DNS Name */
	#define NI_QTYPE_NODEADDR	3 /* Node Addresses */
	#define NI_QTYPE_IPV4ADDR	4 /* IPv4 Addresses */

	#if __BYTE_ORDER == __BIG_ENDIAN
		#define NI_SUPTYPE_FLAG_COMPRESS	0x1
		#define NI_FQDN_FLAG_VALIDTTL		0x1
	#elif __BYTE_ORDER == __LITTLE_ENDIAN
		#define NI_SUPTYPE_FLAG_COMPRESS	0x0100
		#define NI_FQDN_FLAG_VALIDTTL		0x0100
	#endif

	#if __BYTE_ORDER == __BIG_ENDIAN
		#define NI_NODEADDR_FLAG_TRUNCATE	0x1
		#define NI_NODEADDR_FLAG_ALL		0x2
		#define NI_NODEADDR_FLAG_COMPAT		0x4
		#define NI_NODEADDR_FLAG_LINKLOCAL	0x8
		#define NI_NODEADDR_FLAG_SITELOCAL	0x10
		#define NI_NODEADDR_FLAG_GLOBAL		0x20
		#define NI_NODEADDR_FLAG_ANYCAST	0x40 /* just experimental. not in spec */
	#elif __BYTE_ORDER == __LITTLE_ENDIAN
		#define NI_NODEADDR_FLAG_TRUNCATE	0x0100
		#define NI_NODEADDR_FLAG_ALL		0x0200
		#define NI_NODEADDR_FLAG_COMPAT		0x0400
		#define NI_NODEADDR_FLAG_LINKLOCAL	0x0800
		#define NI_NODEADDR_FLAG_SITELOCAL	0x1000
		#define NI_NODEADDR_FLAG_GLOBAL		0x2000
		#define NI_NODEADDR_FLAG_ANYCAST	0x4000 /* just experimental. not in spec */
	#endif

	struct ni_reply_fqdn {
		u_int32_t ni_fqdn_ttl;	/* TTL */
		u_int8_t ni_fqdn_namelen; /* length in octets of the FQDN */
		u_int8_t ni_fqdn_name[3]; /* XXX: alignment */
	} __attribute__ ((__packed__));

#endif


struct ni_reply_ip6 {
	u_int32_t ni_ip6_ttl;	/* TTL */
	struct in6_addr ip6; /* IPv6 address */
} __attribute__ ((__packed__));


struct ni_reply_ip {
	u_int32_t ni_ip_ttl;	/* TTL */
	struct in_addr ip; /* IPv6 address */
} __attribute__ ((__packed__));

struct ni_reply_name {
	u_int32_t ni_name_ttl;	/* TTL */
	unsigned char	ni_name_name; /* IPv6 address */
} __attribute__ ((__packed__));


/* ICMPv6 Types/Codes not defined in some OSes */
#ifndef ICMP6_DST_UNREACH_FAILEDPOLICY
	#define ICMP6_DST_UNREACH_FAILEDPOLICY	5
#endif

#ifndef ICMP6_DST_UNREACH_REJECTROUTE
	#define ICMP6_DST_UNREACH_REJECTROUTE	6
#endif


struct packet{
	unsigned char	*link;
	unsigned char	*ipv6;
	unsigned char	*upper;
	unsigned long	maxsize;
};

struct iface_data{
	char				iface[IFACE_LENGTH];
	unsigned char		iface_f;
	pcap_t				*pfd;
	int					ifindex;
	unsigned char		ifindex_f;
	struct iface_list	iflist;
	int					type;
	int					flags;
	int					fd;
	unsigned int		pending_write_f;
	void				*pending_write_data;
	unsigned int		pending_write_size;
	fd_set				*rset;
	fd_set				*wset;
	fd_set				*eset;
	unsigned int		write_errors;
	struct ether_addr	ether;
	unsigned int		ether_flag;
	unsigned int		linkhsize;
	unsigned int		max_packet_size;
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
	struct ether_addr	hsrcaddr;
	unsigned int		hsrcaddr_f;
	struct ether_addr	hdstaddr;
	unsigned int		hdstaddr_f;
	struct in6_addr		srcaddr;
	unsigned int		srcaddr_f;
	unsigned char		srcpreflen;
	unsigned char		srcprefix_f;
	struct in6_addr		dstaddr;
	unsigned int		dstaddr_f;
	unsigned int		verbose_f;
	unsigned char		listen_f;
	char				loopback_f;

	/* XXX
	   The next four variables are kind of a duplicate of router_ip6 and router_ether above.
       May remove them at some point
     */

	struct in6_addr		nhaddr;
	unsigned char		nhaddr_f;
	struct ether_addr	nhhaddr;
	unsigned char		nhhaddr_f;
	int					nhifindex;
	unsigned char		nhifindex_f;
	char				nhiface[IFACE_LENGTH];
	unsigned char		nh_f;
};


#ifdef __linux__
/* Consulting the routing table */
#define MAX_NLPAYLOAD 1024
#else
#define MAX_RTPAYLOAD 1024
#endif



struct next_hop{
	struct in6_addr	srcaddr;
	unsigned char	srcaddr_f;
	struct in6_addr	dstaddr;
	unsigned char	dstaddr_f;
	struct in6_addr	nhaddr;
	unsigned char	nhaddr_f;
	struct ether_addr nhhaddr;
	unsigned char	nhhaddr_f;
	int				ifindex;
	unsigned char	ifindex_f;
};


/* Flags that specify what the load_dst_and_pcap() function should do */
#define LOAD_PCAP_ONLY		0x01
#define	LOAD_SRC_NXT_HOP	0x02


#ifndef SA_SIZE
#define SA_SIZE(sa)                                            \
        (  (!(sa) || ((struct sockaddr *)(sa))->sa_len == 0) ?  \
           sizeof(long)         :                               \
           1 + ( (((struct sockaddr *)(sa))->sa_len - 1) | (sizeof(long) - 1) ) )
#endif

#ifndef SA_NEXT
#define SA_NEXT(sa) (sa= (struct sockaddr *) ( (char *) sa + SA_SIZE(sa)))
#endif

int					address_contains_ranges(char *);
void				change_endianness(u_int32_t *, unsigned int);
u_int16_t			dec_to_hex(u_int16_t);
int					dns_decode(unsigned char *, unsigned int, unsigned char *, char *, unsigned int, unsigned char **);
int					dns_str2wire(char *, unsigned int, char *, unsigned int);
struct ether_addr	ether_multicast(const struct in6_addr *);
int					ether_ntop(const struct ether_addr *, char *, size_t);
int					ether_pton(const char *, struct ether_addr *, unsigned int);
void				ether_to_ipv6_linklocal(struct ether_addr *etheraddr, struct in6_addr *ipv6addr);
void 				*find_iface_by_index(struct iface_list *, int);
void				*find_iface_by_name(struct iface_list *, char *);
int					find_ipv6_router(pcap_t *, struct ether_addr *, struct in6_addr *, struct ether_addr *, struct in6_addr *);
int					find_ipv6_router_full(pcap_t *, struct iface_data *);
struct iface_entry  *find_matching_address(struct iface_data *, struct iface_list *, struct in6_addr *, struct in6_addr *);
void				generate_slaac_address(struct in6_addr *, struct ether_addr *, struct in6_addr *);
int					get_if_addrs(struct iface_data *);
int					get_local_addrs(struct iface_data *);
int					inc_sdev(u_int32_t *, unsigned int, u_int32_t *, double *);
int					init_iface_data(struct iface_data *);
int					init_filters(struct filters *);
u_int16_t			in_chksum(void *, void *, size_t, u_int8_t);
int					insert_pad_opt(unsigned char *ptrhdr, const unsigned char *, unsigned int);
int					ipv6_to_ether(pcap_t *, struct iface_data *, struct in6_addr *, struct ether_addr *);
unsigned int		ip6_longest_match(struct in6_addr *, struct in6_addr *);
int					is_ip6_in_address_list(struct prefix_list *, struct in6_addr *);
int					is_ip6_in_iface_entry(struct iface_list *, int, struct in6_addr *);
int					is_ip6_in_list(struct in6_addr *, struct host_list *);
int					is_ip6_in_prefix_list(struct in6_addr *, struct prefix_list *);
int					is_eq_in6_addr(struct in6_addr *, struct in6_addr *);
int					is_time_elapsed(struct timeval *, struct timeval *, unsigned long);
int					keyval(char *, unsigned int, char **, char **);
int					load_dst_and_pcap(struct iface_data *, unsigned int);
unsigned int		match_ether(struct ether_addr *, unsigned int, struct ether_addr *);
unsigned int		match_ipv6(struct in6_addr *, u_int8_t *, unsigned int, struct in6_addr *);
int 				match_ipv6_to_prefixes(struct in6_addr *, struct prefix_list *);
void				print_filters(struct iface_data *, struct filters *);
void				print_filter_result(struct iface_data *, const u_char *, unsigned char);
int					print_local_addrs(struct iface_data *);
void				randomize_ether_addr(struct ether_addr *);
void				randomize_ipv6_addr(struct in6_addr *, struct in6_addr *, u_int8_t);
int					read_ipv6_address(char *, unsigned int, struct in6_addr *);
int					read_prefix(char *, unsigned int, char **);
void				release_privileges(void);
void				sanitize_ipv4_prefix(struct prefix4_entry *);
void				sanitize_ipv6_prefix(struct in6_addr *, u_int8_t);
int 				send_neighbor_advert(struct iface_data *, pcap_t *,  const u_char *);
int					send_neighbor_solicit(struct iface_data *, struct in6_addr *);
int					sel_src_addr(struct iface_data *);
struct in6_addr *	sel_src_addr_ra(struct iface_data *, struct in6_addr *);
int					sel_next_hop(struct iface_data *);
int					sel_next_hop_ra(struct iface_data *);
void				sig_alarm(int);
struct in6_addr		solicited_node(const struct in6_addr *);
int					string_escapes(char *, unsigned int *, unsigned int);
size_t				Strnlen(const char *, size_t);


