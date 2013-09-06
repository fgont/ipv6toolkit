#define LUI		long unsigned int
#define	CHAR_CR			0x0d
#define CHAR_LF			0x0a
#define	DATA_BUFFER_LEN		1000
#define LINE_BUFFER_SIZE	80
#define MAX_STRING_SIZE			10 /* For limiting strncmp */
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
#define MIN_HBH_LEN			8
#define	SLLA_OPT_LEN		1
#define	TLLA_OPT_LEN		1
#define MAX_SLLA_OPTION		100
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
#define PCAP_ICMPV6_NA_FILTER	"icmp6 and ip6[7]==255 and ip6[40]==136 and ip6[41]==0"
#define PCAP_ICMPV6_RANS_FILTER	"icmp6 and ip6[7]==255 and ((ip6[40]==134 and ip6[41]==0) or (ip6[40]==135 and ip6[41]==0))"
#define PCAP_ICMPV6_NA_FILTER	"icmp6 and ip6[7]==255 and ip6[40]==136 and ip6[41]==0"
#define PCAP_TCPIPV6_NS_FILTER	"ip6 and (tcp or (icmp6 and ip6[7]==255 and ip6[40]==135 and ip6[41]==0))"
#define PCAP_IPV6_FILTER		"ip6"
#define PCAP_TCPV6_FILTER		"ip6 and tcp"
#define PCAP_UDPV6_FILTER		"ip6 and udp"
#define PCAP_ICMPV6_FILTER		"icmp6"
#define PCAP_ICMPV6_NI_QUERY	"icmp6 and ip6[40]==139"
#define PCAP_ICMPV6_NI_REPLY	"icmp6 and ip6[40]==140"
#define PCAP_NOPACKETS_FILTER	"not ip and not ip6 and not arp"
#define PCAP_ICMPV6NSEXCEEDED_FILTER  "icmp6 and ((ip6[40]==3 and ip6[41]==1) or (ip6[40]==129 and ip6[41]==0))"

#define PCAP_ICMPV6_NSECHOEXCEEDED_FILTER  "icmp6 and ((ip6[40]==3 and ip6[41]==1) or (ip6[40]==129 and ip6[41]==0) OR (ip6[7]==255 and ip6[40]==135 and ip6[41]==0))"

/* Filter to receive Neighbor Solicitations and Fragmented packets */
#define PCAP_ICMPV6NSFRAG_FILTER "(ip6[7]==255 and icmp6 and ip6[40]==135 and ip6[41]==0) or (ip6 and ip6[6]==44)"
#define PCAP_NSTCP_FILTER "(ip6[7]==255 and icmp6 and ip6[40]==135 and ip6[41]==0) or (ip6 and ip6[6]==6)"



/* Constants used for Router Discovery */
#define MAX_PREFIXES_ONLINK		100
#define MAX_PREFIXES_AUTO		100
#define MAX_LOCAL_ADDRESSES		256


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

#if !(defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__))

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

	#if _BYTE_ORDER == _BIG_ENDIAN
		#define NI_SUPTYPE_FLAG_COMPRESS	0x1
		#define NI_FQDN_FLAG_VALIDTTL		0x1
	#elif _BYTE_ORDER == _LITTLE_ENDIAN
		#define NI_SUPTYPE_FLAG_COMPRESS	0x0100
		#define NI_FQDN_FLAG_VALIDTTL		0x0100
	#endif

	#if _BYTE_ORDER == _BIG_ENDIAN
		#define NI_NODEADDR_FLAG_TRUNCATE	0x1
		#define NI_NODEADDR_FLAG_ALL		0x2
		#define NI_NODEADDR_FLAG_COMPAT		0x4
		#define NI_NODEADDR_FLAG_LINKLOCAL	0x8
		#define NI_NODEADDR_FLAG_SITELOCAL	0x10
		#define NI_NODEADDR_FLAG_GLOBAL		0x20
		#define NI_NODEADDR_FLAG_ANYCAST	0x40 /* just experimental. not in spec */
	#elif _BYTE_ORDER == _LITTLE_ENDIAN
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


/* This causes Linux to use the BSD definition of the TCP and UDP header fields */
#ifndef __FAVOR_BSD
	#define __FAVOR_BSD
#endif


struct iface_data{
	char			iface[IFACE_LENGTH];
	int			type;
	int			flags;
	int			fd;
	pcap_t			*pfd;
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
	struct in6_addr		dstaddr;
	unsigned int		dstaddr_f;
	unsigned int		verbose_f;
};


void				change_endianness(u_int32_t *, unsigned int);
int					dns_decode(unsigned char *, unsigned int, unsigned char *, char *, unsigned int, unsigned char **);
int					dns_str2wire(char *, unsigned int, char *, unsigned int);
struct ether_addr	ether_multicast(const struct in6_addr *);
int					ether_ntop(const struct ether_addr *, char *, size_t);
int					ether_pton(const char *, struct ether_addr *, unsigned int);
void				ether_to_ipv6_linklocal(struct ether_addr *etheraddr, struct in6_addr *ipv6addr);
int					find_ipv6_router_full(pcap_t *, struct iface_data *);
void				generate_slaac_address(struct in6_addr *, struct ether_addr *, struct in6_addr *);
int					get_if_addrs(struct iface_data *);
int					inc_sdev(u_int32_t *, unsigned int, u_int32_t *, double *);
int					init_iface_data(struct iface_data *);
int					init_filters(struct filters *);
u_int16_t			in_chksum(void *, void *, size_t, u_int8_t);
int					insert_pad_opt(unsigned char *ptrhdr, const unsigned char *, unsigned int);
int					ipv6_to_ether(pcap_t *, struct iface_data *, struct in6_addr *, struct ether_addr *);
int					is_ip6_in_address_list(struct prefix_list *, struct in6_addr *);
int					is_ip6_in_prefix_list(struct in6_addr *, struct prefix_list *);
int					is_eq_in6_addr(struct in6_addr *, struct in6_addr *);
int					is_time_elapsed(struct timeval *, struct timeval *, unsigned long);
unsigned int		match_ether(struct ether_addr *, unsigned int, struct ether_addr *);
unsigned int		match_ipv6(struct in6_addr *, u_int8_t *, unsigned int, struct in6_addr *);
int 				match_ipv6_to_prefixes(struct in6_addr *, struct prefix_list *);
void				print_filters(struct iface_data *, struct filters *);
void				print_filter_result(struct iface_data *, const u_char *, unsigned char);
void				randomize_ether_addr(struct ether_addr *);
void				randomize_ipv6_addr(struct in6_addr *, struct in6_addr *, u_int8_t);
void				release_privileges(void);
void				sanitize_ipv6_prefix(struct in6_addr *, u_int8_t);
int 				send_neighbor_advert(struct iface_data *, pcap_t *,  const u_char *);
int					send_neighbor_solicit(struct iface_data *, struct in6_addr *);
int					sel_next_hop(struct iface_data *);
void				sig_alarm(int);
struct in6_addr		solicited_node(const struct in6_addr *);
struct in6_addr *	src_addr_sel(struct iface_data *, struct in6_addr *);
int					string_escapes(char *, unsigned int *);
size_t				Strnlen(const char *, size_t);

