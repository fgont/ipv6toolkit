/*
 * Header file for the scan6 tool
 *
 */

#define BUFFER_SIZE		65556

/* Constants used with the multi_scan_local() function */
#define	PROBE_ICMP6_ECHO	1
#define PROBE_UNREC_OPT		2
#define PROBE_TCP		3
#define	LOCAL_SRC		1
#define GLOBAL_SRC		2

#define ICMPV6_ECHO_PAYLOAD_SIZE	56
#define	MAX_IPV6_ENTRIES		65000

/* Constant for the host-scanning functions */
#define	PRINT_ETHER_ADDR		1
#define NOT_PRINT_ETHER_ADDR		0

#define	VALID_MAPPING			1
#define INVALID_MAPPING			0


/* Constants used with the libcap functions */
#define PCAP_ICMPV6_FILTER		"icmp6"
#define PCAP_ICMPV6_NA_FILTER		"icmp6 and ip6[7]==255 and ip6[40]==136 and ip6[41]==0"
#define PCAP_ICMPV6_RANS_FILTER		"icmp6 and ip6[7]==255 and ((ip6[40]==134 and ip6[41]==0) or (ip6[40]==135 and ip6[41]==0))"
#define PCAP_ICMPV6_ERNS_FILTER		"icmp6 and ((ip6[40]==129 and ip6[41]==0) or (ip6[40]==135 and ip6[41]==0))"
#define PCAP_ICMPV6_ERRORNS_FILTER	"icmp6 and ((ip6[40]==4) or (ip6[40]==135 and ip6[41]==0))"

#define PCAP_ICMPV6_ERQNSNA_FILTER	"icmp6 and ((ip6[40]==129 and ip6[41]==0) or ((ip6[40]==135 or ip6[40]==136) and ip6[41]==0 and ip6[7]==255))"
#define PCAP_ICMPV6_ERRORNSNA_FILTER	"icmp6 and ((ip6[40]==4) or ((ip6[7]==255 and ip6[41]==0) and (ip6[40]==135 or ip6[40]==136)))"
#define PCAP_TCP_NSNA_FILTER		"(ip6 and tcp) or (icmp6 and ip6[7]==255 and ip6[41]==0 and (ip6[40]==135 or ip6[40]==136))"

/* Remote scans */
#define LOW_BYTE_1ST_WORD_UPPER		0x1500
#define LOW_BYTE_2ND_WORD_UPPER		0x0100
#define EMBEDDED_PORT_2ND_WORD		5
#define	MAX_IEEE_OUIS_LINE_SIZE		160
#define	OUI_HEX_STRING_SIZE		5
#define	MAX_IEEE_OUIS			1000
#define MAX_SCAN_ENTRIES		65535
#define MAX_PREF_ENTRIES		MAX_SCAN_ENTRIES
#define	SELECT_TIMEOUT			4
#define MAX_RANGE_STR_LEN		79
#define MIN_INC_RANGE			1000
/* #define	MAX_DESTNATIONS			65535 */
#define MAX_IID_ENTRIES			65535

#define ND_RETRIES			0

/* Constants for config file processing */
#define MAX_LINE_SIZE			250
#define MAX_VAR_NAME_LEN		100
#define MAX_FILENAME_SIZE		250


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

