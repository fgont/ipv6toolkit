/*
 * Header file for the scan6 tool
 *
 */

/* Constants used with the multi_scan_local() function */
#define PROBE_ICMP6_ECHO 1
#define PROBE_UNREC_OPT 2
#define PROBE_TCP 3
#define LOCAL_SRC 1
#define GLOBAL_SRC 2

#define ICMPV6_ECHO_PAYLOAD_SIZE 56
#define MAX_IPV6_ENTRIES 65000

/* Constant for the host-scanning functions */
#define PRINT_ETHER_ADDR 1
#define NOT_PRINT_ETHER_ADDR 0

#define VALID_MAPPING 1
#define INVALID_MAPPING 0

/* Remote scans */
#define LOW_BYTE_1ST_WORD_UPPER 0x1500
#define LOW_BYTE_2ND_WORD_UPPER 0x0100
#define EMBEDDED_PORT_2ND_WORD 5
#define MAX_IEEE_OUIS_LINE_SIZE 160
#define OUI_HEX_STRING_SIZE 5
#define MAX_IEEE_OUIS 1000
#define MAX_SCAN_ENTRIES 65535
#define MAX_PORT_ENTRIES 65536
#define MAX_PREF_ENTRIES MAX_SCAN_ENTRIES
#define SELECT_TIMEOUT 4
#define PSCAN_TIMEOUT 1
#define MAX_RANGE_STR_LEN 79
#define MIN_INC_RANGE 1000
/* #define	MAX_DESTNATIONS			65535 */
#define MAX_IID_ENTRIES 65535

#define ND_RETRIES 0

/* Constants for config file processing */
#define MAX_LINE_SIZE 250
#define MAX_VAR_NAME_LEN 100
#define MAX_FILENAME_SIZE 250

union my6_addr {
    uint8_t s6addr[16];
    uint16_t s6addr16[8];
    uint32_t s6addr32[4];
    struct in6_addr in6_addr;
};

/* Stores one remote target to scan */
struct scan_entry {
    union my6_addr start;
    union my6_addr end;
    union my6_addr cur;
};

/* Store the list of remote targets to scan */
struct scan_list {
    struct scan_entry **target;
    unsigned int ctarget;
    unsigned int ntarget;   /* Number of existing enties */
    unsigned int maxtarget; /* Max enties */
    unsigned int inc;       /* Increment size */
};

#define MAX_PORTS_LINE_SIZE 80

/* Stores one port entry to scan */
struct port_entry {
    uint16_t start;
    uint16_t end;
    uint16_t cur;
};

/* Store the list of remote targets to scan */
struct port_list {
    struct port_entry **port;
    unsigned int cport;
    unsigned int nport;
    unsigned int maxport;
    unsigned int proto;
    struct port_table_entry *port_table;
};

/* Store the list of remote targets to scan */
struct port_table_entry {
    unsigned int loaded;
    char name[MAX_PORTS_LINE_SIZE];
};

/* Constants for port scan results */

#define PORT_FILTERED 1
#define PORT_OPEN 2
#define PORT_CLOSED 4
#define PORT_ACT_FILT 8

#define DEFAULT_MIN_PORT 0
#define DEFAULT_MAX_PORT 65535
#define MAX_PORT_RANGE 65536
#define IPPROTO_ALL 0xf1 /* Fake number to indicate both TCP and UDP */

/* Constants for printing the scanning results */

/* Steps into which results will be printed */
#define MAX_STEPS 20

struct print_scan_entry {
    struct timeval start;
    unsigned int nscan_entry;
    struct in6_addr addrstart;
    unsigned int nport_entry;
    uint16_t portstart;
};

struct print_scans_list {
    struct print_scan_entry print_scan_entry[MAX_STEPS];
    /*	unsigned int	max=MAX_STEPS; */
    unsigned int fullq; /* Flag to indicate that the cirdular list is full */
    unsigned int in;    /* Next entry to write */
    unsigned int out;   /* Next entry to read */
    unsigned int donesending;
};

struct hashed_host_entry {
    struct in6_addr ip6;
    unsigned int tcp_results[MAX_PORT_RANGE];
    struct hashed_host_entry *next;
    struct hashed_host_entry *prev;
};

struct hashed_host_list {
    struct hashed_host_entry **host; /* Double-linked list of host entries */
    unsigned int nhosts;             /* Current number of host entries */
    unsigned int maxhosts;           /* Maximum number of host entries */
    uint16_t key_l;                  /* Low-order word of the hash key */
    uint16_t key_h;                  /* High-order word of the hash key */
};
