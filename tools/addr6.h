
#define MAX_LINE_SIZE 250
#define MAX_TYPE_SIZE 25
#define MAX_LIST_ENTRIES 65535
#define MAX_HOST_ENTRIES 4000000000
#define MAX_ADDR_PATTERN 10000000
#define MAX_ADDR_FILTERS MAX_ADDR_PATTERN / 100

/* Filter Constants */
#define MAX_BLOCK 50
#define MAX_ACCEPT 50

struct hashed_host_entry {
    struct in6_addr ip6;
    struct hashed_host_entry *next;
    struct hashed_host_entry *prev;
};

struct hashed_host_list {
    struct hashed_host_entry **host; /* Double-linked list of host entries */
    unsigned long nhosts;            /* Current number of host entries */
    unsigned long maxhosts;          /* Maximum number of host entries */
    uint16_t key_l;                  /* Low-order word of the hash key */
    uint16_t key_h;                  /* High-order word of the hash key */
};

struct stats6 {
    unsigned long total;
    unsigned long ipv6unspecified;
    unsigned long ipv6multicast;
    unsigned long ipv6unicast;

    unsigned long ucastloopback;
    unsigned long ucastv4mapped;
    unsigned long ucastv4compat;
    unsigned long ucastlinklocal;
    unsigned long ucastsitelocal;
    unsigned long ucastuniquelocal;
    unsigned long ucast6to4;
    unsigned long ucastteredo;
    unsigned long ucastglobal;

    unsigned long mcastpermanent;
    unsigned long mcastnonpermanent;
    unsigned long mcastinvalid;
    unsigned long mcastunicastbased;
    unsigned long mcastembedrp;
    unsigned long mcastunknown;

    unsigned long iidmacderived;
    unsigned long iidisatap;
    unsigned long iidmbeddedipv4; /* This one is currently unused */
    unsigned long iidembeddedipv4_32;
    unsigned long iidembeddedipv4_64;
    unsigned long iidembeddedport;
    unsigned long iidembeddedportfwd;
    unsigned long iidembeddedportrev;
    unsigned long iidlowbyte;
    unsigned long iidpatternbytes;
    unsigned long iidrandom;
    unsigned long iidteredo;

    unsigned long mscopereserved;
    unsigned long mscopeinterface;
    unsigned long mnscopelink;
    unsigned long mscopeadmin;
    unsigned long mscopesite;
    unsigned long mscopeorganization;
    unsigned long mscopeglobal;
    unsigned long mscopeunassigned;
    unsigned long mscopeunspecified;
};
