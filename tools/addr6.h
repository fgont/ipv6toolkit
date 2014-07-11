
#define MAX_LINE_SIZE			250
#define MAX_TYPE_SIZE			25
#define MAX_LIST_ENTRIES		65535
#define MAX_HOST_ENTRIES		4000000


/* Filter Constants */
#define MAX_BLOCK			50
#define MAX_ACCEPT			50


struct hashed_host_entry{
	struct in6_addr		ip6;
	struct hashed_host_entry	*next;
	struct hashed_host_entry	*prev;
};

struct hashed_host_list{
	struct hashed_host_entry	**host;			/* Double-linked list of host entries */
	unsigned int		nhosts;			/* Current number of host entries */
	unsigned int		maxhosts;		/* Maximum number of host entries */
	uint16_t			key_l;			/* Low-order word of the hash key */
	uint16_t			key_h;			/* High-order word of the hash key */
};


struct stats6{
	unsigned int	total;
	unsigned int	ipv6unspecified;
	unsigned int	ipv6multicast;
	unsigned int	ipv6unicast;

	unsigned int 	ucastloopback;
	unsigned int	ucastv4mapped;
	unsigned int	ucastv4compat;
	unsigned int	ucastlinklocal;
	unsigned int    ucastsitelocal;
	unsigned int	ucastuniquelocal;
	unsigned int	ucast6to4;
	unsigned int	ucastteredo;
	unsigned int	ucastglobal;

	unsigned int	mcastpermanent;
	unsigned int	mcastnonpermanent;
	unsigned int	mcastinvalid;
	unsigned int	mcastunicastbased;
	unsigned int	mcastembedrp;
	unsigned int	mcastunknown;

	unsigned int	iidmacderived;
	unsigned int	iidisatap;
	unsigned int	iidmbeddedipv4;     /* This one is currently unused */
	unsigned int	iidembeddedipv4_32;
	unsigned int	iidembeddedipv4_64;
	unsigned int	iidembeddedport;
	unsigned int	iidembeddedportrev;
	unsigned int	iidlowbyte;
	unsigned int	iidpatternbytes;
	unsigned int	iidrandom;

	unsigned int	mscopereserved;
	unsigned int	mscopeinterface;
	unsigned int	mnscopelink;
	unsigned int	mscopeadmin;
	unsigned int	mscopesite;
	unsigned int	mscopeorganization;
	unsigned int	mscopeglobal;
	unsigned int	mscopeunassigned;
	unsigned int	mscopeunspecified;
};



