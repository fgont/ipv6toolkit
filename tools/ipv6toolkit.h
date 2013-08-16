#define SI6_TOOLKIT "SI6 Networks' IPv6 Toolkit v1.3.4"

/* Constants to signal special interface types */
#define	IFACE_LOOPBACK			1
#define IFACE_TUNNEL			2


/* Constants used with the libpcap functions */
#define PCAP_SNAP_LEN			65535
#define	PCAP_PROMISC			1
#define	PCAP_OPT			1
#ifndef PCAP_NETMASK_UNKNOWN
	#define PCAP_NETMASK_UNKNOWN	0xffffffff
#endif

#if defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
	#define	PCAP_TIMEOUT			1
#else
	#define	PCAP_TIMEOUT			0
#endif

