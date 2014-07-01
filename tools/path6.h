/*
 * Header file for the path6 tool
 *
 */


#define	PROBE_ICMP6_ECHO		1
#define PROBE_TCP				3
#define PROBE_UDP				4

#define PROBE_PORT_OFFSET		0x00c4
#define PROBE_TIMEOUT			2


struct probe{
	unsigned char	sent;
	unsigned char	received;
	struct timeval	rtstamp;
	struct timeval	ststamp;
	struct in6_addr	srcaddr;
};
