/*
 * Header file for the frag6 tool
 *
 */


#define	QUERY_TIMEOUT			70


/* For Fragment ID assessment */
#define FID_ASSESS_TIMEOUT		(NBATCHES+4)
#define NBATCHES				3
#define NSAMPLES				40
#define FIXED_ORIGIN			1
#define MULTI_ORIGIN			2

#define	PROBE_ICMP6_ECHO		1
#define PROBE_TCP				3
#define PROBE_UDP				4

#define PROBE_PORT_OFFSET		0x00c4

struct probe{
	unsigned char	sent;
	unsigned char	received;
	struct timeval	rtstamp;
	struct timeval	ststamp;
	struct in6_addr	srcaddr;

}
