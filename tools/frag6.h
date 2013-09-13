/*
 * Header file for the frag6 tool
 *
 */


#define	QUERY_TIMEOUT			70

/* For discovering the fragment reassembly policy */
#define	TIMED_OUT			1
#define FIRST_COPY			2
#define LAST_COPY			3
#define TIME_EXCEEDED			4
#define UNKNOWN_COPY			5
#define MIN_FRAG_SIZE			104


/* Constants for the send_fragment() function */
#define	FIRST_FRAGMENT			1
#define LAST_FRAGMENT			2
#define ATOMIC_FRAGMENT			3
#define MIDDLE_FRAGMENT			4
#define TIMESTAMP				1
#define NO_TIMESTAMP			0

#define MAX_FRAG_OFFSET			0xfff8

/* For Fragment ID assessment */
#define FID_ASSESS_TIMEOUT		(NBATCHES+4)
#define NBATCHES				3
#define NSAMPLES				40
#define FIXED_ORIGIN			1
#define MULTI_ORIGIN			2

/* Size of the fragmentation buffer (including link-layer headers) for FID probes */
#define FRAG_BUFFER_SIZE		(MIN_IPV6_HLEN + FRAG_HDR_SIZE + MAX_IPV6_PAYLOAD)

/* For limiting strncmp */
#define MAX_STRING_SIZE			10


