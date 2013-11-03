/*
 * Header file for the tcp6 tool
 *
 */


/* Constants used for specification of TCP connection establishment */
#define	OPEN_PASSIVE			1
#define OPEN_SIMULTANEOUS		2
#define OPEN_ABORT				3
#define OPEN_ACTIVE				4


/* Constants used for specification of TCP connection termination */
#define CLOSE_ACTIVE			1
#define CLOSE_PASSIVE			2
#define CLOSE_SIMULTANEOUS		3
#define CLOSE_ABORT				4
#define CLOSE_FIN_WAIT_1		5
#define CLOSE_FIN_WAIT_2		6
#define CLOSE_LAST_ACK			7


/* Constants for TCP window operation */
#define WIN_CLOSED					1
#define	WIN_MODULATE				2
#define WIN_MODULATE_CLOSED_SIZE	0
#define WIN_MODULATE_CLOSED_LEN		60
#define WIN_MODULATE_OPEN_SIZE		10
#define WIN_MODULATE_OPEN_LEN		30
#define	TCP_RTO						1

/* Constants for specifying the TCP connection state */
#define TCP_CLOSED			1
#define TCP_LISTEN			2
#define TCP_SYN_SENT		3
#define TCP_SYN_RECV		4
#define	TCP_ESTABLISHED		5
#define TCP_FIN_WAIT_1		6
#define TCP_FIN_WAIT_2		7
#define TCP_CLOSE_WAIT		8
#define TCP_LAST_ACK		9
#define TCP_CLOSING			10
#define TCP_TIME_WAIT		11


/* Constants for debug mode */
#define DEBUG_DUMP			1
#define DEBUG_SCRIPT		2

/* Constants for TCP buffers */
#define TCP_BUFFER_SIZE			65535
#define TCP_INPUT_BUFFER_SIZE	TCP_BUFFER_SIZE
#define TCP_OUTPUT_BUFFER_SIZE	TCP_BUFFER_SIZE

struct queue{
	unsigned char	data[TCP_BUFFER_SIZE];
	unsigned char	*in;
	unsigned char	*out;
	unsigned int	size;
/*	unsigned int	data; */
	unsigned int	free;
};

struct tcp{
	struct in6_addr	srcaddr;
	struct in6_addr dstaddr;
	u_int16_t		srcport;
	u_int16_t		dstport;

	struct queue	in;
	u_int32_t		rcv_nxt;
	u_int32_t		rcv_nxtwnd;	

	struct queue	out;
	unsigned char	*out_una;
	unsigned char	*out_nxt;    /*  una         nxt  */
	u_int32_t		snd_una;
	u_int32_t		snd_nxt;
	u_int32_t		snd_nxtwnd;
	u_int32_t		snd_seq; /* TCP seq to use for outgoing segments (for RSTs) */
	u_int32_t		snd_wl1;
	u_int32_t		snd_wl2;

	unsigned char	fin_flag;
	u_int32_t	fin_seq;
		
	struct timeval	time;
	unsigned int	state;
	unsigned int	open;
	unsigned int	close;
	u_int8_t		flags;
	u_int32_t		ack;
	u_int32_t		win;	

	unsigned int		fbytes;
	
	unsigned char		pending_write_f;
	unsigned int		rto;
};


#define SEQ_LT(a,b)     ((int)((a)-(b)) < 0)
#define SEQ_LEQ(a,b)    ((int)((a)-(b)) <= 0)
#define SEQ_GT(a,b)     ((int)((a)-(b)) > 0)
#define SEQ_GEQ(a,b)    ((int)((a)-(b)) >= 0)
#define SEQ_EQ(a,b)     ((int)((a)-(b)) == 0)
