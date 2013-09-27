/*
 * Header file for the tcp6 tool
 *
 */


/* Constants used for specification of TCP connection establishment */
#define	OPEN_PASSIVE			1
#define OPEN_SIMULTANEOUS		2
#define OPEN_ABORT			3


/* Constants used for specification of TCP connection termination */
#define CLOSE_ACTIVE			1
#define CLOSE_PASSIVE			2
#define CLOSE_SIMULTANEOUS		3
#define CLOSE_ABORT			4
#define CLOSE_FIN_WAIT_1		5
#define CLOSE_FIN_WAIT_2		6
#define CLOSE_LAST_ACK			7


/* Constants for TCP window operation */
#define WIN_CLOSED			1
#define	WIN_MODULATE			2
#define WIN_MODULATE_CLOSED_SIZE	0
#define WIN_MODULATE_CLOSED_LEN		60
#define WIN_MODULATE_OPEN_SIZE		10
#define WIN_MODULATE_OPEN_LEN		30


/* Constants for specifying the TCP connection state */
#define TCP_CLOSED			1
#define TCP_LISTEN			2
#define TCP_SYN_SENT		3
#define TCP_SYN_RECV		4
#define	TCP_ESTABLISHED		5
#define TCP_FIN_WAIT1		6
#define TCP_FIN_WAIT2		7
#define TCP_CLOSE_WAIT		8
#define TCP_LAST_ACK		9
#define TCP_CLOSING			10
#define TCP_TIME_WAIT		11


#define TCP_BUFFER_SIZE			65535
#define TCP_INPUT_BUFFER_SIZE	TCP_BUFFER_SIZE
#define TCP_OUTPUT_BUFFER_SIZE	TCP_BUFFER_SIZE

struct tcp{
	unsigned char	in[TCP_INPUT_BUFFER_SIZE];
	unsigned char	*in_in;
	unsigned char	*in_out;
	u_int32_t		in_nxt;
	unsigned char	out[TCP_OUTPUT_BUFFER_SIZE];
	unsigned char	*out_una;
	unsigned char	*out_nxt;    /* una         nxt   out in */
	unsigned char	*out_in;
	struct timeval	sent;
	unsigned int	state;
	u_int32_t		seq_una;
	u_int32_t		seq_nxt;
	u_int32_t		seq_wnd;
	u_int32_t		ack;
	u_int32_t		win;	
};

