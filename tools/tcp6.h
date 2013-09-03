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




