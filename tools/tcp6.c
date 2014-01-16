/*
 * tcp6 : A security assessment tool that exploits potential flaws in the
 *        processing of TCP/IPv6 packets
 *
 * Copyright (C) 2011-2013 Fernando Gont <fgont@si6networks.com>
 *
 * Programmed by Fernando Gont for SI6 Networks <http://www.si6networks.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * Build with: make tcp6
 * 
 * It requires that the libpcap library be installed on your system.
 *
 * Please send any bug reports to Fernando Gont <fgont@si6networks.com>
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/param.h>
#include <setjmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <pwd.h>
#include <net/if.h>
#include <ifaddrs.h>
#ifdef __linux__
	#include <netpacket/packet.h>
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__) || ( !defined(__FreeBSD__) && defined(__FreeBSD_kernel__))
	#include <net/if_dl.h>
#endif
#include <sys/select.h>
#include "ipv6toolkit.h"
#include "tcp6.h"
#include "libipv6.h"


/* Function prototypes */
void				init_packet_data(struct iface_data *);
int				is_valid_tcp_segment(struct iface_data *, const u_char *, struct pcap_pkthdr *);
void				send_packet(struct iface_data *, const u_char *, struct pcap_pkthdr *);
void				print_attack_info(struct iface_data *);
void				usage(void);
void				print_help(void);
void				frag_and_send(struct iface_data *);
unsigned int		queue_data(struct queue *, unsigned char *, unsigned int);
unsigned int		dequeue_data(struct queue *, unsigned char *, unsigned int);
unsigned int		queue_copy(struct queue *, unsigned char *, unsigned int, unsigned char *, unsigned int);
unsigned int		queue_remove(struct queue *, unsigned char *, unsigned int);
void				queue_purge( struct queue *);
int					tcp_init(struct tcp *);
int					tcp_open(struct iface_data *, struct tcp *, unsigned int);
int					tcp_close(struct iface_data *, struct tcp *);
int					tcp_send(struct iface_data *, struct tcp *, unsigned char *, unsigned int);
int					tcp_receive(struct iface_data *, struct tcp *, unsigned char *, unsigned int);
int					tcp_input(struct iface_data *, struct tcp *, const u_char *, struct pcap_pkthdr *, struct packet *);
int					tcp_output(struct iface_data *, struct tcp *, struct packet *, struct timeval *);
int					is_valid_tcp_segment(struct iface_data *, const u_char *, struct pcap_pkthdr *);

/* Flags */
unsigned char 		floodt_f=0;
unsigned char 		listen_f=0, accepted_f=0, loop_f=0, sleep_f=0;
unsigned char		hoplimit_f=0, rand_link_src_f=0, rand_src_f=0;
unsigned char		floods_f=0, floodp_f=0, donesending_f=0, startclose_f=0;
unsigned char		data_f=0, senddata_f=0, useaddrkey_f=0, window_f=0, winmodulate_f=0;

/* Flags used for TCP (specifically) */ 
unsigned char		srcport_f=0, dstport_f=0;
unsigned char		tcpseq_f=0, tcpack_f=0, tcpurg_f=0, tcpflags_f=0, tcpwin_f=0;
unsigned char		rhbytes_f=0, tcpflags_auto_f=0, tcpopen_f=0, tcpclose_f=0;
unsigned char		pps_f=0, bps_f=0, debug_f=0, probe_f=0, retrans_f=0, rto_f=0;
unsigned char		ackdata_f=1, ackflags_f=1;
unsigned int		debug, tcpopen=0, tcpclose=0, win1_size=0, win2_size=0, window=0, time1_len=0, time2_len=0;

u_int16_t			srcport, dstport, tcpurg, tcpwin, tcpwinm;
unsigned int		retrans, rto;
u_int32_t			tcpseq, tcpack;
u_int8_t			tcpflags=0, pkt_tcp_flags;
struct tcp_hdr		*rhtcp;
unsigned int		rhbytes, currentsize, packetsize;


/* Used for router discovery */
struct iface_data	idata;

/* Data structures for packets read from the wire */
struct pcap_pkthdr		*pkthdr;
const u_char			*pktdata;
unsigned char			*pkt_end;
struct ether_header		*pkt_ether;
struct nd_neighbor_solicit	*pkt_ns;
struct ip6_hdr			*pkt_ipv6;
struct tcp_hdr			*pkt_tcp;
struct in6_addr			*pkt_ipv6addr;
unsigned int			pktbytes;


bpf_u_int32			my_netmask;
bpf_u_int32			my_ip;
struct bpf_program	pcap_filter;
char 				dev[64], errbuf[PCAP_ERRBUF_SIZE];
unsigned char		buffer[65556], buffrh[MIN_IPV6_HLEN + MIN_TCP_HLEN];
unsigned char		*v6buffer, *ptr, *startofprefixes;
char				*pref;
char				data[DATA_BUFFER_LEN];
unsigned int		datalen;
char 				iface[IFACE_LENGTH];
char				line[LINE_BUFFER_SIZE];
    
struct ip6_hdr		*ipv6;
struct tcp_hdr		*tcp;

struct ether_header	*ethernet;
struct nd_opt_tlla	*tllaopt;

struct in6_addr		targetaddr, randprefix;
struct ether_addr	linkaddr[MAX_TLLA_OPTION];
unsigned int		nlinkaddr=0, linkaddrs;

char				*lasts, *rpref;
char				*charptr;

size_t				nw;
unsigned long		ul_res, ul_val, rate;
unsigned int		i, j, startrand;
unsigned int		skip;
unsigned int		sources, nsources, ports, nports, nsleep;
unsigned char		randpreflen;

u_int16_t			mask;
u_int8_t			hoplimit;
u_int16_t			addr_key;

char 				plinkaddr[ETHER_ADDR_PLEN];
char 				psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN], pv6addr[INET6_ADDRSTRLEN];


/* Support for Extension Headers */
unsigned int		dstopthdrs, dstoptuhdrs, hbhopthdrs;
char				hbhopthdr_f=0, dstoptuhdr_f=0, dstopthdr_f=0;
unsigned char		*dstopthdr[MAX_DST_OPT_HDR], *dstoptuhdr[MAX_DST_OPT_U_HDR];
unsigned char		*hbhopthdr[MAX_HBH_OPT_HDR];
unsigned int		dstopthdrlen[MAX_DST_OPT_HDR], dstoptuhdrlen[MAX_DST_OPT_U_HDR];
unsigned int		hbhopthdrlen[MAX_HBH_OPT_HDR], m, pad;

struct ip6_frag		fraghdr, *fh;
struct ip6_hdr		*fipv6;
unsigned char		fragh_f=0;
unsigned char		fragbuffer[ETHER_HDR_LEN+MIN_IPV6_HLEN+MAX_IPV6_PAYLOAD];
unsigned char		*fragpart, *fptr, *fptrend, *ptrend, *ptrhdr, *ptrhdrend;
unsigned int		hdrlen, ndstopthdr=0, nhbhopthdr=0, ndstoptuhdr=0;
unsigned int		nfrags, fragsize;
unsigned char		*prev_nh, *startoffragment;

struct filters		filters;

int main(int argc, char **argv){
	extern char		*optarg;	
	char			*endptr; /* Used by strtoul() */
	fd_set			sset, rset;	
/*	fd_set			wset, eset; */
	int				r, sel;
	struct timeval	timeout, stimeout, curtime, lastprobe, wmtimeout;
	/*struct tcp		tcb; */
	/* unsigned char	end_f=0, error_f; */
	unsigned char		end_f=0;
	unsigned long	pktinterval=0; /*Add  datasent=0*/
	unsigned int	retr=0;

	static struct option longopts[] = {
		{"interface", required_argument, 0, 'i'},
		{"src-address", required_argument, 0, 's'},
		{"dst-address", required_argument, 0, 'd'},
		{"hop-limit", required_argument, 0, 'A'},
		{"open-mode", required_argument, 0, 'c'},
		{"close-mode", required_argument, 0, 'C'},
		{"data", required_argument, 0, 'Z'},
		{"dst-opt-hdr", required_argument, 0, 'u'},
		{"dst-opt-u-hdr", required_argument, 0, 'U'},
		{"hbh-opt-hdr", required_argument, 0, 'H'},
		{"frag-hdr", required_argument, 0, 'y'},
		{"link-src-addr", required_argument, 0, 'S'},
		{"link-dst-addr", required_argument, 0, 'D'},
		{"payload-size", required_argument, 0, 'P'},
		{"src-port", required_argument, 0, 'o'},
		{"dst-port", required_argument, 0, 'a'},
		{"tcp-flags", required_argument, 0, 'X'},
		{"tcp-seq", required_argument, 0, 'q'},
		{"tcp-ack", required_argument, 0, 'Q'},
		{"tcp-urg", required_argument, 0, 'V'},
		{"tcp-win", required_argument, 0, 'w'},
		{"window-mode", required_argument, 0, 'W'},
		{"win-modulation", required_argument, 0, 'M'},
		{"not-ack-data", no_argument, 0, 'N'},
		{"not-ack-flags", no_argument, 0, 'n'},
		{"block-src-addr", required_argument, 0, 'j'},
		{"block-dst-addr", required_argument, 0, 'k'},
		{"block-link-src-addr", required_argument, 0, 'J'},
		{"block-link-dst-addr", required_argument, 0, 'K'},
		{"accept-src-addr", required_argument, 0, 'b'},
		{"accept-dst-addr", required_argument, 0, 'g'},
		{"accept-link-src-addr", required_argument, 0, 'B'},
		{"accept-link-dst-addr", required_argument, 0, 'G'},
		{"flood-sources", required_argument, 0, 'F'},
		{"flood-ports", required_argument, 0, 'T'},
		{"rand-src-addr", no_argument, 0, 'f'},
		{"rand-link-src-addr", no_argument, 0, 'R'},
		{"loop", no_argument, 0, 'l'},
		{"rate-limit", required_argument, 0, 'r'},
		{"sleep", required_argument, 0, 'z'},
		{"listen", no_argument, 0, 'L'},
		{"probe", no_argument, 0, 'p'},
		{"retrans", required_argument, 0, 'x'},
		{"verbose", no_argument, 0, 'v'},
		{"debug", required_argument, 0, 'Y'},
		{"help", no_argument, 0, 'h'}
	};

	char shortopts[]= "i:s:d:A:c:C:Z:u:U:H:y:S:D:P:o:a:X:q:Q:V:w:W:M:Nnj:k:J:K:b:g:B:G:F:T:fRlr:z:Lpx:vyY:h";

	char option;

	if(argc<=1){
		usage();
		exit(EXIT_FAILURE);
	}

	hoplimit=255;
	pktinterval= 0;
	lastprobe.tv_sec= 0;
	lastprobe.tv_usec= 0;

	/* Initialize filters structure */
	if(init_filters(&filters) == -1){
		puts("Error initializing internal data structure");
		exit(EXIT_FAILURE);
	}

	if(init_iface_data(&idata) == FAILURE){
		puts("Error initializing internal data structure");
		exit(EXIT_FAILURE);
	}

	while((r=getopt_long(argc, argv, shortopts, longopts, NULL)) != -1) {
		option= r;

		switch(option){
			case 'i':  /* Interface */
				strncpy(idata.iface, optarg, IFACE_LENGTH-1);
				idata.iface[IFACE_LENGTH-1]=0;
				idata.ifindex= if_nametoindex(idata.iface);
				idata.iface_f=TRUE;
				break;

			case 's':	/* IPv6 Source Address */
				if(idata.srcaddr_f){
					puts("Error: Multiple '-s' options have been specified");
					exit(EXIT_FAILURE);
				}

				if((charptr = strtok_r(optarg, "/", &lasts)) == NULL){
					puts("Error in Source Address");
					exit(EXIT_FAILURE);
				}

				if ( inet_pton(AF_INET6, charptr, &(idata.srcaddr)) <= 0){
					puts("inet_pton(): Source Address not valid");
					exit(EXIT_FAILURE);
				}

				idata.srcaddr_f = 1;
		
				if((charptr = strtok_r(NULL, " ", &lasts)) != NULL){
					idata.srcpreflen = atoi(charptr);
		
					if(idata.srcpreflen>128){
						puts("Prefix length error in IPv6 Source Address");
						exit(EXIT_FAILURE);
					}

					if(idata.srcpreflen == 64)
						useaddrkey_f= 1;

					sanitize_ipv6_prefix(&(idata.srcaddr), idata.srcpreflen);
					idata.srcprefix_f=1;
				}

				break;
	    
			case 'd':	/* IPv6 Destination Address */
				if( inet_pton(AF_INET6, optarg, &(idata.dstaddr)) <= 0){
					puts("inet_pton(): address not valid");
					exit(EXIT_FAILURE);
				}
		
				idata.dstaddr_f = 1;
				break;

			case 'A':	/* Hop Limit */
				hoplimit= atoi(optarg);
				hoplimit_f=1;
				break;

			case 'c':
				if(strncmp(optarg, "simultaneous", MAX_CMDLINE_OPT_LEN) == 0){
					tcpopen= OPEN_SIMULTANEOUS;
				}
				else if(strncmp(optarg, "passive", MAX_CMDLINE_OPT_LEN) == 0){
					tcpopen= OPEN_PASSIVE;
				}
				else if(strncmp(optarg, "abort", MAX_CMDLINE_OPT_LEN) == 0){
					tcpopen= OPEN_ABORT;
				}
				else if(strncmp(optarg, "active", MAX_CMDLINE_OPT_LEN) == 0){
					tcpopen= OPEN_ACTIVE;
				}
				else{
					puts("Error: Unknown open mode in '-c' option");
					exit(EXIT_FAILURE);
				}

				tcpopen_f=1;
				break;

			case 'C':
				if(strncmp(optarg, "simultaneous", MAX_CMDLINE_OPT_LEN) == 0){
					tcpclose= CLOSE_SIMULTANEOUS;
				}
				else if(strncmp(optarg, "passive", MAX_CMDLINE_OPT_LEN) == 0){
					tcpclose= CLOSE_PASSIVE;
				}
				else if(strncmp(optarg, "abort", MAX_CMDLINE_OPT_LEN) == 0){
					tcpclose= CLOSE_ABORT;
				}
				else if(strncmp(optarg, "active", MAX_CMDLINE_OPT_LEN) == 0){
					tcpclose= CLOSE_ACTIVE;
				}
				else if( strncmp(optarg, "fin-wait-1", MAX_CMDLINE_OPT_LEN) == 0 || \
					strncmp(optarg, "FIN-WAIT-1", MAX_CMDLINE_OPT_LEN) == 0){
					tcpclose= CLOSE_FIN_WAIT_1;
				}
				else if( strncmp(optarg, "fin-wait-2", MAX_CMDLINE_OPT_LEN) == 0 || \
					strncmp(optarg, "FIN-WAIT-2", MAX_CMDLINE_OPT_LEN) == 0){
					tcpclose= CLOSE_FIN_WAIT_2;
				}
				else if( strncmp(optarg, "last-ack", MAX_CMDLINE_OPT_LEN) == 0 || \
					strncmp(optarg, "LAST-ACK", MAX_CMDLINE_OPT_LEN) == 0){
					tcpclose= CLOSE_LAST_ACK;
				}
				else{
					puts("Error: Unknown close option ('-C')");
					exit(EXIT_FAILURE);
				}

				tcpclose_f=1;
				break;

			case 'Z': /* Data */
				datalen= Strnlen(optarg, MAX_CMDLINE_OPT_LEN);

				if(datalen >= DATA_BUFFER_LEN)
					datalen= DATA_BUFFER_LEN-1;

				strncpy(data, optarg, DATA_BUFFER_LEN-1);
				data_f=1;
				break;

			case 'u':	/* Destinations Options Header */
				if(ndstopthdr >= MAX_DST_OPT_HDR){
					puts("Too many Destination Options Headers");
					exit(EXIT_FAILURE);
				}

				hdrlen= atoi(optarg);
		
				if(hdrlen < 8){
					puts("Bad length in Destination Options Header");
					exit(EXIT_FAILURE);
				}
		    
				hdrlen = ((hdrlen+7)/8) * 8;
				dstopthdrlen[ndstopthdr]= hdrlen;

				if( (dstopthdr[ndstopthdr]= malloc(hdrlen)) == NULL){
					puts("Not enough memory for Destination Options Header");
					exit(EXIT_FAILURE);
				}

				ptrhdr= dstopthdr[ndstopthdr] + 2;
				ptrhdrend= dstopthdr[ndstopthdr] + hdrlen;

				while( ptrhdr < ptrhdrend){

					if( (ptrhdrend-ptrhdr)>257)
						pad= 257;
					else
						pad= ptrhdrend-ptrhdr;
			
					if(!insert_pad_opt(ptrhdr, ptrhdrend, pad)){
						puts("Destination Options Header Too Big");
						exit(EXIT_FAILURE);
					}
		    
					ptrhdr= ptrhdr + pad;
				}

				*(dstopthdr[ndstopthdr]+1)= (hdrlen/8)-1;
				ndstopthdr++;
				dstopthdr_f=1;
				break;

			case 'U':	/* Destination Options Header (Unfragmentable Part) */
				if(ndstoptuhdr >= MAX_DST_OPT_U_HDR){
					puts("Too many Destination Options Headers (Unfragmentable Part)");
					exit(EXIT_FAILURE);
				}

				hdrlen= atoi(optarg);
		
				if(hdrlen < 8){
					puts("Bad length in Destination Options Header (Unfragmentable Part)");
					exit(EXIT_FAILURE);
				}

				hdrlen = ((hdrlen+7)/8) * 8;
				dstoptuhdrlen[ndstoptuhdr]= hdrlen;
		
				if( (dstoptuhdr[ndstoptuhdr]= malloc(hdrlen)) == NULL){
					puts("Not enough memory for Destination Options Header (Unfragmentable Part)");
					exit(EXIT_FAILURE);
				}

				ptrhdr= dstoptuhdr[ndstoptuhdr]+2;
				ptrhdrend= dstoptuhdr[ndstoptuhdr] + hdrlen;
		
				while( ptrhdr < ptrhdrend){

					if( (ptrhdrend-ptrhdr)>257)
						pad= 257;
					else
						pad= ptrhdrend-ptrhdr;

					if(!insert_pad_opt(ptrhdr, ptrhdrend, pad)){
						puts("Destination Options Header (Unfragmentable Part) Too Big");
						exit(EXIT_FAILURE);
					}

					ptrhdr = ptrhdr + pad;
				}

				*(dstoptuhdr[ndstoptuhdr]+1)= (hdrlen/8) - 1;
				ndstoptuhdr++;
				dstoptuhdr_f=1;
				break;

			case 'H':	/* Hop-by-Hop Options Header */
				if(nhbhopthdr >= MAX_HBH_OPT_HDR){
					puts("Too many Hop-by-Hop Options Headers");
					exit(EXIT_FAILURE);
				}

				hdrlen= atoi(optarg);
		
				if(hdrlen <= 8){
					puts("Bad length in Hop-by-Hop Options Header");
					exit(EXIT_FAILURE);
				}
		    
				hdrlen = ((hdrlen+7)/8) * 8;
				hbhopthdrlen[nhbhopthdr]= hdrlen;
		
				if( (hbhopthdr[nhbhopthdr]= malloc(hdrlen)) == NULL){
					puts("Not enough memory for Hop-by-Hop Options Header");
					exit(EXIT_FAILURE);
				}

				ptrhdr= hbhopthdr[nhbhopthdr] + 2;
				ptrhdrend= hbhopthdr[nhbhopthdr] + hdrlen;
		
		
				while( ptrhdr < ptrhdrend){

					if( (ptrhdrend-ptrhdr)>257)
						pad= 257;
					else
						pad= ptrhdrend-ptrhdr;

					if(!insert_pad_opt(ptrhdr, ptrhdrend, pad)){
						puts("Hop-by-Hop Options Header Too Big");
						exit(EXIT_FAILURE);
					}

					ptrhdr = ptrhdr + pad;
				}

				*(hbhopthdr[nhbhopthdr]+1)= (hdrlen/8) - 1;
				nhbhopthdr++;
				hbhopthdr_f=1;
				break;

			case 'y':	/* Fragment header */
				nfrags= atoi(optarg);
				if(nfrags < 8){
					puts("Error in Fragmentation option: Fragment Size must be at least 8 bytes");
					exit(EXIT_FAILURE);
				}
		
				nfrags = (nfrags +7) & 0xfff8;
				fragh_f= 1;
				break;

			case 'S':	/* Source Ethernet address */
				if(ether_pton(optarg, &(idata.hsrcaddr), sizeof(idata.hsrcaddr)) == 0){
					puts("Error in Source link-layer address.");
					exit(EXIT_FAILURE);
				}
		
				idata.hsrcaddr_f = 1;
				break;

			case 'D':	/* Destination Ethernet Address */
				if(ether_pton(optarg, &(idata.hdstaddr), sizeof(idata.hdstaddr)) == 0){
					puts("Error in Source link-layer address.");
					exit(EXIT_FAILURE);
				}
		
				idata.hdstaddr_f = 1;
				break;

			case 'P':	/* Payload Size*/
				rhbytes= atoi(optarg);
				rhbytes_f= 1;
				break;

			case 'o':	/* TCP Source Port */
				srcport= atoi(optarg);
				srcport_f= 1;
				break;

			case 'a':	/* TCP Destination Port */
				dstport= atoi(optarg);
				dstport_f= 1;
				break;

			case 'X':
				if(strncmp(optarg, "auto", 4) == 0){
					tcpflags_auto_f=1;
					break;
				}

				charptr = optarg;
				while(*charptr){
					switch(*charptr){
						case 'F':
							tcpflags= tcpflags | TH_FIN;
							break;

						case 'S':
							tcpflags= tcpflags | TH_SYN;
							break;

						case 'R':
							tcpflags= tcpflags | TH_RST;
							break;

						case 'P':
							tcpflags= tcpflags | TH_PUSH;
							break;

						case 'A':
							tcpflags= tcpflags | TH_ACK;
							break;

						case 'U':
							tcpflags= tcpflags | TH_URG;
							break;

						case 'X': /* No TCP flags */
							break;

						default:
							printf("Unknown TCP flag '%c'\n", *charptr);
							exit(EXIT_FAILURE);
							break;
					}

					if(*charptr == 'X')
						break;

					charptr++;
				}

				tcpflags_f=1;
				break;

			case 'q':	/* TCP Sequence Number */
				if((ul_res = strtoul(optarg, &endptr, 0)) == ULONG_MAX){
					perror("Error in 'TCP Sequence NUmber' parameter");
					exit(EXIT_FAILURE);
				}
		
				if(endptr != optarg){
					tcpseq = ul_res;
					tcpseq_f=1;
				}

				break;

			case 'Q':	/* TCP Acknowledgement Number */
				if((ul_res = strtoul(optarg, &endptr, 0)) == ULONG_MAX){
					perror("Error in 'TCP Sequence NUmber' parameter");
					exit(EXIT_FAILURE);
				}
		
				if(endptr != optarg){
					tcpack = ul_res;
					tcpack_f=1;
				}
				break;

			case 'V':	/* TCP Urgent Pointer */
				tcpurg= atoi(optarg);
				tcpurg_f= 1;
				break;

			case 'w':	/* TCP Window */
				tcpwin= atoi(optarg);
				tcpwin_f=1;
				break;

			case 'W':	/* TCP Window */
				if(strncmp(optarg, "close", MAX_CMDLINE_OPT_LEN) == 0 || strncmp(optarg, "closed", MAX_CMDLINE_OPT_LEN) == 0){
					window= WIN_CLOSED;
				}
				else if(strncmp(optarg, "modulate", MAX_CMDLINE_OPT_LEN) == 0 || strncmp(optarg, "modulation", MAX_CMDLINE_OPT_LEN) == 0){
					window= WIN_MODULATE;
				}
				else{
					puts("Error: Unknown window option ('-W')");
					exit(EXIT_FAILURE);
				}

				window_f=1;
				break;

			case 'M':
				sscanf(optarg, "%u:%u:%u:%u", &win1_size, &time1_len, &win2_size, &time2_len);
				winmodulate_f= 1;
				break;

			case 'N':	/* Do not ack data */
				ackdata_f= 0;
				break;

			case 'n':	/* Do not ack flags */
				ackflags_f= 0;
				break;

			case 'j':	/* IPv6 Source Address (block) filter */
				if(filters.nblocksrc >= MAX_BLOCK_SRC){
					puts("Too many IPv6 Source Address (block) filters.");
					exit(EXIT_FAILURE);
				}
	    
				if((pref = strtok_r(optarg, "/", &lasts)) == NULL){
					printf("Error in IPv6 Source Address (block) filter number %u.\n", \
												filters.nblocksrc+1);
					exit(EXIT_FAILURE);
				}

				if ( inet_pton(AF_INET6, pref, &(filters.blocksrc[filters.nblocksrc])) <= 0){
					printf("Error in IPv6 Source Address (block) filter number %u.", \
											    filters.nblocksrc+1);
					exit(EXIT_FAILURE);
				}

				if((charptr = strtok_r(NULL, " ", &lasts)) == NULL){
		    			filters.blocksrclen[filters.nblocksrc] = 128;
				}
				else{
					filters.blocksrclen[filters.nblocksrc] = atoi(charptr);

					if(filters.blocksrclen[filters.nblocksrc]>128){
						printf("Length error in IPv6 Source Address (block) filter number %u.\n", \
													filters.nblocksrc+1);
						exit(EXIT_FAILURE);
		    			}
				}

				sanitize_ipv6_prefix(&(filters.blocksrc[filters.nblocksrc]), filters.blocksrclen[filters.nblocksrc]);
				(filters.nblocksrc)++;
				break;

			case 'k':	/* IPv6 Destination Address (block) filter */
				if(filters.nblockdst >= MAX_BLOCK_DST){
					puts("Too many IPv6 Destination Address (block) filters.");
					exit(EXIT_FAILURE);
				}

				if((pref = strtok_r(optarg, "/", &lasts)) == NULL){
					printf("Error in IPv6 Destination Address (block) filter number %u.\n", \
													filters.nblockdst+1);
					exit(EXIT_FAILURE);
				}

				if ( inet_pton(AF_INET6, pref, &(filters.blockdst[filters.nblockdst])) <= 0){
					printf("Error in IPv6 Source Address (block) filter number %u.", \
											    filters.nblockdst+1);
					exit(EXIT_FAILURE);
				}

				if((charptr = strtok_r(NULL, " ", &lasts)) == NULL){
					filters.blockdstlen[filters.nblockdst] = 128;
				}
				else{
					filters.blockdstlen[filters.nblockdst] = atoi(charptr);
		
					if(filters.blockdstlen[filters.nblockdst]>128){
						printf("Length error in IPv6 Source Address (block) filter number %u.\n", \
													    filters.nblockdst+1);
						exit(EXIT_FAILURE);
					}
				}
		
				sanitize_ipv6_prefix(&(filters.blockdst[filters.nblockdst]), filters.blockdstlen[filters.nblockdst]);
				(filters.nblockdst)++;
				break;

			case 'J':	/* Link Source Address (block) filter */
				if(filters.nblocklinksrc > MAX_BLOCK_LINK_SRC){
					puts("Too many link-layer Source Address (accept) filters.");
					exit(EXIT_FAILURE);
				}

				if(ether_pton(optarg, &(filters.blocklinksrc[filters.nblocklinksrc]), sizeof(struct ether_addr)) == 0){
					printf("Error in link-layer Source Address (blick) filter number %u.\n", \
												    filters.nblocklinksrc+1);
					exit(EXIT_FAILURE);
				}
		
				(filters.nblocklinksrc)++;
				break;

			case 'K':	/* Link Destination Address (block) filter */
				if(filters.nblocklinkdst > MAX_BLOCK_LINK_DST){
					puts("Too many link-layer Destination Address (block) filters.");
					exit(EXIT_FAILURE);
				}

				if(ether_pton(optarg, &(filters.blocklinkdst[filters.nblocklinkdst]), sizeof(struct ether_addr)) == 0){
					printf("Error in link-layer Destination Address (blick) filter number %u.\n", \
												    filters.nblocklinkdst+1);
					exit(EXIT_FAILURE);
				}
		
				filters.nblocklinkdst++;
				break;

			case 'b':	/* IPv6 Source Address (accept) filter */
				if(filters.nacceptsrc > MAX_ACCEPT_SRC){
					puts("Too many IPv6 Source Address (accept) filters.");
					exit(EXIT_FAILURE);
				}

				if((pref = strtok_r(optarg, "/", &lasts)) == NULL){
					printf("Error in IPv6 Source Address (accept) filter number %u.\n", \
												filters.nacceptsrc+1);
					exit(EXIT_FAILURE);
				}

				if ( inet_pton(AF_INET6, pref, &(filters.acceptsrc[filters.nacceptsrc])) <= 0){
					printf("Error in IPv6 Source Address (accept) filter number %u.\n", \
												filters.nacceptsrc+1);
					exit(EXIT_FAILURE);
				}
		
				if((charptr = strtok_r(NULL, " ", &lasts)) == NULL){
					filters.acceptsrclen[filters.nacceptsrc] = 128;
				}
				else{
					filters.acceptsrclen[filters.nacceptsrc] = atoi(charptr);

					if(filters.acceptsrclen[filters.nacceptsrc]>128){
						printf("Length error in IPv6 Source Address (accept) filter number %u.\n", \
														filters.nacceptsrc+1);
						exit(EXIT_FAILURE);
					}
				}

				sanitize_ipv6_prefix(&(filters.acceptsrc[filters.nacceptsrc]), filters.acceptsrclen[filters.nacceptsrc]);
				(filters.nacceptsrc)++;
				filters.acceptfilters_f=1;
				break;


			case 'g':	/* IPv6 Destination Address (accept) filter */
				if(filters.nacceptdst > MAX_ACCEPT_DST){
					puts("Too many IPv6 Destination Address (accept) filters.");
					exit(EXIT_FAILURE);
				}

				if((pref = strtok_r(optarg, "/", &lasts)) == NULL){
					printf("Error in IPv6 Destination Address (accept) filter number %u.\n", \
													filters.nacceptdst+1);
					exit(EXIT_FAILURE);
				}

				if ( inet_pton(AF_INET6, pref, &(filters.acceptdst[filters.nacceptdst])) <= 0){
					printf("Error in IPv6 Source Address (accept) filter number %u.\n", \
												    filters.nacceptdst+1);
					exit(EXIT_FAILURE);
				}

				if((charptr = strtok_r(NULL, " ", &lasts)) == NULL){
					filters.acceptdstlen[filters.nacceptdst] = 128;
				}
				else{
					filters.acceptdstlen[filters.nacceptdst] = atoi(charptr);
		
					if(filters.acceptdstlen[filters.nacceptdst] > 128){
						printf("Length error in IPv6 Source Address (accept) filter number %u.\n", \
													    filters.nacceptdst+1);
						exit(EXIT_FAILURE);
					}
				}
		
				sanitize_ipv6_prefix(&(filters.acceptdst[filters.nacceptdst]), filters.acceptdstlen[filters.nacceptdst]);
				(filters.nacceptdst)++;
				filters.acceptfilters_f=1;
				break;

			case 'B':	/* Link-layer Source Address (accept) filter */
				if(filters.nacceptlinksrc > MAX_ACCEPT_LINK_SRC){
					puts("Too many link-later Source Address (accept) filters.");
					exit(EXIT_FAILURE);
				}

				if(ether_pton(optarg, &(filters.acceptlinksrc[filters.nacceptlinksrc]), sizeof(struct ether_addr)) == 0){
					printf("Error in link-layer Source Address (accept) filter number %u.\n", \
											    filters.nacceptlinksrc+1);
					exit(EXIT_FAILURE);
				}
		
				(filters.nacceptlinksrc)++;
				filters.acceptfilters_f=1;
				break;

			case 'G':	/* Link Destination Address (accept) filter */
				if(filters.nacceptlinkdst > MAX_ACCEPT_LINK_DST){
					puts("Too many link-layer Destination Address (accept) filters.");
					exit(EXIT_FAILURE);
				}

				if(ether_pton(optarg, &(filters.acceptlinkdst[filters.nacceptlinkdst]), sizeof(struct ether_addr)) == 0){
					printf("Error in link-layer Destination Address (accept) filter number %u.\n",\
												    filters.nacceptlinkdst+1);
					exit(EXIT_FAILURE);
				}
		
				(filters.nacceptlinkdst)++;
				filters.acceptfilters_f=1;
				break;

			case 'F':	/* Flood source addresses */
				nsources= atoi(optarg);
				if(nsources == 0){
					puts("Invalid number of source addresses in option -F");
					exit(EXIT_FAILURE);
				}
		
				floods_f= 1;
				break;

			case 'T':	/* Flood source ports */
				nports= atoi(optarg);

				if(nports == 0){
					puts("Invalid number of source ports in option -T");
					exit(EXIT_FAILURE);
				}
		
				floodp_f= 1;
				break;

			case 'f':
				rand_src_f=1;
				break;

			case 'R':
				rand_link_src_f=1;
				break;

			case 'l':	/* "Loop mode */
				loop_f = 1;
				break;

			case 'r':
				if( Strnlen(optarg, LINE_BUFFER_SIZE-1) >= (LINE_BUFFER_SIZE-1)){
					puts("tcp6: -r option is too long");
					exit(EXIT_FAILURE);
				}

				sscanf(optarg, "%lu%s", &rate, line);
				line[LINE_BUFFER_SIZE-1]=0;

				if(strncmp(line, "pps", 3) == 0)
					pps_f=1;
				else if(strncmp(line, "bps", 3) == 0)
					bps_f=1;
				else{
					puts("tcp6: Unknown unit of for the rate limit ('-r' option). Unit should be 'bps' or 'pps'");
					exit(EXIT_FAILURE);
				}

				break;


			case 'z':	/* Sleep option */
				nsleep=atoi(optarg);
				if(nsleep==0){
					puts("Invalid number of seconds in '-z' option");
					exit(EXIT_FAILURE);
				}
	
				sleep_f=1;
				break;

			case 'L':	/* "Listen mode */
				listen_f = 1;
				break;

			case 'v':	/* Be verbose */
				(idata.verbose_f)++;
				break;

			case 'p':	/* Probe mode */
				probe_f=1;
				break;

			case 'x':	/* Number of retrnasmissions */
				retrans= atoi(optarg);
				retrans_f=1;
				break;

			case 'Y':
				if(strncmp(optarg, "dump", MAX_CMDLINE_OPT_LEN) == 0){
					debug= DEBUG_DUMP;
				}
				else if(strncmp(optarg, "script", MAX_CMDLINE_OPT_LEN) == 0){
					debug= DEBUG_SCRIPT;
				}
				else{
					puts("Error: Unknown open mode in '-Y' option");
					exit(EXIT_FAILURE);
				}

				debug_f=1;
				break;

			case 'h':	/* Help */
				print_help();
				exit(EXIT_FAILURE);
				break;

			default:
				usage();
				exit(EXIT_FAILURE);
				break;
		
		} /* switch */
	} /* while(getopt) */

	if(geteuid()) {
		puts("tcp6 needs root privileges to run.");
		exit(EXIT_FAILURE);
	}

	srandom(time(NULL));

	/*
	  If the flood option ("-F") has been specified, but no prefix has been specified,
	  assume a /64 prefix.
	*/
	if(floods_f && !idata.srcprefix_f){
		idata.srcpreflen=64;
	}

	if(idata.srcprefix_f && !floods_f && loop_f){
		floods_f=1;
		nsources= 1;
	}

	if(!(idata.dstaddr_f) && !listen_f){	/* Must specify IPv6 Destination Address if listening mode not used */
		puts("IPv6 Destination Address not specified (and listening mode not selected)");
		exit(EXIT_FAILURE);
	}

	if(rhbytes_f && data_f){
		puts("Cannot set '--data' and '--payload-size' at the same time");
		exit(EXIT_FAILURE);
	}

	if(!idata.iface_f){
		if(idata.dstaddr_f && IN6_IS_ADDR_LINKLOCAL(&(idata.dstaddr))){
			puts("Must specify a network interface for link-local destinations");
			exit(EXIT_FAILURE);
		}
		else if(listen_f){
			puts("Must specify a network interface when employing the 'listenging' mode");
			exit(EXIT_FAILURE);
		}
	}

	if(load_dst_and_pcap(&idata, (idata.dstaddr_f?LOAD_SRC_NXT_HOP:LOAD_PCAP_ONLY)) == FAILURE){
		puts("Error while learning Souce Address and Next Hop");
		exit(EXIT_FAILURE);
	}

	release_privileges();

	if(data_f){
		data[datalen]=0;

		if(!string_escapes(data, &datalen, DATA_BUFFER_LEN-1)){
			puts("Error in data string option ('-Z')");
			exit(EXIT_FAILURE);
		}

		data[datalen]=0;
	}

	if(!floods_f)
		nsources=1;

	if(!floodp_f)
		nports=1;

	if(!sleep_f)
		nsleep=1;

	if(sleep_f && (pps_f || bps_f)){
		puts("Cannot specify a rate-limit (-r) and a sleep time at the same time");
		exit(EXIT_FAILURE);
	}

	if(pps_f && bps_f){
		puts("Cannot specify a rate-limit in bps and pps at the same time");
		exit(EXIT_FAILURE);
	}

	if(pps_f){
		if(rate < 1)
			rate=1;

		pktinterval= 1000000/rate;
	}

	if(bps_f){
		packetsize= MIN_IPV6_HLEN +  sizeof(struct tcp_hdr) + rhbytes;

		for(i=0; i < ndstopthdr; i++)
			packetsize+= dstopthdrlen[i];

		for(i=0; i < ndstoptuhdr; i++)
			packetsize+= dstoptuhdrlen[i];

		for(i=0; i < nhbhopthdr; i++)
			packetsize+= hbhopthdrlen[i];

		if(fragh_f)
			packetsize+= sizeof(struct ip6_frag);			

		if(rate == 0 || ((packetsize * 8)/rate) <= 0)
			pktinterval= 1000000;
		else
			pktinterval= ((packetsize * 8)/rate) * 1000000;
	}

	/* We Default to 1000 pps */
	if(!pps_f && !bps_f)
		pktinterval= 1000;

	if( !fragh_f && dstoptuhdr_f){
		puts("Dst. Options Header (Unfragmentable Part) set, but Fragmentation not specified");
		exit(EXIT_FAILURE);
	}
    
	if(fragh_f)
		idata.max_packet_size = MAX_IPV6_PAYLOAD + MIN_IPV6_HLEN;
	else
		idata.max_packet_size = idata.mtu;

	/*
	 *  If we are going to send packets to a specified target, we must set some default values
	 */
	if(idata.dstaddr_f){
		if(!tcpflags_auto_f && !tcpflags_f && !tcpopen_f && !tcpclose_f)
			tcpflags= tcpflags | TH_ACK;

		if(!tcpack_f)
			tcpack= random();

		if(!tcpseq_f)
			tcpseq= random();

		if(!srcport_f)
			srcport= random();

		if(!dstport_f)
			dstport= random();

		if(!tcpurg_f)
			tcpurg= 0;
	}

	/* By default, we randomize the TCP Window */
	if(!tcpwin_f)
		tcpwin= ((u_int16_t) random() + 1500) & (u_int16_t)0x7f00;

	if(!rhbytes_f)
		rhbytes=0;

	if(idata.verbose_f){
		print_attack_info(&idata);
	}

	/*
	   Set filter for IPv6 packets (find_ipv6_router() set its own filter fore receiving RAs)
	 */
	if(pcap_compile(idata.pfd, &pcap_filter, PCAP_TCPIPV6_NS_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
		printf("pcap_compile(): %s", pcap_geterr(idata.pfd));
		exit(EXIT_FAILURE);
	}
    
	if(pcap_setfilter(idata.pfd, &pcap_filter) == -1){
		printf("pcap_setfilter(): %s", pcap_geterr(idata.pfd));
		exit(EXIT_FAILURE);
	}

	pcap_freecode(&pcap_filter);

	/* Set initial contents of the attack packet */
	init_packet_data(&idata);
	addr_key= random();

	if(sleep_f)
		pktinterval= (nsleep * 1000000)/(nsources * nports);

	timeout.tv_sec=  pktinterval / 1000000 ;	
	timeout.tv_usec= pktinterval % 1000000;
	stimeout= timeout;

	if(window_f){
		if(window == WIN_MODULATE && !winmodulate_f){
			win1_size= WIN_MODULATE_CLOSED_SIZE;
			time1_len= WIN_MODULATE_CLOSED_LEN;
			win2_size= WIN_MODULATE_OPEN_SIZE;
			time2_len= WIN_MODULATE_OPEN_LEN;
		}
	}

	if(window_f && window == WIN_MODULATE){
		if(gettimeofday(&wmtimeout, NULL) == -1){
			if(idata.verbose_f)
				perror("tcp6");

			exit(EXIT_FAILURE);
		}

		tcpwinm= win1_size;
	}
    

	if(probe_f){
		end_f=0;

		if(!dstport_f)
			dstport= 80;

		if(!srcport_f)
			srcport= 50000 + random() % 15000; /* We select ports from the "high ports" range */

		if(!rto_f)
			rto=1;

		if(!retrans_f)
			retrans=0;

		retr=0;
		retrans++;

		FD_ZERO(&sset);
		FD_SET(idata.fd, &sset);

		lastprobe.tv_sec= 0;	
		lastprobe.tv_usec=0;

		while(!end_f){
			if(gettimeofday(&curtime, NULL) == -1){
				if(idata.verbose_f)
					perror("tcp6");

				exit(EXIT_FAILURE);
			}			

			if(is_time_elapsed(&curtime, &lastprobe, 1) && retr < retrans){
				retr++;
				lastprobe= curtime;
				send_packet(&idata, NULL, NULL);
			}

			if(is_time_elapsed(&curtime, &lastprobe, rto) && retr >= retrans){
				end_f=1;
				break;
			}

			rset= sset;
			timeout.tv_usec=0;
			timeout.tv_sec= (rto < 1)?rto:1;

			if((sel=select(idata.fd+1, &rset, NULL, NULL, &timeout)) == -1){
				if(errno == EINTR){
					continue;
				}
				else{
					puts("Error in select()");
					exit(EXIT_FAILURE);
				}
			}

			if(sel){
				if(FD_ISSET(idata.fd, &rset)){
					/* Read a packet */
					if((r=pcap_next_ex(idata.pfd, &pkthdr, &pktdata)) == -1){
						printf("pcap_next_ex(): %s", pcap_geterr(idata.pfd));
						exit(EXIT_FAILURE);
					}
					else if(r == 0){
						continue; /* Should never happen */
					}

					pkt_ether = (struct ether_header *) pktdata;
					pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata.linkhsize);
					pkt_tcp= (struct tcp_hdr *) ( (char *) pkt_ipv6 + MIN_IPV6_HLEN);
					pkt_ns= (struct nd_neighbor_solicit *) ( (char *) pkt_ipv6 + MIN_IPV6_HLEN);
					pkt_end = (unsigned char *) pktdata + pkthdr->caplen;
					pkt_tcp_flags= pkt_tcp->th_flags;

					/* Check that we are able to look into the IPv6 header */
					if( (pkt_end -  pktdata) < (idata.linkhsize + MIN_IPV6_HLEN))
						continue;

					if(is_eq_in6_addr(&(pkt_ipv6->ip6_src), &(idata.srcaddr))){
						continue;
					}

					if(!is_eq_in6_addr(&(pkt_ipv6->ip6_dst), &(idata.srcaddr))){
						continue;
					}

					if(pkt_tcp->th_sport != htons(dstport)){
						continue;
					}

					if(pkt_tcp->th_dport != htons(srcport)){
						continue;
					}

					/* The TCP checksum must be valid */
					if(in_chksum(pkt_ipv6, pkt_tcp, pkt_end-((unsigned char *)pkt_tcp), IPPROTO_TCP) != 0)
						continue;

					printf("PROBE:RESPONSE:%s%s%s%s%s%s\n", ((pkt_tcp_flags & TH_FIN)?"F":""), \
						((pkt_tcp_flags & TH_SYN)?"S":""), \
						((pkt_tcp_flags & TH_RST)?"R":""), ((pkt_tcp_flags & TH_PUSH)?"P":""),\
						((pkt_tcp_flags & TH_ACK)?"A":""), ((pkt_tcp_flags & TH_URG)?"U":""));

					exit(0);
				}
			}
		}

		puts("PROBE:TIMEOUT:");
		exit(0);
	}


	/* Fire a TCP segment if an IPv6 Destination Address was specified */
	if(!listen_f && idata.dstaddr_f){
		if(loop_f){
			if(idata.verbose_f)
				printf("Sending TCP segments every %u second%s...\n", nsleep, \
											((nsleep>1)?"s":""));
		}

		do{
				send_packet(&idata, NULL, NULL);

				if(loop_f && (sel=select(0, NULL, NULL, NULL, &timeout)) == -1){
					if(errno == EINTR){
						continue;
					}
					else{
						puts("Error in select()");
						exit(EXIT_FAILURE);
					}
				}
		}while(loop_f);

		if(idata.verbose_f)    
			puts("Initial attack packet(s) sent successfully.");

		exit(EXIT_SUCCESS);
	}
	else if(listen_f){
		if( (idata.fd= pcap_fileno(idata.pfd)) == -1){
			puts("Error obtaining descriptor number for pcap_t");
			exit(EXIT_FAILURE);
		}

		FD_ZERO(&sset);
		FD_SET(idata.fd, &sset);

		if(idata.verbose_f){
			print_filters(&idata, &filters);
			puts("Listening to incoming IPv6 messages...");
		}

		while(listen_f){
			rset= sset;

			timeout= stimeout;

			if((sel=select(idata.fd+1, &rset, NULL, NULL, ((floods_f || floodp_f) && !donesending_f)?(&timeout):NULL)) == -1){
				if(errno == EINTR){
					continue;
				}
				else{
					puts("Error in select()");
					exit(EXIT_FAILURE);
				}
			}

			/* If there are some bits set, we need to check whether it's time to send packets */
			if(sel){
				if(gettimeofday(&curtime, NULL) == -1){
					if(idata.verbose_f)
						perror("tcp6");

					exit(EXIT_FAILURE);
				}

				if(window == WIN_MODULATE){
					if(tcpwinm == win1_size){
						if( (curtime.tv_sec - wmtimeout.tv_sec) >= time1_len){
							wmtimeout= curtime;
							tcpwinm = win2_size;
						}
					}
					else{
						if( (curtime.tv_sec - wmtimeout.tv_sec) >= time2_len){
							wmtimeout= curtime;
							tcpwinm = win1_size;
						}
					}
				}
			}

			if(FD_ISSET(idata.fd, &rset)){
				/* Read a packet */
				if((r=pcap_next_ex(idata.pfd, &pkthdr, &pktdata)) == -1){
					printf("pcap_next_ex(): %s", pcap_geterr(idata.pfd));
					exit(EXIT_FAILURE);
				}
				else if(r == 0){
					continue; /* Should never happen */
				}

				pkt_ether = (struct ether_header *) pktdata;
				pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata.linkhsize);
				pkt_tcp= (struct tcp_hdr *) ( (char *) pkt_ipv6 + MIN_IPV6_HLEN);
				pkt_ns= (struct nd_neighbor_solicit *) ( (char *) pkt_ipv6 + MIN_IPV6_HLEN);
				pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

				/* Check that we are able to look into the IPv6 header */
				if( (pkt_end -  pktdata) < (idata.linkhsize + MIN_IPV6_HLEN))
					continue;

				accepted_f=0;

				if(idata.type == DLT_EN10MB && idata.flags != IFACE_LOOPBACK){
					if(filters.nblocklinksrc){
						if(match_ether(filters.blocklinksrc, filters.nblocklinksrc, &(pkt_ether->src))){
							if(idata.verbose_f>1)
								print_filter_result(&idata, pktdata, BLOCKED);
		
							continue;
						}
					}

					if(filters.nblocklinkdst){
						if(match_ether(filters.blocklinkdst, filters.nblocklinkdst, &(pkt_ether->dst))){
							if(idata.verbose_f>1)
								print_filter_result(&idata, pktdata, BLOCKED);
		
							continue;
						}
					}
				}
	
				if(filters.nblocksrc){
					if(match_ipv6(filters.blocksrc, filters.blocksrclen, filters.nblocksrc, &(pkt_ipv6->ip6_src))){
						if(idata.verbose_f>1)
							print_filter_result(&idata, pktdata, BLOCKED);
		
						continue;
					}
				}
	
				if(filters.nblockdst){
					if(match_ipv6(filters.blockdst, filters.blockdstlen, filters.nblockdst, &(pkt_ipv6->ip6_dst))){
						if(idata.verbose_f>1)
							print_filter_result(&idata, pktdata, BLOCKED);
		
						continue;
					}
				}

				if(idata.type == DLT_EN10MB && idata.flags != IFACE_LOOPBACK){	
					if(filters.nacceptlinksrc){
						if(match_ether(filters.acceptlinksrc, filters.nacceptlinksrc, &(pkt_ether->src)))
							accepted_f=1;
					}

					if(filters.nacceptlinkdst && !accepted_f){
						if(match_ether(filters.acceptlinkdst, filters.nacceptlinkdst, &(pkt_ether->dst)))
							accepted_f= 1;
					}
				}

				if(filters.nacceptsrc && !accepted_f){
					if(match_ipv6(filters.acceptsrc, filters.acceptsrclen, filters.nacceptsrc, &(pkt_ipv6->ip6_src)))
						accepted_f= 1;
				}

				if(filters.nacceptdst && !accepted_f){
					if(match_ipv6(filters.acceptdst, filters.acceptdstlen, filters.nacceptdst, &(pkt_ipv6->ip6_dst)))
						accepted_f=1;
				}
	
				if(filters.acceptfilters_f && !accepted_f){
					if(idata.verbose_f>1)
						print_filter_result(&idata, pktdata, BLOCKED);

					continue;
				}

				if(idata.verbose_f>1)
					print_filter_result(&idata, pktdata, ACCEPTED);

				if(pkt_ipv6->ip6_nxt == IPPROTO_TCP){
					/* Check that we are able to look into the TCP header */
					if( (pkt_end -  pktdata) < (idata.linkhsize + MIN_IPV6_HLEN + sizeof(struct tcp_hdr))){
						continue;
					}

					if(idata.dstaddr_f){
						if(!floods_f){
							/* Discard our own packets */
							if(is_eq_in6_addr(&(pkt_ipv6->ip6_src), &(idata.srcaddr))){
								continue;
							}

							if(!is_eq_in6_addr(&(pkt_ipv6->ip6_dst), &(idata.srcaddr))){
								continue;
							}
						}
						else{
							/* Discard our own packets */
							if(!is_eq_in6_addr(&(pkt_ipv6->ip6_src), &(idata.dstaddr))){
								continue;
							}

							if(useaddrkey_f){
								if(pkt_ipv6->ip6_src.s6_addr16[5] ==  (pkt_ipv6->ip6_src.s6_addr16[4] ^ addr_key) && \
									pkt_ipv6->ip6_src.s6_addr16[7] ==  (pkt_ipv6->ip6_src.s6_addr16[6] ^ addr_key)){
									continue;
								}

								if(pkt_ipv6->ip6_dst.s6_addr16[5] !=  (pkt_ipv6->ip6_dst.s6_addr16[4] ^ addr_key) || \
									pkt_ipv6->ip6_dst.s6_addr16[7] !=  (pkt_ipv6->ip6_dst.s6_addr16[6] ^ addr_key)){
									continue;
								}
							}
						}

						/* The TCP checksum must be valid */
						if(in_chksum(pkt_ipv6, pkt_tcp, pkt_end-((unsigned char *)pkt_tcp), IPPROTO_TCP) != 0)
							continue;

						if(pkt_tcp->th_sport != htons(dstport)){
							continue;
						}

						if(!floodp_f && pkt_tcp->th_dport != htons(srcport)){
							continue;
						}
					}

					/* Send a TCP segment */
					send_packet(&idata, pktdata, pkthdr);
				}
				else if(pkt_ipv6->ip6_nxt == IPPROTO_ICMPV6){

					/* Check that we are able to look into the NS header */
					if( (pkt_end -  pktdata) < (idata.linkhsize + MIN_IPV6_HLEN + sizeof(struct nd_neighbor_solicit))){
						continue;
					}

					if(idata.type == DLT_EN10MB && idata.flags != IFACE_LOOPBACK){
						if(floods_f){
							if(useaddrkey_f){
								if(pkt_ns->nd_ns_target.s6_addr16[5] !=  (pkt_ns->nd_ns_target.s6_addr16[4] ^ addr_key) || \
									pkt_ns->nd_ns_target.s6_addr16[7] !=  (pkt_ns->nd_ns_target.s6_addr16[6] ^ addr_key)){
									continue;
								}
							}

							/* Check that the target address belongs to the prefix from which we are sending packets */
							if(!match_ipv6(&(idata.srcaddr), &idata.srcpreflen, 1, &(pkt_ns->nd_ns_target))){
								continue;
							}
						}
						else{
							if(!is_eq_in6_addr( &(pkt_ns->nd_ns_target), &(idata.srcaddr)) ){
								continue;
							}
						}

						if(send_neighbor_advert(&idata, idata.pfd, pktdata) == -1){
							puts("Error sending Neighbor Advertisement");
							exit(EXIT_FAILURE);
						}
					}
				}
			}
			if((!sel || is_time_elapsed(&curtime, &lastprobe, pktinterval)) && !donesending_f){
				lastprobe= curtime;
				send_packet(&idata, NULL, NULL);
			}
		}
    
		exit(EXIT_SUCCESS);
	}

	if(!(idata.dstaddr_f) && !listen_f){
		puts("Error: Nothing to send! (Destination Address left unspecified, and not using listening mode)");
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
}



/*
 * Function: init_packet_data()
 *
 * Initialize the contents of the attack packet (Ethernet header, IPv6 Header, and ICMPv6 header)
 * that are expected to remain constant for the specified attack.
 */
void init_packet_data(struct iface_data *idata){
	ethernet= (struct ether_header *) buffer;
	v6buffer = buffer + idata->linkhsize;
	ipv6 = (struct ip6_hdr *) v6buffer;

	if(idata->flags != IFACE_TUNNEL && idata->flags != IFACE_LOOPBACK){
		ethernet->src = idata->hsrcaddr;
		ethernet->dst = idata->hdstaddr;
		ethernet->ether_type = htons(ETHERTYPE_IPV6);
	}

	ipv6->ip6_flow=0;
	ipv6->ip6_vfc= 0x60;
	ipv6->ip6_hlim= hoplimit;
	ipv6->ip6_src= idata->srcaddr;
	ipv6->ip6_dst= idata->dstaddr;

	prev_nh = (unsigned char *) &(ipv6->ip6_nxt);

	ptr = (unsigned char *) v6buffer + MIN_IPV6_HLEN;
    
	if(hbhopthdr_f){
		hbhopthdrs=0;
	
		while(hbhopthdrs < nhbhopthdr){
			if((ptr+ hbhopthdrlen[hbhopthdrs]) > (v6buffer+ idata->mtu)){
				puts("Packet too large while processing HBH Opt. Header");
				exit(EXIT_FAILURE);
			}
	    
			*prev_nh = IPPROTO_HOPOPTS;
			prev_nh = ptr;
			memcpy(ptr, hbhopthdr[hbhopthdrs], hbhopthdrlen[hbhopthdrs]);
			ptr = ptr + hbhopthdrlen[hbhopthdrs];
			hbhopthdrs++;
		}
	}

	if(dstoptuhdr_f){
		dstoptuhdrs=0;
	
		while(dstoptuhdrs < ndstoptuhdr){
			if((ptr+ dstoptuhdrlen[dstoptuhdrs]) > (v6buffer+ idata->mtu)){
				puts("Packet too large while processing Dest. Opt. Header (Unfrag. Part)");
				exit(EXIT_FAILURE);
			}

			*prev_nh = IPPROTO_DSTOPTS;
			prev_nh = ptr;
			memcpy(ptr, dstoptuhdr[dstoptuhdrs], dstoptuhdrlen[dstoptuhdrs]);
			ptr = ptr + dstoptuhdrlen[dstoptuhdrs];
			dstoptuhdrs++;
		}
	}

	/* Everything that follows is the Fragmentable Part of the packet */
	fragpart = ptr;

	if(fragh_f){
		/* Check that we are able to send the Unfragmentable Part, together with a 
		   Fragment Header and a chunk data over our link layer
		 */
		if( (fragpart+sizeof(fraghdr)+nfrags) > (v6buffer+idata->mtu)){
			puts("Unfragmentable part too large for current MTU");
			exit(EXIT_FAILURE);
		}

		/* We prepare a separete Fragment Header, but we do not include it in the packet to be sent.
		   This Fragment Header will be used (an assembled with the rest of the packet by the 
		   send_packet() function.
		*/
		bzero(&fraghdr, FRAG_HDR_SIZE);
		*prev_nh = IPPROTO_FRAGMENT;
		prev_nh = (unsigned char *) &fraghdr;
	}

	if(dstopthdr_f){
		dstopthdrs=0;
	
		while(dstopthdrs < ndstopthdr){
			if((ptr+ dstopthdrlen[dstopthdrs]) > (v6buffer+ idata->max_packet_size)){
			puts("Packet too large while processing Dest. Opt. Header (should be using the Frag. option?)");
			exit(EXIT_FAILURE);
			}
    
			*prev_nh = IPPROTO_DSTOPTS;
			prev_nh = ptr;
			memcpy(ptr, dstopthdr[dstopthdrs], dstopthdrlen[dstopthdrs]);
			ptr = ptr + dstopthdrlen[dstopthdrs];
			dstopthdrs++;
		}
	}


	*prev_nh = IPPROTO_TCP;

	startofprefixes=ptr;
}



/*
 * Function: send_packet()
 *
 * Initialize the remaining fields of the TCP segment, and send the attack packet(s).
 */
void send_packet(struct iface_data *idata, const u_char *pktdata, struct pcap_pkthdr *pkthdr){
	static unsigned int	sources=0, ports=0;	
	ptr=startofprefixes;

	startclose_f= 0;
	senddata_f= 0;

	if(pktdata != NULL){   /* Sending a TCP segment in response to a received packet */
		pkt_ether = (struct ether_header *) pktdata;
		pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata->linkhsize);
		pkt_tcp= (struct tcp_hdr *)( (char *) pkt_ipv6 + sizeof(struct ip6_hdr));
		pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

		/* The packet length is the minimum of what we capured, and what is specified in the
		   IPv6 Total Lenght field
		 */
		if( pkt_end > ((unsigned char *)pkt_ipv6 + sizeof(struct ip6_hdr) + pkt_ipv6->ip6_plen) )
			pkt_end = (unsigned char *)pkt_ipv6 + sizeof(struct ip6_hdr) + pkt_ipv6->ip6_plen;


		pkt_ipv6addr = &(pkt_ipv6->ip6_src);

		/*
		   We don't send any packets if the Source Address of the captured packet is the unspecified
		   address or a multicast address
		 */
		if(IN6_IS_ADDR_UNSPECIFIED(pkt_ipv6addr) || IN6_IS_ADDR_MULTICAST(pkt_ipv6addr)){
			return;
		}
		else{
			ipv6->ip6_dst = pkt_ipv6->ip6_src;

			if(idata->type == DLT_EN10MB && idata->flags != IFACE_LOOPBACK)
				ethernet->dst = pkt_ether->src;
		}

		pkt_ipv6addr = &(pkt_ipv6->ip6_dst);

		/*
		   We do not send any packets if the Destination Address of the captured packet is the unspecified
		   address or a multicast address
		 */
		if(IN6_IS_ADDR_MULTICAST(pkt_ipv6addr) || IN6_IS_ADDR_MULTICAST(pkt_ipv6addr)){
			return;
		}
		else{
			ipv6->ip6_src = pkt_ipv6->ip6_dst;

			if(idata->type == DLT_EN10MB && idata->flags != IFACE_LOOPBACK)
				ethernet->src = pkt_ether->dst;
		}


		if( (ptr+sizeof(struct tcp_hdr)) > (v6buffer+ idata->max_packet_size)){
			puts("Packet Too Large while inserting TCP header");
			exit(EXIT_FAILURE);
		}

		/* If we are setting the flags automatically, do not respond to RST segments */
		if((tcpflags_auto_f || tcpopen_f || tcpclose_f) && pkt_tcp->th_flags & TH_RST)
			return;

		tcp = (struct tcp_hdr *) ptr;
		bzero(tcp, sizeof(struct tcp_hdr));

		tcp->th_sport= pkt_tcp->th_dport;
		tcp->th_dport= pkt_tcp->th_sport;

		if(tcpseq_f)
			tcp->th_seq= htonl(tcpseq);
		else
			tcp->th_seq = pkt_tcp->th_ack;

		if( pkt_tcp->th_flags & TH_SYN){
			if(tcpopen_f){
				if(tcpopen == OPEN_PASSIVE){
					/* If it is a pure SYN, respond with a SYN/ACK */
					if(!(pkt_tcp->th_flags & TH_ACK)){
						tcp->th_flags = tcp->th_flags | TH_SYN | TH_ACK;
						tcp->th_seq= random();
						tcp->th_ack= htonl(ntohl(pkt_tcp->th_seq) + ((pkt_end - (unsigned char *)pkt_tcp) - (pkt_tcp->th_off << 2)));
						tcp->th_ack= htonl(ntohl(tcp->th_ack) + ((pkt_tcp->th_flags & TH_FIN)?1:0) + \
							((pkt_tcp->th_flags & TH_SYN)?1:0));
					}
				}
				else if(tcpopen == OPEN_SIMULTANEOUS){
					/* If it is a pure SYN, respond with a SYN */
					if(!(pkt_tcp->th_flags & TH_ACK)){
						tcp->th_flags = tcp->th_flags | TH_SYN;
						tcp->th_seq= random();
						tcp->th_ack= 0;
					}
					else{
					/* If we receive a SYN/ACK (product of the above SYN), send a SYN/ACK */
						tcp->th_flags = tcp->th_flags | TH_SYN | TH_ACK;
						tcp->th_seq= (pkt_tcp->th_ack) - (rhbytes + 1);
						tcp->th_ack= htonl(ntohl(pkt_tcp->th_seq) + ((pkt_end - (unsigned char *)pkt_tcp) - (pkt_tcp->th_off << 2)));
						tcp->th_ack= htonl(ntohl(tcp->th_ack) + ((pkt_tcp->th_flags & TH_FIN)?1:0) + \
							((pkt_tcp->th_flags & TH_SYN)?1:0));

						if(data_f)
							senddata_f= 1;
					}
				}
				else if(tcpopen == OPEN_ABORT){
					/* If we receive a SYN, send RST */
					tcp->th_flags = tcp->th_flags | TH_RST | TH_ACK;
					if(pkt_tcp->th_flags & TH_ACK)
						tcp->th_seq= pkt_tcp->th_ack;
					else
						tcp->th_seq= 0;

					tcp->th_ack= htonl(ntohl(pkt_tcp->th_seq) + ((pkt_end - (unsigned char *)pkt_tcp) - (pkt_tcp->th_off << 2)));
					tcp->th_ack= htonl(ntohl(tcp->th_ack) + ((pkt_tcp->th_flags & TH_FIN)?1:0) + \
							((pkt_tcp->th_flags & TH_SYN)?1:0));
				}
			}
			else{
				/* We have received a SYN/ACK */
				if(pkt_tcp->th_flags & TH_ACK){
					/* It's a SYN/ACK, and we are doing an active open */
					if(tcpack_f){
						tcp->th_ack= htonl(tcpack);
					}
					else{
						if( !tcpflags_f || (tcpflags_f && (tcpflags & TH_ACK))){
							tcp->th_ack= pkt_tcp->th_seq;

							if(ackdata_f){
								tcp->th_ack= htonl(ntohl(tcp->th_ack) + ((pkt_end - (unsigned char *)pkt_tcp) - (pkt_tcp->th_off << 2)));
							}

							if(ackflags_f){
								tcp->th_ack= htonl(ntohl(tcp->th_ack) + ((pkt_tcp->th_flags & TH_FIN)?1:0) + \
										((pkt_tcp->th_flags & TH_SYN)?1:0));
							}
						}
					}

					if(tcpflags_f){
						tcp->th_flags= tcpflags;
					}
					else{
						tcp->th_flags= TH_ACK;

						/* If the incoming packet was a SYN, we should respond with a SYN/ACK */
						if( (pkt_tcp->th_flags & TH_SYN) && !(pkt_tcp->th_flags & TH_ACK))
								tcp->th_flags = tcp->th_flags | TH_SYN;
					}

					if(data_f)
						senddata_f= 1;

					if(tcpclose_f && tcpclose != CLOSE_FIN_WAIT_2 && tcpclose != CLOSE_PASSIVE)
						startclose_f= 1;
				}
				else{
					/* Simple SYN segment */
					if(tcpack_f){
						tcp->th_ack= htonl(tcpack);
					}
					else{
						if( !tcpflags_f || (tcpflags_f && (tcpflags & TH_ACK))){
							tcp->th_ack= pkt_tcp->th_seq;

							if(ackdata_f){
								tcp->th_ack= htonl(ntohl(tcp->th_ack) + ((pkt_end - (unsigned char *)pkt_tcp) - (pkt_tcp->th_off << 2)));
							}

							if(ackflags_f){
								tcp->th_ack= htonl(ntohl(tcp->th_ack) + ((pkt_tcp->th_flags & TH_FIN)?1:0) + \
										((pkt_tcp->th_flags & TH_SYN)?1:0));
							}
						}
					}

					if(tcpflags_f){
						tcp->th_flags= tcpflags;
					}
					else{
						tcp->th_flags= TH_ACK;

						/* If the incoming packet was a SYN, we should respond with a SYN/ACK */
						if( (pkt_tcp->th_flags & TH_SYN) && !(pkt_tcp->th_flags & TH_ACK))
								tcp->th_flags = tcp->th_flags | TH_SYN;
					}
				}
			}

			tcp->th_win= htons(tcpwin);
		}
		else if(pkt_tcp->th_flags & TH_FIN){
			if(tcpclose_f && (tcpclose == CLOSE_SIMULTANEOUS || tcpclose == CLOSE_PASSIVE || tcpclose == CLOSE_ABORT)){
				if(tcpclose == CLOSE_SIMULTANEOUS){
					tcp->th_flags = TH_ACK | TH_FIN;
					tcp->th_seq= pkt_tcp->th_ack;
					tcp->th_ack= pkt_tcp->th_seq;
				}
				else if(tcpclose == CLOSE_PASSIVE){
					tcp->th_flags = TH_ACK | TH_FIN;
					tcp->th_seq= pkt_tcp->th_ack;
					tcp->th_ack= htonl(ntohl(pkt_tcp->th_seq) + ((pkt_end - (unsigned char *)pkt_tcp) - (pkt_tcp->th_off << 2)));
					tcp->th_ack= htonl(ntohl(tcp->th_ack) + ((pkt_tcp->th_flags & TH_FIN)?1:0) + \
								((pkt_tcp->th_flags & TH_SYN)?1:0));
				}
				else if(tcpclose == CLOSE_ABORT){
					tcp->th_flags = TH_ACK | TH_RST;
					tcp->th_seq= pkt_tcp->th_ack;
					tcp->th_ack= htonl(ntohl(pkt_tcp->th_seq) + ((pkt_end - (unsigned char *)pkt_tcp) - (pkt_tcp->th_off << 2)));
					tcp->th_ack= htonl(ntohl(tcp->th_ack) + ((pkt_tcp->th_flags & TH_FIN)?1:0) + \
							((pkt_tcp->th_flags & TH_SYN)?1:0));
				}
			}
			else{
				if(tcpflags_f){
					tcp->th_flags= tcpflags;
				}
				else{
					tcp->th_flags= TH_ACK;
				}

				if(tcpack_f){
					tcp->th_ack= htonl(tcpack);
				}
				else{
					if( !tcpflags_f || (tcpflags_f && (tcpflags & TH_ACK))){
						tcp->th_ack= pkt_tcp->th_seq;

						if(ackdata_f){
							tcp->th_ack= htonl(ntohl(tcp->th_ack) + ((pkt_end - (unsigned char *)pkt_tcp) - (pkt_tcp->th_off << 2)));
						}

						if(ackflags_f && !(tcpclose_f && tcpclose == CLOSE_LAST_ACK) && !(tcpclose_f && tcpclose == CLOSE_FIN_WAIT_1)){
							tcp->th_ack= htonl(ntohl(tcp->th_ack) + ((pkt_tcp->th_flags & TH_FIN)?1:0) + \
									((pkt_tcp->th_flags & TH_SYN)?1:0));
						}
					}
				}
			}

			if(window_f){
				if(window == WIN_CLOSED){
					tcp->th_win= htons(0);
				}
				else if(window == WIN_MODULATE){
					tcp->th_win= htons(tcpwinm);
				}
			}
			else
				tcp->th_win= htons(tcpwin);
		}
		else if(pkt_tcp->th_flags & TH_ACK){
			if(tcpclose_f && tcpclose == CLOSE_ABORT){
				tcp->th_flags = TH_ACK | TH_RST;
				tcp->th_seq= pkt_tcp->th_ack;
				tcp->th_ack= htonl(ntohl(pkt_tcp->th_seq) + ((pkt_tcp->th_flags & TH_FIN)?1:0) + \
								((pkt_tcp->th_flags & TH_SYN)?1:0));
			}
			else{
				if(tcpflags_f){
					tcp->th_flags= tcpflags;
				}
				else{
					tcp->th_flags= TH_ACK;
				}

				if(tcpack_f){
					tcp->th_ack= htonl(tcpack);
				}
				else{
					if( !tcpflags_f || (tcpflags_f && (tcpflags & TH_ACK))){
						tcp->th_ack= pkt_tcp->th_seq;

						if(ackdata_f){
							tcp->th_ack= htonl(ntohl(tcp->th_ack) + ((pkt_end - (unsigned char *)pkt_tcp) - (pkt_tcp->th_off << 2)));
						}

						if(ackflags_f){
							tcp->th_ack= htonl(ntohl(tcp->th_ack) + ((pkt_tcp->th_flags & TH_FIN)?1:0) + \
									((pkt_tcp->th_flags & TH_SYN)?1:0));
						}
					}
				}
			}

			if(window_f){
				if(window == WIN_CLOSED){
					tcp->th_win= htons(0);
				}
				else if(window == WIN_MODULATE){
					tcp->th_win= htons(tcpwinm);
				}
			}
			else
				tcp->th_win= htons(tcpwin);
		}

		tcp->th_urp= htons(tcpurg);

		/* Current version of tcp6 does not support sending TCP options */
		tcp->th_off= sizeof(struct tcp_hdr) >> 2;
		ptr+= tcp->th_off << 2;

		if(rhbytes){
			if( (ptr + rhbytes) > v6buffer+ idata->max_packet_size){
				puts("Packet Too Large while inserting TCP segment");
				exit(EXIT_FAILURE);
			}

			while(rhbytes>=4){
				*(u_int32_t *)ptr = random();
				ptr += sizeof(u_int32_t);
				rhbytes -= sizeof(u_int32_t);
			}

			while(rhbytes>0){
				*(u_int8_t *) ptr= (u_int8_t) random();
				ptr++;
				rhbytes--;
			}
		}

		tcp->th_sum = 0;
		tcp->th_sum = in_chksum(v6buffer, tcp, ptr-((unsigned char *)tcp), IPPROTO_TCP);

		frag_and_send(idata);

		if(senddata_f){
			tcp->th_seq= htonl( ntohl(tcp->th_seq) + ptr-((unsigned char *)tcp + (tcp->th_off << 2)));
			ptr= (unsigned char *)tcp + sizeof(struct tcp_hdr);

			if((ptr+ datalen) > (v6buffer + idata->max_packet_size)){
				if(idata->verbose_f)
					puts("Packet too large while inserting TCP data");
				exit(EXIT_FAILURE);
			}

			memcpy(ptr, data, datalen);
			ptr+= datalen;

			if(window_f){
				if(window == WIN_CLOSED)
					tcp->th_win = htons(0);
				else
					tcp->th_win = htons((u_int16_t) win1_size);
			}
			else{
				tcp->th_win = htons(tcpwin);
			}

			tcp->th_sum = 0;
			tcp->th_sum = in_chksum(v6buffer, tcp, ptr-((unsigned char *)tcp), IPPROTO_TCP);
			frag_and_send(idata);
		}

		if(startclose_f){
			tcp->th_seq= htonl( ntohl(tcp->th_seq) + ptr-((unsigned char *)tcp + (tcp->th_off << 2)));
			ptr= (unsigned char *) tcp + sizeof(struct tcp_hdr);

			if(tcpclose == CLOSE_ABORT){
				tcp->th_flags= TH_ACK | TH_RST;
			}
			else if(tcpclose == CLOSE_ACTIVE || tcpclose == CLOSE_LAST_ACK){
				tcp->th_flags= TH_ACK | TH_FIN;
			}

			tcp->th_sum = 0;
			tcp->th_sum = in_chksum(v6buffer, tcp, ptr-((unsigned char *)tcp), IPPROTO_TCP);
			frag_and_send(idata);
		}	

		return;
	}
	else{
		if(ports >= nports){
			sources++;
			ports= 0;
		}

		if(sources >= nsources){
			if(loop_f){
				sources= 0;
			}
			else{
				donesending_f= 1;
				return;
			}
		}

		if( (ptr+sizeof(struct tcp_hdr)) > (v6buffer + idata->max_packet_size)){
			puts("Packet Too Large while inserting TCP header");
			exit(EXIT_FAILURE);
		}

		tcp= (struct tcp_hdr *) ptr;
		bzero(ptr, sizeof(struct tcp_hdr));
		tcp->th_sport= htons(srcport);
		tcp->th_dport= htons(dstport);
		tcp->th_seq = htonl(tcpseq);

		if(tcpack_f || (tcpflags & TH_ACK))
			tcp->th_ack= htonl(tcpack);
		else
			tcp->th_ack= 0;

		if(tcpflags_auto_f || tcpopen_f || tcpclose_f){
			tcp->th_flags= TH_SYN;
		}
		else{
			tcp->th_flags= tcpflags;
		}

		tcp->th_urp= htons(tcpurg);
		tcp->th_win= htons(tcpwin);
		tcp->th_off= sizeof(struct tcp_hdr) >> 2;

		ptr += tcp->th_off << 2;

		if( (ptr + rhbytes) > v6buffer + idata->max_packet_size){
			puts("Packet Too Large while inserting TCP segment");
			exit(EXIT_FAILURE);
		}

		while(rhbytes>=4){
			*(u_int32_t *)ptr = random();
			ptr += sizeof(u_int32_t);
			rhbytes -= sizeof(u_int32_t);
		}

		while(rhbytes>0){
			*(u_int8_t *) ptr= (u_int8_t) random();
			ptr++;
			rhbytes--;
		}


		if(pktdata == NULL && (floods_f && ports == 0)){
			/* 
			   Randomizing the IPv6 Source address based on the prefix specified by 
			   "srcaddr" and srcpreflen.
			 */  

			randomize_ipv6_addr( &(ipv6->ip6_src), &(idata->srcaddr), idata->srcpreflen);

			/*
			   If we need to respond to incomming packets, we set the Interface ID such that we can
			   detect which IPv6 addresses we have used.
			 */
			if(listen_f && useaddrkey_f){
				ipv6->ip6_src.s6_addr16[4]= random();
				ipv6->ip6_src.s6_addr16[5]= ipv6->ip6_src.s6_addr16[4] ^ addr_key;
				ipv6->ip6_src.s6_addr16[6]= random();
				ipv6->ip6_src.s6_addr16[7]= ipv6->ip6_src.s6_addr16[6] ^ addr_key;
			}

			if(idata->type == DLT_EN10MB && idata->flags != IFACE_LOOPBACK && !(idata->hsrcaddr_f)){
				for(i=0; i<6; i++)
					ethernet->src.a[i]= random();
			}
		}

		if(pktdata == NULL && floodp_f){
			tcp->th_sport= random();
		}

		tcp->th_sum = 0;
		tcp->th_sum = in_chksum(v6buffer, tcp, ptr-((unsigned char *)tcp), IPPROTO_TCP);

		frag_and_send(idata);

		if(pktdata == NULL)	
			ports++;

		return;
	}
}


/*
 * Function: frag_and_send()
 *
 * Send an IPv6 datagram, and fragment if selected
 */
void frag_and_send(struct iface_data *idata){
	if(!fragh_f){
		ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);

		if((nw=pcap_inject(idata->pfd, buffer, ptr - buffer)) == -1){
			printf("pcap_inject(): %s\n", pcap_geterr(idata->pfd));
			exit(EXIT_FAILURE);
		}

		if(nw != (ptr-buffer)){
			printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", \
						(LUI) nw, (LUI) (ptr-buffer));
			exit(EXIT_FAILURE);
		}
	}
	else{
		ptrend= ptr;
		ptr= fragpart;
		fptr = fragbuffer;
		fipv6 = (struct ip6_hdr *) (fragbuffer + idata->linkhsize);
		fptrend = fptr + idata->linkhsize+MIN_IPV6_HLEN+MAX_IPV6_PAYLOAD;
		memcpy(fptr, buffer, fragpart-buffer);
		fptr = fptr + (fragpart-buffer);

		if( (fptr+FRAG_HDR_SIZE)> fptrend){
			puts("Unfragmentable Part is Too Large");
			exit(EXIT_FAILURE);
		}

		memcpy(fptr, (char *) &fraghdr, FRAG_HDR_SIZE);
		fh= (struct ip6_frag *) fptr;
		fh->ip6f_ident=random();
		startoffragment = fptr + FRAG_HDR_SIZE;

		/*
		 * Check that the selected fragment size is not larger than the largest 
		 * fragment size that can be sent
		 */
		if(nfrags <= (fptrend - fptr))
			fragsize=nfrags;
		else
			fragsize= (fptrend-fptr) & IP6F_OFF_MASK;

		m=IP6F_MORE_FRAG;

		while((ptr< ptrend) && m==IP6F_MORE_FRAG){
			fptr= startoffragment;

			if( (ptrend-ptr) <= fragsize){
				fragsize= ptrend-ptr;
				m=0;
			}

			memcpy(fptr, ptr, fragsize);
			fh->ip6f_offlg = (htons(ptr-fragpart) & IP6F_OFF_MASK) | m;
			ptr+=fragsize;
			fptr+=fragsize;

			fipv6->ip6_plen = htons((fptr - fragbuffer) - MIN_IPV6_HLEN - idata->linkhsize);
		
			if((nw=pcap_inject(idata->pfd, fragbuffer, fptr - fragbuffer)) == -1){
				printf("pcap_inject(): %s\n", pcap_geterr(idata->pfd));
				exit(EXIT_FAILURE);
			}

			if(nw != (fptr- fragbuffer)){
				printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", \
								(LUI) nw, (LUI) (ptr-buffer));
				exit(EXIT_FAILURE);
			}
		} /* Sending fragments */
	} /* Sending fragmented datagram */
}


/*
 * Function: usage()
 *
 * Prints the syntax of the tcp6 tool
 */
void usage(void){
	puts("usage: tcp6 -i INTERFACE [-S LINK_SRC_ADDR] [-D LINK-DST-ADDR] "
	 "[-s SRC_ADDR[/LEN]] [-d DST_ADDR] [-A HOP_LIMIT] [-y FRAG_SIZE] [-u DST_OPT_HDR_SIZE] "
	 "[-U DST_OPT_U_HDR_SIZE] [-H HBH_OPT_HDR_SIZE] [-P PAYLOAD_SIZE] [-o SRC_PORT] "
	 "[-a DST_PORT] [-X TCP_FLAGS] [-q TCP_SEQ] [-Q TCP_ACK] [-V TCP_URP] [-w TCP_WIN] "
	 "[-N] [-f] [-j PREFIX[/LEN]] [-k PREFIX[/LEN]] [-J LINK_ADDR] [-K LINK_ADDR] "
	 "[-b PREFIX[/LEN]] [-g PREFIX[/LEN]] [-B LINK_ADDR] [-G LINK_ADDR] "
	 "[-F N_SOURCES] [-T N_PORTS] [-L | -l] [-z SECONDS] [-v] [-h]");
}


/*
 * Function: print_help()
 *
 * Prints help information for the tcp6 tool
 */
void print_help(void){
	puts(SI6_TOOLKIT);
	puts( "tcp6: Security assessment tool for attack vectors based on TCP/IPv6 packets\n");
	usage();
    
	puts("\nOPTIONS:\n"
	     "  --interface, -i           Network interface\n"
	     "  --src-address, -s         IPv6 Source Address\n"
	     "  --dst-address, -d         IPv6 Destination Address\n"
	     "  --hop-limit, -A           IPv6 Hop Limit\n"
	     "  --frag-hdr. -y            Fragment Header\n"
	     "  --dst-opt-hdr, -u         Destination Options Header (Fragmentable Part)\n"
	     "  --dst-opt-u-hdr, -U       Destination Options Header (Unfragmentable Part)\n"
	     "  --hbh-opt-hdr, -H         Hop by Hop Options Header\n"
	     "  --link-src-address, -S    Link-layer Destination Address\n"
	     "  --link-dst-address, -D    Link-layer Source Address\n"
	     "  --payload-size, -P        TCP Payload Size\n"
	     "  --src-port, -o            TCP Source Port\n"
	     "  --dst-port, -a            TCP Destination Port\n"
	     "  --tcp-flags, -X           TCP Flags\n"
	     "  --tcp-seq, -q             TCP Sequence Number\n"
	     "  --tcp-ack, -Q             TCP Acknowledgment Number\n"
	     "  --tcp-urg, -V             TCP Urgent Pointer\n"
	     "  --tcp-win, -w             TCP Window\n"
	     "  --not-ack-data, -N        Do not acknowledge the TCP payload\n"
	     "  --not-ack-flags, -f       Do not acknowledge the TCP flags\n"
	     "  --block-src, -j           Block IPv6 Source Address prefix\n"
	     "  --block-dst, -k           Block IPv6 Destination Address prefix\n"
	     "  --block-link-src, -J      Block Ethernet Source Address\n"
	     "  --block-link-dst, -K      Block Ethernet Destination Address\n"
	     "  --accept-src, -b          Accept IPv6 Source Addres prefix\n"
	     "  --accept-dst, -g          Accept IPv6 Destination Address prefix\n"
	     "  --accept-link-src, -B     Accept Ethernet Source Address\n"
	     "  --accept-link-dst, -G     Accept Ethernet Destination Address\n"
	     "  --flood-sources, -F       Flood from multiple IPv6 Source Addresses\n"
	     "  --flood-ports, -T         Flood from multiple TCP Source Ports\n"
	     "  --listen, -L              Listen to incoming packets\n"
	     "  --loop, -l                Send periodic TCP segments\n"
	     "  --sleep, -z               Pause between sending TCP segments\n"
	     "  --help, -h                Print help for the tcp6 tool\n"
	     "  --verbose, -v             Be verbose\n"
	     "\n"
	     "Programmed by Fernando Gont for SI6 Networks <http://www.si6networks.com>\n"
	     "Please send any bug reports to <fgont@si6networks.com>\n"
	);
}


/*
 * Function: print_attack_info()
 *
 * Prints attack details (when the verbose ("-v") option is specified).
 */
 
void print_attack_info(struct iface_data *idata){
	puts( "tcp6: Security assessment tool for attack vectors based on TCP/IPv6 packets\n");

	if(floods_f)
		printf("Flooding the target from %u different IPv6 Source Addresses\n", nsources);

	if(floodp_f)
		printf("Flooding the target from %u different TCP ports\n", nports);

	if(idata->type == DLT_EN10MB && idata->flags != IFACE_LOOPBACK){
		if(idata->hsrcaddr_f){
				if(ether_ntop(&(idata->hsrcaddr), plinkaddr, sizeof(plinkaddr)) == 0){
					puts("ether_ntop(): Error converting address");
					exit(EXIT_FAILURE);
				}

				printf("Ethernet Source Address: %s\n", plinkaddr);
		}
		else{
			if(idata->dstaddr_f){
				if(ether_ntop(&(idata->hsrcaddr), plinkaddr, sizeof(plinkaddr)) == 0){
					puts("ether_ntop(): Error converting address");
					exit(EXIT_FAILURE);
				}

				printf("Ethernet Source Address: %s%s\n", plinkaddr, ((!(idata->hsrcaddr_f))?" (randomized)":""));
			}
			else
				puts("Ethernet Source Address: Automatically selected for each packet");
		}

		/* 
		   Ethernet Destination Address only used if a IPv6 Destination Address or an
		   Ethernet Destination Address were specified.
		 */
		if(idata->dstaddr_f){
			if(ether_ntop(&(idata->hdstaddr), plinkaddr, sizeof(plinkaddr)) == 0){
				puts("ether_ntop(): Error converting address");
				exit(EXIT_FAILURE);
			}

			printf("Ethernet Destination Address: %s\n", plinkaddr);
		}
	}

	if(inet_ntop(AF_INET6, &(idata->srcaddr), psrcaddr, sizeof(psrcaddr)) == NULL){
		puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
		exit(EXIT_FAILURE);
	}

	if(!floods_f){
		if(idata->dstaddr_f){
			printf("IPv6 Source Address: %s%s\n", psrcaddr, ((!(idata->srcaddr_f))?" (randomized)":""));
		}
	}
	else{
		printf("IPv6 Source Address: randomized, from the %s/%u prefix%s\n", psrcaddr, idata->srcpreflen, \
    									(!idata->srcprefix_f)?" (default)":"");
	}

	if(idata->dstaddr_f){
		if(inet_ntop(AF_INET6, &(idata->dstaddr), pdstaddr, sizeof(pdstaddr)) == NULL){
			puts("inet_ntop(): Error converting IPv6 Destination Address to presentation format");
			exit(EXIT_FAILURE);
		}

		printf("IPv6 Destination Address: %s\n", pdstaddr);
	}

	printf("IPv6 Hop Limit: %u%s\n", hoplimit, (hoplimit_f)?"":" (default)");

	for(i=0; i<ndstoptuhdr; i++)
		printf("Destination Options Header (Unfragmentable part): %u bytes\n", dstoptuhdrlen[i]);

	for(i=0; i<nhbhopthdr; i++)
		printf("Hop by Hop Options Header: %u bytes\n", hbhopthdrlen[i]);

	for(i=0; i<ndstopthdr; i++)
		printf("Destination Options Header: %u bytes\n", dstopthdrlen[i]);

	if(fragh_f)
		printf("Sending each packet in fragments of %u bytes (plus the Unfragmentable part)\n", nfrags);

	if(idata->dstaddr_f){
		if(!floodp_f || (floodp_f && nports ==1)){
			printf("Source Port: %u%s\t",  srcport, (srcport_f?"":" (randomized)"));
		}
		else{
			printf("Source Port: (randomized)\t");
		}

		printf("Destination Port: %u%s\n", dstport, (dstport_f?"":" (randomized)"));

		if( (floods_f || floodp_f) && (nsources != 1 || nports != 1)){
			printf("SEQ Number: (randomized)\t");
		}
		else{
			printf("SEQ Number: %u%s\t", tcpseq, (tcpseq_f?"":" (randomized)"));
		}

		printf("ACK Number: %u%s\n", tcpack, (tcpack_f?"":" (randomized)"));

		if(tcpflags_f){
			printf("Flags: %s%s%s%s%s%s%s%s\t", ((tcpflags & TH_FIN)?"F":""), ((tcpflags & TH_SYN)?"S":""), \
						((tcpflags & TH_RST)?"R":""), ((tcpflags & TH_PUSH)?"P":""),\
						((tcpflags & TH_ACK)?"A":""), ((tcpflags & TH_URG)?"U":""),\
						((!tcpflags)?"none":""), ((!tcpflags_f)?" (default)":""));
		}
		else{
			printf("Flags: Auto\t");
		}

		if(window_f){
			printf("Window (initial): %u%s\t", tcpwin, (tcpwin_f?"":" (randomized)"));

			if(window == WIN_CLOSED)
				printf("Window: Closed\n");
			else if(window == WIN_MODULATE)
				printf("\nWindow: Modulated (%u byte%s (%u second%s), %u byte%s (%u second%s))\n",\
						win1_size, ((win1_size>1)?"s":""), time1_len, ((time1_len>1)?"s":""), \
						win2_size, ((win2_size>1)?"s":""), time2_len, ((time2_len>1)?"s":""));
		}
		else{
			printf("Window: %u%s\t", tcpwin, (tcpwin_f?"":" (randomized)"));
		}

		printf("URG Pointer: %u%s\n", tcpurg, (tcpurg_f?"":" (default)"));
	}
	else{
		printf("Source Port: Auto\tDestination Port: Auto\n");

		if(tcpseq_f){
			printf("SEQ Number: %u\t", tcpseq);
		}
		else{
			printf("SEQ Number: Auto\t");
		}

		if(tcpack_f){
			printf("ACK Number: %u\n", tcpack);
		}
		else{
			printf("ACK Number: Auto\n");
		}

		if(tcpflags_f){
			printf("Flags: %s%s%s%s%s%s%s\t", ((tcpflags & TH_FIN)?"F":""), ((tcpflags & TH_SYN)?"S":""), \
					((tcpflags & TH_RST)?"R":""), ((tcpflags & TH_PUSH)?"P":""),\
					((tcpflags & TH_ACK)?"A":""), ((tcpflags & TH_URG)?"U":""),\
					((!tcpflags)?"none":""));
		}
		else{
			printf("Flags: Auto\t");
		}

		if(window_f){
			printf("Window (initial): %u%s\t", tcpwin, (tcpwin_f?"":" (randomized)"));

			if(window == WIN_CLOSED)
				printf("Window: Closed\n");
			else if(window == WIN_MODULATE)
				printf("\nWindow: Modulated (%u byte%s (%u second%s), %u byte%s (%u second%s))\n",\
						win1_size, ((win1_size>1)?"s":""), time1_len, ((time1_len>1)?"s":""), \
						win2_size, ((win2_size>1)?"s":""), time2_len, ((time2_len>1)?"s":""));
		}
		else{
			printf("Window: %u%s\n", tcpwin, (tcpwin_f?"":" (randomized)"));
		}

	}
}



/*
 * Function: queue_data()
 *
 * Puts data into a queue
 */

unsigned int queue_data(struct queue *q, unsigned char *data, unsigned int nbytes){
	unsigned int	fbytes, nleft;

	/*
	   We have to scenarios: in >= out and in < out
	   In the first scenario, the circular buffer may be "split in two". In the second one,
	   all available space is clustered together.
	 */
	if(q->in >= q->out){
		fbytes= (q->data+ q->size) - q->in -1;
		fbytes= fbytes+ (q->out - q->data);

		if(nbytes > fbytes)
			nbytes= fbytes;
		
		/* There is enough space available on the right side of the buffer */
		if( (q->data + q->size - q->in) >= nbytes){
			memcpy(q->in, data, nbytes);

			q->in= q->in + nbytes;
			
			if(q->in == (q->data + q->size))
				q->in= q->data;

			return(nbytes);
		}
		else{
			nleft= nbytes;
			memcpy(q->in, data, (q->data + q->size - q->in));

			nleft= nleft - (q->data + q->size - q->in);
			q->in= q->data;

			memcpy(q->in, data, nleft);
			return(nbytes);
		}
	}
	else{
		fbytes= q->out - q->in - 1;

		if(nbytes > fbytes)
			nbytes= fbytes;

		memcpy(q->in, data, nbytes);
		q->in= q->in + nbytes;

		if(q->in == (q->data + q->size))
			q->in= q->data;

		return(nbytes);
	}

	/* Should never reach here, but avoid compiler warnings */
	return(0);
}


/*
 * Function: dequeue_data()
 *
 * Reads data from a queue
 */

unsigned int dequeue_data(struct queue *q, unsigned char *data, unsigned int nbytes){
	unsigned int	dbytes, nleft;

	/*
	   We have to scenarios: out > in and out <= in
	   In the first scenario, the circular buffer may be "split in two". In the second one,
	   all available data are clustered together.
	 */
	if(q->out > q->in){
		dbytes= (q->data+ q->size) - q->out;
		dbytes= dbytes+ (q->in - q->out);

		if(nbytes > dbytes)
			nbytes= dbytes;
		
		/* There is enough data available on the right side of the buffer */
		if( (q->data + q->size - q->out) >= nbytes){
			memcpy(data, q->out, nbytes);

			q->out= q->out + nbytes;
			
			if(q->out == (q->data + q->size))
				q->out= q->data;

			return(nbytes);
		}
		else{
			/* Data are split in two parts */
			nleft= nbytes;
			memcpy(data, q->out, (q->data + q->size - q->out));
			data= data+ (q->data + q->size - q->out);

			nleft= nleft - (q->data + q->size - q->out);
			q->out= q->data;

			memcpy(data, q->out, nleft);
			q->out= q->out + nleft;

			return(nbytes);
		}
	}
	else{
		dbytes= q->in - q->out;

		if(nbytes > dbytes)
			nbytes= dbytes;

		memcpy(data, q->out, nbytes);
		q->out= q->out + nbytes;

		if(q->out == (q->data + q->size))
			q->out= q->data;

		return(nbytes);
	}

	/* Should never reach here, but avoid compiler warnings */
	return(0);
}



/*
 * Function: queue_copy()
 *
 * Copies data from queue, without removing it
 */

unsigned int queue_copy(struct queue *q, unsigned char *org, unsigned int offset, unsigned char *data, unsigned int nbytes){
	unsigned int	dbytes, nleft;

	if(org+offset >= (q->data + q->size)){
		org= q->data + offset - (q->data + q->size - org);
	}

	/* | in    out
	   We have to scenarios: out > in and out <= in
	   In the first scenario, the circular buffer may be "split in two". In the second one,
	   all available data are clustered together.
	 */
	if(org > q->in){
		dbytes= (q->data+ q->size) - org;
		dbytes= dbytes+ (q->in - org);

		if(nbytes > dbytes)
			nbytes= dbytes;
		
		/* There is enough data available on the right side of the buffer */
		if( (q->data + q->size - org) >= nbytes){
			memcpy(data, org, nbytes);
			return(nbytes);
		}
		else{
			/* Data are split in two parts */
			nleft= nbytes;
			memcpy(data, org, (q->data + q->size - org));
			data= data + (q->data + q->size - org);

			nleft= nleft - (q->data + q->size - org);
			org= q->data;

			memcpy(data, org, nleft);
			return(nbytes);
		}
	}
	else{
		dbytes= q->in - org;

		if(nbytes > dbytes)
			nbytes= dbytes;

		memcpy(data, org, nbytes);
		return(nbytes);
	}

	/* Should never reach here, buts avoid compiler warnings */
	return(0);
}


/*
 * Function: queue_remove()
 *
 * Discards data from queue
 * Note: This function is employed to discard data from the TCP send buffer when they are ACKed
 * by the remote TCP endpoint.
 */

unsigned int queue_remove(struct queue *q, unsigned char *data, unsigned int nbytes){
	unsigned int	dbytes, nleft;

	/*
	   We have to scenarios: out > in and out <= in
	   In the first scenario, the circular buffer may be "split in two". In the second one,
	   all available data are clustered together.
	 */
	if(q->out > q->in){
		dbytes= (q->data+ q->size) - q->out;
		dbytes= dbytes+ (q->in - q->out);

		if(nbytes > dbytes)
			nbytes= dbytes;
		
		/* There is enough data available on the right side of the buffer */
		if( (q->data + q->size - q->out) >= nbytes){
			q->out= q->out + nbytes;
			
			if(q->out == (q->data + q->size))
				q->out= q->data;

			return(nbytes);
		}
		else{
			/* Data are split in two parts */
			nleft= nbytes;
			data= data+ (q->data + q->size - q->out);
			nleft= nleft - (q->data + q->size - q->out);
			q->out= q->data;
			q->out= q->out + nleft;
			return(nbytes);
		}
	}
	else{
		dbytes= q->in - q->out;

		if(nbytes > dbytes)
			nbytes= dbytes;

		memcpy(data, q->out, nbytes);
		q->out= q->out + nbytes;

		if(q->out == (q->data + q->size))
			q->out= q->data;

		return(nbytes);
	}

	/* Should never reach here, but avoid compiler warnings */
	return(0);
}



/*
 * Function: tcp_init()
 *
 * Initilizes a TCP structure
 */

int tcp_init(struct tcp *tcp){
	memset(&(tcp->srcaddr), 0, sizeof(struct in6_addr));
	memset(&(tcp->dstaddr), 0, sizeof(struct in6_addr));
	tcp->srcport= 0;
	tcp->dstport= 0;

	tcp->in.in = tcp->in.data;
	tcp->in.out= tcp->in.data;
	tcp->in.size= sizeof(tcp->in.data);

	tcp->rcv_nxt= 0;
	tcp->rcv_nxtwnd= 0;

	tcp->out.in= tcp->out.data;
	tcp->out.out= tcp->out.data;
	tcp->out.size= sizeof(tcp->out.data);

	tcp->out_una= tcp->out.data;
	tcp->out_nxt= tcp->out.data;

	tcp->snd_una=0;
	tcp->snd_nxtwnd=0;
	
	memset(&(tcp->time), 0, sizeof(struct timeval));
	tcp->state= TCP_CLOSED;

	tcp->ack= 0;
	tcp->win= sizeof(tcp->in.data) - 1;

	return(SUCCESS);
}



/*
 * Function: tcp_open()
 *
 * Performs an open (active or passive) on a TCP socket
 */

int tcp_open(struct iface_data *idata, struct tcp *tcb, unsigned int mode){
	if(mode == OPEN_ACTIVE){
		tcb->state= TCP_SYN_SENT;
		tcb->flags= TH_SYN;
		tcb->snd_una= random();
		tcb->snd_nxt= tcb->snd_una + 1;
		tcb->pending_write_f= TRUE;
		return(SUCCESS);
	}
	else if(mode == OPEN_PASSIVE){
		tcb->state= TCP_LISTEN;
		return(SUCCESS);
	}

	return(FAILURE);
}


/*
 * Function: tcp_close()
 *
 * Performs a close on a TCP socket
 */

int tcp_close(struct iface_data *idata, struct tcp *tcb){
	tcb->fin_flag= TRUE;
	tcb->fin_seq= tcb->snd_nxt;
	tcb->pending_write_f= TRUE;
	return(SUCCESS);
}


/*
 * Function: tcp_send()
 *
 * Sends data over TCP (actually copies it to the TCP send buffer)
 */

int tcp_send(struct iface_data *idata, struct tcp *tcb, unsigned char *data, unsigned int nbytes){
	if(tcb->fin_flag == TRUE)
		return(-1);
	else
		return(queue_data( &(tcb->out), data, nbytes));
}


/*
 * Function: tcp_receive()
 *
 * Receive data from a TCP socket
 */

int tcp_receive(struct iface_data *idata, struct tcp *tcb, unsigned char *data, unsigned int nbytes){
	unsigned int	r;

	r= dequeue_data(&(tcb->in), data, nbytes);

	if(r > 0)
		tcb->pending_write_f= TRUE;

	return(r);
}


/*
 * Function: tcp_input()
 *
 * Processes an incoming TCP segment
 */

int tcp_input(struct iface_data *idata, struct tcp *tcb, const u_char *pktdata, struct pcap_pkthdr *pkthdr, struct packet *packet){
	return(SUCCESS);
}



/*
 * Function: tcp_output()
 *
 * Sends TCP segments as necessary
 */

int tcp_output(struct iface_data *idata, struct tcp *tcb, struct packet *packet, struct timeval *curtime){
	/* Placeholder */
	return(SUCCESS);
}



/*
 * Function: is_valid_tcp_segment()
 *
 * Performs sanity checks on an incomming TCP/IPv6 segment
 */

int is_valid_tcp_segment(struct iface_data *idata, const u_char *pktdata, struct pcap_pkthdr *pkthdr){
	struct ether_header	*pkt_ether;
	struct ip6_hdr		*pkt_ipv6;
	struct tcp_hdr		*pkt_tcp;
	unsigned char		*pkt_end;

	pkt_ether = (struct ether_header *) pktdata;
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata->linkhsize);
	pkt_tcp = (struct tcp_hdr *) ((char *) pkt_ipv6 + MIN_IPV6_HLEN);

	pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

	/* XXX: We are assuming no extension headers on incoming packets -- this should be improved! */

	/* The packet length is the minimum of what we capured, and what is specified in the
	   IPv6 Total Lenght field
	 */
	if( pkt_end > ((unsigned char *)pkt_tcp + pkt_ipv6->ip6_plen) )
		pkt_end = (unsigned char *)pkt_tcp + pkt_ipv6->ip6_plen;

	/*
	   Discard the packet if it is not of the minimum size to contain a TCP header
	 */
	if( (pkt_end - (unsigned char *) pkt_tcp) < sizeof(struct tcp_hdr)){
		return FALSE;
	}

	/* Check that the TCP checksum is correct */
	if(in_chksum(pkt_ipv6, pkt_tcp, pkt_end-((unsigned char *)pkt_tcp), IPPROTO_TCP) != 0){
		return FALSE;
	}


	/* XXX: Should perform additional checks on the IPv6 header */
	/*
	   Sanity checks on the Source Address and the Destination Address
	 */
	if(IN6_IS_ADDR_UNSPECIFIED(&(pkt_ipv6->ip6_src)) || IN6_IS_ADDR_UNSPECIFIED(&(pkt_ipv6->ip6_dst))){
		return FALSE;
	}

	if(IN6_IS_ADDR_MULTICAST(&(pkt_ipv6->ip6_src)) || IN6_IS_ADDR_MULTICAST(&(pkt_ipv6->ip6_dst))){
		return FALSE;
	}

	return TRUE;
}

