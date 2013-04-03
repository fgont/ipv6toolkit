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
 * 
 * Build with: gcc tcp6.c -Wall -lpcap -o tcp6
 * 
 * This program has been tested to compile and run on: Debian GNU/Linux 6.0,
 * FreeBSD 8.2, NetBSD 5.1, OpenBSD 5.0, and Ubuntu 11.10.
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
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
	#include <net/if_dl.h>
#endif
#include <sys/select.h>
#include "tcp6.h"
#include "ipv6toolkit.h"
#include <netinet/tcp.h>


/* Function prototypes */
int					init_iface_data(struct iface_data *);
void				init_packet_data(void);
int					insert_pad_opt(unsigned char *ptrhdr, const unsigned char *, unsigned int);
void				send_packet(const u_char *);
void				print_attack_info(void);
void				print_filters(void);
void				print_filter_result(const u_char *, unsigned char);
void				usage(void);
void				print_help(void);
int					ether_pton(const char *, struct ether_addr *, unsigned int);
int					ether_ntop(const struct ether_addr *, char *, size_t);
u_int16_t			in_chksum(void *, void *, size_t, u_int8_t);
int					is_ip6_in_prefix_list(struct in6_addr *, struct prefix_list *);
unsigned int		match_ipv6(struct in6_addr *, u_int8_t *, unsigned int, struct in6_addr *);
unsigned int		match_ether(struct ether_addr *, unsigned int, struct ether_addr *);
void				sanitize_ipv6_prefix(struct in6_addr *, u_int8_t);
void				randomize_ipv6_addr(struct in6_addr *, struct in6_addr *, u_int8_t);
void				randomize_ether_addr(struct ether_addr *);
void				ether_to_ipv6_linklocal(struct ether_addr *etheraddr, struct in6_addr *ipv6addr);
void				generate_slaac_address(struct in6_addr *, struct ether_addr *, struct in6_addr *);
void				sig_alarm(int);
int					is_eq_in6_addr(struct in6_addr *, struct in6_addr *);
int					find_ipv6_router_full(pcap_t *, struct iface_data *);
int					ipv6_to_ether(pcap_t *, struct iface_data *, struct in6_addr *, struct ether_addr *);
struct in6_addr		solicited_node(const struct in6_addr *);
struct ether_addr	ether_multicast(const struct in6_addr *);
int 				match_ipv6_to_prefixes(struct in6_addr *, struct prefix_list *);
int					get_if_addrs(struct iface_data *);
struct in6_addr *	src_addr_sel(struct iface_data *, struct in6_addr *);


/* Flags used for TCP (specifically) */ 
unsigned int		srcport_f=0, dstport_f=0;
unsigned int		tcpseq_f=0, tcpack_f=0, tcpurg_f=0, tcpflags_f=0, tcpwin_f=0;
unsigned int		rhbytes_f=0;
unsigned int		ackdata_f=1, ackflags_f=1;
u_int16_t			srcport, dstport, tcpurg, tcpwin;
u_int32_t			tcpseq, tcpack;
u_int8_t			tcpflags=0;
struct tcphdr		*rhtcp;
unsigned int		rhbytes, currentsize;


/* Used for router discovery */
struct iface_data	idata;
struct prefix_entry	*prefix_ols[MAX_PREFIXES_ONLINK], *prefix_acs[MAX_PREFIXES_AUTO];
struct prefix_entry	*prefix_local[MAX_LOCAL_ADDRESSES];


/* Data structures for packets read from the wire */
pcap_t				*pfd;
struct pcap_pkthdr	*pkthdr;
const u_char		*pktdata;
unsigned char		*pkt_end;
struct ether_header	*pkt_ether;
struct ip6_hdr		*pkt_ipv6;
struct tcphdr		*pkt_tcp;
struct in6_addr		*pkt_ipv6addr;
unsigned int		pktbytes;


bpf_u_int32			my_netmask;
bpf_u_int32			my_ip;
struct bpf_program	pcap_filter;
char 				dev[64], errbuf[PCAP_ERRBUF_SIZE];
unsigned char		buffer[65556], buffrh[MIN_IPV6_HLEN + MIN_TCP_HLEN];
unsigned char		*v6buffer, *ptr, *startofprefixes;
char				*pref;
char 				iface[IFACE_LENGTH];
    
struct ip6_hdr		*ipv6;
struct tcphdr		*tcp;

struct ether_header	*ethernet;
struct ether_addr	hsrcaddr, hdstaddr;
struct nd_opt_tlla	*tllaopt;

struct in6_addr		srcaddr, dstaddr, targetaddr, randprefix;
struct ether_addr	linkaddr[MAX_TLLA_OPTION];
unsigned int		nlinkaddr=0, linkaddrs;

char				*lasts, *rpref;
char				*charptr;

size_t				nw;
unsigned long		ul_res, ul_val;
unsigned int		i, j, startrand;
unsigned int		skip;
unsigned int		sources, nsources, ports, nports, nsleep;
unsigned char		srcpreflen, randpreflen;

u_int16_t			mask;
u_int8_t			hoplimit;

char 				plinkaddr[ETHER_ADDR_PLEN];
char 				psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN], pv6addr[INET6_ADDRSTRLEN];
unsigned char 		verbose_f=0, iface_f=0, acceptfilters_f=0, floodt_f=0;
unsigned char 		srcaddr_f=0, dstaddr_f=0, hsrcaddr_f=0, hdstaddr_f=0;
unsigned char 		listen_f=0, accepted_f=0, loop_f=0, sleep_f=0;
unsigned char		srcprefix_f=0, hoplimit_f=0, rand_link_src_f=0, rand_src_f=0;
unsigned char		floods_f=0, floodp_f=0, tunnel_f=0, loopback_f=0;

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
unsigned int		nfrags, fragsize, max_packet_size, linkhsize;
unsigned char		*prev_nh, *startoffragment;


/* Block Filters */
struct in6_addr 	blocksrc[MAX_BLOCK_SRC], blockdst[MAX_BLOCK_DST];
struct in6_addr		blocktarget[MAX_BLOCK_TARGET];
u_int8_t			blocksrclen[MAX_BLOCK_SRC], blockdstlen[MAX_BLOCK_DST];
u_int8_t			blocktargetlen[MAX_BLOCK_TARGET];
struct ether_addr	blocklinksrc[MAX_BLOCK_LINK_SRC], blocklinkdst[MAX_BLOCK_LINK_DST];
unsigned int		nblocksrc=0, nblockdst=0, nblocktarget=0;
unsigned int		nblocklinksrc=0, nblocklinkdst=0;

/* Accept Filters */
struct in6_addr		acceptsrc[MAX_ACCEPT_SRC], acceptdst[MAX_ACCEPT_DST];
struct in6_addr		accepttarget[MAX_ACCEPT_TARGET];
u_int8_t			acceptsrclen[MAX_ACCEPT_SRC], acceptdstlen[MAX_ACCEPT_DST];
u_int8_t			accepttargetlen[MAX_ACCEPT_TARGET];
struct ether_addr	acceptlinksrc[MAX_ACCEPT_LINK_SRC], acceptlinkdst[MAX_ACCEPT_LINK_DST];
unsigned int		nacceptsrc=0, nacceptdst=0, naccepttarget=0;
unsigned int		nacceptlinksrc=0, nacceptlinkdst=0;

/* IPv6 Address Resolution */
sigjmp_buf			env;
unsigned int		canjump;

int main(int argc, char **argv){
	extern char	*optarg;	
	extern int	optind;
	char		*endptr; /* Used by strtoul() */
	uid_t		ruid;
	gid_t		rgid;
	fd_set		sset, rset;
	int			r, sel;
	struct passwd	*pwdptr;

	static struct option longopts[] = {
		{"interface", required_argument, 0, 'i'},
		{"src-address", required_argument, 0, 's'},
		{"dst-address", required_argument, 0, 'd'},
		{"hop-limit", required_argument, 0, 'A'},
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
		{"not-ack-data", no_argument, 0, 'N'},
		{"not-ack-flags", no_argument, 0, 'f'},
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
		{"rand-src-addr", no_argument, 0, 'r'},
		{"rand-link-src-addr", no_argument, 0, 'R'},
		{"loop", no_argument, 0, 'l'},
		{"sleep", required_argument, 0, 'z'},
		{"listen", no_argument, 0, 'L'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'}
	};

	char shortopts[]= "i:s:d:A:u:U:H:y:S:D:P:o:a:X:q:Q:V:w:Nfj:k:J:K:b:g:B:G:F:T:rRlz:Lvh";

	char option;

	if(argc<=1){
		usage();
		exit(1);
	}

	hoplimit=255;
	init_iface_data(&idata);

	while((option=getopt_long(argc, argv, shortopts, longopts, NULL)) != -1) {
		switch(option) {

			case 'i':  /* Interface */
				strncpy(idata.iface, optarg, IFACE_LENGTH-1);
				iface_f=1;
				break;

			case 's':	/* IPv6 Source Address */
				if((charptr = strtok_r(optarg, "/", &lasts)) == NULL){
					puts("Error in Source Address");
					exit(1);
				}

				if ( inet_pton(AF_INET6, charptr, &srcaddr) <= 0){
					puts("inet_pton(): Source Address not valid");
					exit(1);
				}

				srcaddr_f = 1;
		
				if((charptr = strtok_r(NULL, " ", &lasts)) != NULL){
					srcpreflen = atoi(charptr);
		
					if(srcpreflen>128){
						puts("Prefix length error in IPv6 Source Address");
						exit(1);
					}

					sanitize_ipv6_prefix(&srcaddr, srcpreflen);
					srcprefix_f=1;
				}

				break;
	    
			case 'd':	/* IPv6 Destination Address */
				if( inet_pton(AF_INET6, optarg, &dstaddr) <= 0){
					puts("inet_pton(): address not valid");
					exit(1);
				}
		
				dstaddr_f = 1;
				break;

			case 'A':	/* Hop Limit */
				hoplimit= atoi(optarg);
				hoplimit_f=1;
				break;

			case 'u':	/* Destinations Options Header */
				if(ndstopthdr >= MAX_DST_OPT_HDR){
					puts("Too many Destination Options Headers");
					exit(1);
				}

				hdrlen= atoi(optarg);
		
				if(hdrlen < 8){
					puts("Bad length in Destination Options Header");
					exit(1);
				}
		    
				hdrlen = ((hdrlen+7)/8) * 8;
				dstopthdrlen[ndstopthdr]= hdrlen;

				if( (dstopthdr[ndstopthdr]= malloc(hdrlen)) == NULL){
					puts("Not enough memory for Destination Options Header");
					exit(1);
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
						exit(1);
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
					exit(1);
				}

				hdrlen= atoi(optarg);
		
				if(hdrlen < 8){
					puts("Bad length in Destination Options Header (Unfragmentable Part)");
					exit(1);
				}

				hdrlen = ((hdrlen+7)/8) * 8;
				dstoptuhdrlen[ndstoptuhdr]= hdrlen;
		
				if( (dstoptuhdr[ndstoptuhdr]= malloc(hdrlen)) == NULL){
					puts("Not enough memory for Destination Options Header (Unfragmentable Part)");
					exit(1);
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
						exit(1);
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
					exit(1);
				}

				hdrlen= atoi(optarg);
		
				if(hdrlen <= 8){
					puts("Bad length in Hop-by-Hop Options Header");
					exit(1);
				}
		    
				hdrlen = ((hdrlen+7)/8) * 8;
				hbhopthdrlen[nhbhopthdr]= hdrlen;
		
				if( (hbhopthdr[nhbhopthdr]= malloc(hdrlen)) == NULL){
					puts("Not enough memory for Hop-by-Hop Options Header");
					exit(1);
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
						exit(1);
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
					exit(1);
				}
		
				nfrags = (nfrags +7) & 0xfff8;
				fragh_f= 1;
				break;

			case 'S':	/* Source Ethernet address */
				if(ether_pton(optarg, &hsrcaddr, sizeof(hsrcaddr)) == 0){
					puts("Error in Source link-layer address.");
					exit(1);
				}
		
				hsrcaddr_f = 1;
				break;

			case 'D':	/* Destination Ethernet Address */
				if(ether_pton(optarg, &hdstaddr, sizeof(hdstaddr)) == 0){
					puts("Error in Source link-layer address.");
					exit(1);
				}
		
				hdstaddr_f = 1;
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
							exit(1);
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
					exit(1);
				}
		
				if(endptr != optarg){
					tcpseq = ul_res;
					tcpseq_f=1;
				}

				break;

			case 'Q':	/* TCP Acknowledgement Number */
				if((ul_res = strtoul(optarg, &endptr, 0)) == ULONG_MAX){
					perror("Error in 'TCP Sequence NUmber' parameter");
					exit(1);
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

			case 'N':	/* Do not ack data */
				ackdata_f= 0;
				break;

			case 'f':	/* Do not ack flags */
				ackflags_f= 0;
				break;

			case 'j':	/* IPv6 Source Address (block) filter */
				if(nblocksrc >= MAX_BLOCK_SRC){
					puts("Too many IPv6 Source Address (block) filters.");
					exit(1);
				}
	    
				if((pref = strtok_r(optarg, "/", &lasts)) == NULL){
					printf("Error in IPv6 Source Address (block) filter number %u.\n", \
												nblocksrc+1);
					exit(1);
				}

				if ( inet_pton(AF_INET6, pref, &blocksrc[nblocksrc]) <= 0){
					printf("Error in IPv6 Source Address (block) filter number %u.", \
											    nblocksrc+1);
					exit(1);
				}

				if((charptr = strtok_r(NULL, " ", &lasts)) == NULL){
		    			blocksrclen[nblocksrc] = 128;
				}
				else{
					blocksrclen[nblocksrc] = atoi(charptr);

					if(blocksrclen[nblocksrc]>128){
						printf("Length error in IPv6 Source Address (block) filter number %u.\n", \
													nblocksrc+1);
						exit(1);
		    			}
				}

				sanitize_ipv6_prefix(&blocksrc[nblocksrc], blocksrclen[nblocksrc]);
				nblocksrc++;
				break;

			case 'k':	/* IPv6 Destination Address (block) filter */
				if(nblockdst >= MAX_BLOCK_DST){
					puts("Too many IPv6 Destination Address (block) filters.");
					exit(1);
				}

				if((pref = strtok_r(optarg, "/", &lasts)) == NULL){
					printf("Error in IPv6 Destination Address (block) filter number %u.\n", \
													nblockdst+1);
					exit(1);
				}

				if ( inet_pton(AF_INET6, pref, &blockdst[nblockdst]) <= 0){
					printf("Error in IPv6 Source Address (block) filter number %u.", \
											    nblockdst+1);
					exit(1);
				}

				if((charptr = strtok_r(NULL, " ", &lasts)) == NULL){
					blockdstlen[nblockdst] = 128;
				}
				else{
					blockdstlen[nblockdst] = atoi(charptr);
		
					if(blockdstlen[nblockdst]>128){
						printf("Length error in IPv6 Source Address (block) filter number %u.\n", \
													    nblockdst+1);
						exit(1);
					}
				}
		
				sanitize_ipv6_prefix(&blockdst[nblockdst], blockdstlen[nblockdst]);
				nblockdst++;
				break;

			case 'J':	/* Link Source Address (block) filter */
				if(nblocklinksrc > MAX_BLOCK_LINK_SRC){
					puts("Too many link-layer Source Address (accept) filters.");
					exit(1);
				}

				if(ether_pton(optarg, &blocklinksrc[nblocklinksrc], sizeof(struct ether_addr)) == 0){
					printf("Error in link-layer Source Address (blick) filter number %u.\n", \
												    nblocklinksrc+1);
					exit(1);
				}
		
				nblocklinksrc++;
				break;

			case 'K':	/* Link Destination Address (block) filter */
				if(nblocklinkdst > MAX_BLOCK_LINK_DST){
					puts("Too many link-layer Destination Address (block) filters.");
					exit(1);
				}

				if(ether_pton(optarg, &blocklinkdst[nblocklinkdst], sizeof(struct ether_addr)) == 0){
					printf("Error in link-layer Destination Address (blick) filter number %u.\n", \
												    nblocklinkdst+1);
					exit(1);
				}
		
				nblocklinkdst++;
				break;

			case 'b':	/* IPv6 Source Address (accept) filter */
				if(nacceptsrc > MAX_ACCEPT_SRC){
					puts("Too many IPv6 Source Address (accept) filters.");
					exit(1);
				}

				if((pref = strtok_r(optarg, "/", &lasts)) == NULL){
					printf("Error in IPv6 Source Address (accept) filter number %u.\n", \
												nacceptsrc+1);
					exit(1);
				}

				if ( inet_pton(AF_INET6, pref, &acceptsrc[nacceptsrc]) <= 0){
					printf("Error in IPv6 Source Address (accept) filter number %u.\n", \
												nacceptsrc+1);
					exit(1);
				}
		
				if((charptr = strtok_r(NULL, " ", &lasts)) == NULL){
					acceptsrclen[nacceptsrc] = 128;
				}
				else{
					acceptsrclen[nacceptsrc] = atoi(charptr);

					if(acceptsrclen[nacceptsrc]>128){
						printf("Length error in IPv6 Source Address (accept) filter number %u.\n", \
														nacceptsrc+1);
						exit(1);
					}
				}

				sanitize_ipv6_prefix(&acceptsrc[nacceptsrc], acceptsrclen[nacceptsrc]);
				nacceptsrc++;
				acceptfilters_f=1;
				break;


			case 'g':	/* IPv6 Destination Address (accept) filter */
				if(nacceptdst > MAX_ACCEPT_DST){
					puts("Too many IPv6 Destination Address (accept) filters.");
					exit(1);
				}

				if((pref = strtok_r(optarg, "/", &lasts)) == NULL){
					printf("Error in IPv6 Destination Address (accept) filter number %u.\n", \
													nacceptdst+1);
					exit(1);
				}

				if ( inet_pton(AF_INET6, pref, &acceptdst[nacceptdst]) <= 0){
					printf("Error in IPv6 Source Address (accept) filter number %u.\n", \
												    nacceptdst+1);
					exit(1);
				}

				if((charptr = strtok_r(NULL, " ", &lasts)) == NULL){
					acceptdstlen[nacceptdst] = 128;
				}
				else{
					acceptdstlen[nacceptdst] = atoi(charptr);
		
					if(acceptdstlen[nacceptdst]>128){
						printf("Length error in IPv6 Source Address (accept) filter number %u.\n", \
													    nacceptdst+1);
						exit(1);
					}
				}
		
				sanitize_ipv6_prefix(&acceptdst[nacceptdst], acceptdstlen[nacceptdst]);
				nacceptdst++;
				acceptfilters_f=1;
				break;

			case 'B':	/* Link-layer Source Address (accept) filter */
				if(nacceptlinksrc > MAX_ACCEPT_LINK_SRC){
					puts("Too many link-later Source Address (accept) filters.");
					exit(1);
				}

				if(ether_pton(optarg, &acceptlinksrc[nacceptlinksrc], sizeof(struct ether_addr)) == 0){
					printf("Error in link-layer Source Address (accept) filter number %u.\n", \
											    nacceptlinksrc+1);
					exit(1);
				}
		
				nacceptlinksrc++;
				acceptfilters_f=1;
				break;

			case 'G':	/* Link Destination Address (accept) filter */
				if(nacceptlinkdst > MAX_ACCEPT_LINK_DST){
					puts("Too many link-layer Destination Address (accept) filters.");
					exit(1);
				}

				if(ether_pton(optarg, &acceptlinkdst[nacceptlinkdst], sizeof(struct ether_addr)) == 0){
					printf("Error in link-layer Destination Address (accept) filter number %u.\n",\
												    nacceptlinkdst+1);
					exit(1);
				}
		
				nacceptlinkdst++;
				acceptfilters_f=1;
				break;

			case 'F':	/* Flood source addresses */
				nsources= atoi(optarg);
				if(nsources == 0){
					puts("Invalid number of source addresses in option -F");
					exit(1);
				}
		
				floods_f= 1;
				break;

			case 'T':	/* Flood source ports */
				nports= atoi(optarg);
				if(nports == 0){
					puts("Invalid number of source ports in option -T");
					exit(1);
				}
		
				floodp_f= 1;
				break;

			case 'r':
				rand_src_f=1;
				break;

			case 'R':
				rand_link_src_f=1;
				break;

			case 'l':	/* "Loop mode */
				loop_f = 1;
				break;

			case 'z':	/* Sleep option */
				nsleep=atoi(optarg);
				if(nsleep==0){
					puts("Invalid number of seconds in '-z' option");
					exit(1);
				}
	
				sleep_f=1;
				break;

			case 'L':	/* "Listen mode */
				listen_f = 1;
				break;

			case 'v':	/* Be verbose */
				verbose_f++;
				break;
		
			case 'h':	/* Help */
				print_help();
		
				exit(1);
				break;

			default:
				usage();
				exit(1);
				break;
		
		} /* switch */
	} /* while(getopt) */

	if(geteuid()) {
		puts("tcp6 needs root privileges to run.");
		exit(1);
	}

	if(!iface_f){
		puts("Must specify the network interface with the -i option");
		exit(1);
	}

	if(listen_f && loop_f){
		puts("'Error: listen' mode and 'loop' mode are incompatible");
		exit(1);
	}

	if( (pfd= pcap_open_live(idata.iface, PCAP_SNAP_LEN, PCAP_PROMISC, PCAP_TIMEOUT, errbuf)) == NULL){
		printf("pcap_open_live(): %s\n", errbuf);
		exit(1);
	}

	/* 
	   If the real UID is not root, we setuid() and setgid() to that user and group, releasing superuser
	   privileges. Otherwise, if the real UID is 0, we try to setuid() to "nobody", releasing superuser 
	   privileges.
	 */
	if( (ruid=getuid()) && (rgid=getgid())){
		if(setgid(rgid) == -1){
			puts("Error while releasing superuser privileges (changing to real GID)");
			exit(1);
		}

		if(setuid(ruid) == -1){
			puts("Error while releasing superuser privileges (changing to real UID)");
			exit(1);
		}
	}
	else{
		if((pwdptr=getpwnam("nobody"))){
			if(!pwdptr->pw_uid || !pwdptr->pw_gid){
				puts("User 'nobody' has incorrect privileges");
				exit(1);
			}

			if(setgid(pwdptr->pw_gid) == -1){
				puts("Error while releasing superuser privileges (changing to nobody's group)");
				exit(1);
			}

			if(setuid(pwdptr->pw_uid) == -1){
				puts("Error while releasing superuser privileges (changing to 'nobody')");
				exit(1);
			}
		}
	}

	if( (idata.type = pcap_datalink(pfd)) == DLT_EN10MB){
		linkhsize= ETH_HLEN;
		idata.mtu= ETH_DATA_LEN;
	}
	else if( idata.type == DLT_RAW){
		linkhsize=0;
		idata.mtu= MIN_IPV6_MTU;
		tunnel_f=1;
	}
	else if(idata.type == DLT_NULL){
		linkhsize=4;
		idata.mtu= MIN_IPV6_MTU;
		tunnel_f=1;
	}
	else{
		printf("Error: Interface %s is not an Ethernet or tunnel interface", iface);
		exit(1);
	}

	srandom(time(NULL));

	/*
	  If the flood option ("-F") has been specified, but no prefix has been specified,
	  select the random Source Addresses from the link-local unicast prefix (fe80::/64).
	*/
	if(floods_f && !srcprefix_f){
		srcpreflen=0;
	}

	if(!dstaddr_f && !listen_f){	/* Must specify IPv6 Destination Address if listening mode not used */
		puts("IPv6 Destination Address not specified (and listening mode not selected)");
		exit(1);
	}

	if(!hsrcaddr_f)	/* Source link-layer address is randomized by default */
			randomize_ether_addr(&hsrcaddr);

	if(get_if_addrs(&idata) == -1){
		puts("Error obtaining local addresses");
		exit(1);
	}

/* XXX: Borrowed from frag.c
	if((idata.ip6_local_flag && idata.ip6_global_flag) && !srcaddr_f)
		localaddr_f=1;
*/
	if(!idata.ether_flag){
		randomize_ether_addr(&idata.ether);
		idata.ether_flag=1;
	}

	if(!hsrcaddr_f)
		hsrcaddr=idata.ether;

	if(!idata.ip6_local_flag){
		ether_to_ipv6_linklocal(&idata.ether, &idata.ip6_local);
	}

	if(idata.type == DLT_EN10MB && !loopback_f){
		if(find_ipv6_router_full(pfd, &idata) == 1){
			if(!hdstaddr_f && dstaddr_f){
				if(IN6_IS_ADDR_MC_LINKLOCAL(&dstaddr)){
					hdstaddr= ether_multicast(&dstaddr);
				}
				else if(match_ipv6_to_prefixes(&dstaddr, &idata.prefix_ol)){
					/* Must perform Neighbor Discovery for the local address */
					if(ipv6_to_ether(pfd, &idata, &dstaddr, &hdstaddr) != 1){
						puts("Error while performing Neighbor Discovery for the Destination Address");
						exit(1);
					}
				}
				else{
					hdstaddr= idata.router_ether;
				}
			}
		}
		else{
			if(verbose_f)
				puts("Couldn't find local router. Now trying Neighbor Discovery for the target node");
			/*
			 * If we were not able to find a local router, we assume the destination is "on-link" (as
			 * a last ressort), and thus perform Neighbor Discovery for that destination
			 */
			if(ipv6_to_ether(pfd, &idata, &dstaddr, &hdstaddr) != 1){
				puts("Error while performing Neighbor Discovery for the Destination Address");
				exit(1);
			}
		}
	}

	if(srcprefix_f){
		randprefix=srcaddr;
		randpreflen=srcpreflen;
		randomize_ipv6_addr(&srcaddr, &randprefix, randpreflen);
		srcaddr_f=1;
	}
	else if(!srcaddr_f){
		srcaddr= *src_addr_sel(&idata, &dstaddr);
	}

	if(!floods_f)
		nsources=1;

	if(!floodp_f)
		nports=1;

	if(!sleep_f)
		nsleep=1;

	if( !fragh_f && dstoptuhdr_f){
		puts("Dst. Options Header (Unfragmentable Part) set, but Fragmentation not specified");
		exit(1);
	}
    
	if(fragh_f)
		max_packet_size = MAX_IPV6_PAYLOAD + MIN_IPV6_HLEN;
	else
		max_packet_size = idata.mtu;

	/*
	 *  If we are going to send packets to a specified target, we must set some default values
	 */
	if(dstaddr_f){
		if(!tcpflags_f)
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

	/* BY default, we randomize the TCP Window */
	if(!tcpwin_f)
		tcpwin= ((u_int16_t) random() + 1500) & (u_int16_t)0x7f00;

	if(!rhbytes_f)
		rhbytes=0;

	if(verbose_f){
		print_attack_info();
	}

	/*
	   Set filter for IPv6 packets (find_ipv6_router() set its own filter fore receiving RAs)
	 */
	if(pcap_compile(pfd, &pcap_filter, PCAP_TCPIPV6_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
		printf("pcap_compile(): %s", pcap_geterr(pfd));
		exit(1);
	}
    
	if(pcap_setfilter(pfd, &pcap_filter) == -1){
		printf("pcap_setfilter(): %s", pcap_geterr(pfd));
		exit(1);
	}

	pcap_freecode(&pcap_filter);

	/* Set initial contents of the attack packet */
	init_packet_data();
    
	/* Fire a TCP segment if an IPv6 Destination Address was specified */
	if(dstaddr_f){
		send_packet(NULL);

		if(verbose_f)    
			puts("Initial attack packet(s) sent successfully.");

		if(loop_f){
			if(verbose_f)
				printf("Now sending TCP segments every %u second%s...\n", nsleep, \
											((nsleep>1)?"s":""));
			while(loop_f){
				sleep(nsleep);
				send_packet(NULL);
			}

			exit(0);
		}
	}

	if(listen_f){
		if( (idata.fd= pcap_fileno(pfd)) == -1){
			puts("Error obtaining descriptor number for pcap_t");
			exit(1);
		}

		FD_ZERO(&sset);
		FD_SET(idata.fd, &sset);

		if(verbose_f){
			print_filters();
			puts("Listening to incoming IPv6 messages...");
		}

		while(listen_f){
			rset= sset;

			if((sel=select(idata.fd+1, &rset, NULL, NULL, NULL)) == -1){
				if(errno == EINTR){
					continue;
				}
				else{
					puts("Error in select()");
					exit(1);
				}
			}

			/* Read a TCP segment */
			if((r=pcap_next_ex(pfd, &pkthdr, &pktdata)) == -1){
				printf("pcap_next_ex(): %s", pcap_geterr(pfd));
				exit(1);
			}
			else if(r == 0){
				continue; /* Should never happen */
			}

			pkt_ether = (struct ether_header *) pktdata;
			pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + linkhsize);

			accepted_f=0;

			if(idata.type == DLT_EN10MB && !loopback_f){
				if(nblocklinksrc){
					if(match_ether(blocklinksrc, nblocklinksrc, &(pkt_ether->src))){
						if(verbose_f>1)
							print_filter_result(pktdata, BLOCKED);
		
						continue;
					}
				}

				if(nblocklinkdst){
					if(match_ether(blocklinkdst, nblocklinkdst, &(pkt_ether->dst))){
						if(verbose_f>1)
							print_filter_result(pktdata, BLOCKED);
		
						continue;
					}
				}
			}
	
			if(nblocksrc){
				if(match_ipv6(blocksrc, blocksrclen, nblocksrc, &(pkt_ipv6->ip6_src))){
					if(verbose_f>1)
						print_filter_result(pktdata, BLOCKED);
		
					continue;
				}
			}
	
			if(nblockdst){
				if(match_ipv6(blockdst, blockdstlen, nblockdst, &(pkt_ipv6->ip6_dst))){
					if(verbose_f>1)
						print_filter_result(pktdata, BLOCKED);
		
					continue;
				}
			}

			if(idata.type == DLT_EN10MB && !loopback_f){	
				if(nacceptlinksrc){
					if(match_ether(acceptlinksrc, nacceptlinksrc, &(pkt_ether->src)))
						accepted_f=1;
				}

				if(nacceptlinkdst && !accepted_f){
					if(match_ether(acceptlinkdst, nacceptlinkdst, &(pkt_ether->dst)))
						accepted_f= 1;
				}
			}

			if(nacceptsrc && !accepted_f){
				if(match_ipv6(acceptsrc, acceptsrclen, nacceptsrc, &(pkt_ipv6->ip6_src)))
					accepted_f= 1;
			}

			if(nacceptdst && !accepted_f){
				if(match_ipv6(acceptdst, acceptdstlen, nacceptdst, &(pkt_ipv6->ip6_dst)))
					accepted_f=1;
			}
	
			if(acceptfilters_f && !accepted_f){
				if(verbose_f>1)
					print_filter_result(pktdata, BLOCKED);

				continue;
			}

			if(verbose_f>1)
				print_filter_result(pktdata, ACCEPTED);

			/* Send a TCP segment */
			send_packet(pktdata);
		}
    
		exit(0);
	}
    

	if(!dstaddr_f && !listen_f){
		puts("Error: Nothing to send! (Destination Address left unspecified, and not using listening mode)");
		exit(1);
	}

	exit(0);
}



/*
 * Function: init_packet_data()
 *
 * Initialize the contents of the attack packet (Ethernet header, IPv6 Header, and ICMPv6 header)
 * that are expected to remain constant for the specified attack.
 */
void init_packet_data(void){
	ethernet= (struct ether_header *) buffer;
	v6buffer = buffer + linkhsize;
	ipv6 = (struct ip6_hdr *) v6buffer;

	if(!tunnel_f){
		ethernet->src = hsrcaddr;
		ethernet->dst = hdstaddr;
		ethernet->ether_type = htons(0x86dd);
	}

	ipv6->ip6_flow=0;
	ipv6->ip6_vfc= 0x60;
	ipv6->ip6_hlim= hoplimit;
	ipv6->ip6_src= srcaddr;
	ipv6->ip6_dst= dstaddr;

	prev_nh = (unsigned char *) &(ipv6->ip6_nxt);

	ptr = (unsigned char *) v6buffer + MIN_IPV6_HLEN;
    
	if(hbhopthdr_f){
		hbhopthdrs=0;
	
		while(hbhopthdrs < nhbhopthdr){
			if((ptr+ hbhopthdrlen[hbhopthdrs]) > (v6buffer+ idata.mtu)){
				puts("Packet too large while processing HBH Opt. Header");
				exit(1);
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
			if((ptr+ dstoptuhdrlen[dstoptuhdrs]) > (v6buffer+ idata.mtu)){
				puts("Packet too large while processing Dest. Opt. Header (Unfrag. Part)");
				exit(1);
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
		if( (fragpart+sizeof(fraghdr)+nfrags) > (v6buffer+idata.mtu)){
			puts("Unfragmentable part too large for current MTU");
			exit(1);
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
			if((ptr+ dstopthdrlen[dstopthdrs]) > (v6buffer+max_packet_size)){
			puts("Packet too large while processing Dest. Opt. Header (should be using the Frag. option?)");
			exit(1);
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
void send_packet(const u_char *pktdata){
	ptr=startofprefixes;

	if(pktdata != NULL){   /* Sending a TCP segment in response to a received packet */
		pkt_ether = (struct ether_header *) pktdata;
		pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + linkhsize);
		pkt_tcp= (struct tcphdr *)( (char *) pkt_ipv6 + sizeof(struct ip6_hdr));
		pkt_end = (unsigned char *) pktdata + pkthdr->len;

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

			if(idata.type == DLT_EN10MB && !loopback_f)
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

			if(idata.type == DLT_EN10MB && !loopback_f)
				ethernet->src = pkt_ether->dst;
		}


		if( (ptr+sizeof(struct tcphdr)) > (v6buffer+max_packet_size)){
			puts("Packet Too Large while inserting TCP header");
			exit(1);
		}

		tcp = (struct tcphdr *) ptr;
		bzero(tcp, sizeof(struct tcphdr));

		tcp->th_sport= pkt_tcp->th_dport;
		tcp->th_dport= pkt_tcp->th_sport;

		if(tcpseq_f)
			tcp->th_seq= htonl(tcpseq);
		else
			tcp->th_seq = pkt_tcp->th_ack;

		if(tcpack_f){
			tcp->th_ack= htonl(tcpack);
		}
		else{
			tcp->th_ack= pkt_tcp->th_seq;

			if(ackdata_f){
				tcp->th_ack= htonl(ntohl(tcp->th_ack) + ((pkt_end - (unsigned char *)pkt_tcp) - (tcp->th_off << 2)));
			}

			if(ackflags_f){
				tcp->th_ack= htonl(ntohl(tcp->th_ack) + ((pkt_tcp->th_flags & TH_FIN)?1:0) + \
						((pkt_tcp->th_flags & TH_SYN)?1:0));
			}
		}

		if(tcpflags_f)
			tcp->th_flags= tcpflags;
		else{
			tcp->th_flags= TH_ACK;

			/* If the incoming packet was a SYN, we should respond with a SYN/ACK */
			if( (pkt_tcp->th_flags & TH_SYN) && !(pkt_tcp->th_flags & TH_ACK))
					tcp->th_flags = tcp->th_flags | TH_SYN;
		}

		tcp->th_urp= htons(tcpurg);
		tcp->th_win= htons(tcpwin);

		/* Current version of tcp6 does not support sending TCP options */
		tcp->th_off= sizeof(struct tcphdr) >> 2;
		ptr+= tcp->th_off << 2;
	}
	else{
		if( (ptr+sizeof(struct tcphdr)) > (v6buffer+max_packet_size)){
			puts("Packet Too Large while inserting TCP header");
			exit(1);
		}

		tcp= (struct tcphdr *) ptr;
		bzero(ptr, sizeof(struct tcphdr));
		tcp->th_sport= htons(srcport);
		tcp->th_dport= htons(dstport);
		tcp->th_seq = htonl(tcpseq);

		if(tcpack_f || (tcpflags & TH_ACK))
			tcp->th_ack= htonl(tcpack);
		else
			tcp->th_ack= 0;

		tcp->th_flags= tcpflags;
		tcp->th_urp= htons(tcpurg);
		tcp->th_win= htons(tcpwin);
		tcp->th_off= sizeof(struct tcphdr) >> 2;

		ptr += tcp->th_off << 2;
	}

	if( (ptr + rhbytes) > v6buffer+max_packet_size){
		puts("Packet Too Large while inserting TCP segment");
		exit(1);
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

	sources=0;

	do{
		if(floods_f){
			/* 
			   Randomizing the IPv6 Source address based on the prefix specified by 
			   "srcaddr" and srcpreflen.
			 */  
			startrand= srcpreflen/16;

			for(i=0; i<startrand; i++)
				ipv6->ip6_src.s6_addr16[i]= 0;

			for(i=startrand; i<8; i++)
				ipv6->ip6_src.s6_addr16[i]=random();

			if(srcpreflen%16){
				mask=0xffff;
	    
				for(i=0; i<(srcpreflen%16); i++)
					mask= mask>>1;

				ipv6->ip6_src.s6_addr16[startrand]= ipv6->ip6_src.s6_addr16[startrand] \
											& htons(mask);
			}

			for(i=0; i<=(srcpreflen/16); i++)
				ipv6->ip6_src.s6_addr16[i]= ipv6->ip6_src.s6_addr16[i] | srcaddr.s6_addr16[i];

			if(idata.type == DLT_EN10MB && !loopback_f && !hsrcaddr_f){
				for(i=0; i<6; i++)
					ethernet->src.a[i]= random();
			}
		}

		ports=0;

		do{
			if(floodp_f){
				tcp->th_sport= random();
			}
			tcp->th_sum = 0;
			tcp->th_sum = in_chksum(v6buffer, tcp, ptr-((unsigned char *)tcp), IPPROTO_TCP);

			if(!fragh_f){
				ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);

				if((nw=pcap_inject(pfd, buffer, ptr - buffer)) == -1){
					printf("pcap_inject(): %s\n", pcap_geterr(pfd));
					exit(1);
				}

				if(nw != (ptr-buffer)){
					printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", \
								(LUI) nw, (LUI) (ptr-buffer));
					exit(1);
				}
			}
			else{
				ptrend= ptr;
				ptr= fragpart;
				fptr = fragbuffer;
				fipv6 = (struct ip6_hdr *) (fragbuffer + linkhsize);
				fptrend = fptr + linkhsize+MIN_IPV6_HLEN+MAX_IPV6_PAYLOAD;
				memcpy(fptr, buffer, fragpart-buffer);
				fptr = fptr + (fragpart-buffer);

				if( (fptr+FRAG_HDR_SIZE)> fptrend){
					puts("Unfragmentable Part is Too Large");
					exit(1);
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

					fipv6->ip6_plen = htons((fptr - fragbuffer) - MIN_IPV6_HLEN - linkhsize);
		
					if((nw=pcap_inject(pfd, fragbuffer, fptr - fragbuffer)) == -1){
						printf("pcap_inject(): %s\n", pcap_geterr(pfd));
						exit(1);
					}

					if(nw != (fptr- fragbuffer)){
						printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", \
										(LUI) nw, (LUI) (ptr-buffer));
						exit(1);
					}
				} /* Sending fragments */
			} /* Sending fragmented datagram */

			ports++;
		}while(ports<nports);

		sources++;
	}while(sources<nsources);
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
 * Function: in_chksum()
 *
 * Calculate the 16-bit ICMPv6 checksum
 */

u_int16_t in_chksum(void *ptr_ipv6, void *ptr_icmpv6, size_t len, u_int8_t proto){
	struct ipv6pseudohdr pseudohdr;
	struct ip6_hdr *v6packet;
	size_t nleft;
	unsigned int sum = 0;
	u_int16_t *w;
	u_int16_t answer = 0;

	v6packet=ptr_ipv6;
	
	bzero(&pseudohdr, sizeof(struct ipv6pseudohdr));
	pseudohdr.srcaddr= v6packet->ip6_src;
	pseudohdr.dstaddr= v6packet->ip6_dst;
	pseudohdr.len = htons(len);
	pseudohdr.nh = proto;

	nleft=40;
	w= (u_int16_t *) &pseudohdr;

	while(nleft > 1){
		sum += *w++;
		nleft -= 2;
	}

	nleft= len;
	w= (u_int16_t *) ptr_icmpv6;

	while(nleft > 1){
		sum += *w++;
		nleft -= 2;
	}

	if(nleft == 1){
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return(answer);
}




/*
 * Function: print_attack_info()
 *
 * Prints attack details (when the verbose ("-v") option is specified).
 */
 
void print_attack_info(void){
	puts( "tcp6\nAssessment tool for attack vectors based on TCP/IPv6 packets\n");

	if(floods_f)
		printf("Flooding the target from %u different IPv6 Source Addresses\n", nsources);

	if(floods_f)
		printf("Flooding the target from %u different TCP ports\n", nports);

	if(idata.type == DLT_EN10MB && !loopback_f){
		if(hsrcaddr_f){
				if(ether_ntop(&hsrcaddr, plinkaddr, sizeof(plinkaddr)) == 0){
					puts("ether_ntop(): Error converting address");
					exit(1);
				}

				printf("Ethernet Source Address: %s\n", plinkaddr);
		}
		else{
			if(!floods_f && dstaddr_f){
				if(ether_ntop(&hsrcaddr, plinkaddr, sizeof(plinkaddr)) == 0){
					puts("ether_ntop(): Error converting address");
					exit(1);
				}

				printf("Ethernet Source Address: %s%s\n", plinkaddr, ((!hsrcaddr_f)?" (randomized)":""));
			}
			else
				puts("Ethernet Source Address: Automatically selected for each packet");
		}

		/* 
		   Ethernet Destination Address only used if a IPv6 Destination Address or an
		   Ethernet Destination Address were specified.
		 */
		if(dstaddr_f){
			if(ether_ntop(&hdstaddr, plinkaddr, sizeof(plinkaddr)) == 0){
				puts("ether_ntop(): Error converting address");
				exit(1);
			}

			printf("Ethernet Destination Address: %s\n", plinkaddr);
		}
	}

	if(inet_ntop(AF_INET6, &srcaddr, psrcaddr, sizeof(psrcaddr))<=0){
		puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
		exit(1);
	}

	if(!floods_f){
		if(dstaddr_f){
			printf("IPv6 Source Address: %s%s\n", psrcaddr, ((!srcaddr_f)?" (randomized)":""));
		}
	}
	else{
		printf("IPv6 Source Address: randomized, from the %s/%u prefix%s\n", psrcaddr, srcpreflen, \
    									(!srcprefix_f)?" (default)":"");
	}

	if(dstaddr_f){
		if(inet_ntop(AF_INET6, &dstaddr, pdstaddr, sizeof(pdstaddr))<=0){
			puts("inet_ntop(): Error converting IPv6 Destination Address to presentation format");
			exit(1);
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

	if(dstaddr_f){
		printf("Source Port: %u%s\tDestination Port: %u%s\n",  srcport, (srcport_f?"":" (randomized)"),\
							dstport, (dstport_f?"":" (randomized)"));

		printf("SEQ Number: %u%s\tACK Number: %u%s\n", tcpseq, (tcpseq_f?"":" (randomized)"), \
								tcpack, (tcpack_f?"":" (randomized)"));

		printf("Flags: %s%s%s%s%s%s%s%s\t", ((tcpflags & TH_FIN)?"F":""), ((tcpflags & TH_SYN)?"S":""), \
					((tcpflags & TH_RST)?"R":""), ((tcpflags & TH_PUSH)?"P":""),\
					((tcpflags & TH_ACK)?"A":""), ((tcpflags & TH_URG)?"U":""),\
					((!tcpflags)?"none":""), ((!tcpflags_f)?" (default)":""));

		printf("Window: %u%s\tURG Pointer: %u%s\n", tcpwin, (tcpwin_f?"":" (randomized)"), \
								tcpurg, (tcpurg_f?"":" (default)"));
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

		printf("Window: %u%s\tURG Pointer: %u%s\n", tcpwin, (tcpwin_f?"":" (randomized)"), \
								tcpurg, (tcpurg_f?"":" (default)"));
	}
}



/*
 * Function: print_filters()
 *
 * Prints the filters that will be applied to incoming packets.
 */

void print_filters(void){
	if(nblocksrc){
		printf("Block filter for IPv6 Source Addresss: ");
	
		for(i=0; i<nblocksrc; i++){
			if(inet_ntop(AF_INET6, &blocksrc[i], pv6addr, sizeof(pv6addr))<=0){
				puts("inet_ntop(): Error converting IPv6 Src. Addr. filter to presentation format");
				exit(1);
			}

			printf("%s/%u   ", pv6addr, blocksrclen[i]);
		}
		printf("\n");
	}

	if(nblockdst){
		printf("Block filter for IPv6 Destination Address: ");
	
		for(i=0; i<nblockdst; i++){
			if(inet_ntop(AF_INET6, &blockdst[i], pv6addr, sizeof(pv6addr))<=0){
				puts("inet_ntop(): Error converting IPv6 Dst. Addr. filter to presentation format");
				exit(1);
			}

			printf("%s/%u   ", pv6addr, blockdstlen[i]);
		}
		printf("\n");
	}

	if(idata.type == DLT_EN10MB && !loopback_f){
		if(nblocklinksrc){
			printf("Block filter for link-layer Source Address: ");
	
			for(i=0; i<nblocklinksrc; i++){
				if(ether_ntop(&blocklinksrc[i], plinkaddr, sizeof(plinkaddr)) == 0){
					puts("ether_ntop(): Error converting address");
					exit(1);
				}
			
				printf("%s   ", plinkaddr);
			}
			printf("\n");
		}

		if(nblocklinkdst){
			printf("Block filter for link-layer Destination Address: ");
	
			for(i=0; i<nblocklinkdst; i++){
				if(ether_ntop(&blocklinkdst[i], plinkaddr, sizeof(plinkaddr)) == 0){
					puts("ether_ntop(): Error converting address");
					exit(1);
				}
		
				printf("%s   ", plinkaddr);
			}
			printf("\n");
		}
	}

	if(nacceptsrc){
		printf("Accept filter for IPv6 Source Addresss: ");

		for(i=0; i<nacceptsrc; i++){
			if(inet_ntop(AF_INET6, &acceptsrc[i], pv6addr, sizeof(pv6addr))<=0){
				puts("inet_ntop(): Error converting IPv6 Src. Addr. filter to presentation format");
				exit(1);
			}

			printf("%s/%u   ", pv6addr, acceptsrclen[i]);
		}
		printf("\n");
	}

	if(nacceptdst){
		printf("Accept filter for IPv6 Destination Address: ");
	
		for(i=0; i<nacceptdst; i++){
			if(inet_ntop(AF_INET6, &acceptdst[i], pv6addr, sizeof(pv6addr))<=0){
				puts("inet_ntop(): Error converting IPv6 Dst. Addr. filter to presentation format");
				exit(1);
			}

			printf("%s/%u   ", pv6addr, acceptdstlen[i]);
		}
		printf("\n");
	}

	if(idata.type == DLT_EN10MB && !loopback_f){
		if(nacceptlinksrc){
			printf("Accept filter for link-layer Source Address: ");

			for(i=0; i<nacceptlinksrc; i++){
				if(ether_ntop(&acceptlinksrc[i], plinkaddr, sizeof(plinkaddr)) == 0){
					puts("ether_ntop(): Error converting address");
					exit(1);
				}
		
				printf("%s   ", plinkaddr);
			}
			printf("\n");
		}

		if(nacceptlinkdst){
			printf("Accept filter for link-layer Destination Address: ");
	
			for(i=0; i<nacceptlinkdst; i++){
				if(ether_ntop(&acceptlinkdst[i], plinkaddr, sizeof(plinkaddr)) == 0){
					puts("ether_ntop(): Error converting address");
					exit(1);
				}
			
				printf("%s   ", plinkaddr);
			}
			printf("\n");
		}
	}
}


/*
 * Function: print_filter_result()
 *
 * Prints infromation about an incoming packet and whether it was blocked or
 * accepted by a filter.
 */

void print_filter_result(const u_char *pkt_data, unsigned char fresult){
	struct ip6_hdr *pkt_ipv6;
	
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_data + linkhsize);

	if(inet_ntop(AF_INET6, &(pkt_ipv6->ip6_src), psrcaddr, sizeof(psrcaddr))<=0){
	    puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
	    exit(1);
	}

	if(inet_ntop(AF_INET6, &(pkt_ipv6->ip6_dst), pdstaddr, sizeof(pdstaddr))<=0){
	    puts("inet_ntop(): Error converting IPv6 Destination Address to presentation format");
	    exit(1);
	}

	printf("Received IPv6 packet from %s to %s (%s)\n", psrcaddr, pdstaddr, \
					    ((fresult == ACCEPTED)?"accepted":"blocked") );

}



/*
 * Function: ether_pton()
 *
 * Convert a string (printable Ethernet Address) into binary format
 */

int ether_pton(const char *ascii, struct ether_addr *etheraddr, unsigned int s){
	unsigned int i, a[6];

	if(s < ETHER_ADDR_LEN)
		return 0;
	
	if(ascii){
		if( sscanf(ascii,"%x:%x:%x:%x:%x:%x", &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]) == 6){ 
			for(i=0;i<6;i++)
				etheraddr->a[i]= a[i];

			return 1;
		}
	}

	return 0;
}



/*
 * Function: ether_ntop()
 *
 * Convert binary Ethernet Address into printable foramt (an ASCII string)
 */

int ether_ntop(const struct ether_addr *ether, char *ascii, size_t s){
	unsigned int r;

	if(s < ETHER_ADDR_PLEN)
		return 0;

	r=snprintf(ascii, s, "%02x:%02x:%02x:%02x:%02x:%02x", ether->a[0], ether->a[1], ether->a[2], ether->a[3], \
											ether->a[4], ether->a[5]);

	if(r != 17)
		return 0;

	return 1;
}


/*
 * Function match_ipv6()
 *
 * Finds if an IPv6 address matches a prefix in a list of prefixes.
 */

unsigned int match_ipv6(struct in6_addr *prefixlist, u_int8_t *prefixlen, unsigned int nprefix, 
								struct in6_addr *ipv6addr){

	unsigned int 	i;
	struct in6_addr	dummyipv6;
    
	for(i=0; i<nprefix; i++){
		dummyipv6 = *ipv6addr;
		sanitize_ipv6_prefix(&dummyipv6, prefixlen[i]);
	
		for(j=0; j<4; j++)
			if(dummyipv6.s6_addr32[j] != prefixlist[i].s6_addr32[j])
				break;

		if(j==4)
			return 1;
	}

	return 0;
}


/*
 * match_ether()
 *
 * Finds if an Ethernet address matches any of the Ethernet addreses contained in an array.
 */

unsigned int match_ether(struct ether_addr *addrlist, unsigned int naddr, \
							    struct ether_addr *linkaddr){

	unsigned int i, j;

	for(i=0; i<naddr; i++){
		for(j=0; j<6; j++)
			if(linkaddr->a[j] != addrlist[i].a[j])
				break;

		if(j==6)
			return 1;
	}

	return 0;
}


/*
 * sanitize_ipv6_prefix()
 *
 * Clears those bits in an IPv6 address that are not within a prefix length.
 */

void sanitize_ipv6_prefix(struct in6_addr *ipv6addr, u_int8_t prefixlen){
	unsigned int	skip, i;
	u_int16_t	mask;

	skip= (prefixlen+15)/16;

	if(prefixlen%16){
		mask=0;
		for(i=0; i<(prefixlen%16); i++)
			mask= (mask>>1) | 0x8000;
	    
		ipv6addr->s6_addr16[skip-1]= ipv6addr->s6_addr16[skip-1] & htons(mask);
	}
			
	for(i=skip;i<8;i++)
		ipv6addr->s6_addr16[i]=0;
}


/*
 * randomize_ipv6_addr()
 *
 * Select a random IPv6 from a given prefix.
 */

void randomize_ipv6_addr(struct in6_addr *ipv6addr, struct in6_addr *prefix, u_int8_t preflen){
	u_int16_t mask;
	u_int8_t startrand;	
	unsigned int i;

	startrand= preflen/16;

	for(i=0; i<startrand; i++)
		ipv6addr->s6_addr16[i]= 0;

	for(i=startrand; i<8; i++)
		ipv6addr->s6_addr16[i]=random();

	if(preflen%16){
		mask=0xffff;

		for(i=0; i<(preflen%16); i++)
			mask= mask>>1;

		ipv6addr->s6_addr16[startrand]= ipv6addr->s6_addr16[startrand] & htons(mask);
	}

	for(i=0; i<=(preflen/16); i++)
		ipv6addr->s6_addr16[i]= ipv6addr->s6_addr16[i] | prefix->s6_addr16[i];

}



/*
 * randomize_ether_addr()
 *
 * Select a random Ethernet address.
 */

void randomize_ether_addr(struct ether_addr *ethaddr){
	for(i=0; i<6; i++)
		ethaddr->a[i]= random();

	ethaddr->a[0]= (ethaddr->a[0] & 0xfc) | 0x02;
}


/*
 * Function: inset_pad_opt()
 *
 * Insert a padding option (Pad1 or PadN) into an IPv6 extension header
 */

int insert_pad_opt(unsigned char *ptrhdr, const unsigned char *ptrhdrend, unsigned int padn){
	unsigned char *ptr;

	if( (ptrhdrend - ptrhdr) < padn)
		return 0;

	if(padn == 1){
		*ptrhdr= 0x00;
		return 1;
	}
	else{
		ptr=ptrhdr;
		*ptr= 0x01;
		ptr++;
		*ptr= padn-2;
		ptr+=2;
	
		while(ptr < (ptrhdr+padn)){
			*ptr= 0x00;
			ptr++;
		}    
		return 1;
	}
}


/*
 * Function: ipv6_to_ether()
 *
 * Obtains the Ethernet address corresponding to an IPv6 address (by means of Neighbor Discovery)
 */

int ipv6_to_ether(pcap_t *pfd, struct iface_data *idata, struct in6_addr *targetaddr, struct ether_addr *result_ether){
	struct bpf_program		pcap_filter;
	struct pcap_pkthdr		*pkthdr;
	const u_char			*pktdata;
	struct ip6_hdr			*pkt_ipv6;
	struct nd_neighbor_advert 	*pkt_na;
	unsigned char			*pkt_end;
	volatile unsigned char	*ptr, *p;

	unsigned char			buffer[65556];
	unsigned int 			ns_max_packet_size;
	struct ether_header		*ether;
	unsigned char 			*v6buffer;
	struct ip6_hdr			*ipv6;
	struct nd_neighbor_solicit	*ns;
	struct nd_opt_slla		*sllaopt;
	volatile unsigned int		tries=0;
	unsigned int			foundaddr=0;
	struct sigaction		new_sig, old_sig;
	int				result;
	unsigned char			error_f=0, closefd_f=0;

	ns_max_packet_size = idata->mtu;

	ether = (struct ether_header *) buffer;
	v6buffer = buffer + sizeof(struct ether_header);
	ipv6 = (struct ip6_hdr *) v6buffer;

	if(pfd == NULL){
		if( (pfd= pcap_open_live(idata->iface, PCAP_SNAP_LEN, PCAP_PROMISC, PCAP_TIMEOUT, errbuf)) == NULL){
			if(verbose_f>1)
				printf("pcap_open_live(): %s\n", errbuf);

			return(-1);
		}

		if( pcap_datalink(pfd) != DLT_EN10MB){
			if(verbose_f>1)
				printf("Error: Interface %s is not an Ethernet interface", iface);

			return(-1);
		}

		closefd_f=1;
	}

	if(pcap_compile(pfd, &pcap_filter, PCAP_ICMPV6_NA_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
		if(verbose_f>1)
			printf("pcap_compile(): %s", pcap_geterr(pfd));

		if(closefd_f)
			pcap_close(pfd);

		return(-1);
	}
    
	if(pcap_setfilter(pfd, &pcap_filter) == -1){
		if(verbose_f>1)
			printf("pcap_setfilter(): %s", pcap_geterr(pfd));

		if(closefd_f)
			pcap_close(pfd);

		return(-1);
	}

	pcap_freecode(&pcap_filter);

	ipv6->ip6_flow=0;
	ipv6->ip6_vfc= 0x60;
	ipv6->ip6_hlim= 255;
	ipv6->ip6_src= idata->ip6_local;
	ipv6->ip6_dst= solicited_node(targetaddr);

	ether->src = idata->ether;
	ether->dst = ether_multicast(&(ipv6->ip6_dst));
	ether->ether_type = htons(0x86dd);

	prev_nh = (unsigned char *) &(ipv6->ip6_nxt);
	*prev_nh = IPPROTO_ICMPV6;

	ptr = (unsigned char *) v6buffer + MIN_IPV6_HLEN;

	if( (ptr+sizeof(struct nd_neighbor_solicit)) > (v6buffer+ns_max_packet_size)){
		if(verbose_f>1)
			puts("Packet too large while inserting Neighbor Solicitation header");

		if(closefd_f)
			pcap_close(pfd);

		return(-1);
	}

	ns= (struct nd_neighbor_solicit *) (ptr);

	ns->nd_ns_type = ND_NEIGHBOR_SOLICIT;
	ns->nd_ns_code = 0;
	ns->nd_ns_reserved = 0;
	ns->nd_ns_target = *targetaddr;

	ptr += sizeof(struct nd_neighbor_solicit);
	sllaopt = (struct nd_opt_slla *) ptr;    

	if( (ptr+sizeof(struct nd_opt_slla)) > (v6buffer+ns_max_packet_size)){
		if(verbose_f>1)
			puts("NS message too large while processing source link-layer addresss opt.");

		if(closefd_f)
			pcap_close(pfd);

		return(-1);
	}

	sllaopt->type= ND_OPT_SOURCE_LINKADDR;
	sllaopt->length= SLLA_OPT_LEN;
	bcopy( &(idata->ether.a), sllaopt->address, ETH_ALEN);
	ptr += sizeof(struct nd_opt_slla);

	ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);
	ns->nd_ns_cksum = 0;
	ns->nd_ns_cksum = in_chksum(v6buffer, ns, ptr-((unsigned char *)ns), IPPROTO_ICMPV6);

	/* We set the signal handler, and the anchor for siglongjump() */
	canjump=0;
	bzero(&new_sig, sizeof(struct sigaction));
	sigemptyset(&new_sig.sa_mask);
	new_sig.sa_handler= &sig_alarm;

	alarm(0);

	if( sigaction(SIGALRM, &new_sig, &old_sig) == -1){
		if(verbose_f>1)
			puts("Error setting up 'Alarm' signal");

		if(closefd_f)
			pcap_close(pfd);

		return(-1);
	}

	if(sigsetjmp(env, 1) != 0)
		tries++;

	canjump=1;

	while(tries<3 && !foundaddr && !error_f){
		if((nw=pcap_inject(pfd, buffer, ptr - buffer)) == -1){
			if(verbose_f>1)
				printf("pcap_inject(): %s\n", pcap_geterr(pfd));

			error_f=1;
			break;
		}

		if(nw != (ptr-buffer)){
			if(verbose_f>1)
				printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, \
												(LUI) (ptr-buffer));
			error_f=1;
			break;
		}

		alarm(idata->local_timeout);
		
		while(!foundaddr && !error_f){
			do{
				if( (result=pcap_next_ex(pfd, &pkthdr, &pktdata)) == -1){
					if(verbose_f>1)
						printf("pcap_next_ex(): %s", pcap_geterr(pfd));

					error_f=1;
					break;
				}
			}while(result==0);			

			if(error_f)
				break;	

			pkt_ether = (struct ether_header *) pktdata;
			pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + ETHER_HDR_LEN);
			pkt_na = (struct nd_neighbor_advert *) ((char *) pkt_ipv6 + MIN_IPV6_HLEN);
			pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

			/* The packet length is the minimum of what we capured, and what is specified in the
			   IPv6 Total Lenght field
			 */
			if( pkt_end > ((unsigned char *)pkt_na+ pkt_ipv6->ip6_plen) )
				pkt_end = (unsigned char *)pkt_na + pkt_ipv6->ip6_plen;

			/*
			   Discard the packet if it is not of the minimum size to contain a Neighbor Advertisement
			   message with a source link-layer address option
			 */
			if( (pkt_end - (unsigned char *) pkt_na) < (sizeof(struct nd_neighbor_advert) + \
										sizeof(struct nd_opt_tlla)))
				continue;

			/*
			   Neighbor Discovery packets must have a Hop Limit of 255
			 */
			if(pkt_ipv6->ip6_hlim != 255)
				continue;

			/* 
			   Check that that the Destination Address of the Neighbor Advertisement is the one
			   that we used for sending the Neighbor Solicitation message
			 */
			if(!is_eq_in6_addr(&(pkt_ipv6->ip6_dst), &(ipv6->ip6_src)))
				continue;

			/* Check that the ICMPv6 checksum is correct */
			if(in_chksum(pkt_ipv6, pkt_na, pkt_end-((unsigned char *)pkt_na), IPPROTO_ICMPV6) != 0)
				continue;

			/* Check that the ICMPv6 Target Address is the one we had asked for */
			if(!is_eq_in6_addr(&(pkt_na->nd_na_target), targetaddr))
				continue;

			p= (unsigned char *) pkt_na + sizeof(struct nd_neighbor_advert);

			/* Process Neighbor Advertisement options */
			while( (p+sizeof(struct nd_opt_tlla)) <= pkt_end && (*(p+1) != 0)){
				if(*p == ND_OPT_TARGET_LINKADDR){
					if( (*(p+1) * 8) != sizeof(struct nd_opt_tlla))
						break;

					/* Got a response, so we shouln't time out */
					alarm(0);

					/* Save the link-layer address */
					*result_ether= *(struct ether_addr *) (p+2);
					foundaddr=1;
					break;
				}

				p= p + *(p+1) * 8;
			} /* Processing options */

		} /* Processing packets */

	} /* Resending Neighbor Solicitations */

	alarm(0);

	if(closefd_f)
		pcap_close(pfd);

	if( sigaction(SIGALRM, &old_sig, NULL) == -1){
		if(verbose_f>1)
			puts("Error setting up 'Alarm' signal");

		return(-1);
	}

	if(foundaddr)
		return 1;
	else
		return 0;
}


/*
 * Function: solicited_node()
 *
 * Obtains the Solicited-node multicast address corresponding to an IPv6 address.
 */

struct in6_addr solicited_node(const struct in6_addr *ipv6addr){
	struct in6_addr solicited;

	solicited.s6_addr16[0]= htons(0xff02);
	solicited.s6_addr16[1]= 0x0000;
	solicited.s6_addr16[2]= 0x0000;
	solicited.s6_addr16[3]= 0x0000;
	solicited.s6_addr16[4]= 0x0000;
	solicited.s6_addr16[5]= htons(0x0001);
	solicited.s6_addr16[6]= htons(0xff00) | ipv6addr->s6_addr16[6];
	solicited.s6_addr16[7]= ipv6addr->s6_addr16[7];

	return solicited;
}


/*
 * Function: ether_multicast()
 *
 * Obtains the Ethernet multicast address corresponding to an IPv6 multicast address.
 */

struct ether_addr ether_multicast(const struct in6_addr *ipv6addr){
	unsigned int i;
	struct ether_addr ether;

	ether.a[0]=0x33;
	ether.a[1]=0x33;

	for(i=2;i<6;i++)
		ether.a[i]= ipv6addr->s6_addr[i+10];

	return ether;
}


/*
 * Function: init_iface_data()
 *
 * Initializes the contents of "iface_data" structure
 */

int init_iface_data(struct iface_data *idata){
	bzero(idata, sizeof(struct iface_data));
	idata->local_retrans = 0;
	idata->local_timeout = 1;

	idata->ip6_global.prefix= prefix_local;
	idata->ip6_global.nprefix=0;
	idata->ip6_global.maxprefix= MAX_LOCAL_ADDRESSES;

	idata->prefix_ol.prefix= prefix_ols;
	idata->prefix_ol.nprefix= 0;
	idata->prefix_ol.maxprefix= MAX_PREFIXES_ONLINK;

	idata->prefix_ac.prefix= prefix_acs;
	idata->prefix_ac.nprefix= 0;
	idata->prefix_ac.maxprefix= MAX_PREFIXES_AUTO;

	return 0;
}


/*
 * Function: find_ipv6_router_full()
 *
 * Finds a local router (by means of Neighbor Discovery)
 */

int find_ipv6_router_full(pcap_t *pfd, struct iface_data *idata){
	struct pcap_pkthdr			*pkthdr;
	const u_char				*pktdata;
	struct ip6_hdr				*pkt_ipv6;
	struct nd_router_advert 	*pkt_ra;
	unsigned char				*pkt_end;
	volatile unsigned char		*ptr;
	volatile unsigned char		*p;

	unsigned char				buffer[65556];
	unsigned int 				rs_max_packet_size;
	struct ether_header 		*ether;
	unsigned char 				*v6buffer;
	struct ip6_hdr 				*ipv6;
	struct nd_router_solicit	*rs;
	struct nd_opt_slla 			*sllaopt;
	struct nd_opt_prefix_info	*pio;
	volatile unsigned int 		tries=0;
	volatile unsigned int 		foundrouter=0;
	struct sigaction 			new_sig, old_sig;
	unsigned char				closefd_f=0, error_f=0;
	int							result;

	rs_max_packet_size = idata->mtu;
	ether = (struct ether_header *) buffer;
	v6buffer = buffer + sizeof(struct ether_header);
	ipv6 = (struct ip6_hdr *) v6buffer;

	if(pfd == NULL){
		if( (pfd= pcap_open_live(idata->iface, PCAP_SNAP_LEN, PCAP_PROMISC, PCAP_TIMEOUT, errbuf)) == NULL){
			if(verbose_f>1)
				printf("pcap_open_live(): %s\n", errbuf);

			return(-1);
		}

		if( pcap_datalink(pfd) != DLT_EN10MB){
			if(verbose_f>1)
				printf("Error: Interface %s is not an Ethernet interface", idata->iface);

			return(-1);
		}

		closefd_f=1;
	}

	if(pcap_compile(pfd, &pcap_filter, PCAP_ICMPV6_RANS_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
		if(verbose_f>1)
			printf("pcap_compile(): %s", pcap_geterr(pfd));

		if(closefd_f)
			pcap_close(pfd);

		return(-1);
	}
    
	if(pcap_setfilter(pfd, &pcap_filter) == -1){
		if(verbose_f>1)
			printf("pcap_setfilter(): %s", pcap_geterr(pfd));

		if(closefd_f)
			pcap_close(pfd);

		return(-1);
	}

	pcap_freecode(&pcap_filter);

	ipv6->ip6_flow=0;
	ipv6->ip6_vfc= 0x60;
	ipv6->ip6_hlim= 255;
	ipv6->ip6_src= idata->ip6_local;

	if ( inet_pton(AF_INET6, ALL_ROUTERS_MULTICAST_ADDR, &(ipv6->ip6_dst)) <= 0){
		if(verbose_f>1)
			puts("inet_pton(): Error converting All Routers address from presentation to network format");

		if(closefd_f)
			pcap_close(pfd);

		return(-1);
	}

	ether->src = idata->ether;

	if(ether_pton(ETHER_ALLROUTERS_LINK_ADDR, &(ether->dst), sizeof(struct ether_addr)) == 0){
		if(verbose_f>1)
			puts("ether_pton(): Error converting all-nodes multicast address");

		if(closefd_f)
			pcap_close(pfd);

		return(-1);
	}

	ether->ether_type = htons(0x86dd);

	prev_nh = (unsigned char *) &(ipv6->ip6_nxt);
	*prev_nh = IPPROTO_ICMPV6;

	ptr = (unsigned char *) v6buffer + MIN_IPV6_HLEN;

	if( (ptr+sizeof(struct nd_router_solicit)) > (v6buffer+rs_max_packet_size)){
		if(verbose_f>1)
			puts("Packet too large while inserting Router Solicitation header");

		if(closefd_f)
			pcap_close(pfd);

		return(-1);
	}

	rs= (struct nd_router_solicit *) (ptr);

	rs->nd_rs_type = ND_ROUTER_SOLICIT;
	rs->nd_rs_code = 0;
	rs->nd_rs_reserved = 0;

	ptr += sizeof(struct nd_router_solicit);
	sllaopt = (struct nd_opt_slla *) ptr;    

	if( (ptr+sizeof(struct nd_opt_slla)) > (v6buffer+rs_max_packet_size)){
		if(verbose_f>1)
			puts("RS message too large while processing source link-layer addresss opt.");

		if(closefd_f)
			pcap_close(pfd);

		return(-1);
	}

	sllaopt->type= ND_OPT_SOURCE_LINKADDR;
	sllaopt->length= SLLA_OPT_LEN;
	bcopy( &(idata->ether.a), sllaopt->address, ETH_ALEN);
	ptr += sizeof(struct nd_opt_slla);

	ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);
	rs->nd_rs_cksum = 0;
	rs->nd_rs_cksum = in_chksum(v6buffer, rs, ptr-((unsigned char *)rs), IPPROTO_ICMPV6);

	/* We set the signal handler, and the anchor for siglongjump() */
	canjump=0;
	bzero(&new_sig, sizeof(struct sigaction));
	sigemptyset(&new_sig.sa_mask);
	new_sig.sa_handler= &sig_alarm;

	alarm(0);

	if( sigaction(SIGALRM, &new_sig, &old_sig) == -1){
		if(verbose_f>1)
			puts("Error setting up 'Alarm' signal");

		if(closefd_f)
			pcap_close(pfd);

		return(-1);
	}

	if(sigsetjmp(env, 1) != 0)
		tries++;

	canjump=1;

	while(tries<3 && !foundrouter && !error_f){
		if((nw=pcap_inject(pfd, buffer, ptr - buffer)) == -1){
			if(verbose_f>1)
				printf("pcap_inject(): %s\n", pcap_geterr(pfd));

			error_f=1;
			break;
		}

		if(nw != (ptr-buffer)){
			if(verbose_f>1)
				printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, \
												(LUI) (ptr-buffer));

			error_f=1;
			break;
		}

		alarm(idata->local_timeout + 1);
		
		while(!foundrouter && !error_f){

			do{
				if( (result=pcap_next_ex(pfd, &pkthdr, &pktdata)) == -1){
					if(verbose_f>1)
						printf("pcap_next_ex(): %s", pcap_geterr(pfd));

					error_f=1;
					break;
				}
			}while(result==0);			

			if(error_f)
				break;

			pkt_ether = (struct ether_header *) pktdata;
			pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + ETHER_HDR_LEN);
			pkt_ra = (struct nd_router_advert *) ((char *) pkt_ipv6 + MIN_IPV6_HLEN);
			pkt_end = (unsigned char *) pktdata + pkthdr->caplen;


			/* The packet length is the minimum of what we capured, and what is specified in the
			   IPv6 Total Lenght field
			 */
			if( pkt_end > ((unsigned char *)pkt_ra + pkt_ipv6->ip6_plen) )
				pkt_end = (unsigned char *)pkt_ra + pkt_ipv6->ip6_plen;

			/*
			   Discard the packet if it is not of the minimum size to contain a Neighbor Advertisement
			   message with a source link-layer address option
			 */
			if( (pkt_end - (unsigned char *) pkt_ra) < (sizeof(struct nd_router_advert) + \
										sizeof(struct nd_opt_slla)))
				continue;

			/*
			   Neighbor Discovery packets must have a Hop Limit of 255
			 */
			if(pkt_ipv6->ip6_hlim != 255)
				continue;

			/*
			   Check that the IPv6 Source Address of the Router Advertisement is an IPv6 link-local
			   address.
			 */
			if( (pkt_ipv6->ip6_src.s6_addr16[0] & htons(0xffc0)) != htons(0xfe80))
				continue;

			/* 
			   Check that that the Destination Address of the Router Advertisement is either the one
			   that we used for sending the Router Solicitation message or a multicast address 
			   (typically the all-nodes)
			 */
			if(!is_eq_in6_addr(&(pkt_ipv6->ip6_dst), &(ipv6->ip6_src)) \
					&& !IN6_IS_ADDR_MULTICAST(&(pkt_ipv6->ip6_dst)))
				continue;

			/* Check that the ICMPv6 checksum is correct. If the received checksum is valid,
			   and we compute the checksum over the received packet (including the Checkdum field)
			   the result is 0. Otherwise, the packet has been corrupted.
			*/
			if(in_chksum(pkt_ipv6, pkt_ra, pkt_end- (unsigned char *)pkt_ra, IPPROTO_ICMPV6) != 0)
				continue;

			p= (unsigned char *) pkt_ra + sizeof(struct nd_router_advert);

			/* Process Router Advertisement options */
			while( (p+ *(p+1) * 8) <= pkt_end && *(p+1)!=0 && !error_f){
				switch(*p){
					case ND_OPT_SOURCE_LINKADDR:
						if( (*(p+1) * 8) != sizeof(struct nd_opt_tlla))
							break;

						/* Got a response, so we shouln't time out */
						alarm(0);

						/* Save the link-layer address */
						idata->router_ether = *(struct ether_addr *) (p+2);
						idata->router_ip6= pkt_ipv6->ip6_src;
						foundrouter=1;
						break;

					case ND_OPT_PREFIX_INFORMATION:
						if(*(p+1) != 4)
							break;

						pio= (struct nd_opt_prefix_info *) p;

						if((idata->prefix_ol.nprefix) < idata->prefix_ol.maxprefix){
							if( (pio->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_ONLINK) && \
								(pio->nd_opt_pi_prefix_len <= 128) && !is_ip6_in_prefix_list(&(pio->nd_opt_pi_prefix), \
								&(idata->prefix_ol))){

								if( (idata->prefix_ol.prefix[idata->prefix_ol.nprefix] = \
																		malloc(sizeof(struct prefix_entry))) == NULL){
									if(verbose_f>1)
										puts("Error in malloc() while learning prefixes");

									error_f=1;
									break;
								}

								(idata->prefix_ol.prefix[idata->prefix_ol.nprefix])->ip6= pio->nd_opt_pi_prefix;
								(idata->prefix_ol.prefix[idata->prefix_ol.nprefix])->len= pio->nd_opt_pi_prefix_len;
								sanitize_ipv6_prefix(&((idata->prefix_ol.prefix[idata->prefix_ol.nprefix])->ip6), \
														(idata->prefix_ol.prefix[idata->prefix_ol.nprefix])->len);
								(idata->prefix_ol.nprefix)++;
							}
						}

						if(idata->prefix_ac.nprefix < idata->prefix_ac.maxprefix){
							if( (pio->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_AUTO) && \
								(pio->nd_opt_pi_prefix_len == 64) && !is_ip6_in_prefix_list(&(pio->nd_opt_pi_prefix), \
																							&(idata->prefix_ac))){

								if((idata->prefix_ac.prefix[idata->prefix_ac.nprefix] = \
																		malloc(sizeof(struct prefix_entry))) == NULL){
									if(verbose_f>1)
										puts("Error in malloc() while learning prefixes");

									error_f=1;
									break;
								}

								(idata->prefix_ac.prefix[idata->prefix_ac.nprefix])->ip6= \
												pio->nd_opt_pi_prefix;
								(idata->prefix_ac.prefix[idata->prefix_ac.nprefix])->len= \
												pio->nd_opt_pi_prefix_len;

								sanitize_ipv6_prefix(&((idata->prefix_ac.prefix[idata->prefix_ac.nprefix])->ip6), \
														(idata->prefix_ac.prefix[idata->prefix_ac.nprefix])->len);

								if(!idata->ip6_global_flag && idata->ip6_global.nprefix < idata->ip6_global.maxprefix){
								
									if( (idata->ip6_global.prefix[idata->ip6_global.nprefix] = \
																	malloc(sizeof(struct prefix_entry))) == NULL){
										if(verbose_f>1)
											puts("Error in malloc() creating local SLAAC addresses");

										error_f=1;
										break;
									}

									generate_slaac_address(&(idata->prefix_ac.prefix[idata->prefix_ac.nprefix]->ip6), \
										&(idata->ether), &((idata->ip6_global.prefix[idata->ip6_global.nprefix])->ip6));
									(idata->ip6_global.prefix[idata->ip6_global.nprefix])->len = 64;
									(idata->ip6_global.nprefix)++;
								}
								(idata->prefix_ac.nprefix)++;
							}
						}

						break;
				}

				p= p + *(p+1) * 8;
			} /* Processing options */

		} /* Processing packets */

	} /* Resending Router Solicitations */

	/* If we added at least one global address, we set the corresponding flag to 1 */
	if(idata->ip6_global.nprefix)
		idata->ip6_global_flag=1;

	if(closefd_f)
		pcap_close(pfd);

	if( sigaction(SIGALRM, &old_sig, NULL) == -1){
		if(verbose_f>1)
			puts("Error setting up 'Alarm' signal");

		return(-1);
	}

	if(foundrouter)
		return 1;
	else
		return 0;
}



/*
 * Function: is_eq_in6_addr()
 *
 * Compares two IPv6 addresses. Returns 0 if they are equal.
 */

int is_eq_in6_addr(struct in6_addr *ip1, struct in6_addr *ip2){
	unsigned int i;

	for(i=0; i<8; i++)
		if(ip1->s6_addr16[i] != ip2->s6_addr16[i])
			return 0;

	return 1;
}


/*
 * Function: ether_to_ipv6_linklocal()
 *
 * Generates an IPv6 link-local address (with modified EUI-64 identifiers) based on
 * an Ethernet address.
 */

void ether_to_ipv6_linklocal(struct ether_addr *etheraddr, struct in6_addr *ipv6addr){
	ipv6addr->s6_addr16[0]= htons(0xfe80); /* Link-local unicast prefix */

	for(i=1;i<4;i++)
		ipv6addr->s6_addr16[i]=0x0000;

	ipv6addr->s6_addr16[4]=  htons(((u_int16_t)etheraddr->a[0] << 8) | etheraddr->a[1]);
	ipv6addr->s6_addr16[5]=  htons( ((u_int16_t)etheraddr->a[2] << 8) | 0xff);
	ipv6addr->s6_addr16[6]=  htons((u_int16_t) 0xfe00 | etheraddr->a[3]);
	ipv6addr->s6_addr16[7]=  htons(((u_int16_t)etheraddr->a[4] << 8) | etheraddr->a[5]);
}




/*
 * Handler for the ALARM signal.
 *
 * Used for setting a timeout on libpcap reads
 */

void sig_alarm(int num){
	if(canjump == 0)
		return;

	siglongjmp(env, 1);
}


/*
 * Function: get_if_addrs()
 *
 * Obtains Ethernet and IPv6 addresses of a network interface card
 */

int get_if_addrs(struct iface_data *idata){
	struct ifaddrs	*ifptr, *ptr;
	struct sockaddr_in6	*sockin6ptr;

#ifdef __linux__
	struct sockaddr_ll	*sockpptr;
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
	struct sockaddr_dl	*sockpptr;
#endif

	if(getifaddrs(&ifptr) != 0){
		if(verbose_f > 1){
			printf("Error while learning addresses of the %s interface\n", idata->iface);
		}
		return(-1);
	}

	for(ptr=ifptr; ptr != NULL; ptr= ptr->ifa_next){
		if(ptr->ifa_addr == NULL)
			continue;

#ifdef __linux__
		if( !(idata->ether_flag) && ((ptr->ifa_addr)->sa_family == AF_PACKET)){
			if(strncmp(idata->iface, ptr->ifa_name, IFACE_LENGTH-1) == 0){
				sockpptr = (struct sockaddr_ll *) (ptr->ifa_addr);
				if(sockpptr->sll_halen == 6){
					idata->ether = *((struct ether_addr *)sockpptr->sll_addr);
					idata->ether_flag=1;
				}
			}
		}
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
		if( !(idata->ether_flag) && ((ptr->ifa_addr)->sa_family == AF_LINK)){
			if(strncmp(idata->iface, ptr->ifa_name, IFACE_LENGTH-1) == 0){
				sockpptr = (struct sockaddr_dl *) (ptr->ifa_addr);
				if(sockpptr->sdl_alen == 6){
					idata->ether= *((struct ether_addr *)(sockpptr->sdl_data + sockpptr->sdl_nlen));
					idata->ether_flag= 1;
				}
			}
		}
#endif
		else if((ptr->ifa_addr)->sa_family == AF_INET6){
			sockin6ptr= (struct sockaddr_in6 *) (ptr->ifa_addr);

			if( !rand_src_f && !(idata->ip6_local_flag) &&  (((sockin6ptr->sin6_addr).s6_addr16[0] & htons(0xffc0)) \
															== htons(0xfe80))){
				if(strncmp(idata->iface, ptr->ifa_name, IFACE_LENGTH-1) == 0){
					idata->ip6_local = sockin6ptr->sin6_addr;
#if defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
					/* BSDs store the interface index in s6_addr16[1], so we must clear it */
					idata->ip6_local.s6_addr16[1] =0;
					idata->ip6_local.s6_addr16[2] =0;
					idata->ip6_local.s6_addr16[3] =0;					
#endif
					idata->ip6_local_flag= 1;
				}
			}
			else if( !rand_src_f && (((sockin6ptr->sin6_addr).s6_addr16[0] & htons(0xffc0)) \
											!= htons(0xfe80))){
				if(strncmp(idata->iface, ptr->ifa_name, IFACE_LENGTH-1) == 0){
					if(!is_ip6_in_prefix_list( &(sockin6ptr->sin6_addr), &(idata->ip6_global))){
						if(idata->ip6_global.nprefix < idata->ip6_global.maxprefix){
							if( (idata->ip6_global.prefix[idata->ip6_global.nprefix] = \
												malloc(sizeof(struct prefix_entry))) == NULL){
								if(verbose_f > 1)
									puts("Error while storing Source Address");

								return(-1);
							}

							(idata->ip6_global.prefix[idata->ip6_global.nprefix])->len = 64;
							(idata->ip6_global.prefix[idata->ip6_global.nprefix])->ip6 = sockin6ptr->sin6_addr;
							idata->ip6_global.nprefix++;
							idata->ip6_global_flag= 1;
						}
					}
				}
			}
		}
	}

	freeifaddrs(ifptr);
	return(0);
}




/*
 * Function: is_ip6_in_list()
 *
 * Checks whether an IPv6 address is present in an address list.
 */

int is_ip6_in_prefix_list(struct in6_addr *target, struct prefix_list *plist){
	unsigned int i, j, full16, rest16;
	u_int16_t	mask16;

	for(i=0; i < plist->nprefix; i++){
		full16=(plist->prefix[i])->len / 16;
		rest16=(plist->prefix[i])->len % 16;
		mask16 = 0xffff;

		for(j=0; j < full16; j++)
			if(target->s6_addr16[j] != (plist->prefix[i])->ip6.s6_addr16[j])
				break;

		if( (j == full16) && rest16){
			mask16 = mask16 << (16 - rest16);

			if( (target->s6_addr16[full16] & mask16) == ((plist->prefix[i])->ip6.s6_addr16[full16] & mask16))
				return 1;
		}
	}

	return 0;
}


/*
 * match_ipv6_to_prefixes()
 *
 * Finds out whether an IPv6 address matches any IPv6 prefix in an array
 */

int match_ipv6_to_prefixes(struct in6_addr *ipv6addr, struct prefix_list *pf){
	unsigned int	i, j, full16, rbits;
	u_int16_t	mask;

	for(i=0; i < pf->nprefix; i++){
		full16= (pf->prefix[i])->len/16;
		for(j=0; j<full16; j++){
			if(ipv6addr->s6_addr16[j] != (pf->prefix[i])->ip6.s6_addr16[j])
				break;
		}

		if(j == full16){
			if((rbits= (pf->prefix[i])->len%16) == 0)
				return 1;
			else{
				mask= 0xffff;
				mask= mask<<rbits;
				if((pf->prefix[i])->ip6.s6_addr16[full16] == (ipv6addr->s6_addr16[full16] & htons(mask)))
					return 1;
			}
		}
	}

	return 0;
}


/*
 * Function: generate_slaac_address()
 *
 * Generates an IPv6 address (with modified EUI-64 identifiers) based on
 * a IPv6 prefix and an Ethernet address.
 */

void generate_slaac_address(struct in6_addr *prefix, struct ether_addr *etheraddr, struct in6_addr *ipv6addr){
	ipv6addr->s6_addr16[0]= htons(0xfe80); /* Link-local unicast prefix */

	for(i=0;i<4;i++)
		ipv6addr->s6_addr16[i]= prefix->s6_addr16[i];

	ipv6addr->s6_addr16[4]=  htons(((u_int16_t) (etheraddr->a[0] | 0x02) << 8) | etheraddr->a[1]);
	ipv6addr->s6_addr16[5]=  htons( ((u_int16_t)etheraddr->a[2] << 8) | 0xff);
	ipv6addr->s6_addr16[6]=  htons((u_int16_t) 0xfe00 | etheraddr->a[3]);
	ipv6addr->s6_addr16[7]=  htons(((u_int16_t)etheraddr->a[4] << 8) | etheraddr->a[5]);
}


/*
 * Function: src_addr_sel()
 *
 * Selects a Source Address for a given Destination Address
 */

struct in6_addr *src_addr_sel(struct iface_data *idata, struct in6_addr *dst){
	u_int16_t	mask16;
	unsigned int	i, j, full16, rest16;
	/*
	   If the destination address is a link-local address, we select our link-local
	   address as the Source Address. If the dst address is a global unicast address
	   we select our first matching address, or else our first global address.
	   Worst case scenario, we don't have global address and must use our link-local
	   address.
	*/   

	if( (dst->s6_addr16[0] & htons(0xffc0)) == htons(0xfe80)){
		return( &(idata->ip6_local));
	}
	else if(IN6_IS_ADDR_MC_LINKLOCAL(dst) || IN6_IS_ADDR_LINKLOCAL(dst)){
		return( &(idata->ip6_local));
	}
	else if(idata->ip6_global_flag){
		for(i=0; i < idata->ip6_global.nprefix; i++){
				full16=(idata->ip6_global.prefix[i])->len / 16;
				rest16=(idata->ip6_global.prefix[i])->len % 16;
				mask16 = 0xffff;

				for(j=0; j < full16; j++)
					if( dst->s6_addr16[j] != (idata->ip6_global.prefix[i])->ip6.s6_addr16[j])
						break;

				if( (j == full16) && rest16){
					mask16 = mask16 << (16 - rest16);

					if( (dst->s6_addr16[full16] & mask16) == ((idata->ip6_global.prefix[i])->ip6.s6_addr16[full16] & mask16))
						return( &((idata->ip6_global.prefix[i])->ip6));
				}
		}

		return( &((idata->ip6_global.prefix[0])->ip6));
	}
	else{
		return( &(idata->ip6_local));
	}
}


