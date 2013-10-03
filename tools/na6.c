/*
 * na6: A security assessment tool for attack vectors based on
 *      ICMPv6 Neighbor Advertisement messages
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
 * Build with: make na6
 * 
 * The libpcap library must be previsously installed on your system.
 *
 * Please send any bug reports to Fernando Gont <fgont@si6networks.com>
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include "na6.h"
#include "libipv6.h"
#include "ipv6toolkit.h"

/* Function prototypes */
void			init_packet_data(struct iface_data *);
int				send_packet(struct iface_data *, struct pcap_pkthdr *, const u_char *);
void			print_attack_info(struct iface_data *);
void			usage(void);
void			print_help(void);

struct pcap_pkthdr	*pkthdr;
const u_char		*pktdata;
struct in6_addr		*pkt_ipv6addr;    
bpf_u_int32			my_netmask;
bpf_u_int32			my_ip;
struct bpf_program	pcap_filter;
char 				dev[64], errbuf[PCAP_ERRBUF_SIZE];
char 				all_nodes_addr[]= ALL_NODES_MULTICAST_ADDR;
unsigned char		buffer[65556];
unsigned char		*v6buffer, *ptr, *startofprefixes;
   
struct ip6_hdr		*ipv6, *pkt_ipv6;
struct nd_neighbor_advert	*na;

struct nd_neighbor_solicit	*pkt_ns;
struct ether_header	*ethernet, *pkt_ether;
struct nd_opt_tlla	*tllaopt;

struct in6_addr		targetaddr;
struct ether_addr	linkaddr[MAX_TLLA_OPTION];
unsigned int		nlinkaddr=0, linkaddrs;

char				*lasts, *pref, *rpref, *endptr;
char				*charptr;

size_t				nw;
unsigned long		ul_res, ul_val;
unsigned int		i, j, startrand;
unsigned int		skip;
unsigned int		ntargets, sources, nsources, targets, nsleep;
unsigned char		targetpreflen;

u_int16_t			mask;
u_int8_t			hoplimit;

char				plinkaddr[ETHER_ADDR_PLEN];
char 				psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN], pv6addr[INET6_ADDRSTRLEN];
unsigned char 		floodt_f=0, targetaddr_f=0;
unsigned char 		listen_f = 0, multicastdst_f=0, accepted_f=0, loop_f=0, sleep_f=0;
unsigned char		tllaopt_f=0, tllaopta_f=0, targetprefix_f=0, hoplimit_f=0;
unsigned char		newdata_f=0, floods_f=0;
u_int32_t			router_f=0, solicited_f=0, override_f=0;

/* Support for Extension Headers */
unsigned int		dstopthdrs, dstoptuhdrs, hbhopthdrs;
unsigned char		hbhopthdr_f=0, dstoptuhdr_f=0, dstopthdr_f=0;
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
unsigned int		nfrags, fragsize, max_packet_size;
unsigned char		*prev_nh, *startoffragment;
struct filters		filters;
struct iface_data	idata;

int main(int argc, char **argv){
	extern char		*optarg;
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
		{"target", required_argument, 0, 't'},
		{"router", no_argument, 0, 'r'},
		{"solicited", no_argument, 0, 'c'},
		{"override", no_argument, 0, 'o'},
		{"target-addr-opt", required_argument, 0, 'E'},
		{"add-target-opt", no_argument, 0, 'e'},
		{"block-src-addr", required_argument, 0, 'j'},
		{"block-dst-addr", required_argument, 0, 'k'},
		{"block-link-src-addr", required_argument, 0, 'J'},
		{"block-link-dst-addr", required_argument, 0, 'K'},
		{"block-target-addr", required_argument, 0, 'w'},
		{"accept-src-addr", required_argument, 0, 'b'},
		{"accept-dst-addr", required_argument, 0, 'g'},
		{"accept-link-src-addr", required_argument, 0, 'B'},
		{"accept-link-dst-addr", required_argument, 0, 'G'},
		{"accept-target-addr", required_argument, 0, 'W'},
		{"flood-sources", required_argument, 0, 'F'},
		{"flood-targets", required_argument, 0, 'T'},
		{"loop", no_argument, 0, 'l'},
		{"sleep", required_argument, 0, 'z'},
		{"listen", no_argument, 0, 'L'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'}
	};

    char shortopts[]= "i:s:d:A:u:U:H:y:S:D:t:roceE:j:k:J:K:w:b:g:B:G:W:T:F:lz:vhL";

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

			case 'y':	/* Fragment header */
				nfrags= atoi(optarg);
				if(nfrags < 8){
					puts("Error in Fragmentation option: Fragment Size must be at least 8 bytes");
					exit(EXIT_FAILURE);
				}
		
				nfrags = (nfrags +7) & 0xfff8;
				fragh_f= 1;
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

			case 't':	/* NA Target address */
				if((charptr = strtok_r(optarg, "/", &lasts)) == NULL){
					puts("Target Address not valid");
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

			case 'r':	/* "Router" flag */
				router_f = ND_NA_FLAG_ROUTER;
				break;
	
			case 'o':	/* "Override" flag */
				override_f = ND_NA_FLAG_OVERRIDE;
				break;	    	    

			case 'c':	/* Solicited flag */
				solicited_f = ND_NA_FLAG_SOLICITED;
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

			case 'e':	/* Add target link-layer option */
				tllaopt_f = 1;
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

			case 'w':	/* ND Target Address (block) filter */
				if(filters.nblocktarget > MAX_BLOCK_TARGET){
					puts("Too many Target Address (block) filters.");
					exit(EXIT_FAILURE);
				}
	    
				if((pref = strtok_r(optarg, "/", &lasts)) == NULL){
					printf("Error in Target Address (block) filter number %u.\n", filters.nblocktarget+1);
					exit(EXIT_FAILURE);
				}

				if ( inet_pton(AF_INET6, pref, &(filters.blocktarget[filters.nblocktarget])) <= 0){
					printf("Error in Target Address (block) filter number %u.\n", filters.nblocktarget+1);
					exit(EXIT_FAILURE);
				}

				if((charptr = strtok_r(NULL, " ", &lasts)) == NULL){
					filters.blocktargetlen[filters.nblocktarget] = 128;
				}
				else{
					filters.blocktargetlen[filters.nblocktarget] = atoi(charptr);
		
					if(filters.blocktargetlen[filters.nblocktarget]>128){
						printf("Length error in Target Address (block) filter number %u.\n", filters.nblocktarget+1);
						exit(EXIT_FAILURE);
					}
				}

				sanitize_ipv6_prefix(&(filters.blocktarget[filters.nblocktarget]), filters.blocktargetlen[filters.nblocktarget]);
				filters.nblocktarget++;
				break;

			case 'W':	/* ND Target Address (accept) filter */
				if(filters.naccepttarget >= MAX_ACCEPT_TARGET){
					puts("Too many Target Address (accept) filters.");
					exit(EXIT_FAILURE);
				}
	    
				if((pref = strtok_r(optarg, "/", &lasts)) == NULL){
					printf("Error in Target Address (accept) filter number %u.\n", filters.naccepttarget+1);
					exit(EXIT_FAILURE);
				}

				if ( inet_pton(AF_INET6, pref, &(filters.accepttarget[filters.naccepttarget])) <= 0){
					printf("Error in Target Address (accept) filter number %u.\n", filters.naccepttarget+1);
					exit(EXIT_FAILURE);
				}
		
				if((charptr = strtok_r(NULL, " ", &lasts)) == NULL){
					filters.accepttargetlen[filters.naccepttarget] = 128;
				}
				else{
					filters.accepttargetlen[filters.naccepttarget] = atoi(charptr);
		
					if(filters.accepttargetlen[filters.naccepttarget]>128){
						printf("Length error in Target Address (accept) filter number %u.\n", \
									    filters.naccepttarget+1);
						exit(EXIT_FAILURE);
					}
				}

				sanitize_ipv6_prefix(&(filters.accepttarget[filters.naccepttarget]), filters.accepttargetlen[filters.naccepttarget]);
				filters.naccepttarget++;
				filters.acceptfilters_f=1;
				break;

			case 'L':	/* "Listen mode */
				listen_f = 1;
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
		puts("na6 needs root privileges to run.");
		exit(EXIT_FAILURE);
	}

	if(!idata.iface_f){
		puts("Must specify the network interface with the -i option");
		exit(EXIT_FAILURE);
	}

	if(load_dst_and_pcap(&idata, LOAD_PCAP_ONLY) == FAILURE){
		puts("Error while learning Souce Address and Next Hop");
		exit(EXIT_FAILURE);
	}

	release_privileges();

	if(listen_f && loop_f){
		puts("'Error: listen' mode and 'loop' mode are incompatible");
		exit(EXIT_FAILURE);
	}

	if(listen_f && floodt_f){
		puts("Error: 'listen' mode and 'flood targets' are incompatible");
		exit(EXIT_FAILURE);
	}

	if(pcap_compile(idata.pfd, &pcap_filter, PCAP_ICMPV6_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
		printf("pcap_compile(): %s", pcap_geterr(idata.pfd));
		exit(EXIT_FAILURE);
	}
    
	if(pcap_setfilter(idata.pfd, &pcap_filter) == -1){
		printf("pcap_setfilter(): %s", pcap_geterr(idata.pfd));
		exit(EXIT_FAILURE);
	}

	pcap_freecode(&pcap_filter);

	srandom(time(NULL));
    
	if(!floods_f && !idata.srcaddr_f){    
	    /* When randomizing a link-local IPv6 address, select addresses that belong to the
	    prefix fe80::/64 (that's what a link-local address looks-like in legitimate cases).
	    The KAME implementation discards addresses in which the second highe-order 16 bits
	    (srcaddr.s6_addr16[1] in our case) are not zero.
	    */  
		idata.srcaddr.s6_addr16[0]= htons(0xfe80); /* Link-local unicast prefix */
	
		for(i=1;i<4;i++)
			idata.srcaddr.s6_addr16[i]=0x0000;	
	    
		for(i=4; i<8; i++)
			idata.srcaddr.s6_addr16[i]=random();
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

	if(!idata.dstaddr_f){		/* Destination Address defaults to all-nodes (ff02::1) */
		if( inet_pton(AF_INET6, ALL_NODES_MULTICAST_ADDR, &(idata.dstaddr)) <= 0){
			puts("inet_pton(): Error converting all-nodes multicast address");
			exit(EXIT_FAILURE);
		}
	}

	if(!idata.hsrcaddr_f)	/* Source link-layer address is randomized by default */
		for(i=0; i<6; i++)
			idata.hsrcaddr.a[i]= random();

	if(!idata.hdstaddr_f)		/* Destination link-layer address defaults to all-nodes */
		if(ether_pton(ETHER_ALLNODES_LINK_ADDR, &(idata.hdstaddr), sizeof(idata.hdstaddr)) == 0){
			puts("ether_pton(): Error converting all-nodes multicast address");
			exit(EXIT_FAILURE);
		}
    
	if(tllaopt_f && !tllaopta_f){	/* The value of the target link-layer address      */
		linkaddr[0] = idata.hsrcaddr;		/* option defaults to the Ethernet Source Address  */
		nlinkaddr++;
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

	if(!floods_f)
		nsources=1;

	if(!floodt_f)
		ntargets=1;

	if(!sleep_f)
		nsleep=1;

	if( !fragh_f && dstoptuhdr_f){
		puts("Dst. Options Header (Unfragmentable Part) set, but Fragmentation not specified");
		exit(EXIT_FAILURE);
	}
    
	if(fragh_f)
		idata.max_packet_size = MAX_IPV6_PAYLOAD + MIN_IPV6_HLEN;
	else
		idata.max_packet_size = idata.mtu;

	if(idata.verbose_f){
		print_attack_info(&idata);
	}

	/* Set initial contents of the attack packet */
	init_packet_data(&idata);
    
	/* Fire a Neighbor Advertisement if a IPv6 Destination Address or an Ethernet
	 * Destination Address were specified
	 */
	if((idata.dstaddr_f || idata.hdstaddr_f) && (targetaddr_f || floodt_f)){
		if(send_packet(&idata, NULL, NULL) == FAILURE){
			puts("Error while sending packet");
			exit(EXIT_FAILURE);
		}

		if(idata.verbose_f)    
			puts("Initial attack packet(s) sent successfully.");

		if(loop_f){
			if(idata.verbose_f)
				printf("Now sending Neighbor Advertisements every %u second%s...\n", nsleep, \
											((nsleep>1)?"s":""));
			while(loop_f){
				sleep(nsleep);
				if(send_packet(&idata, NULL, NULL) == FAILURE){
					puts("Error while sending packet");
					exit(EXIT_FAILURE);
				}
	 		}

			exit(EXIT_SUCCESS);
		}
	}

	if(listen_f){
		if( (idata.fd= pcap_fileno(idata.pfd)) == -1){
			puts("Error obtaining descriptor number for pcap_t");
			exit(EXIT_FAILURE);
		}

		FD_ZERO(&sset);
		FD_SET(idata.fd, &sset);

		if(idata.verbose_f){
			print_filters(&idata, &filters);
			puts("Listening to incoming ICMPv6 Neighbor Solicitation messages...");
		}

		while(listen_f){
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

			/* Read a Neighbor Solicitation message */
			if((r=pcap_next_ex(idata.pfd, &pkthdr, &pktdata)) == -1){
				printf("pcap_next_ex(): %s", pcap_geterr(idata.pfd));
				exit(EXIT_FAILURE);
			}
			else if(r == 0){
				continue; /* Should never happen */
			}

			pkt_ether = (struct ether_header *) pktdata;
			pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + ETHER_HDR_LEN);
			pkt_ns = (struct nd_neighbor_solicit *) ((char *) pkt_ipv6 + MIN_IPV6_HLEN);

			accepted_f=0;


			if(idata.verbose_f>1)
				print_filter_result(&idata, pktdata, ACCEPTED);

			/* Send a Neighbor Advertisement */
			if(send_packet(&idata, pkthdr, pktdata) == FAILURE){
				puts("Error while sending packet");
				exit(EXIT_FAILURE);
			}
		}
    
		exit(EXIT_SUCCESS);
	}
    

	if(!((idata.dstaddr_f || idata.hdstaddr_f) && (targetaddr_f || floodt_f)) && !listen_f){
		puts("Error: Nothing to send! (Destination Address or ND Target Address missing?)");
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
			if((ptr+ dstopthdrlen[dstopthdrs]) > (v6buffer+max_packet_size)){
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

	if( (ptr+sizeof(struct nd_neighbor_advert)) > (v6buffer+max_packet_size)){
		puts("Packet too large while inserting Neighbor Advertisement header (should be using Frag. option?)");
		exit(EXIT_FAILURE);
	}

	na= (struct nd_neighbor_advert *) ptr;

	na->nd_na_type = ND_NEIGHBOR_ADVERT;
	na->nd_na_code = 0;
	na->nd_na_flags_reserved = router_f | solicited_f | override_f;
	na->nd_na_target = targetaddr;
    
	ptr += sizeof(struct nd_neighbor_advert);

	if(tllaopt_f && nlinkaddr==1){
		if( (ptr+sizeof(struct nd_opt_tlla)) <= (v6buffer+max_packet_size) ){
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
int send_packet(struct iface_data *idata, struct pcap_pkthdr *pkthdr, const u_char *pktdata){
	if(pktdata == NULL){
		sources=0;
	}
	else{   /* Sending a response to a Neighbor Solicitation message */
		pkt_ether = (struct ether_header *) pktdata;
		pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + ETHER_HDR_LEN);
		pkt_ns = (struct nd_neighbor_solicit *) ((char *) pkt_ipv6 + MIN_IPV6_HLEN);
	
		/* If the IPv6 Source Address of the incoming Neighbor Solicitation is the unspecified 
		   address (::), the Neighbor Advertisement must be directed to the IPv6 all-nodes 
		   multicast address (and the Ethernet Destination address should be 33:33:33:00:00:01). 
		   Otherwise, the Neighbor Advertisement is sent to the IPv6 Source Address (and 
		   Ethernet Source Address) of the incoming Neighbor Solicitation message
		 */
		pkt_ipv6addr = &(pkt_ipv6->ip6_src);

		na->nd_na_flags_reserved = router_f | solicited_f | override_f;

		if(IN6_IS_ADDR_UNSPECIFIED(pkt_ipv6addr)){
			if ( inet_pton(AF_INET6, ALL_NODES_MULTICAST_ADDR, &(ipv6->ip6_dst)) <= 0){
				puts("inetr_pton(): Error converting all-nodes multicast address");
				return(FAILURE);
			}

			if(ether_pton(ETHER_ALLNODES_LINK_ADDR, &(ethernet->dst), ETHER_ADDR_LEN) == 0){
				puts("ether_pton(): Error converting all-nodes link-local address");
				return(FAILURE);
			}
		}
		else{
			ipv6->ip6_dst = pkt_ipv6->ip6_src;
			ethernet->dst = pkt_ether->src;

			/* 
			   Set the "Solicited" flag if NS was sent from an address other than the unspecified
			   address (i.e., the response will be unicast). 
			 */ 

			na->nd_na_flags_reserved = na->nd_na_flags_reserved | ND_NA_FLAG_SOLICITED;
		}

		pkt_ipv6addr = &(pkt_ipv6->ip6_dst);

		/* 
		   If the Neighbor Solicitation message was directed to a unicast address (unlikely), the
		   IPv6 Source Address and the Ethernet Source Address of the Neighbor Advertisement are set
		   to the IPv6 Destination Address and the Ethernet Destination Address	of the incoming
		   Neighbor Solicitation, respectively. Otherwise, the IPv6 Source Address is set to the
		   ND Target Address (unless a specific IPv6 Source Address was specified with the "-s"
		   option), and the Ethernet is set to that specified by the "-S" option (or randomized).
		 */
		if(IN6_IS_ADDR_MULTICAST(pkt_ipv6addr)){
			if( !idata->srcaddr_f && ((pkt_ns->nd_ns_target.s6_addr16[0] & htons(0xffc0)) == htons(0xfe80)) )
				ipv6->ip6_src = pkt_ns->nd_ns_target;
			else
				ipv6->ip6_src = idata->srcaddr;

			ethernet->src = idata->hsrcaddr;
			sources=0;
			multicastdst_f=1;
		}
		else{
			ipv6->ip6_src = pkt_ipv6->ip6_dst;
			ethernet->src = pkt_ether->dst;
			sources=nsources;
			multicastdst_f=0;
		}

		na->nd_na_target= pkt_ns->nd_ns_target;
	}


	do{
		if(floods_f && (pktdata==NULL || (pktdata != NULL && multicastdst_f))){
			/* 
			   Randomizing the IPv6 Source address based on the prefix specified by 
			   "srcaddr" and prefix length.
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

		targets=0;

		do{
			if(floodt_f){
				/* 
				   Randomizing the ND Target Address based on the prefix specified by "targetaddr" 
				   and targetpreflen.
				 */  
				startrand= targetpreflen/16;

				for(i=0; i<startrand; i++)
					na->nd_na_target.s6_addr16[i]= 0;

				for(i=startrand; i<8; i++)
					na->nd_na_target.s6_addr16[i]=random();

				if(targetpreflen%16){
					mask=0xffff;

					for(i=0; i<(targetpreflen%16); i++)
						mask= mask>>1;

					na->nd_na_target.s6_addr16[startrand]= na->nd_na_target.s6_addr16[startrand] \
													& htons(mask);
				}

				for(i=0; i<=(targetpreflen/16); i++)
					na->nd_na_target.s6_addr16[i]= na->nd_na_target.s6_addr16[i] | \
										targetaddr.s6_addr16[i];

			}

			/*
			 * If a single target link-layer address option is to be included, it is included
			 * by init_packet_data()
			 */
			if(nlinkaddr==1)
				linkaddrs=1;
			else
				linkaddrs=0;

			do{
				newdata_f=0;
				ptr=startofprefixes;

				while(linkaddrs<nlinkaddr && ((ptr+sizeof(struct nd_opt_tlla))-v6buffer)<=max_packet_size){
					tllaopt = (struct nd_opt_tlla *) ptr;
					tllaopt->type= ND_OPT_TARGET_LINKADDR;
					tllaopt->length= TLLA_OPT_LEN;
					bcopy(linkaddr[linkaddrs].a, tllaopt->address, ETH_ALEN);
					ptr += sizeof(struct nd_opt_tlla);
					linkaddrs++;
					newdata_f=1;
				}

				na->nd_na_cksum = 0;
				na->nd_na_cksum = in_chksum(v6buffer, na, ptr-((unsigned char *)na), IPPROTO_ICMPV6);


				if(!fragh_f){
					ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);

					if((nw=pcap_inject(idata->pfd, buffer, ptr - buffer)) == -1){
						printf("pcap_inject(): %s\n", pcap_geterr(idata->pfd));
						return(FAILURE);
					}

					if(nw != (ptr-buffer)){
						printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, \
																					(LUI) (ptr-buffer));
						return(FAILURE);
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
						return(FAILURE);
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
							return(FAILURE);
						}

						if(nw != (fptr- fragbuffer)){
							printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n"\
													, (LUI) nw, (LUI) (ptr-buffer));
							return(FAILURE);
						}
					}
				}
			}while(linkaddrs<nlinkaddr && newdata_f);

			targets++;

		}while(targets<ntargets);

		sources++;
	}while(sources<nsources);

	return(SUCCESS);
}



/*
 * Function: usage()
 *
 * Prints the syntax of the na6 tool
 */
void usage(void){
    puts("usage: na6 -i INTERFACE [-s SRC_ADDR[/LEN]] [-d DST_ADDR] [-S LINK_SRC_ADDR] "
	 "[-y FRAG_SIZE] [-u DST_OPT_HDR_SIZE] [-U DST_OPT_U_HDR_SIZE] [-H HBH_OPT_HDR_SIZE] "
	 "[-D LINK-DST-ADDR] [-t TARGET_ADDR[/LEN]] [-r] [-c] [-o] [-E LINK_ADDR] [-e] "
	 "[-j PREFIX[/LEN]] [-k PREFIX[/LEN]] [-J LINK_ADDR] [-K LINK_ADDR] [-w PREFIX[/LEN]] "
	 "[-b PREFIX[/LEN]] [-g PREFIX[/LEN]] [-B LINK_ADDR] [-G LINK_ADDR] [-W PREFIX[/LEN]] "
	 "[-F N_SOURCES] [-T N_TARGETS] [-L | -l] [-z] [-v] [-V] [-h]");
}


/*
 * Function: print_help()
 *
 * Prints help information for the na6 tool
 */
void print_help(void){
	puts(SI6_TOOLKIT);
	puts("na6: Security Assessment tool for attack vectors based on NA messages\n");
	usage();
    
    puts("\nOPTIONS:\n"
	"  --interface, -i            Network interface\n"
	"  --src-address, -s          IPv6 Source Address\n"
	"  --dst-address, -d          IPv6 Destination Address\n"
	"  --frag-hdr. -y             Fragment Header\n"
	"  --dst-opt-hdr, -u          Destination Options Header (Fragmentable Part)\n"
	"  --dst-opt-u-hdr, -U        Destination Options Header (Unfragmentable Part)\n"
	"  --hbh-opt-hdr, -H          Hop by Hop Options Header\n"
	"  --link-src-address, -S     Link-layer Destination Address\n"
	"  --link-dst-address, -D     Link-layer Source Address\n"
	"  --target, -t               ND IPv6 Target Address\n"
	"  --target-lla-opt, -E       Source link-layer address option\n"
	"  --add-tlla-opt, -e         Add Source link-layer address option\n"
	"  --router, -r               Set the 'Router Flag'\n"
	"  --solicited, -c            Set the 'Solicited' flag\n"
	"  --override, -o             Set the 'Override' flag\n"
	"  --block-src, -j            Block IPv6 Source Address prefix\n"
	"  --block-dst, -k            Block IPv6 Destination Address prefix\n"
	"  --block-link-src, -J       Block Ethernet Source Address\n"
	"  --block-link-dst, -K       Block Ethernet Destination Address\n"
	"  --block-target, -w         Block ND Target IPv6 prefix\n"
	"  --accept-src, -b           Accept IPv6 Source Addres prefix\n"
	"  --accept-dst, -g           Accept IPv6 Destination Addres prefix\n"
	"  --accept-link-src, -B      Accept Ethernet Source Address\n"
	"  --accept-link-dst, -G      Accept Ethernet Destination Address\n"
	"  --accept-target, -W        Accept ND Target IPv6 prefix\n"
	"  --flood-targets, -T        Flood with NA's for multiple Target Addresses\n"
	"  --flood-sources, -F        Number of Source Addresses to forge randomly\n"
	"  --listen, -L               Listen to Neighbor Solicitation messages\n"
	"  --loop, -l                 Send periodic Neighbor Advertisements\n"
	"  --sleep, -z                Pause between sending NA messages\n"
	"  --help, -h                 Print help for the na6 tool\n"
	"  --verbose, -v              Be verbose\n"
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
    if(floods_f)
	printf("Flooding the target from %u different IPv6 Source Addresses\n", nsources);

    if(floodt_f)
	printf("Flooding the target with %u ND Target Addresses\n", ntargets);

    if(!floods_f){
	if(ether_ntop(&(idata->hsrcaddr), plinkaddr, sizeof(plinkaddr)) == 0){
	    puts("ether_ntop(): Error converting address");
	    exit(EXIT_FAILURE);
	}

	printf("Ethernet Source Address: %s%s\n", plinkaddr, ((!idata->hsrcaddr_f)?" (randomized)":""));
    }
    else{
	if(idata->hsrcaddr_f){
	    if(ether_ntop(&(idata->hsrcaddr), plinkaddr, sizeof(plinkaddr)) == 0){
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
    if(idata->dstaddr_f || idata->hdstaddr_f){
	if(ether_ntop(&(idata->hdstaddr), plinkaddr, sizeof(plinkaddr)) == 0){
	    puts("ether_ntop(): Error converting address");
	    exit(EXIT_FAILURE);
	}

	printf("Ethernet Destination Address: %s%s\n", plinkaddr, \
					((!idata->hdstaddr_f)?" (all-nodes multicast)":""));
    }


    if(inet_ntop(AF_INET6, &(idata->srcaddr), psrcaddr, sizeof(psrcaddr)) == NULL){
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

    /* IPv6 Destination Address is only used if a target IPv6 address or a target Ethernet
     * address were specified
     */
    if(idata->dstaddr_f || idata->hdstaddr_f){
	if(inet_ntop(AF_INET6, &(idata->dstaddr), pdstaddr, sizeof(pdstaddr)) == NULL){
	    puts("inet_ntop(): Error converting IPv6 Destination Address to presentation format");
	    exit(EXIT_FAILURE);
	}

	printf("IPv6 Destination Address: %s%s\n", pdstaddr, \
				((!idata->dstaddr_f)?" (all-nodes link-local multicast)":""));
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

    if(!floodt_f){
	if(targetaddr_f){
	    if(inet_ntop(AF_INET6, &targetaddr, pv6addr, sizeof(pv6addr)) == NULL){
		puts("inet_ntop(): Error converting ND IPv6 Target Address to presentation format");
		exit(EXIT_FAILURE);
	    }

	    printf("ND Target Address: %s\n", pv6addr);
	}
    }
    else{
	if(inet_ntop(AF_INET6, &targetaddr, pv6addr, sizeof(pv6addr)) == NULL){
	    puts("inet_ntop(): Error converting ND IPv6 Target Address to presentation format");
	    exit(EXIT_FAILURE);
	}

	printf("ND Target Address: randomized, from the %s/%u prefix%s\n", pv6addr, targetpreflen,\
    									(!targetprefix_f)?" (default)":"");
    }
    		
    printf("Flags: %s%s%s%s\n", ((router_f)?"R":""), ((solicited_f)?"S":""), ((override_f)?"O":""),\
	    ((!router_f && !solicited_f && !override_f)?"none":""));
	
    for(i=0;i<nlinkaddr;i++){
	if(ether_ntop(&linkaddr[i], plinkaddr, sizeof(plinkaddr)) == 0){
	    puts("ether_ntop(): Error converting address");
	    exit(EXIT_FAILURE);
	}

	printf("Target Link-layer Address option -> Address: %s\n", \
		    ((floods_f && !tllaopta_f)?"(randomized for each packet)":plinkaddr));
    }

}

