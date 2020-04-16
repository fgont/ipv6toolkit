/*
 * udp6 : A security assessment tool that exploits potential flaws in the
 *        processing of UDP/IPv6 packets
 *
 * Copyright (C) 2011-2020 Fernando Gont <fgont@si6networks.com>
 *
 * Programmed by Fernando Gont for SI6 Networks <https://www.si6networks.com>
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
 * Build with: make udp6
 * 
 * It requires that the libpcap library be installed on your system.
 *
 * Please send any bug reports to Fernando Gont <fgont@si6networks.com>
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/select.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <limits.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <setjmp.h>
#include <pwd.h>

#include "udp6.h"
#include "ipv6toolkit.h"
#include "libipv6.h"


/* Function prototypes */
void				init_packet_data(struct iface_data *);
void				send_packet(struct iface_data *, const u_char *, struct pcap_pkthdr *);
void				print_attack_info(struct iface_data *);
void				usage(void);
void				print_help(void);
void				frag_and_send(struct iface_data *);
int					is_valid_udp_datagram(struct iface_data *, const u_char *, struct pcap_pkthdr *);

/* Flags */
unsigned char 		floodt_f=0;
unsigned char 		listen_f=0, accepted_f=0, loop_f=0, sleep_f=0;
unsigned char		hoplimit_f=0, rand_link_src_f=0, rand_src_f=0;
unsigned char		floods_f=0, floodp_f=0, donesending_f=0;
unsigned char		data_f=0, senddata_f=0, useaddrkey_f=0;

/* Flags used for UDP (specifically) */ 
unsigned char		srcport_f=0, dstport_f=0;
unsigned char		rhbytes_f=0;
unsigned char		pps_f=0, bps_f=0, probemode_f=0, retrans_f=0, rto_f=0;
unsigned int		probemode;

uint16_t			srcport, dstport;
unsigned int		retrans, rto;
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
struct udp_hdr			*pkt_udp;
struct in6_addr			*pkt_ipv6addr;
unsigned int			pktbytes;


bpf_u_int32			my_netmask;
bpf_u_int32			my_ip;
struct bpf_program	pcap_filter;
char 				dev[64], errbuf[PCAP_ERRBUF_SIZE];
unsigned char		buffer[65556], buffrh[MIN_IPV6_HLEN + MIN_UDP_HLEN];
unsigned char		*v6buffer, *ptr, *startofprefixes;
char				*pref;
char				data[DATA_BUFFER_LEN];
unsigned int		datalen;
char 				iface[IFACE_LENGTH];
char				line[LINE_BUFFER_SIZE];
    
struct ip6_hdr		*ipv6;
struct udp_hdr		*udp;

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

uint16_t			mask;
uint8_t				hoplimit;
uint16_t			addr_key;

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

unsigned char		fragbuffer[ETHER_HDR_LEN+MIN_IPV6_HLEN+MAX_IPV6_PAYLOAD];
unsigned char		*fragpart, *fptr, *fptrend, *ptrend, *ptrhdr, *ptrhdrend;
unsigned int		hdrlen, ndstopthdr=0, nhbhopthdr=0, ndstoptuhdr=0;
unsigned int		nfrags, fragsize;
unsigned char		*prev_nh, *startoffragment;

struct filters		filters;

int main(int argc, char **argv){
	extern char		*optarg;	
/*	char			*endptr;  Used by strtoul() */
	fd_set			sset, rset;	
/*	fd_set			wset, eset; */
	int				r, sel;
	struct timeval	timeout, stimeout, curtime, lastprobe;
	unsigned char		end_f=0;
	unsigned long	pktinterval=0;
	unsigned int	retr=0;
	struct target_ipv6	targetipv6;

	static struct option longopts[] = {
		{"interface", required_argument, 0, 'i'},
		{"src-addr", required_argument, 0, 's'},
		{"dst-addr", required_argument, 0, 'd'},
		{"hop-limit", required_argument, 0, 'A'},
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
		{"loop", no_argument, 0, 'l'},
		{"rate-limit", required_argument, 0, 'r'},
		{"sleep", required_argument, 0, 'z'},
		{"listen", no_argument, 0, 'L'},
		{"probe-mode", required_argument, 0, 'p'},
		{"retrans", required_argument, 0, 'x'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0,  0 }
	};

	char shortopts[]= "i:s:d:A:Z:u:U:H:y:S:D:P:o:a:j:k:J:K:b:g:B:G:F:T:lr:z:Lp:x:vh";

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
				strncpy( targetipv6.name, optarg, NI_MAXHOST);
				targetipv6.name[NI_MAXHOST-1]= 0;
				targetipv6.flags= AI_CANONNAME;

				if( (r=get_ipv6_target(&targetipv6)) != 0){

					if(r < 0){
						printf("Unknown Destination: %s\n", gai_strerror(targetipv6.res));
					}
					else{
						puts("Unknown Destination: No IPv6 address found for specified destination");
					}

					exit(1);
				}

				idata.dstaddr= targetipv6.ip6;
				idata.dstaddr_f = 1;
				break;

			case 'A':	/* Hop Limit */
				hoplimit= atoi(optarg);
				hoplimit_f=1;
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
		
				if(hdrlen < 8){
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

				idata.fragh_f= 1;
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

			case 'o':	/* UDP Source Port */
				srcport= atoi(optarg);
				srcport_f= 1;
				break;

			case 'a':	/* UDP Destination Port */
				dstport= atoi(optarg);
				dstport_f= 1;
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
					puts("udp6: -r option is too long");
					exit(EXIT_FAILURE);
				}

				sscanf(optarg, "%lu%s", &rate, line);
				line[LINE_BUFFER_SIZE-1]=0;

				if(strncmp(line, "pps", 3) == 0)
					pps_f=1;
				else if(strncmp(line, "bps", 3) == 0)
					bps_f=1;
				else{
					puts("udp6: Unknown unit of for the rate limit ('-r' option). Unit should be 'bps' or 'pps'");
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

			case 'p':	/* Probe mode */
				if(strncmp(optarg, "dump", MAX_CMDLINE_OPT_LEN) == 0){
					probemode= PROBE_DUMP;
				}
				else if(strncmp(optarg, "script", MAX_CMDLINE_OPT_LEN) == 0){
					probemode= PROBE_SCRIPT;
				}
				else{
					puts("Error: Unknown open mode in '-Y' option");
					exit(EXIT_FAILURE);
				}

				probemode_f=1;
				break;

			case 'x':	/* Number of retrnasmissions */
				retrans= atoi(optarg);
				retrans_f=1;
				break;

			case 'v':	/* Be verbose */
				(idata.verbose_f)++;
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
		puts("udp6 needs root privileges to run.");
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
		puts("Error while learning Source Address and Next Hop");
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
		packetsize= MIN_IPV6_HLEN +  sizeof(struct udp_hdr) + rhbytes;

		for(i=0; i < ndstopthdr; i++)
			packetsize+= dstopthdrlen[i];

		for(i=0; i < ndstoptuhdr; i++)
			packetsize+= dstoptuhdrlen[i];

		for(i=0; i < nhbhopthdr; i++)
			packetsize+= hbhopthdrlen[i];

		if(idata.fragh_f)
			packetsize+= sizeof(struct ip6_frag);			

		if(rate == 0 || ((packetsize * 8)/rate) <= 0)
			pktinterval= 1000000;
		else
			pktinterval= ((packetsize * 8)/rate) * 1000000;
	}

	/* We Default to 1000 pps */
	if(!pps_f && !bps_f)
		pktinterval= 1000;

	if( !idata.fragh_f && dstoptuhdr_f){
		puts("Dst. Options Header (Unfragmentable Part) set, but Fragmentation not specified");
		exit(EXIT_FAILURE);
	}
    
	/*
	 *  If we are going to send packets to a specified target, we must set some default values
	 */
	if(idata.dstaddr_f){
		if(!srcport_f)
			srcport= random();

		if(!dstport_f)
			dstport= random();
	}

	if(!rhbytes_f)
		rhbytes=0;

	if(idata.verbose_f){
		print_attack_info(&idata);
	}

	/*
	   Set filter for IPv6 packets (find_ipv6_router() set its own filter fore receiving RAs)
	 */
	if(pcap_compile(idata.pfd, &pcap_filter, PCAP_UDPIPV6_NS_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
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

	if(probemode_f){
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
					perror("udp6");

				exit(EXIT_FAILURE);
			}			

			if(is_time_elapsed(&curtime, &lastprobe, rto * 1000000) && retr < retrans){
				retr++;
				lastprobe= curtime;
				send_packet(&idata, NULL, NULL);
			}

			if(is_time_elapsed(&curtime, &lastprobe, rto * 1000000) && retr >= retrans){
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

#if !defined(sun) && !defined(__sun) && !defined(__linux__)
			if(sel && FD_ISSET(idata.fd, &rset)){
#else
			if(TRUE){
#endif
				/* Read a packet */

				if((r=pcap_next_ex(idata.pfd, &pkthdr, &pktdata)) == -1){
					printf("pcap_next_ex(): %s", pcap_geterr(idata.pfd));
					exit(EXIT_FAILURE);
				}
				else if(r == 1 && pktdata != NULL){
					pkt_ether = (struct ether_header *) pktdata;
					pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata.linkhsize);
					pkt_udp= (struct udp_hdr *) ( (char *) pkt_ipv6 + MIN_IPV6_HLEN);
					pkt_ns= (struct nd_neighbor_solicit *) ( (char *) pkt_ipv6 + MIN_IPV6_HLEN);
					pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

					/* Some preliminar sanity checks. */
					/* XXX: Might need/could remove some of the checks below */
					if(!is_valid_udp_datagram(&idata, pktdata, pkthdr))
						continue;

					/* Check that we are able to look into the IPv6 header */
					if( (pkt_end -  pktdata) < (idata.linkhsize + MIN_IPV6_HLEN))
						continue;

					if(is_eq_in6_addr(&(pkt_ipv6->ip6_src), &(idata.srcaddr))){
						continue;
					}

					if(!is_eq_in6_addr(&(pkt_ipv6->ip6_dst), &(idata.srcaddr))){
						continue;
					}

					if(pkt_udp->uh_sport != htons(dstport)){
						continue;
					}

					if(pkt_udp->uh_dport != htons(srcport)){
						continue;
					}

					/* The UDP checksum must be valid */
					if(in_chksum(pkt_ipv6, pkt_udp, pkt_end-((unsigned char *)pkt_udp), IPPROTO_UDP) != 0)
						continue;

					printf("RESPONSE:UDP6\n");
					exit(EXIT_SUCCESS);
				}
			}
		}

		puts("RESPONSE:TIMEOUT:");
		exit(EXIT_SUCCESS);
	}


	/* Fire a UDP packet if an IPv6 Destination Address was specified */
	if(!listen_f && idata.dstaddr_f){
		if(loop_f){
			if(idata.verbose_f)
				printf("Sending UDP datagrams every %u second%s...\n", nsleep, \
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
		FD_ZERO(&sset);
		FD_SET(idata.fd, &sset);

		if(idata.verbose_f){
			print_filters(&idata, &filters);
			puts("Listening to incoming UDP datagrams...");
		}

		while(listen_f){
			rset= sset;

			timeout= stimeout;

/* XXX: need to address the select() thing */
#if !defined(sun) && !defined(__sun) && !defined(__linux__)
			if((sel=select(idata.fd+1, &rset, NULL, NULL, ((floods_f || floodp_f) && !donesending_f)?(&timeout):NULL)) == -1){
#else
			timeout.tv_usec=10000;
			timeout.tv_sec= 0;
			if((sel=select(idata.fd+1, &rset, NULL, NULL, &timeout)) == -1){
#endif
				if(errno == EINTR){
					continue;
				}
				else{
					puts("Error in select()");
					exit(EXIT_FAILURE);
				}
			}

			/* If there are some bits set, we need to check whether it's time to send packets */
#if !defined(sun) && !defined(__sun) && !defined(__linux__)
			if(sel){
#else
			if(TRUE){
#endif
				if(gettimeofday(&curtime, NULL) == -1){
					if(idata.verbose_f)
						perror("udp6");

					exit(EXIT_FAILURE);
				}
			}

#if !defined(sun) && !defined(__sun) && !defined(__linux__)
			if(sel && FD_ISSET(idata.fd, &rset)){
#else
			if(TRUE){
#endif
				/* Read a packet */
				if((r=pcap_next_ex(idata.pfd, &pkthdr, &pktdata)) == -1){
					printf("pcap_next_ex(): %s", pcap_geterr(idata.pfd));
					exit(EXIT_FAILURE);
				}
				else if(r == 1 && pktdata != NULL){
					pkt_ether = (struct ether_header *) pktdata;
					pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata.linkhsize);
					pkt_udp= (struct udp_hdr *) ( (char *) pkt_ipv6 + MIN_IPV6_HLEN);
					pkt_ns= (struct nd_neighbor_solicit *) ( (char *) pkt_ipv6 + MIN_IPV6_HLEN);
					pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

					/* Check that we are able to look into the IPv6 header */
					if( (pkt_end -  pktdata) < (idata.linkhsize + MIN_IPV6_HLEN))
						continue;

					accepted_f=0;

					if(idata.type == DLT_EN10MB && !(idata.flags & IFACE_LOOPBACK)){
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

					if(idata.type == DLT_EN10MB && !(idata.flags & IFACE_LOOPBACK)){	
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

					if(pkt_ipv6->ip6_nxt == IPPROTO_UDP){
						/* Some preliminar sanity checks. */
						/* XXX: Might need/could remove some of the checks below */
						if(!is_valid_udp_datagram(&idata, pktdata, pkthdr))
							continue;

						/* Check that we are able to look into the UDP header */
						if( (pkt_end -  pktdata) < (idata.linkhsize + MIN_IPV6_HLEN + sizeof(struct udp_hdr))){
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
									if( (ntohl(pkt_ipv6->ip6_src.s6_addr32[2]) & 0x0000ffff) ==  ( (uint16_t)(ntohl(pkt_ipv6->ip6_src.s6_addr32[2])>>16) ^ addr_key) && \
										(ntohl(pkt_ipv6->ip6_src.s6_addr32[3]) & 0x0000ffff) ==  ( (uint16_t)(ntohl(pkt_ipv6->ip6_src.s6_addr32[3])>>16) ^ addr_key)){
										continue;
									}

									if( (ntohl(pkt_ipv6->ip6_dst.s6_addr32[2]) & 0x0000ffff) !=  ((uint16_t)(ntohl(pkt_ipv6->ip6_dst.s6_addr32[2]) >> 16) ^ addr_key) || \
										(ntohl(pkt_ipv6->ip6_dst.s6_addr32[3]) & 0x0000ffff) !=  ((uint16_t)(ntohl(pkt_ipv6->ip6_dst.s6_addr32[3])>>16) ^ addr_key)){
										continue;
									}
								}
							}

							/* The UDP checksum must be valid */
							if(in_chksum(pkt_ipv6, pkt_udp, pkt_end-((unsigned char *)pkt_udp), IPPROTO_UDP) != 0)
								continue;

							if(pkt_udp->uh_sport != htons(dstport)){
								continue;
							}

							if(!floodp_f && pkt_udp->uh_dport != htons(srcport)){
								continue;
							}
						}

						/* Send a UDP datagram */
						send_packet(&idata, pktdata, pkthdr);
					}
					else if(pkt_ipv6->ip6_nxt == IPPROTO_ICMPV6){

						/* Check that we are able to look into the NS header */
						if( (pkt_end -  pktdata) < (idata.linkhsize + MIN_IPV6_HLEN + sizeof(struct nd_neighbor_solicit))){
							continue;
						}

						if(idata.type == DLT_EN10MB && !(idata.flags & IFACE_LOOPBACK)){
							if(floods_f){
								if(useaddrkey_f){
									if( (ntohl(pkt_ns->nd_ns_target.s6_addr32[2]) & 0x0000ffff) !=  ( (ntohl(pkt_ns->nd_ns_target.s6_addr32[2]) >>16) ^ addr_key) || \
										(ntohl(pkt_ns->nd_ns_target.s6_addr32[3]) & 0x0000ffff) !=  ( (ntohl(pkt_ns->nd_ns_target.s6_addr32[3]) >>16) ^ addr_key)){
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
			}

			if(idata.dstaddr_f && !donesending_f && is_time_elapsed(&curtime, &lastprobe, pktinterval)){
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
	struct dlt_null *dlt_null;
	ethernet= (struct ether_header *) buffer;
	dlt_null= (struct dlt_null *) buffer;
	v6buffer = buffer + idata->linkhsize;
	ipv6 = (struct ip6_hdr *) v6buffer;

	if(idata->type == DLT_EN10MB){
		ethernet->ether_type = htons(ETHERTYPE_IPV6);

		if(!(idata->flags & IFACE_LOOPBACK)){
			ethernet->src = idata->hsrcaddr;
			ethernet->dst = idata->hdstaddr;
		}
	}
	else if(idata->type == DLT_NULL){
		dlt_null->family= PF_INET6;
	}
#if defined (__OpenBSD__)
	else if(idata->type == DLT_LOOP){
		dlt_null->family= htonl(PF_INET6);
	}
#endif

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

	if(idata->fragh_f){
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
		memset(&fraghdr, 0, FRAG_HDR_SIZE);
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


	*prev_nh = IPPROTO_UDP;

	startofprefixes=ptr;
}



/*
 * Function: send_packet()
 *
 * Initialize the remaining fields of the UDP datagram, and send the attack packet(s).
 */
void send_packet(struct iface_data *idata, const u_char *pktdata, struct pcap_pkthdr *pkthdr){
	static unsigned int	sources=0, ports=0;	
	ptr=startofprefixes;
	senddata_f= 0;

	if(pktdata != NULL){   /* Sending an UDP datagram in response to a received packet */
		pkt_ether = (struct ether_header *) pktdata;
		pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata->linkhsize);
		pkt_udp= (struct udp_hdr *)( (char *) pkt_ipv6 + sizeof(struct ip6_hdr));
		pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

		/* The packet length is the minimum of what we capured, and what is specified in the
		   IPv6 Total Lenght field
		 */
		if( pkt_end > ((unsigned char *)pkt_ipv6 + sizeof(struct ip6_hdr) + ntohs(pkt_ipv6->ip6_plen)) )
			pkt_end = (unsigned char *)pkt_ipv6 + sizeof(struct ip6_hdr) + ntohs(pkt_ipv6->ip6_plen);


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

			if(idata->type == DLT_EN10MB && !(idata->flags & IFACE_LOOPBACK))
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

			if(idata->type == DLT_EN10MB && !(idata->flags & IFACE_LOOPBACK))
				ethernet->src = pkt_ether->dst;
		}


		if( (ptr+sizeof(struct udp_hdr)) > (v6buffer+ idata->max_packet_size)){
			puts("Packet Too Large while inserting UDP header");
			exit(EXIT_FAILURE);
		}

		udp = (struct udp_hdr *) ptr;
		memset(udp, 0, sizeof(struct udp_hdr));

		udp->uh_sport= pkt_udp->uh_dport;
		udp->uh_dport= pkt_udp->uh_sport;
		ptr+= sizeof(struct udp_hdr);

		if(rhbytes_f){
			if( (ptr + rhbytes) > v6buffer+ idata->max_packet_size){
				puts("Packet Too Large while inserting UDP datagram");
				exit(EXIT_FAILURE);
			}

			while(rhbytes>=4){
				*(uint32_t *)ptr = random();
				ptr += sizeof(uint32_t);
				rhbytes -= sizeof(uint32_t);
			}

			while(rhbytes>0){
				*(uint8_t *) ptr= (uint8_t) random();
				ptr++;
				rhbytes--;
			}
		}
		else if(data_f){
			ptr= (unsigned char *)udp + sizeof(struct udp_hdr);

			if((ptr+ datalen) > (v6buffer + idata->max_packet_size)){
				if(idata->verbose_f)
					puts("Packet too large while inserting UDP data");
				exit(EXIT_FAILURE);
			}

			memcpy(ptr, data, datalen);
			ptr+= datalen;
		}

		udp->uh_ulen= htons(ptr - (unsigned char *) udp);
		udp->uh_sum = 0;
		udp->uh_sum = in_chksum(v6buffer, udp, ptr-((unsigned char *)udp), IPPROTO_UDP);

		frag_and_send(idata);

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

		if( (ptr+sizeof(struct udp_hdr)) > (v6buffer + idata->max_packet_size)){
			puts("Packet Too Large while inserting UDP header");
			exit(EXIT_FAILURE);
		}

		udp= (struct udp_hdr *) ptr;
		memset(ptr, 0, sizeof(struct udp_hdr));
		udp->uh_sport= htons(srcport);
		udp->uh_dport= htons(dstport);
		ptr += sizeof(struct udp_hdr);

		if(rhbytes_f){
			if( (ptr + rhbytes) > v6buffer + idata->max_packet_size){
				puts("Packet Too Large while inserting UDP datagram");
				exit(EXIT_FAILURE);
			}

			while(rhbytes>=4){
				*(uint32_t *)ptr = random();
				ptr += sizeof(uint32_t);
				rhbytes -= sizeof(uint32_t);
			}

			while(rhbytes>0){
				*(uint8_t *) ptr= (uint8_t) random();
				ptr++;
				rhbytes--;
			}
		}
		else if(data_f){
			ptr= (unsigned char *)udp + sizeof(struct udp_hdr);

			if((ptr+ datalen) > (v6buffer + idata->max_packet_size)){
				if(idata->verbose_f)
					puts("Packet too large while inserting UDP data");
				exit(EXIT_FAILURE);
			}

			memcpy(ptr, data, datalen);
			ptr+= datalen;
		}

		udp->uh_ulen= htons(ptr - (unsigned char *) udp);

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
				ipv6->ip6_src.s6_addr32[2]= ntohl((uint32_t)random() <<16);
				ipv6->ip6_src.s6_addr32[2]= htonl(ntohl(ipv6->ip6_src.s6_addr32[2]) | ((ntohl(ipv6->ip6_src.s6_addr32[2])>>16) ^ addr_key));

				ipv6->ip6_src.s6_addr32[3]= ntohl((uint32_t)random() <<16);
				ipv6->ip6_src.s6_addr32[3]= htonl(ntohl(ipv6->ip6_src.s6_addr32[3]) | (uint32_t)((ntohl(ipv6->ip6_src.s6_addr32[3]) >>16) ^ addr_key));
			}

			if(idata->type == DLT_EN10MB && !(idata->flags & IFACE_LOOPBACK) && !(idata->hsrcaddr_f)){
				for(i=0; i<6; i++)
					ethernet->src.a[i]= random();
			}
		}

		if(pktdata == NULL && floodp_f){
			udp->uh_sport= random();
		}

		udp->uh_sum = 0;
		udp->uh_sum = in_chksum(v6buffer, udp, ptr-((unsigned char *)udp), IPPROTO_UDP);

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
	if(!idata->fragh_f){
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
		if(nfrags > (fptrend - fptr))
			nfrags= (fptrend-fptr);

		m=IP6F_MORE_FRAG;

		while((ptr< ptrend) && m==IP6F_MORE_FRAG){
			fptr= startoffragment;

			if( (ptrend-ptr) <= nfrags){
				fragsize= ptrend-ptr;
				m=0;
			}
			else{
				fragsize = (nfrags + 7) & ntohs(IP6F_OFF_MASK);
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
 * Prints the syntax of the udp6 tool
 */
void usage(void){
	puts("usage: udp6 [-i INTERFACE] [-S LINK_SRC_ADDR] [-D LINK-DST-ADDR] "
	 "[-s SRC_ADDR[/LEN]] [-d DST_ADDR] [-A HOP_LIMIT] [-y FRAG_SIZE] [-u DST_OPT_HDR_SIZE] "
	 "[-U DST_OPT_U_HDR_SIZE] [-H HBH_OPT_HDR_SIZE] [-P PAYLOAD_SIZE] [-o SRC_PORT] "
	 "[-a DST_PORT] "
	 "[-N] [-f] [-j PREFIX[/LEN]] [-k PREFIX[/LEN]] [-J LINK_ADDR] [-K LINK_ADDR] "
	 "[-b PREFIX[/LEN]] [-g PREFIX[/LEN]] [-B LINK_ADDR] [-G LINK_ADDR] "
	 "[-F N_SOURCES] [-T N_PORTS] [-L | -l] [-z SECONDS] [-v] [-h]");
}


/*
 * Function: print_help()
 *
 * Prints help information for the udp6 tool
 */
void print_help(void){
	puts(SI6_TOOLKIT);
	puts( "udp6: Security assessment tool for attack vectors based on UDP/IPv6 packets\n");
	usage();
 
	puts("\nOPTIONS:\n"
	     "  --interface, -i           Network interface\n"
	     "  --src-addr, -s            IPv6 Source Address\n"
	     "  --dst-addr, -d            IPv6 Destination Address\n"
	     "  --hop-limit, -A           IPv6 Hop Limit\n"
	     "  --frag-hdr. -y            Fragment Header\n"
	     "  --dst-opt-hdr, -u         Destination Options Header (Fragmentable Part)\n"
	     "  --dst-opt-u-hdr, -U       Destination Options Header (Unfragmentable Part)\n"
	     "  --hbh-opt-hdr, -H         Hop by Hop Options Header\n"
	     "  --link-src-addr, -S       Link-layer Destination Address\n"
	     "  --link-dst-addr, -D       Link-layer Source Address\n"
	     "  --payload-size, -P        UDP Payload Size\n"
	     "  --src-port, -o            UDP Source Port\n"
	     "  --dst-port, -a            UDP Destination Port\n"
	     "  --data, -Z                UDP payload data\n"
	     "  --rate-limit, -r          Rate limit the address scan to specified rate\n"
         "  --probe-mode, -p          UDP probe mode {dump,script}\n"
	     "  --block-src, -j           Block IPv6 Source Address prefix\n"
	     "  --block-dst, -k           Block IPv6 Destination Address prefix\n"
	     "  --block-link-src, -J      Block Ethernet Source Address\n"
	     "  --block-link-dst, -K      Block Ethernet Destination Address\n"
	     "  --accept-src, -b          Accept IPv6 Source Addres prefix\n"
	     "  --accept-dst, -g          Accept IPv6 Destination Address prefix\n"
	     "  --accept-link-src, -B     Accept Ethernet Source Address\n"
	     "  --accept-link-dst, -G     Accept Ethernet Destination Address\n"
	     "  --flood-sources, -F       Flood from multiple IPv6 Source Addresses\n"
	     "  --flood-ports, -T         Flood from multiple UDP Source Ports\n"
	     "  --listen, -L              Listen to incoming packets\n"
	     "  --loop, -l                Send periodic UDP segments\n"
	     "  --sleep, -z               Pause between sending UDP segments\n"
	     "  --help, -h                Print help for the udp6 tool\n"
	     "  --verbose, -v             Be verbose\n"
	     "\n"
	     "Programmed by Fernando Gont for SI6 Networks <https://www.si6networks.com>\n"
	     "Please send any bug reports to <fgont@si6networks.com>\n"
	);
}


/*
 * Function: print_attack_info()
 *
 * Prints attack details (when the verbose ("-v") option is specified).
 */
 
void print_attack_info(struct iface_data *idata){
	puts(SI6_TOOLKIT);
	puts( "udp6: Security assessment tool for attack vectors based on UDP/IPv6 packets\n");

	if(floods_f)
		printf("Flooding the target from %u different IPv6 Source Addresses\n", nsources);

	if(floodp_f)
		printf("Flooding the target from %u different UDP ports\n", nports);

	if(idata->type == DLT_EN10MB && !(idata->flags & IFACE_LOOPBACK)){
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
			printf("IPv6 Source Address: %s%s\n", psrcaddr, ((idata->srcaddr_f != TRUE)?" (randomized)":""));
		}
	}
	else{
		printf("IPv6 Source Address: randomized, from the fc00:1::/%u prefix%s\n", idata->srcpreflen, \
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

	if(idata->fragh_f)
		printf("Sending each packet in fragments of %u bytes (plus the Unfragmentable part)\n", nfrags);

	if(idata->dstaddr_f){
		if(!floodp_f || (floodp_f && nports ==1)){
			printf("Source Port: %u%s\t",  srcport, (srcport_f?"":" (randomized)"));
		}
		else{
			printf("Source Port: (randomized)\t");
		}

		printf("Destination Port: %u%s\n", dstport, (dstport_f?"":" (randomized)"));
	}
	else{
		printf("Source Port: Auto\tDestination Port: Auto\n");
	}
}




/*
 * Function: is_valid_tcp_segment()
 *
 * Performs sanity checks on an incomming UDP/IPv6 segment
 */

int is_valid_udp_datagram(struct iface_data *idata, const u_char *pktdata, struct pcap_pkthdr *pkthdr){
	struct ether_header	*pkt_ether;
	struct ip6_hdr		*pkt_ipv6;
	struct udp_hdr		*pkt_udp;
	unsigned char		*pkt_end;

	pkt_ether = (struct ether_header *) pktdata;
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata->linkhsize);
	pkt_udp = (struct udp_hdr *) ((char *) pkt_ipv6 + MIN_IPV6_HLEN);

	pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

	/* XXX: We are assuming no extension headers on incoming packets -- this should be improved! */

	/* The packet length is the minimum of what we capured, and what is specified in the
	   IPv6 Total Lenght field
	 */
	if( pkt_end > ((unsigned char *)pkt_udp + ntohs(pkt_ipv6->ip6_plen)) )
		pkt_end = (unsigned char *)pkt_udp + ntohs(pkt_ipv6->ip6_plen);

	/*
	   Discard the packet if it is not of the minimum size to contain a UDP header
	 */
	if( (pkt_end - (unsigned char *) pkt_udp) < sizeof(struct udp_hdr)){
		return FALSE;
	}

	/*
	   Discard the packet if it is not of the minimum size to contain a UDP header
	 */
	if( (pkt_end - (unsigned char *) pkt_udp) < ntohs(pkt_udp->uh_ulen)){
		return FALSE;
	}

	/* Check that the UDP checksum is correct */
	if(in_chksum(pkt_ipv6, pkt_udp, pkt_end-((unsigned char *)pkt_udp), IPPROTO_UDP) != 0){
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

