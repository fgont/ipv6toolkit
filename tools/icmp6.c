/*
 * icmp6: A security assessment tool that exploits potential flaws
 *        in the processing of ICMPv6 Error messages
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
 * Build with: make icmp6
 * 
 * The libpcap library must be previously installed on your system.
 *
 * Please send any bug reports to Fernando Gont <fgont@si6networks.com>
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/param.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <ifaddrs.h>
#ifdef __linux__
	#include <netpacket/packet.h>
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__) || ( !defined(__FreeBSD__) && defined(__FreeBSD_kernel__))
	#include <net/if_dl.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <pcap.h>

#include "icmp6.h"
#include "ipv6toolkit.h"
#include "libipv6.h"


/* Function prototypes */
void				init_packet_data(struct iface_data *);
void				send_packet(struct iface_data *, const u_char *, struct pcap_pkthdr *);
void				print_attack_info(struct iface_data *);
void				usage(void);
void				print_help(void);

/* Flags used for the ICMPv6 Redirect (specifically) */
unsigned int		icmp6type_f=0, icmp6code_f=0, mtu_f=0, pointer_f=0;
unsigned int		targetaddr_f=0, redirprefix_f=0, targetportl_f=0, targetporth_f=0;
unsigned int		peeraddr_f=0, peerportl_f=0, peerporth_f=0;
unsigned int		rhip6_f=0, rhtcp_f=0, rhudp_f=0, rhicmp6_f=0, nopayload_f=0, rheader_f=0;
unsigned int		tcpseq_f=0, tcpack_f=0, tcpurg_f=0, tcpflags_f=0, tcpwin_f=0;
unsigned int		icmp6id_f=0, icmp6seq_f=0;
unsigned int		rhlength_f=0, floodr_f=0, respmcast_f=0, makeonlink_f=0;
unsigned int		ip6hoplimit_f=0, ip6length_f=0, rhdefault_f=0;
unsigned int		learnrouter_f=0, sanityfilters_f=0, useaddrkey_f=0;

/* Variables used for ICMPv6 Error messages (specifically) */
u_int8_t			icmp6type=0, icmp6code=0;
u_int32_t			mtu, pointer;
u_int16_t			ip6length;
struct in6_addr		targetaddr, peeraddr;
unsigned char		redirpreflen, targetpreflen;
unsigned int		targetport, peerport;
u_int16_t			targetportl, targetporth, peerportl, peerporth, auxint16;
u_int16_t			tcpurg, tcpwin, icmp6id, icmp6seq;
u_int32_t			tcpseq, tcpack;
u_int8_t			tcpflags=0, ip6hoplimit;
struct ip6_hdr		*rhipv6;
struct udp_hdr		*rhudp;
struct tcp_hdr		*rhtcp;
struct icmp6_hdr	*rhicmp6;
unsigned int		nredirs, redirs;
unsigned int		rhbytes, rhlength, currentsize;
unsigned char		rh_hoplimit;
unsigned char		rhbuff[100]; /* This one must be able to hold the IPv6 header and the upper layer header */


/* Variables used for learning the default router */
struct iface_data	idata;
struct prefix_entry	*prefix_ols[MAX_PREFIXES_ONLINK], *prefix_acs[MAX_PREFIXES_AUTO];
struct prefix_entry	*prefix_local[MAX_LOCAL_ADDRESSES];
struct ether_addr	router_ether, rs_ether;
struct in6_addr		router_ipv6, rs_ipv6;
struct in6_addr		randprefix;
unsigned char		randpreflen;


/* Data structures for packets read from the wire */
struct pcap_pkthdr	*pkthdr;
const u_char		*pktdata;
unsigned char		*pkt_end;
struct ether_header	*pkt_ether;
struct ip6_hdr		*pkt_ipv6;
struct in6_addr		*pkt_ipv6addr;
unsigned int		pktbytes;


bpf_u_int32			my_netmask;
bpf_u_int32			my_ip;
struct bpf_program	pcap_filter;
char 				dev[64], errbuf[PCAP_ERRBUF_SIZE];
unsigned char		buffer[65556], buffrh[MIN_IPV6_HLEN + MIN_TCP_HLEN];
unsigned char		*v6buffer, *ptr, *startofprefixes;
char				*pref;
    
struct ip6_hdr		*ipv6;
struct icmp6_hdr	*icmp6;

struct ether_header	*ethernet;
struct dlt_null		*dlt_null;

char				*lasts, *rpref;
char				*charptr;

size_t				nw;
unsigned long		ul_res, ul_val;
unsigned int		i, j, startrand;
unsigned int		skip;
unsigned int		ntargets, sources, nsources, targets, nsleep;

u_int16_t			mask;
u_int8_t			hoplimit;

char 				plinkaddr[ETHER_ADDR_PLEN];
char 				psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN], pv6addr[INET6_ADDRSTRLEN];
unsigned char 		floodt_f=0, listen_f = 0, multicastdst_f=0, accepted_f=0, loop_f=0, sleep_f=0;
unsigned char		targetprefix_f=0, hoplimit_f=0, newdata_f=0, floods_f=0;

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

struct filters		filters;

int main(int argc, char **argv){
	extern char		*optarg;
	char			*endptr; /* Used by strtoul() */
	int				r, sel;
	fd_set			sset, rset;

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
		{"icmp6", required_argument, 0, 't'},
		{"icmp6-dest-unreach", required_argument, 0, 'e'},
		{"icmp6-packet-too-big", no_argument, 0, 'E'},
		{"icmp6-time-exceeded", required_argument, 0, 'A'},
		{"icmp6-param-problem", no_argument, 0, 'R'},
		{"mtu", required_argument, 0, 'm'},
		{"pointer", required_argument, 0, 'O'},
		{"sanity-filters", no_argument, 0, 'f'},
		{"payload-type", required_argument, 0, 'p'},
		{"payload-size", required_argument, 0, 'P'},
		{"no-payload", no_argument, 0, 'n'},
		{"ipv6-hlim", required_argument, 0, 'C'},
		{"target-addr", required_argument, 0, 'r'},
		{"peer-addr", required_argument, 0, 'x'},
		{"target-port", required_argument, 0, 'o'},
		{"peer-port", required_argument, 0, 'a'},
		{"tcp-flags", required_argument, 0, 'X'},
		{"tcp-seq", required_argument, 0, 'q'},
		{"tcp-ack", required_argument, 0, 'Q'},
		{"tcp-urg", required_argument, 0, 'V'},
		{"tcp-win", required_argument, 0, 'w'},
		{"resp-mcast", no_argument, 0, 'M'},
		{"block-src-addr", required_argument, 0, 'j'},
		{"block-dst-addr", required_argument, 0, 'k'},
		{"block-link-src-addr", required_argument, 0, 'J'},
		{"block-link-dst-addr", required_argument, 0, 'K'},
		{"accept-src-addr", required_argument, 0, 'b'},
		{"accept-dst-addr", required_argument, 0, 'g'},
		{"accept-link-src-addr", required_argument, 0, 'B'},
		{"accept-link-dst-addr", required_argument, 0, 'G'},
		{"sanity-filters", no_argument, 0, 'f'},
		{"loop", no_argument, 0, 'l'},
		{"sleep", required_argument, 0, 'z'},
		{"listen", no_argument, 0, 'L'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'}
	};

	char shortopts[]= "i:s:d:c:u:U:H:y:S:D:r:t:e:EA:R:m:O:p:P:nC:x:o:a:X:q:Q:V:w:MO:j:k:J:K:b:g:B:G:flz:Lvh";

	char option;

	if(argc<=1){
		usage();
		exit(EXIT_FAILURE);
	}

	/* Initialize filters structure */
	if(init_filters(&filters) == -1){
		puts("Error initializing internal data structure");
		exit(EXIT_FAILURE);
	}

	if(init_iface_data(&idata) == FAILURE){
		puts("Error initializing internal data structure");
		exit(EXIT_FAILURE);
	}

	hoplimit=64+random()%180;

	while((r=getopt_long(argc, argv, shortopts, longopts, NULL)) != -1) {
		option= r;

		switch(option) {

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

			case 'r':	/* Target address */

				if((charptr = strtok_r(optarg, "/", &lasts)) == NULL){
					puts("Error in Redirected Address");
					exit(EXIT_FAILURE);
				}

				if ( inet_pton(AF_INET6, charptr, &targetaddr) <= 0){
					puts("inet_pton(): Redirected Address not valid");
					exit(EXIT_FAILURE);
				}

				targetaddr_f = 1;
		
				if((charptr = strtok_r(NULL, " ", &lasts)) != NULL){
					redirpreflen = atoi(charptr);
		
					if(redirpreflen>128){
						puts("Prefix length error in IPv6 Source Address");
						exit(EXIT_FAILURE);
					}

					sanitize_ipv6_prefix(&targetaddr, redirpreflen);
					redirprefix_f=1;
				}

				break;

			case 't':	/* ICMPv6 Type and Code */
				if((charptr = strtok_r(optarg, ":", &lasts)) == NULL){
					puts("Error in ICMPv6 message Type/Code");
					exit(EXIT_FAILURE);
				}

				icmp6type= atoi(charptr);
				icmp6type_f=1;

				if((charptr = strtok_r(NULL, " ", &lasts)) != NULL){
		    			icmp6code= atoi(charptr);
					icmp6code_f=1;
				}

				break;

			case 'e':	/* ICMPv6 Destination Unreachable */
				icmp6type= 1;
				icmp6type_f= 1;
				icmp6code= atoi(optarg);
				icmp6code_f= 1;
				break;

			case 'E':	/* ICMPv6 Packet Too Big */
				icmp6type= 2;
				icmp6type_f= 1;
				icmp6code= 0;
				icmp6code_f= 1;
				break;

			case 'A':	/* ICMPv6 Time Exceeded */
				icmp6type= 3;
				icmp6type_f= 1;
				icmp6code= atoi(optarg);
				icmp6code_f= 1;
				break;

			case 'R':	/* ICMPv6 Parameter Problem */
				icmp6type=4;
				icmp6type_f= 1;
				icmp6code= atoi(optarg);
				icmp6code_f= 1;
				break;

			case 'm':	/* Next-Hop MTU (for ICMPv6 PTB messages) */
				if((ul_res = strtoul(optarg, &endptr, 0)) == ULONG_MAX){
					perror("Error in 'MTU' parameter");
					exit(EXIT_FAILURE);
				}
		
				if(endptr != optarg){
					mtu = ul_res;
					mtu_f=1;
				}
				break;

			case 'O':	/* Pointer (for ICMPv6 "Parameter Problem" messages) */
				if((ul_res = strtoul(optarg, &endptr, 0)) == ULONG_MAX){
					perror("Error in 'Pointer' parameter");
					exit(EXIT_FAILURE);
				}
		
				if(endptr != optarg){
					pointer = ul_res;
					pointer_f=1;
				}
				break;

			case 'p':	/* Protocol used in the ICMPv6 Payload */
				if(strcmp(optarg, "TCP") == 0)
					rhtcp_f = 1;
				else if(strcmp(optarg, "ICMP6") == 0)
					rhicmp6_f = 1;
				else if(strcmp(optarg, "UDP") == 0)
					rhudp_f = 1;
				else if(strcmp(optarg, "IP6") == 0){
					rhip6_f= 1;
				}
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

			case 'n':	/* No ICMPv6 Payload */
				nopayload_f=1;
				break;

			case 'C':	/* Hop Limit of the IPv6 Payload */
				ip6hoplimit= atoi(optarg);
				ip6hoplimit_f=1;
				break;

			case 'x':	/* Source Address of the ICMPv6 payload */
				if( inet_pton(AF_INET6, optarg, &peeraddr) <= 0){
					puts("inet_pton(): address not valid");
					exit(EXIT_FAILURE);
				}
		
				peeraddr_f = 1;
				break;

			case 'o':	/* Target port */
				if((charptr = strtok_r(optarg, ":-", &lasts)) == NULL){
					printf("Error in TCP/UDP target port");
					exit(EXIT_FAILURE);
				}

				targetportl= atoi(charptr);
				targetportl_f= 1;

				if((charptr = strtok_r(NULL, " ", &lasts)) == NULL){

					targetporth= targetportl;
				}
				else{
					targetporth=atoi(charptr);
					targetporth_f=1;

					if(targetportl > targetporth){
						auxint16= targetportl;
						targetportl= targetporth;
						targetporth= auxint16;
					}
				}
				break;

			case 'a':	/* Peer port */
				if((charptr = strtok_r(optarg, ":-", &lasts)) == NULL){
					printf("Error in TCP/UDP peer port");
					exit(EXIT_FAILURE);
				}

				peerportl= atoi(charptr);
				peerportl_f= 1;

				if((charptr = strtok_r(NULL, " ", &lasts)) == NULL){
					peerporth= peerportl;
				}
				else{
					peerporth=atoi(charptr);
					peerporth_f=1;

					if(peerportl > peerporth){
						auxint16= peerportl;
						peerportl= peerporth;
						peerporth= auxint16;
					}
				}
				break;

			case 'X':	/* TCP flags */
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
		puts("icmp6 needs root privileges to run.");
		exit(EXIT_FAILURE);
	}

	if(listen_f && !idata.iface_f){
		puts("Must specify a network interface with the -i option when listening mode is selected");
		exit(EXIT_FAILURE);
	}

	if(listen_f && loop_f){
		puts("'Error: listen' mode and 'loop' mode are incompatible");
		exit(EXIT_FAILURE);
	}
    
	if(!idata.dstaddr_f && !listen_f){	/* Must specify IPv6 Destination Address if listening mode not used */
		puts("IPv6 Destination Address not specified (and listening mode not selected)");
		exit(EXIT_FAILURE);
	}

	if(load_dst_and_pcap(&idata, LOAD_SRC_NXT_HOP) == FAILURE){
		puts("Error while learning Souce Address and Next Hop");
		exit(EXIT_FAILURE);
	}

	release_privileges();

	srandom(time(NULL));

	if(sanityfilters_f){
		if(filters.nblocksrc >= MAX_BLOCK_SRC){
			puts("Too many Source Address (block) filters while adding sanity filters.");
			exit(EXIT_FAILURE);
		}

		filters.blocksrc[filters.nblocksrc]= idata.srcaddr;
		filters.blocksrclen[filters.nblocksrc]=128;
		filters.nblocklinksrc++;
	}

	if(!sleep_f)
		nsleep=1;

	if( !fragh_f && dstoptuhdr_f){
		puts("Dst. Options Header (Unfragmentable Part) set, but Fragmentation not specified");
		exit(EXIT_FAILURE);
	}
    
	if(fragh_f)
		max_packet_size = MAX_IPV6_PAYLOAD + MIN_IPV6_HLEN;
	else
		max_packet_size = ETH_DATA_LEN;

	if(!nopayload_f && !(rhtcp_f || rhudp_f || rhicmp6_f))
		rhdefault_f=1;

	if(!ip6hoplimit_f)
		ip6hoplimit=64+random()%180;

	if(!ip6length_f)
		ip6length=1460;

	if(!targetaddr_f)
		targetaddr= idata.dstaddr;

	if(!peeraddr_f){
		if( inet_pton(AF_INET6, "::", &randprefix) <= 0){
			puts("inet_pton(): Error while randomizing Destination Address of the ICMPv6 payload");
			exit(EXIT_FAILURE);
		}
		randpreflen=0;

		randomize_ipv6_addr(&peeraddr, &randprefix, randpreflen);
	}

	if(rhtcp_f || rhdefault_f){
		if(!tcpflags_f)
			tcpflags= tcpflags | TH_ACK;

		if(!tcpack_f)
			tcpack= random();

		if(!tcpseq_f)
			tcpseq= random();

		if(!tcpwin_f)
			tcpwin= ((u_int16_t) random() + 1500) & (u_int16_t)0x7f00;

		if(!peerportl_f){
			peerportl= random();
			peerporth= peerportl;
		}

		if(!targetportl_f){
			targetportl= random();
			targetporth= targetportl;
		}

		if(!tcpurg_f)
			tcpurg= 0;
	}

	if(rhudp_f){
		if(!peerportl_f){
			peerportl= random();
			peerporth= peerportl;
		}

		if(!targetportl_f){
			targetportl= random();
			targetporth= targetportl;
		}
	}

	if(rhicmp6_f){
		if(!icmp6id_f)
			icmp6id= random();

		if(!icmp6seq_f)
			icmp6seq= random();
	}

	if(!icmp6type_f){
		icmp6type= ICMP6_PARAM_PROB;
		icmp6code= ICMP6_PARAMPROB_HEADER;
	}

	switch(icmp6type){
		case ICMP6_PACKET_TOO_BIG:
			if(!mtu_f)
				mtu= 296;
			break;

		case ICMP6_PARAM_PROB:
			if(pointer_f)
				pointer= random()%40;
			break;

		case ICMP6_DST_UNREACH:
		case ICMP6_TIME_EXCEEDED:
		default:
			break;
	}

	if(rhtcp_f){
		if(pcap_compile(idata.pfd, &pcap_filter, PCAP_TCPV6_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
			printf("pcap_compile(): %s", pcap_geterr(idata.pfd));
			exit(EXIT_FAILURE);
		}
	}
	else if(rhudp_f){
		if(pcap_compile(idata.pfd, &pcap_filter, PCAP_UDPV6_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
			printf("pcap_compile(): %s", pcap_geterr(idata.pfd));
			exit(EXIT_FAILURE);
		}
	}
	else if(rhicmp6_f){
		if(pcap_compile(idata.pfd, &pcap_filter, PCAP_ICMPV6_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
			printf("pcap_compile(): %s", pcap_geterr(idata.pfd));
			exit(EXIT_FAILURE);
		}
	}
	else if(pcap_compile(idata.pfd, &pcap_filter, PCAP_IPV6_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
		printf("pcap_compile(): %s", pcap_geterr(idata.pfd));
		exit(EXIT_FAILURE);
	}
    
	if(pcap_setfilter(idata.pfd, &pcap_filter) == -1){
		printf("pcap_setfilter(): %s", pcap_geterr(idata.pfd));
		exit(EXIT_FAILURE);
	}

	pcap_freecode(&pcap_filter);

	if(idata.verbose_f){
		print_attack_info(&idata);
	}

	/* Set initial contents of the attack packet */
	init_packet_data(&idata);
    
	/* Fire an ICMPv6 error message if an IPv6 Destination Address was specified 	*/
	if(idata.dstaddr_f){
		send_packet(&idata, NULL, NULL);
		if(idata.verbose_f)    
			puts("Initial attack packet(s) sent successfully.");

		if(loop_f){
			if(idata.verbose_f)
				printf("Now sending ICMPv6 error messages every %u second%s...\n", nsleep, \
											((nsleep>1)?"s":""));
			while(loop_f){
				sleep(nsleep);
				send_packet(&idata, NULL, NULL);
			}

			exit(EXIT_SUCCESS);
		}
	}

	if(listen_f){
		if(idata.verbose_f){
			print_filters(&idata, &filters);
			if(rhtcp_f){
				puts("Listening to incoming TCP packets...");
			}
			else if(rhudp_f){
				puts("Listening to incoming UDP packets...");
			}
			else if(rhicmp6_f){
				puts("Listening to incoming ICMPv6 packets...");
			}
			else{
				puts("Listening to incoming IPv6 packets...");
			}
		}

		if( (idata.fd= pcap_fileno(idata.pfd)) == -1){
			puts("Error obtaining descriptor number for pcap_t");
			exit(EXIT_FAILURE);
		}

		FD_ZERO(&sset);
		FD_SET(idata.fd, &sset);

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
			pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + linkhsize);

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
 * Function: init_packet_data()
 *
 * Initialize the contents of the attack packet (Ethernet header, IPv6 Header, and ICMPv6 header)
 * that are expected to remain constant for the specified attack.
 */
void init_packet_data(struct iface_data *idata){
	ethernet= (struct ether_header *) buffer;
	dlt_null= (struct dlt_null *) buffer;
	v6buffer = buffer + linkhsize;
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
		if( (fragpart+sizeof(fraghdr)+nfrags) > (v6buffer+ idata->mtu)){
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

	if( (ptr+sizeof(struct icmp6_hdr)) > (v6buffer+ idata->max_packet_size)){
		puts("Packet too large while inserting ICMPv6 header (should be using Frag. option?)");
		exit(EXIT_FAILURE);
	}

	icmp6= (struct icmp6_hdr *) ptr;

	icmp6->icmp6_type = icmp6type;
	icmp6->icmp6_code = icmp6code;

	switch(icmp6type){
		case ICMP6_PACKET_TOO_BIG:
			icmp6->icmp6_mtu= htonl(mtu);
			break;

		case ICMP6_PARAM_PROB:
			icmp6->icmp6_pptr=htonl(pointer);
			break;

		case ICMP6_TIME_EXCEEDED:
		case ICMP6_DST_UNREACH:
		default:
			icmp6->icmp6_data32[0]=0;
			break;
	}

	ptr += sizeof(struct icmp6_hdr);

	startofprefixes=ptr;
}



/*
 * Function: send_packet()
 *
 * Initialize the remaining fields of the Neighbor Advertisement Message, and
 * send the attack packet(s).
 */
void send_packet(struct iface_data *idata, const u_char *pktdata, struct pcap_pkthdr * pkthdr){
	if(pktdata != NULL){   /* Sending a Redirect in response to a received packet */
		pkt_ether = (struct ether_header *) pktdata;
		pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata->linkhsize);
	
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
			return;
		}
		else{
			ipv6->ip6_dst = pkt_ipv6->ip6_src;

			if(idata->type == DLT_EN10MB && idata->type != IFACE_LOOPBACK)
				ethernet->dst = pkt_ether->src;
		}

		pkt_ipv6addr = &(pkt_ipv6->ip6_dst);

		/*
		   We respond to packets sent to a multicast address only if the tool has been explicitly instructed
		   to do so. 
		 */
		if(IN6_IS_ADDR_MULTICAST(pkt_ipv6addr) && !respmcast_f)
			return;
	}

	targetport= targetportl;

	do{
		peerport= peerportl;

		do{
			ptr=startofprefixes;

			/*  We include a Redirected Header by default */
			if(!nopayload_f){
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
						if(currentsize > 1280)
							rhbytes=48;
						else
							rhbytes= 1280- currentsize;
					}

					pktbytes= pkthdr->caplen;

					if( rhbytes > pktbytes)
						rhbytes= pktbytes;

					rhbytes= (rhbytes>>3) << 3;

					if( (ptr+rhbytes) > (v6buffer+max_packet_size)){
						puts("Packet Too Large while inserting ICMPv6 payload");
						exit(EXIT_FAILURE);
					}

					bcopy(pkt_ipv6, ptr, rhbytes);
					ptr+= rhbytes;
				}
				else{
					/* The ICMPv6 Error is *not* being sent in response to a received packet */

					if(rhlength_f){
						rhbytes= rhlength;
					}
					else{
						currentsize= ptr - (unsigned char *)ipv6;
						if(currentsize > 1280)
							rhbytes=48;
						else
							rhbytes= 1280- currentsize;
					}

					rhbytes= (rhbytes>>3) << 3;

					if( (ptr+rhbytes) > (v6buffer+max_packet_size)){
						puts("Packet Too Large while inserting Redirected Header Option");
						exit(EXIT_FAILURE);
					}

					rhipv6 = (struct ip6_hdr *) rhbuff;
					rhipv6->ip6_flow= 0;
					rhipv6->ip6_vfc= 0x60;
					rhipv6->ip6_plen= htons(ip6length);
					rhipv6->ip6_hlim= ip6hoplimit;
					rhipv6->ip6_src= targetaddr;
					rhipv6->ip6_dst= peeraddr;

					if(rhtcp_f || rhdefault_f){
						rhipv6->ip6_nxt= IPPROTO_TCP;
						rhtcp= (struct tcp_hdr *) (rhbuff + sizeof(struct ip6_hdr));
						bzero(rhtcp, sizeof(struct tcp_hdr));
						rhtcp->th_sport= htons((u_int16_t) targetport);
						rhtcp->th_dport= htons((u_int16_t) peerport);
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
						rhudp->uh_sport= htons(targetport);
						rhudp->uh_dport= htons(peerport);
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

			icmp6->icmp6_cksum = 0;
			icmp6->icmp6_cksum = in_chksum(v6buffer, icmp6, ptr-((unsigned char *)icmp6), IPPROTO_ICMPV6);

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
				fipv6 = (struct ip6_hdr *) (fragbuffer + linkhsize);
				fptrend = fptr + linkhsize+MIN_IPV6_HLEN+MAX_IPV6_PAYLOAD;
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

					fipv6->ip6_plen = htons((fptr - fragbuffer) - MIN_IPV6_HLEN - linkhsize);
		
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

			peerport++;

		}while(peerport<=peerporth);

		targetport++;
	}while(targetport<=targetporth);
}



/*
 * Function: usage()
 *
 * Prints the syntax of the icmp6 tool
 */
void usage(void){
    puts("usage: icmp6 [-i INTERFACE] [-s SRC_ADDR[/LEN]] [-d DST_ADDR]\n"
	 "       [-S LINK_SRC_ADDR] [-D LINK-DST-ADDR] [-c HOP_LIMIT] [-y FRAG_SIZE]\n"
	 "       [-u DST_OPT_HDR_SIZE] [-U DST_OPT_U_HDR_SIZE] [-H HBH_OPT_HDR_SIZE]\n"
	 "       [-t TYPE[:CODE] | -e CODE | -A CODE -V CODE -R CODE] [-r TARGET_ADDR]\n"
	 "       [-x PEER_ADDR] [-c HOP_LIMIT] [-m MTU] [-O POINTER] [-p PAYLOAD_TYPE]\n"
	 "       [-P PAYLOAD_SIZE] [-n] [-a SRC_PORTL[:SRC_PORTH]]\n"
	 "       [-o DST_PORTL[:DST_PORTH]] [-X TCP_FLAGS] [-q TCP_SEQ] [-Q TCP_ACK]\n"
	 "       [-V TCP_URP] [-w TCP_WIN] [-M] [-j PREFIX[/LEN]] [-k PREFIX[/LEN]]\n"
	 "       [-J LINK_ADDR] [-K LINK_ADDR] [-b PREFIX[/LEN]] [-g PREFIX[/LEN]]\n"
	 "       [-B LINK_ADDR] [-G LINK_ADDR] [-f] [-L | -l] [-z] [-v] [-h]");
}


/*
 * Function: print_help()
 *
 * Prints help information for the icmp6 tool
 */
void print_help(void){
	puts(SI6_TOOLKIT);
	puts("icmp6: Security assessment tool for attack vectors based on ICMPv6 error messages\n");
	usage();
    
	puts("\nOPTIONS:\n"
	     "  --interface, -i             Network interface\n"
	     "  --src-address, -s           IPv6 Source Address\n"
	     "  --dst-address, -d           IPv6 Destination Address\n"
	     "  --hop-limit, -c             IPv6 Hop Limit\n"
	     "  --frag-hdr. -y              Fragment Header\n"
	     "  --dst-opt-hdr, -u           Destination Options Header (Fragmentable Part)\n"
	     "  --dst-opt-u-hdr, -U         Destination Options Header (Unfragmentable Part)\n"
	     "  --hbh-opt-hdr, -H           Hop by Hop Options Header\n"
	     "  --link-src-address, -S      Link-layer Destination Address\n"
	     "  --link-dst-address, -D      Link-layer Source Address\n"
	     "  --icmp6, -t                 ICMPv6 Type:Code\n"
	     "  --icmp6-dest-unreach, -e    ICMPv6 Destination Unreachable\n"
	     "  --icmp6-packet-too-big, -E  ICMPv6 Packet Too Big\n"
	     "  --icmp6-time-exceeded, -A   ICMPv6 Time Exceeeded\n"
	     "  --icmp6-param-problem, -R   ICMPv6 Parameter Problem\n"
	     "  --mtu, -m                   Next-Hop MTU (ICMPv6 Packet Too Big)\n"
	     "  --pointer, -O               Pointer (ICMPv6 Parameter Problem\n"
	     "  --payload-type, -p          Redirected Header Payload Type\n"
	     "  --payload-size, -P          Redirected Header Payload Size\n"
	     "  --no-payload, -n            Do not include a Redirected Header Option\n"
	     "  --ipv6-hlim, -C             ICMPv6 Payload's Hop Limit\n"
	     "  --target-addr, -r           ICMPv6 Payload's IPv6 Source Address\n"
	     "  --peer-addr, -x             ICMPv6 Payload's IPv6 Destination Address\n"
	     "  --target-port, -o           ICMPv6 Payload's Source Port\n"
	     "  --peer-port, -a             ICMPv6 Payload's Destination Port\n"
	     "  --tcp-flags, -X             ICMPv6 Payload's TCP Flags\n"
	     "  --tcp-seq, -q               ICMPv6 Payload's TCP SEQ Number\n"
	     "  --tcp-ack, -Q               ICMPv6 Payload's TCP ACK Number\n"
	     "  --tcp-urg, -V               ICMPv6 Payload's TCP URG Pointer\n"
	     "  --tcp-win, -w               ICMPv6 Payload's TCP Window\n"
	     "  --resp-mcast, -M            Respond to Multicast Packets\n"
	     "  --block-src, -j             Block IPv6 Source Address prefix\n"
	     "  --block-dst, -k             Block IPv6 Destination Address prefix\n"
	     "  --block-link-src, -J        Block Ethernet Source Address\n"
	     "  --block-link-dst, -K        Block Ethernet Destination Address\n"
	     "  --accept-src, -b            Accept IPv6 Source Addres prefix\n"
	     "  --accept-dst, -g            Accept IPv6 Destination Address prefix\n"
	     "  --accept-link-src, -B       Accept Ethernet Source Address\n"
	     "  --accept-link-dst, -G       Accept Ethernet Destination Address\n"
	     "  --sanity-filters, -f        Add sanity filters\n"
	     "  --listen, -L                Listen to incoming traffic\n"
	     "  --loop, -l                  Send periodic ICMPv6 error messages\n"
	     "  --sleep, -z                 Pause between sending ICMPv6 error messages\n"
	     "  --help, -h                  Print help for the icmp6 tool\n"
	     "  --verbose, -v               Be verbose\n"
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
	puts( "icmp6: Security ssessment tool for attack vectors based on ICMPv6 error messages\n");

	if(idata->type == DLT_EN10MB && idata->flags != IFACE_LOOPBACK){
		if(ether_ntop(&(idata->hsrcaddr), plinkaddr, sizeof(plinkaddr)) == 0){
			puts("ether_ntop(): Error converting address");
			exit(EXIT_FAILURE);
		}

		printf("Ethernet Source Address: %s%s\n", plinkaddr, ((!idata->hsrcaddr_f)?" (randomized)":""));

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
	}

	if(inet_ntop(AF_INET6, &(idata->srcaddr), psrcaddr, sizeof(psrcaddr)) == NULL){
		puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
		exit(EXIT_FAILURE);
	}

	printf("IPv6 Source Address: %s%s\n", psrcaddr, ((!idata->srcaddr_f)?" (randomized)":""));

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

	switch(icmp6type){
		case ICMP6_DST_UNREACH:
			printf("ICMPv6 Destination Unreachable (Type %u)", icmp6type);
			switch(icmp6code){
				case ICMP6_DST_UNREACH_NOROUTE:
					printf(", No route to destination (Code %u)\n", icmp6code);
					break;
				case ICMP6_DST_UNREACH_ADMIN:
					printf(", Communication administratively prohibited (Code %u)\n", icmp6code);
					break;

				case ICMP6_DST_UNREACH_BEYONDSCOPE:
					printf(", Beyond scope of source address (Code %u)\n", icmp6code);
					break;

				case ICMP6_DST_UNREACH_ADDR:
					printf(", Address Unreachable (Code %u)\n", icmp6code);
					break;

				case ICMP6_DST_UNREACH_NOPORT:
					printf(", Port Unreachable (Code %u)\n", icmp6code);
					break;

				case ICMP6_DST_UNREACH_FAILEDPOLICY:
					printf(", Source address failed ingress/egress policy (Code %u)\n", icmp6code);
					break;

				case ICMP6_DST_UNREACH_REJECTROUTE:
					printf(", Reject route to destination (Code %u)\n", icmp6code);
					break;

				default:
					printf(", Unknown ICMPv6 code (Code %u)\n", icmp6code);
					break;
			}
			break;

		case ICMP6_PACKET_TOO_BIG:
			printf("ICMPv6 Packet Too Big (Type %u)", icmp6type);

			switch(icmp6code){
				case 0:
					printf(", Code 0\n");
					printf("Next-Hop MTU: %u\n", mtu);
					break;

				default:
					printf(", Unknown ICMPv6 code (Code %u)\n", icmp6code);
					break;
			}
			break;

		case ICMP6_PARAM_PROB:
			printf("ICMPv6 Parameter Problem (Type %u)", icmp6type);

			switch(icmp6code){
				case ICMP6_PARAMPROB_HEADER:
					printf(", Erroneous header field (Code %u)\n", icmp6code);
					break;

				case ICMP6_PARAMPROB_NEXTHEADER:
					printf(", Unrecognized Next Header (Code %u)\n", icmp6code);
					break;

				case ICMP6_PARAMPROB_OPTION:
					printf(", Unrecognized IPv6 option (Code %u)\n)", icmp6code);
					break;

				default:
					printf(", Unknown ICMPv6 code (Code %u)\n", icmp6code);
					break;
			}
			break;

		case ICMP6_TIME_EXCEEDED:
			printf("ICMPv6 Time Exceeded (Type %u)", icmp6type);

			switch(icmp6code){
				case ICMP6_TIME_EXCEED_TRANSIT:
					printf(", Hop Limit exceeded in transit (Code %u)\n", icmp6code);
					break;

				case ICMP6_TIME_EXCEED_REASSEMBLY:
					printf(", Fragment reassembly time exceeded (Code %u)\n", icmp6code);
					break;

				default:
					printf(", Unknown ICMPv6 code (Code %u)\n", icmp6code);
					break;
			}

			break;

		default:
			printf("Unknown ICMPv6 Type/Code (Type=%u, Code %u)\n", icmp6type, icmp6code);
			break;
	}

	if((rhtcp_f || rhdefault_f) && idata->dstaddr_f){
		printf("Payload Type: IPv6/TCP%s\n", (rhdefault_f?" (default)":""));
	}
	else if(rhudp_f && idata->dstaddr_f){
		puts("Payload Type: IPv6/UDP");
	}
	else if(rhicmp6_f && idata->dstaddr_f){
		puts("Payload Type: IPv6/ICMPv6 Echo Request");
	}

	if(inet_ntop(AF_INET6, &targetaddr, pv6addr, sizeof(pv6addr)) == NULL){
		puts("inet_ntop(): Error converting Redirected Address to presentation format");
		exit(EXIT_FAILURE);
	}

	if(idata->dstaddr_f){
		printf("Source Address: %s%s\n", pv6addr, ((!targetaddr_f)?" (automatically-selected)":""));
	}

	if(inet_ntop(AF_INET6, &peeraddr, pv6addr, sizeof(pv6addr)) == NULL){
		puts("inet_ntop(): Error converting Redirect Target Address to presentation format");
		exit(EXIT_FAILURE);
	}

	if(idata->dstaddr_f){
		printf("Destination Address: %s%s\n", pv6addr, ((!peeraddr_f)?" (randomized)":""));
	}

	printf("Hop Limit: %u%s\n", ip6hoplimit, (ip6hoplimit_f)?"":" (randomized)");

	if((rhtcp_f || rhdefault_f) && idata->dstaddr_f){
		if(targetporth_f){
			printf("Source Port: %u-%u\t", targetportl, targetporth);
		}
		else{
			printf("Source Port: %u%s\t", targetportl, (targetportl_f?"":" (randomized)"));

		}

		if(peerporth_f){
			printf("Destination Port: %u-%u\t", peerportl, peerporth);
		}
		else{
			printf("Destination Port: %u%s\n", peerportl, (peerportl_f?"":" (randomized)"));

		}

		printf("SEQ Number: %u%s\tACK Number: %u%s\n", tcpseq, (tcpseq_f?"":" (randomized)"), \
								tcpack, (tcpack_f?"":" (randomized)"));

		printf("Flags: %s%s%s%s%s%s%s%s\t", ((tcpflags & TH_FIN)?"F":""), ((tcpflags & TH_SYN)?"S":""), \
					((tcpflags & TH_RST)?"R":""), ((tcpflags & TH_PUSH)?"P":""),\
					((tcpflags & TH_ACK)?"A":""), ((tcpflags & TH_URG)?"U":""),\
					((!tcpflags)?"none":""), ((!tcpflags_f)?" (default)":""));

		printf("Window: %u%s\tURG Pointer: %u%s\n", tcpwin, (tcpwin_f?"":" (randomized)"), \
								tcpurg, (tcpurg_f?"":" (default)"));
	}

	else if(rhudp_f && idata->dstaddr_f){
		if(targetporth_f){
			printf("Source Port: %u-%u\t", targetportl, targetporth);
		}
		else{
			printf("Source Port: %u%s\t", targetportl, (targetportl_f?"":" (randomized)"));

		}

		if(peerporth_f){
			printf("Destination Port: %u-%u\t", peerportl, peerporth);
		}
		else{
			printf("Destination Port: %u%s\t", peerportl, (peerportl_f?"":" (randomized)"));

		}
	}

	else if(rhicmp6_f && idata->dstaddr_f){
		printf("Identifier: %u%s\tSequence Number: %u%s\n", icmp6id, (icmp6id_f?"":" (randomized)"), \
								icmp6seq, (icmp6seq_f?"":" (randomized)"));
	}
}

