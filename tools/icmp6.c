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
 * 
 * Build with: gcc icmp6.c -Wall -lpcap -o icmp6
 * 
 * This program has been tested to compile and run on: Debian GNU/Linux 6.0,
 * FreeBSD 8.2, NetBSD 5.1, OpenBSD 5.0, and Ubuntu 11.10.
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
#include "icmp6.h"
#include <netinet/tcp.h>
#include <netinet/udp.h>


/* Function prototypes */
void				init_packet_data(void);
int					insert_pad_opt(unsigned char *ptrhdr, const unsigned char *, unsigned int);
void				send_packet(const u_char *, struct pcap_pkthdr *);
void				print_attack_info(void);
void				print_filters(void);
void				print_filter_result(const u_char *, unsigned char);
void				usage(void);
void				print_help(void);
int					ether_pton(const char *, struct ether_addr *, unsigned int);
int					ether_ntop(const struct ether_addr *, char *, size_t);
u_int16_t			in_chksum(void *, void *, size_t);
unsigned int		match_ipv6(struct in6_addr *, u_int8_t *, unsigned int, struct in6_addr *);
unsigned int		match_ether(struct ether_addr *, unsigned int, struct ether_addr *);
void				sanitize_ipv6_prefix(struct in6_addr *, u_int8_t);
void				randomize_ipv6_addr(struct in6_addr *, struct in6_addr *, u_int8_t);
void				randomize_ether_addr(struct ether_addr *);
void 				ether_to_ipv6_linklocal(struct ether_addr *etheraddr, struct in6_addr *ipv6addr);
void				sig_alarm(int);
int					is_eq_in6_addr(struct in6_addr *, struct in6_addr *);
int					find_ipv6_router_full(pcap_t *, struct iface_data *);
int					is_ip6_in_prefix_list(struct in6_addr *, struct prefix_list *);
int					ipv6_to_ether(pcap_t *, struct iface_data *, struct in6_addr *, struct ether_addr *);
int					send_neighbor_advert(struct iface_data *, pcap_t *,  const u_char *);
struct in6_addr		solicited_node(const struct in6_addr *);
struct ether_addr	ether_multicast(const struct in6_addr *);
int					match_ipv6_to_prefixes(struct in6_addr *, struct prefix_list *);

/* Flags used for the ICMPv6 Redirect (specifically) */
unsigned int		icmp6type_f=0, icmp6code_f=0, mtu_f=0, pointer_f=0;
unsigned int		targetaddr_f=0, redirprefix_f=0, targetportl_f=0, targetporth_f=0;
unsigned int		peeraddr_f=0, peerportl_f=0, peerporth_f=0;
unsigned int		rhip6_f=0, rhtcp_f=0, rhudp_f=0, rhicmp6_f=0, nopayload_f=0, rheader_f=0;
unsigned int		tcpseq_f=0, tcpack_f=0, tcpurg_f=0, tcpflags_f=0, tcpwin_f=0;
unsigned int		icmp6id_f=0, icmp6seq_f=0;
unsigned int		rhlength_f=0, floodr_f=0, respmcast_f=0, makeonlink_f=0;
unsigned int		ip6hoplimit_f=0, ip6length_f=0, rhdefault_f=0;
unsigned int		learnrouter_f=0, sanityfilters_f=0;

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
struct udphdr		*rhudp;
struct tcphdr		*rhtcp;
struct icmp6_hdr	*rhicmp6;
unsigned int		nredirs, redirs;
unsigned int		rhbytes, rhlength, currentsize;
unsigned char		rh_hoplimit;
unsigned char		rhbuff[100]; /* This one must be able to hold the IPv6 header and the upper layer header */


/* Variables used for learning the default router */
struct iface_data	idata;
struct prefix_entry	*prefix_ols[MAX_PREFIXES_ONLINK], *prefix_acs[MAX_PREFIXES_AUTO];
struct ether_addr	router_ether, rs_ether;
struct in6_addr		router_ipv6, rs_ipv6;
struct in6_addr		randprefix;
unsigned char		randpreflen;


/* Data structures for packets read from the wire */
pcap_t				*pfd;
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
struct ether_addr	hsrcaddr, hdstaddr;

struct in6_addr		srcaddr, dstaddr;

char				*lasts, *rpref;
char				*charptr;

size_t				nw;
unsigned long		ul_res, ul_val;
unsigned int		i, j, startrand;
unsigned int		skip;
unsigned int		ntargets, sources, nsources, targets, nsleep;
unsigned char		srcpreflen;

u_int16_t			mask;
u_int8_t			hoplimit;

char 				plinkaddr[ETHER_ADDR_PLEN];
char 				psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN], pv6addr[INET6_ADDRSTRLEN];
unsigned char 		verbose_f=0, iface_f=0, acceptfilters_f=0, floodt_f=0;
unsigned char 		srcaddr_f=0, dstaddr_f=0, hsrcaddr_f=0, hdstaddr_f=0, loopback_f=0, tunnel_f=0;
unsigned char 		listen_f = 0, multicastdst_f=0, accepted_f=0, loop_f=0, sleep_f=0;
unsigned char		targetprefix_f=0, srcprefix_f=0, hoplimit_f=0;
unsigned char		newdata_f=0, floods_f=0;

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
	extern char		*optarg;	
	extern int		optind;
	char			*endptr; /* Used by strtoul() */
	uid_t			ruid;
	gid_t			rgid;
	int				r, sel;
	fd_set			sset, rset;
	struct passwd	*pwdptr;

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
		exit(1);
	}

	hoplimit=64+random()%180;

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

			case 'c':	/* Hop Limit */
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

			case 'r':	/* Target address */

				if((charptr = strtok_r(optarg, "/", &lasts)) == NULL){
					puts("Error in Redirected Address");
					exit(1);
				}

				if ( inet_pton(AF_INET6, charptr, &targetaddr) <= 0){
					puts("inet_pton(): Redirected Address not valid");
					exit(1);
				}

				targetaddr_f = 1;
		
				if((charptr = strtok_r(NULL, " ", &lasts)) != NULL){
					redirpreflen = atoi(charptr);
		
					if(redirpreflen>128){
						puts("Prefix length error in IPv6 Source Address");
						exit(1);
					}

					sanitize_ipv6_prefix(&targetaddr, redirpreflen);
					redirprefix_f=1;
				}

				break;

			case 't':	/* ICMPv6 Type and Code */
				if((charptr = strtok_r(optarg, ":", &lasts)) == NULL){
					puts("Error in ICMPv6 message Type/Code");
					exit(1);
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
					exit(1);
				}
		
				if(endptr != optarg){
					mtu = ul_res;
					mtu_f=1;
				}
				break;

			case 'O':	/* Pointer (for ICMPv6 "Parameter Problem" messages) */
				if((ul_res = strtoul(optarg, &endptr, 0)) == ULONG_MAX){
					perror("Error in 'Pointer' parameter");
					exit(1);
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
					exit(1);
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
					exit(1);
				}
		
				peeraddr_f = 1;
				break;

			case 'o':	/* Target port */
				if((charptr = strtok_r(optarg, ":-", &lasts)) == NULL){
					printf("Error in TCP/UDP target port");
					exit(1);
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
					exit(1);
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

			case 'M':	/* Respond to multicast packets */
				respmcast_f=1;
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
		puts("icmp6 needs root privileges to run.");
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
    
	if(!dstaddr_f && !listen_f){	/* Must specify IPv6 Destination Address if listening mode not used */
		puts("IPv6 Destination Address not specified (and listening mode not selected)");
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

	if( (idata.type = pcap_datalink(idata.pd)) == DLT_EN10MB){
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
		printf("Error: Interface %s is not an Ethernet or tunnel interface", idata.iface);
		exit(1);
	}

	srandom(time(NULL));

	if(!hsrcaddr_f){
		randomize_ether_addr(&hsrcaddr);
	}

	if(!srcaddr_f || srcprefix_f){
		if(srcprefix_f){
			randprefix=srcaddr;
			randpreflen=srcpreflen;
		}
		else{
			if( inet_pton(AF_INET6, "::", &randprefix) <= 0){
				puts("inet_pton(): Error while randomizing IPv6 Source Address");
				exit(1);
			}
			randpreflen=0;
		}

		randomize_ipv6_addr(&srcaddr, &randprefix, randpreflen);
	}

	if(sanityfilters_f){
		if(nblocksrc >= MAX_BLOCK_SRC){
			puts("Too many Source Address (block) filters while adding sanity filters.");
			exit(1);
		}

		blocksrc[nblocksrc]= srcaddr;
		blocksrclen[nblocksrc]=128;
		nblocklinksrc++;
	}

	if(!sleep_f)
		nsleep=1;

	if( !fragh_f && dstoptuhdr_f){
		puts("Dst. Options Header (Unfragmentable Part) set, but Fragmentation not specified");
		exit(1);
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
		targetaddr= dstaddr;

	if(!peeraddr_f){
		if( inet_pton(AF_INET6, "::", &randprefix) <= 0){
			puts("inet_pton(): Error while randomizing Destination Address of the ICMPv6 payload");
			exit(1);
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

	if(idata.type == DLT_EN10MB && !loopback_f){
		if(!hdstaddr_f && dstaddr_f){
			ether_to_ipv6_linklocal(&idata.ether, &idata.ip6_local);

			idata.mtu= ETH_DATA_LEN;

			if(find_ipv6_router_full(pfd, &idata) != 1){
				puts("Failed learning default IPv6 router");
				exit(1);
			}

			if(match_ipv6_to_prefixes(&dstaddr, &idata.prefix_ol)){
				/* Must perform Neighbor Discovery for the local address */
				if(ipv6_to_ether(pfd, &idata, &dstaddr, &hdstaddr) != 1){
					puts("Error while performing Neighbor Discovery for the Destination Address");
				}
			}
			else{
				hdstaddr= router_ether;
			}
		}
	}

	if(rhtcp_f){
		if(pcap_compile(pfd, &pcap_filter, PCAP_TCPV6_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
			printf("pcap_compile(): %s", pcap_geterr(pfd));
			exit(1);
		}
	}
	else if(rhudp_f){
		if(pcap_compile(pfd, &pcap_filter, PCAP_UDPV6_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
			printf("pcap_compile(): %s", pcap_geterr(pfd));
			exit(1);
		}
	}
	else if(rhicmp6_f){
		if(pcap_compile(pfd, &pcap_filter, PCAP_ICMPV6_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
			printf("pcap_compile(): %s", pcap_geterr(pfd));
			exit(1);
		}
	}
	else if(pcap_compile(pfd, &pcap_filter, PCAP_IPV6_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
		printf("pcap_compile(): %s", pcap_geterr(pfd));
		exit(1);
	}
    
	if(pcap_setfilter(pfd, &pcap_filter) == -1){
		printf("pcap_setfilter(): %s", pcap_geterr(pfd));
		exit(1);
	}

	pcap_freecode(&pcap_filter);

	if(verbose_f){
		print_attack_info();
	}

	/* Set initial contents of the attack packet */
	init_packet_data();
    
	/* Fire an ICMPv6 Redirect if an IPv6 Destination Address was specified 	*/
	if(dstaddr_f){
		send_packet(NULL, NULL);
		if(verbose_f)    
			puts("Initial attack packet(s) sent successfully.");

		if(loop_f){
			if(verbose_f)
				printf("Now sending ICMPv6 error messages every %u second%s...\n", nsleep, \
											((nsleep>1)?"s":""));
			while(loop_f){
				sleep(nsleep);
				send_packet(NULL, NULL);
			}

			exit(0);
		}
	}

	if(listen_f){
		if(verbose_f){
			print_filters();
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

		if( (idata.fd= pcap_fileno(pfd)) == -1){
			puts("Error obtaining descriptor number for pcap_t");
			exit(1);
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
					exit(1);
				}
			}

			/* Read a Neighbor Solicitation message */
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
						if(verbose_f>2)
							print_filter_result(pktdata, BLOCKED);
		
						continue;
					}
				}

				if(nblocklinkdst){
					if(match_ether(blocklinkdst, nblocklinkdst, &(pkt_ether->dst))){
						if(verbose_f>2)
							print_filter_result(pktdata, BLOCKED);
		
						continue;
					}
				}
			}
	
			if(nblocksrc){
				if(match_ipv6(blocksrc, blocksrclen, nblocksrc, &(pkt_ipv6->ip6_src))){
					if(verbose_f>2)
						print_filter_result(pktdata, BLOCKED);
		
					continue;
				}
			}
	
			if(nblockdst){
				if(match_ipv6(blockdst, blockdstlen, nblockdst, &(pkt_ipv6->ip6_dst))){
					if(verbose_f>2)
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
				if(verbose_f>2)
					print_filter_result(pktdata, BLOCKED);

				continue;
			}

			if(verbose_f>1)
				print_filter_result(pktdata, ACCEPTED);

			/* Send a Neighbor Advertisement */
			send_packet(pktdata, pkthdr);
		}
    
		exit(0);
	}
    

	if(!dstaddr_f && !listen_f){
		puts("Error: Nothing to send! (key parameters left unspecified, and not using listening mode)");
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
	dlt_null= (struct dlt_null *) buffer;
	v6buffer = buffer + linkhsize;
	ipv6 = (struct ip6_hdr *) v6buffer;

	if(idata.type == DLT_EN10MB && !loopback_f){
		ethernet->src = hsrcaddr;
		ethernet->dst = hdstaddr;
		ethernet->ether_type = htons(0x86dd);
	}
	else if(idata.type == DLT_NULL){
		dlt_null->family= PF_INET6;
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
			if((ptr+ hbhopthdrlen[hbhopthdrs]) > (v6buffer+ ETH_DATA_LEN)){
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
			if((ptr+ dstoptuhdrlen[dstoptuhdrs]) > (v6buffer+ ETH_DATA_LEN)){
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
		if( (fragpart+sizeof(fraghdr)+nfrags) > (v6buffer+ idata.mtu)){
			puts("Unfragmentable part too large for current MTU (1500 bytes)");
			exit(1);
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
			exit(1);
			}
    
			*prev_nh = IPPROTO_DSTOPTS;
			prev_nh = ptr;
			memcpy(ptr, dstopthdr[dstopthdrs], dstopthdrlen[dstopthdrs]);
			ptr = ptr + dstopthdrlen[dstopthdrs];
			dstopthdrs++;
		}
	}


	*prev_nh = IPPROTO_ICMPV6;

	if( (ptr+sizeof(struct icmp6_hdr)) > (v6buffer+max_packet_size)){
		puts("Packet too large while inserting ICMPv6 header (should be using Frag. option?)");
		exit(1);
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
void send_packet(const u_char *pktdata, struct pcap_pkthdr * pkthdr){
	if(pktdata != NULL){   /* Sending a Redirect in response to a received packet */
		pkt_ether = (struct ether_header *) pktdata;
		pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + linkhsize);
	
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

			if(idata.type == DLT_EN10MB && !loopback_f)
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
						exit(1);
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
						exit(1);
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
						rhtcp= (struct tcphdr *) (rhbuff + sizeof(struct ip6_hdr));
						bzero(rhtcp, sizeof(struct tcphdr));
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
						rhudp = (struct udphdr *) (rhbuff + sizeof(struct ip6_hdr));
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
			icmp6->icmp6_cksum = in_chksum(v6buffer, icmp6, ptr-((unsigned char *)icmp6));

			if(!fragh_f){
				ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);

				if((nw=pcap_inject(pfd, buffer, ptr - buffer)) == -1){
					printf("pcap_inject(): %s\n", pcap_geterr(pfd));
					exit(1);
				}

				if(nw != (ptr-buffer)){
					printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, \
												(LUI) (ptr-buffer));
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
    puts("usage: icmp6 -i INTERFACE [-s SRC_ADDR[/LEN]] [-d DST_ADDR]\n"
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
	puts("SI6 Networks' IPv6 Toolkit v1.3");
	puts("icmp6: Assessment tool for attack vectors based on ICMPv6 error messages\n");
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
 * Function: in_chksum()
 *
 * Calculate the 16-bit ICMPv6 checksum
 */

u_int16_t in_chksum(void *ptr_ipv6, void *ptr_icmpv6, size_t len){
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
	pseudohdr.nh = IPPROTO_ICMPV6;

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

	puts( "icmp6 version 1.1\nAssessment tool for attack vectors based on ICMPv6 error messages\n");

	if(idata.type == DLT_EN10MB && !loopback_f){
		if(ether_ntop(&hsrcaddr, plinkaddr, sizeof(plinkaddr)) == 0){
			puts("ether_ntop(): Error converting address");
			exit(1);
		}

		printf("Ethernet Source Address: %s%s\n", plinkaddr, ((!hsrcaddr_f)?" (randomized)":""));

		/* 
		   Ethernet Destination Address only used if a IPv6 Destination Address or an
		   Ethernet Destination Address were specified.
		 */
		if(dstaddr_f){
			if(ether_ntop(&hdstaddr, plinkaddr, sizeof(plinkaddr)) == 0){
				puts("ether_ntop(): Error converting address");
				exit(1);
			}

			printf("Ethernet Destination Address: %s%s\n", plinkaddr, \
						((!hdstaddr_f)?" (automatically selected)":""));
		}
	}

	if(inet_ntop(AF_INET6, &srcaddr, psrcaddr, sizeof(psrcaddr))<=0){
		puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
		exit(1);
	}

	printf("IPv6 Source Address: %s%s\n", psrcaddr, ((!srcaddr_f)?" (randomized)":""));

	if(dstaddr_f){
		if(inet_ntop(AF_INET6, &dstaddr, pdstaddr, sizeof(pdstaddr))<=0){
			puts("inet_ntop(): Error converting IPv6 Destination Address to presentation format");
			exit(1);
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

	if((rhtcp_f || rhdefault_f) && dstaddr_f){
		printf("Payload Type: IPv6/TCP%s\n", (rhdefault_f?" (default)":""));
	}
	else if(rhudp_f && dstaddr_f){
		puts("Payload Type: IPv6/UDP");
	}
	else if(rhicmp6_f && dstaddr_f){
		puts("Payload Type: IPv6/ICMPv6 Echo Request");
	}

	if(inet_ntop(AF_INET6, &targetaddr, pv6addr, sizeof(pv6addr))<=0){
		puts("inet_ntop(): Error converting Redirected Address to presentation format");
		exit(1);
	}

	if(dstaddr_f){
		printf("Source Address: %s%s\n", pv6addr, ((!targetaddr_f)?" (automatically-selected)":""));
	}

	if(inet_ntop(AF_INET6, &peeraddr, pv6addr, sizeof(pv6addr))<=0){
		puts("inet_ntop(): Error converting Redirect Target Address to presentation format");
		exit(1);
	}

	if(dstaddr_f){
		printf("Destination Address: %s%s\n", pv6addr, ((!peeraddr_f)?" (randomized)":""));
	}

	printf("Hop Limit: %u%s\n", ip6hoplimit, (ip6hoplimit_f)?"":" (randomized)");

	if((rhtcp_f || rhdefault_f) && dstaddr_f){
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

	else if(rhudp_f && dstaddr_f){
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

	else if(rhicmp6_f && dstaddr_f){
		printf("Identifier: %u%s\tSequence Number: %u%s\n", icmp6id, (icmp6id_f?"":" (randomized)"), \
								icmp6seq, (icmp6seq_f?"":" (randomized)"));
	}
}



/*
 * Function: print_filters()
 *
 * Prints the filters that will be applied to incoming Neighbor SOlicitation messages.
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
 * Prints infromation about an incoming Neighbor Solicitation message and whether it
 * was blocked or accepted by a filter.
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
	unsigned char			*ptr;

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
	v6buffer = buffer + linkhsize;
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
	ns->nd_ns_cksum = in_chksum(v6buffer, ns, ptr-((unsigned char *)ns));

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

		alarm(2);
		
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
			if(in_chksum(pkt_ipv6, pkt_na, pkt_end-((unsigned char *)pkt_na)) != 0)
				continue;

			/* Check that the ICMPv6 Target Address is the one we had asked for */
			if(!is_eq_in6_addr(&(pkt_na->nd_na_target), targetaddr))
				continue;

			ptr= (unsigned char *) pkt_na + sizeof(struct nd_neighbor_advert);

			/* Process Neighbor Advertisement options */
			while( (ptr+sizeof(struct nd_opt_tlla)) <= pkt_end && (*(ptr+1) != 0)){
				if(*ptr == ND_OPT_TARGET_LINKADDR){
					if( (*(ptr+1) * 8) != sizeof(struct nd_opt_tlla))
						break;

					/* Got a response, so we shouln't time out */
					alarm(0);

					/* Save the link-layer address */
					*result_ether= *(struct ether_addr *) (ptr+2);
					foundaddr=1;
					break;
				}

				ptr= ptr + *(ptr+1) * 8;
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
 * Function: find_ipv6_router_full()
 *
 * Finds a local router (by means of Neighbor Discovery)
 */

int find_ipv6_router_full(pcap_t *pfd, struct iface_data *idata){
	struct pcap_pkthdr		*pkthdr;
	const u_char			*pktdata;
	struct ip6_hdr			*pkt_ipv6;
	struct nd_router_advert 	*pkt_ra;
	unsigned char			*pkt_end;
	unsigned char			*ptr;

	unsigned char			buffer[65556];
	unsigned int 			rs_max_packet_size;
	struct ether_header 		*ether;
	unsigned char 			*v6buffer;
	struct ip6_hdr 			*ipv6;
	struct nd_router_solicit	*rs;
	struct nd_opt_slla 		*sllaopt;
	struct nd_opt_prefix_info	*pio;
	volatile unsigned int 		tries=0;
	volatile unsigned int 		foundrouter=0;
	struct sigaction 		new_sig, old_sig;
	unsigned char			closefd_f=0, error_f=0;
	int				result;

	/* Initializing the relevant fields of the idata structure */
	bzero(&(idata->router_ip6), sizeof(struct in6_addr));
	bzero(&(idata->router_ether), sizeof(struct ether_addr));

	idata->prefix_ol.prefix= prefix_ols;
	idata->prefix_ol.nprefix= 0;
	idata->prefix_ol.maxprefix= MAX_PREFIXES_ONLINK;

	idata->prefix_ac.prefix= prefix_acs;
	idata->prefix_ac.nprefix= 0;
	idata->prefix_ac.maxprefix= MAX_PREFIXES_AUTO;

	rs_max_packet_size = idata->mtu;
	ether = (struct ether_header *) buffer;
	v6buffer = buffer + linkhsize;
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
	rs->nd_rs_cksum = in_chksum(v6buffer, rs, ptr-((unsigned char *)rs));

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

		alarm(1);
		
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
			if(in_chksum(pkt_ipv6, pkt_ra, pkt_end- (unsigned char *)pkt_ra) != 0)
				continue;

			ptr= (unsigned char *) pkt_ra + sizeof(struct nd_router_advert);

			/* Process Router Advertisement options */
			while( (ptr+ *(ptr+1) * 8) <= pkt_end && *(ptr+1)!=0 && !error_f){
				switch(*ptr){
					case ND_OPT_SOURCE_LINKADDR:
						if( (*(ptr+1) * 8) != sizeof(struct nd_opt_tlla))
							break;

						/* Got a response, so we shouln't time out */
						alarm(0);

						/* Save the link-layer address */
						idata->router_ether = *(struct ether_addr *) (ptr+2);
						idata->router_ip6= pkt_ipv6->ip6_src;
						foundrouter=1;
						break;

					case ND_OPT_PREFIX_INFORMATION:
						if(*(ptr+1) != 4)
							break;

						pio= (struct nd_opt_prefix_info *) ptr;

						if((idata->prefix_ol.nprefix) < idata->prefix_ol.maxprefix){
							if( (pio->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_ONLINK) && \
								(pio->nd_opt_pi_prefix_len <= 128) && !is_ip6_in_prefix_list(&(pio->nd_opt_pi_prefix), &(idata->prefix_ol))){

								if( (idata->prefix_ol.prefix[idata->prefix_ol.nprefix] = malloc(sizeof(struct prefix_entry))) == NULL){
									if(verbose_f>1)
										puts("Error in malloc() while learning prefixes");

									error_f=1;
									break;
								}

								(idata->prefix_ol.prefix[idata->prefix_ol.nprefix])->ip6= \
												pio->nd_opt_pi_prefix;
								(idata->prefix_ol.prefix[idata->prefix_ol.nprefix])->len= \
												pio->nd_opt_pi_prefix_len;
								sanitize_ipv6_prefix(&((idata->prefix_ol.prefix[idata->prefix_ol.nprefix])->ip6), (idata->prefix_ol.prefix[idata->prefix_ol.nprefix])->len);
								(idata->prefix_ol.nprefix)++;
							}
						}

						if(idata->prefix_ac.nprefix < idata->prefix_ac.maxprefix){
							if( (pio->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_AUTO) && \
								(pio->nd_opt_pi_prefix_len == 64) && !is_ip6_in_prefix_list(&(pio->nd_opt_pi_prefix), &(idata->prefix_ac))){

								if((idata->prefix_ac.prefix[idata->prefix_ac.nprefix] = malloc(sizeof(struct prefix_entry))) == NULL){
									if(verbose_f>1)
										puts("Error in malloc() while learning prefixes");
									error_f=1;
									break;
								}

								(idata->prefix_ac.prefix[idata->prefix_ac.nprefix])->ip6= \
												pio->nd_opt_pi_prefix;
								(idata->prefix_ac.prefix[idata->prefix_ac.nprefix])->len= \
												pio->nd_opt_pi_prefix_len;

								sanitize_ipv6_prefix(&((idata->prefix_ac.prefix[idata->prefix_ac.nprefix])->ip6), (idata->prefix_ac.prefix[idata->prefix_ac.nprefix])->len);

								if(idata->prefix_ac.nprefix == 0 && !idata->ip6_global_flag){
									for(i=0; i<4; i++)
										idata->ip6_global.s6_addr16[i]= (idata->prefix_ac.prefix[0])->ip6.s6_addr16[i];

									for(i=4; i<8; i++)
										idata->ip6_global.s6_addr16[i]= idata->ip6_local.s6_addr16[i];

									idata->ip6_global_flag=1;

								}
								(idata->prefix_ac.nprefix)++;
							}
						}

						break;
				}

				ptr= ptr + *(ptr+1) * 8;
			} /* Processing options */

		} /* Processing packets */

	} /* Resending Router Solicitations */

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
 * Function: send_neighbor_advertisement()
 *
 * Send a Neighbor advertisement in response to a Neighbor Solicitation message
 */

int send_neighbor_advert(struct iface_data *idata, pcap_t *pfd,  const u_char *pktdata){
	struct ip6_hdr			*pkt_ipv6;
	struct nd_neighbor_solicit	*pkt_ns;
	unsigned char			*ptr;

	unsigned char			buffer[65556];
	unsigned char 			*v6buffer;
	struct ip6_hdr			*ipv6;
	struct nd_neighbor_advert	*na;
	struct	nd_opt_tlla		*tllaopt;


	ethernet= (struct ether_header *) buffer;
	v6buffer = buffer + sizeof(struct ether_header);
	ipv6 = (struct ip6_hdr *) v6buffer;
	na= (struct nd_neighbor_advert *) ((char *) v6buffer + MIN_IPV6_HLEN);
	ptr = (unsigned char *) na;

	pkt_ether = (struct ether_header *) pktdata;
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + ETHER_HDR_LEN);
	pkt_ns = (struct nd_neighbor_solicit *) ((char *) pkt_ipv6 + MIN_IPV6_HLEN);

	ethernet->ether_type = htons(0x86dd);
	ipv6->ip6_flow=0;
	ipv6->ip6_vfc= 0x60;
	ipv6->ip6_hlim= 255;
	ipv6->ip6_nxt= IPPROTO_ICMPV6;

	if( (ptr+sizeof(struct nd_neighbor_advert)) > (v6buffer+idata->mtu)){
		if(verbose_f>1)
			puts("Packet too large while constructing Neighbor Advertisement message");

		return(-1);
	}

	na->nd_na_type = ND_NEIGHBOR_ADVERT;
	na->nd_na_code = 0;
	ptr += sizeof(struct nd_neighbor_advert);

	if( (ptr+sizeof(struct nd_opt_tlla)) <= (v6buffer+idata->mtu) ){
		tllaopt = (struct nd_opt_tlla *) ptr;
		tllaopt->type= ND_OPT_TARGET_LINKADDR;
		tllaopt->length= TLLA_OPT_LEN;
		bcopy(idata->ether.a, tllaopt->address, ETH_ALEN);
		ptr += sizeof(struct nd_opt_tlla);
	}
	else{
		if(verbose_f>1)
			puts("Packet Too Large while inserting TLLA option in NA message");

		return(-1);
	}

	/* If the IPv6 Source Address of the incoming Neighbor Solicitation is the unspecified 
	   address (::), the Neighbor Advertisement must be directed to the IPv6 all-nodes 
	   multicast address (and the Ethernet Destination address should be 33:33:33:00:00:01). 
	   Otherwise, the Neighbor Advertisement is sent to the IPv6 Source Address (and 
	   Ethernet Source Address) of the incoming Neighbor Solicitation message
	 */
	pkt_ipv6addr = &(pkt_ipv6->ip6_src);

	if(IN6_IS_ADDR_UNSPECIFIED(pkt_ipv6addr)){
		na->nd_na_flags_reserved = 0;

		if ( inet_pton(AF_INET6, ALL_NODES_MULTICAST_ADDR, &(ipv6->ip6_dst)) <= 0){
			if(verbose_f>1)
				puts("inetr_pton(): Error converting all-nodes multicast address");

			return(-1);
		}

		if(ether_pton(ETHER_ALLNODES_LINK_ADDR, &(ethernet->dst), ETHER_ADDR_LEN) == 0){
			if(verbose_f>1)
				puts("ether_pton(): Error converting all-nodes link-local address");

			return(-1);
		}
	}
	else{
		ipv6->ip6_dst = pkt_ipv6->ip6_src;
		ethernet->dst = pkt_ether->src;

		/* 
		   Set the "Solicited" flag if NS was sent from an address other than the unspecified
		   address (i.e., the response will be unicast). 
		 */ 

		na->nd_na_flags_reserved =  ND_NA_FLAG_OVERRIDE | ND_NA_FLAG_SOLICITED;
	}

	ethernet->src = idata->ether;

	/* 
	   If the Neighbor Solicitation message was directed to our global unicast address, the IPv6 Source
	   Address is set to that address. Otherwise, we set the IPv6 SOurce Address to our link-local address.
	 */

	pkt_ipv6addr = &(pkt_ipv6->ip6_dst);

	if(IN6_IS_ADDR_MULTICAST(pkt_ipv6addr)){
		ipv6->ip6_src = idata->ip6_local;
	}
	else{
		if(idata->ip6_global_flag && is_eq_in6_addr(pkt_ipv6addr, &(idata->ip6_global)))
			ipv6->ip6_src = idata->ip6_global;
		else
			ipv6->ip6_src = idata->ip6_local;
	}

	na->nd_na_target= pkt_ns->nd_ns_target;

	na->nd_na_cksum = 0;
	na->nd_na_cksum = in_chksum(v6buffer, na, ptr-((unsigned char *)na));


	if(!fragh_f){
		ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);

		if((nw=pcap_inject(pfd, buffer, ptr - buffer)) == -1){
			if(verbose_f>1)
				printf("pcap_inject(): %s\n", pcap_geterr(pfd));

			return(-1);
		}

		if(nw != (ptr-buffer)){
			if(verbose_f>1)
				printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, (LUI) (ptr-buffer));

			return(-1);
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
			if(verbose_f>1)
				puts("Unfragmentable Part is Too Large");

			return(-1);
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
		
			if((nw=pcap_inject(pfd, fragbuffer, fptr - fragbuffer)) == -1){
				if(verbose_f>1)
					printf("pcap_inject(): %s\n", pcap_geterr(pfd));

				return(-1);
			}

			if(nw != (fptr- fragbuffer)){
				if(verbose_f>1)
					printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, \
												(LUI) (ptr-buffer));

				return(-1);
			}
		}
	}

	return 0;
}


/*
 * Function: is_ip6_in_list()
 *
 * Checks whether an IPv6 address is present in an address list.
 */

int is_ip6_in_prefix_list(struct in6_addr *target, struct prefix_list *plist){
	unsigned int i;

	for(i=0; i < plist->nprefix; i++)
		if( is_eq_in6_addr(target, &((plist->prefix[i])->ip6)))
			return 1;

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

