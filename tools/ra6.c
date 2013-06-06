/*
 * ra6: A security assessment tool for attack vectors based on 
 *      ICMPv6 Router Advertisement messages
 *
 * Copyright (C) 2009-2013 Fernando Gont
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
 * Build with: gcc ra6.c -Wall -lpcap -o ra6
 * 
 * This program has been tested to compile and run on: Debian GNU/Linux 6.0,
 * FreeBSD 8.2, NetBSD 5.1, OpenBSD 5.0, and Ubuntu 11.10.
 *
 * It requires that the libpcap library be installed on your system.
 *
 * Please send any bug reports to Fernando Gont <fgont@si6networks.com>
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <pwd.h>
#include "ra6.h"
#include "ipv6toolkit.h"

void	 		init_packet_data(void);
int 			insert_pad_opt(char *ptrhdr, const char *, unsigned int);
void	 		send_packet(const u_char *);
void	 		usage(void);
void			print_help(void);
int				ether_pton(const char *, struct ether_addr *, unsigned int);
int				ether_ntop(const struct ether_addr *, char *, size_t);
u_int16_t		in_chksum(void *, void *, size_t);
void			print_attack_info(void);


/* Functions used for filter implementation */
unsigned int	match_ipv6(struct in6_addr *, u_int8_t *, unsigned int, struct in6_addr *);
unsigned int	match_ether(struct ether_addr *, unsigned int, struct ether_addr *);
void			sanitize_ipv6_prefix(struct in6_addr *, u_int8_t);
void			print_filters(void);
void			print_filter_result(const u_char *, unsigned char);


pcap_t				*pfd;
struct pcap_pkthdr	*pkthdr;
const u_char		*pktdata;
struct in6_addr		*pkt_ipv6addr;    
bpf_u_int32			my_netmask;
bpf_u_int32			my_ip;
struct bpf_program	pcap_filter;
char				dev[64], errbuf[PCAP_ERRBUF_SIZE];
char				all_nodes_addr[]= ALL_NODES_MULTICAST_ADDR;

char				buffer[ETHER_HDR_LEN+MIN_IPV6_HLEN+MAX_IPV6_PAYLOAD];
char				fragbuffer[ETHER_HDR_LEN+MIN_IPV6_HLEN+MAX_IPV6_PAYLOAD];
char 				*v6buffer, *ptr, *startofprefixes, *ptrhdr, *ptrhdrend;
char				*fragpart, *fptr, *fptrend, *ptrend;

char 				iface[IFACE_LENGTH];
    
struct ip6_hdr				*ipv6, *pkt_ipv6, *fipv6;
struct nd_router_advert		*ra;
struct nd_router_solicit	*pkt_rs;
struct nd_opt_rdnss_l		*dnsopt;
struct ether_header			*ethernet, *pkt_ether;
struct ether_addr			hsrcaddr, hdstaddr;
struct nd_opt_mtu			*mtuopt;
struct nd_opt_slla			*sllaopt;
struct nd_opt_prefix_info	*prefixopt;
struct nd_opt_route_info_l	*routeopt;

struct in6_addr				srcaddr, dstaddr;
char						*lasts, *rpref, *endptr;
    
size_t						nw;
u_int16_t					lifetime;
u_int32_t					reachable;
u_int32_t					retrans;
u_int8_t					curhop, hoplimit;
char						preference=0, prefbits=0;
unsigned int				nprefixes=0, nroutes=0, nfrags=0;
unsigned int				hdrlen, ndstopthdr=0, nhbhopthdr=0, ndstoptuhdr=0;
unsigned int				dstopthdrs, dstoptuhdrs, hbhopthdrs;
char						hbhopthdr_f=0, dstoptuhdr_f=0, dstopthdr_f=0;
char						*dstopthdr[MAX_DST_OPT_HDR], *dstoptuhdr[MAX_DST_OPT_U_HDR];
char						*hbhopthdr[MAX_HBH_OPT_HDR];
unsigned int				dstopthdrlen[MAX_DST_OPT_HDR], dstoptuhdrlen[MAX_DST_OPT_U_HDR];
unsigned int				hbhopthdrlen[MAX_HBH_OPT_HDR], nfrags, fragsize, max_packet_size, m, pad;
struct ip6_frag				fraghdr, *fh;

char						*prev_nh, *startoffragment;

unsigned long				ul_res, ul_val;
    
unsigned int				i, j, startrand, sources, nsources, prefixes, routes, mtus;
unsigned int				nfloodp, nfloodr, endrand;
    
unsigned int				nfloodda, nflooddoa, nsleep;
u_int16_t					mask;
u_int8_t					prefixlen[MAX_PREFIX_OPTION];
u_int32_t					prefixvalid[MAX_PREFIX_OPTION];
u_int32_t					prefixpref[MAX_PREFIX_OPTION];
struct in6_addr				prefix[MAX_PREFIX_OPTION];
u_int8_t					prefixflags[MAX_PREFIX_OPTION];

struct in6_addr				route[MAX_ROUTE_OPTION];
u_int8_t					routelen[MAX_ROUTE_OPTION];
u_int32_t					routelife[MAX_ROUTE_OPTION];
u_int8_t					routepref[MAX_ROUTE_OPTION];
    
struct in6_addr				rdnss[MAX_RDNSS_OPTION][MAX_RDNSS_OPT_ADDRS];
u_int32_t					rdnsslife[MAX_RDNSS_OPTION];
unsigned int				nrdnss=0, dnsopts;
unsigned int				nrdnssopt[MAX_RDNSS_OPTION];
int 						smaxaddrs;

u_int16_t					mtu[MAX_MTU_OPTION];
unsigned int				nmtu=0;

struct ether_addr			linkaddr[MAX_SLLA_OPTION];
unsigned int				nlinkaddr=0, linkaddrs;
    
char			 			*pref;
char 						*preflen;
char 						*prefvalid;
char 						*prefpref;
char 						*prefflags;
char 						*charptr;
    
char 						plinkaddr[ETHER_ADDR_PLEN], phsrcaddr[ETHER_ADDR_PLEN], phdstaddr[ETHER_ADDR_PLEN];
char 						psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN], pprefix[INET6_ADDRSTRLEN];
char						pv6addr[INET6_ADDRSTRLEN];
unsigned char				srcpreflen;


/* FLgas used for option processing */
unsigned char 				verbose_f=0, managed_f=0, other_f=0, home_f=0, proxy_f=0;
unsigned char 				mtuopt_f=0, sllopt_f=0, sllopta_f=0, iface_f=0, srcprefix_f=0, prefopt_f=0;;
unsigned char 				srcaddr_f=0, dstaddr_f=0, hsrcaddr_f=0, hdstaddr_f=0;
unsigned char				fragh_f=0, hoplimit_f=0;
unsigned char 				listen_f = 0, floodp_f=0, floods_f=0, floodr_f=0, multicastdst_f=0, floodd_f=0;
unsigned char				loop_f=0, sleep_f=0, acceptfilters_f=0, accepted_f=0;
unsigned char				newdata_f=0;


/* Block Filters */
struct in6_addr 			blocksrc[MAX_BLOCK_SRC], blockdst[MAX_BLOCK_DST];
u_int8_t					blocksrclen[MAX_BLOCK_SRC], blockdstlen[MAX_BLOCK_DST];
struct ether_addr			blocklinksrc[MAX_BLOCK_LINK_SRC], blocklinkdst[MAX_BLOCK_LINK_DST];
unsigned int				nblocksrc=0, nblockdst=0;
unsigned int				nblocklinksrc=0, nblocklinkdst=0;

/* Accept Filters */
struct in6_addr				acceptsrc[MAX_ACCEPT_SRC], acceptdst[MAX_ACCEPT_DST];
u_int8_t					acceptsrclen[MAX_ACCEPT_SRC], acceptdstlen[MAX_ACCEPT_DST];
struct ether_addr			acceptlinksrc[MAX_ACCEPT_LINK_SRC], acceptlinkdst[MAX_ACCEPT_LINK_DST];
unsigned int				nacceptsrc=0, nacceptdst=0;
unsigned int				nacceptlinksrc=0, nacceptlinkdst=0;


int main(int argc, char **argv){
	extern char		*optarg;	
	extern int		optind;
	uid_t			ruid;
	gid_t			rgid;
	int				r, sel, fd;
	fd_set			sset, rset;
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
		{"curhop", required_argument, 0, 'c'},
		{"lifetime", required_argument, 0, 't'},
		{"reachable", required_argument, 0, 'r'},
		{"retrans", required_argument, 0, 'x'},
		{"managed", no_argument, 0, 'm'},	
		{"other", no_argument, 0, 'o'},
		{"home-agent", no_argument, 0, 'a'},
		{"nd-proxy", no_argument, 0, 'q'},
		{"preference", required_argument, 0, 'p'},
		{"src-link-opt", required_argument, 0, 'E'},
		{"add-slla-opt", no_argument, 0, 'e'},
		{"prefix-opt", required_argument, 0, 'P'},
		{"route-opt", required_argument, 0, 'R'},
		{"mtu-opt", required_argument, 0, 'M'},
		{"rdnss-opt", required_argument, 0, 'N'},
		{"link-src-address", required_argument, 0, 'S'},
		{"link-dst-address", required_argument, 0, 'D'},
		{"flood-prefixes", required_argument, 0, 'f'},
		{"flood-sources", required_argument, 0, 'F'},
		{"flood-routes", required_argument, 0, 'w'},
		{"flood-dns", required_argument, 0, 'W'},
		{"block-src-addr", required_argument, 0, 'j'},
		{"block-dst-addr", required_argument, 0, 'k'},
		{"block-link-src-addr", required_argument, 0, 'J'},
		{"block-link-dst-addr", required_argument, 0, 'K'},
		{"accept-src-addr", required_argument, 0, 'b'},
		{"accept-dst-addr", required_argument, 0, 'g'},
		{"accept-link-src-addr", required_argument, 0, 'B'},
		{"accept-link-dst-addr", required_argument, 0, 'G'},
		{"loop", no_argument, 0, 'l'},
		{"sleep", required_argument, 0, 'z'},
		{"listen", no_argument, 0, 'L'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'}
	};

	char shortopts[]= "i:s:d:A:u:U:H:y:c:t:r:x:moaqp:E:eP:R:M:N:S:D:f:F:w:W:lz:Lj:k:J:K:b:g:B:G:vh";
	char option;

	if(argc<=1){
		usage();
		exit(1);
	}

	hoplimit=255;
	curhop=255;
	prefbits= DEFAULT_ROUTER_PREFERENCE;
	preference= prefbits>>3;
	lifetime= DEFAULT_ROUTER_LIFETIME;
	reachable= DEFAULT_ROUTER_REACHABLE;
	retrans= DEFAULT_ROUTER_RETRANS;
	srandom(time(NULL));

	while((option=getopt_long(argc, argv, shortopts, longopts, NULL)) != -1) {
		switch(option) {

			case 'i':  /* Interface */
				strncpy(iface, optarg, IFACE_LENGTH-1);
				iface_f=1;
				break;

			case 's':	/* IPv6 Source Address */
				if((charptr = strtok_r(optarg, "/", &lasts)) == NULL){
					puts("inet_pton(): address not valid");
					exit(1);
				}

				if ( inet_pton(AF_INET6, charptr, &srcaddr) <= 0){
					puts("inet_pton(): address not valid");
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

			case 'y':	/* Fragment header */
				nfrags= atoi(optarg);
				if(nfrags < 8){
					puts("Error in Fragmentation option: Fragment Size must be at least 8 bytes");
					exit(1);
				}
		
				nfrags = (nfrags +7) & 0xfff8;
				fragh_f= 1;
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

			case 'S':	/* Source Ethernet address */
				hsrcaddr_f = 1;
		
				if(ether_pton(optarg, &hsrcaddr, sizeof(hsrcaddr)) == 0){
					puts("Error in Source link-layer address.");
					exit(1);
				}
				break;

			case 'D':	/* Destination Ethernet Address */
				hdstaddr_f = 1;
		
				if(ether_pton(optarg, &hdstaddr, sizeof(hdstaddr)) == 0){
					puts("Error in Source link-layer address.");
					exit(1);
				}
				break;

			case 'c':	/* CurHop value */
				curhop = abs(atoi(optarg));
				break;

			case 'm':	/* "Managed" bit */
				managed_f = ND_RA_FLAG_MANAGED;
				break;
	
			case 'o':	/* "Other" bit */
				other_f = ND_RA_FLAG_OTHER;
				break;

			case 'a':	/* "Home Agent" bit */
				home_f = ND_RA_FLAG_HOME_AGENT;
				break;
		
			case 'q':	/* ND Proxy bit */
				proxy_f= ND_RA_FLAG_ND_PROXY;
				break;

			case 'p':	/* "Preference" bits */
				preference= atoi(optarg);
				if(preference<-2 || preference >1){
					puts("Error in 'preference' paramater");
					exit(1);
				}
		
				prefbits = (preference << 3) & 0x18;
				break;	    	    

		    case 't':	/* Router Lifetime */
				if((ul_res = strtoul(optarg, &endptr, 0)) == ULONG_MAX){
					perror("Error in 'lifetime' parameter");
					exit(1);
				}

				if(endptr != optarg)
					lifetime = ul_res;

				break;
		
			case 'r':	/* Reachable Time */
				if((ul_res = strtoul(optarg, &endptr, 0)) == ULONG_MAX){
					perror("Error in 'reachable' parameter");
					exit(1);
				}
		
				if(endptr != optarg)
					reachable = ul_res;
		
				break;

			case 'x':	/* Retrans Time */
				if((ul_res = strtoul(optarg, &endptr, 0)) == ULONG_MAX){
					perror("Error in 'retransmit' parameter");
					exit(1);
				}

				if(endptr != optarg)
					retrans = ul_res;

				break;

			case 'E':	/* Source link-layer option */
				sllopt_f = 1;
		
				if(ether_pton(optarg, &linkaddr[nlinkaddr], sizeof(struct ether_addr)) == 0){
					puts("Error in Source link-layer address option.");
					exit(1);
				}
		
				sllopta_f=1;
				nlinkaddr++;
				break;

			case 'e':	/* Add Source link-layer option */
				sllopt_f = 1;
				break;

			case 'P':	/* Prefix Information option */
				if(nprefixes >= MAX_PREFIX_OPTION){
					puts("Too many Prefix Options");
					exit(1);
				}
	    
				if((pref = strtok_r(optarg, "/", &lasts)) == NULL){
					printf("Error in prefix option number %u. \n", nprefixes+1);
					exit(1);
				}

				if ( inet_pton(AF_INET6, pref, &prefix[nprefixes]) <= 0){
					printf("Error in prefix option number %u. ", nprefixes+1);
					perror("inet_pton():");
					exit(1);
				}
		
				if((preflen= strtok_r(NULL, "#", &lasts)) == NULL){
					printf("Length error in prefix option number %u.\n", nprefixes+1);
					exit(1);		    
				}

				prefixlen[nprefixes] = atoi(preflen);
		
				if(prefixlen[nprefixes]>128){
					printf("Length error in prefix option number %u.\n", nprefixes+1);
					exit(1);		    
				}
		
				prefixflags[nprefixes]=0;
				prefixpref[nprefixes] = DEFAULT_PREFIX_PREFERRED;
				prefixvalid[nprefixes] = DEFAULT_PREFIX_VALID;

				if((prefflags= strtok_r(NULL, "#", &lasts)) == NULL){
					nprefixes++;
					prefopt_f=1;
					break;
				}
		
						
				while(*prefflags){
					if(*prefflags == 'L')
						prefixflags[nprefixes] = prefixflags[nprefixes] | ND_OPT_PI_FLAG_ONLINK;
					else if(*prefflags == 'A')
						prefixflags[nprefixes] = prefixflags[nprefixes] | ND_OPT_PI_FLAG_AUTO;
					else if(*prefflags == 'R')
						prefixflags[nprefixes] = prefixflags[nprefixes] | ND_OPT_PI_FLAG_RADDR;
					else if(*prefflags == '-')
						break;
				    else{
						printf("Flags error in prefix option number %u\n", nprefixes+1);
						exit(1);
					}
		    
					prefflags++;
				}

				if((prefvalid= strtok_r(NULL, "#", &lasts)) == NULL){
					nprefixes++;
					prefopt_f=1;
					break;
				}
		
				if((ul_res = strtoul(prefvalid, &endptr, 0)) == ULONG_MAX){
					printf("Error in prefix option number %u. ", nprefixes+1);
					perror("strtoul()");
					exit(1);
				}
		
				if(endptr != optarg){
					prefixvalid[nprefixes] = ul_res;
				}
				else{
					nprefixes++;
					prefopt_f=1;
					break;
				}
	    
				if((prefpref= strtok_r(NULL, "#", &lasts)) == NULL){
					nprefixes++;
					prefopt_f=1;
					break;
				}
		
				if((ul_res = strtoul(prefpref, &endptr, 0)) == ULONG_MAX){
					printf("Error in prefix option number %u. ", nprefixes+1);
					perror("strtoul()");
					exit(1);
				}

				if(endptr != prefpref)
					prefixpref[nprefixes] = ul_res;

				nprefixes++;
				prefopt_f=1;	
				break;


			case 'R':	/* Route Information option */
				if(nroutes >= MAX_ROUTE_OPTION){
					puts("Too many Route Information Options");
					exit(1);
				}
	    
				if((pref = strtok_r(optarg, "/", &lasts)) == NULL){
					printf("Error in Route Information option number %u. \n", nroutes+1);
					exit(1);
				}

				if ( inet_pton(AF_INET6, pref, &route[nroutes]) <= 0){
					printf("Error in Route Information option number %u.\n", nroutes+1);
					perror("inet_pton():");
					exit(1);
				}
		
				if((preflen= strtok_r(NULL, "#", &lasts)) == NULL){
					printf("Length error in Route Information option number %u.\n", nroutes+1);
					exit(1);		    
				}

				routelen[nroutes] = atoi(preflen);
		
				if(routelen[nroutes]>128){
					printf("Length error in Route Information option number %u.\n", nroutes+1);
					exit(1);		    
				}

				routepref[nroutes] = DEFAULT_ROUTE_OPT_PREF;
				routelife[nroutes]= DEFAULT_ROUTE_OPT_LIFE;

				if((rpref = strtok_r(NULL, "#", &lasts)) == NULL){
					nroutes++;
					break;
				}
		
				routepref[nroutes]= atoi(rpref);
				routepref[nroutes] = (routepref[nroutes]<<3) & 0x18;

				if((ul_res = strtoul(lasts, &endptr, 0)) == ULONG_MAX){
					printf("Error in 'lifetime' parameter of Route Information option number %u\n", \
								nroutes+1);
					exit(1);
				}

				if(endptr != lasts)
					routelife[nroutes]= ul_res;

				nroutes++;
				break;

			case 'N':	/* Recursive DNS Server option */
				if(nrdnss >= MAX_RDNSS_OPTION){
					puts("Too many Recursive DNS Server");
					exit(1);
				}

				if((charptr = strtok_r(optarg, "#", &lasts)) == NULL){
					printf("Error in Recursive DNS Server option number %u. \n", nrdnss+1);
					exit(1);
				}

				if((ul_val = strtoul(charptr, &endptr, 0)) == ULONG_MAX){
					printf("Error in 'lifetime' parameter of Recursive DNS Server option number %u\n",\
					                                                                        nrdnss+1);
					exit(1);
				}

				if(endptr == charptr){
					printf("Error in Recursive DNS Server option number %u. \n", nrdnss+1);
					exit(1);
				}

				rdnsslife[nrdnss]= ul_val;
				nrdnssopt[nrdnss]= 0;

				while(nrdnssopt[nrdnss]< MAX_RDNSS_OPT_ADDRS && (charptr = strtok_r(NULL, "#", &lasts)) != NULL){
					if ( inet_pton(AF_INET6, charptr, &rdnss[nrdnss][nrdnssopt[nrdnss]]) <= 0){
						printf("Error in address #%u of Recursive DNS Server option number %u.\n", \
						                                              nrdnssopt[nrdnss]+1, nrdnss+1);
						perror("inet_pton():");
						exit(1);
					}
		    
					nrdnssopt[nrdnss]++;
				}

				nrdnss++;
				break;

			case 'M':	/* MTU option */
				mtu[nmtu]= atoi(optarg);
				nmtu++;
				break;

			case 'w':	/* Flood Routes */
				nfloodr= atoi(optarg);
				floodr_f= 1;
				break;

			case 'f':	/* Flood prefixes */
				nfloodp= atoi(optarg);
				floodp_f= 1;
				break;

			case 'F':	/* Flood sources */
				nsources= atoi(optarg);
				if(nsources == 0){
					puts("Invalid number of sources in option -F");
					exit(1);
				}

				floods_f= 1;
				break;

			case 'W':	/* Flood DNS */
				if((charptr = strtok_r(optarg, "#", &lasts)) == NULL){
					puts("Error in option '-k'");
					exit(1);
				}
		
				nfloodda = atoi(charptr);

				if((charptr = strtok_r(NULL, "#", &lasts)) == NULL){
					nflooddoa=127;
				}
				else{
					nflooddoa=atoi(charptr);
					if(nfloodda>MAX_RDNSS_OPT_ADDRS){
						puts("Error in '-k' option: Number of addresses per option exceeds 127");
						exit(1);
					}
				}

				floodd_f= 1;
				break;

			case 'L':	/* "Listen mode */
				listen_f = 1;
				break;

			case 'j':	/* IPv6 Source Address (block) filter */
				if(nblocksrc >= MAX_BLOCK_SRC){
					puts("Too many IPv6 Source Address (block) filters.");
					exit(1);
				}
	    
				if((pref = strtok_r(optarg, "/", &lasts)) == NULL){
					printf("Error in IPv6 Source Address (block) filter number %u.\n", nblocksrc+1);
					exit(1);
				}

				if ( inet_pton(AF_INET6, pref, &blocksrc[nblocksrc]) <= 0){
					printf("Error in IPv6 Source Address (block) filter number %u.", nblocksrc+1);
					exit(1);
				}

				if((charptr = strtok_r(NULL, " ", &lasts)) == NULL){
					blocksrclen[nblocksrc] = 128;
				}
				else{
					blocksrclen[nblocksrc] = atoi(charptr);
		
					if(blocksrclen[nblocksrc]>128){
						printf("Length error in IPv6 Source Address (block) filter number %u.\n", nblocksrc+1);
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
					printf("Error in IPv6 Destination Address (block) filter number %u.\n", nblockdst+1);
					exit(1);
				}

				if ( inet_pton(AF_INET6, pref, &blockdst[nblockdst]) <= 0){
					printf("Error in IPv6 Source Address (block) filter number %u.", nblockdst+1);
					exit(1);
				}

				if((charptr = strtok_r(NULL, " ", &lasts)) == NULL){
					blockdstlen[nblockdst] = 128;
				}
				else{
					blockdstlen[nblockdst] = atoi(charptr);
		
					if(blockdstlen[nblockdst]>128){
						printf("Length error in IPv6 Source Address (block) filter number %u.\n", nblockdst+1);
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
					printf("Error in link-layer Source Address (blick) filter number %u.\n", nblocklinksrc+1);
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
					printf("Error in link-layer Destination Address (blick) filter number %u.\n", nblocklinkdst+1);
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
					printf("Error in IPv6 Source Address (accept) filter number %u.\n", nacceptsrc+1);
				    exit(1);
				}

				if ( inet_pton(AF_INET6, pref, &acceptsrc[nacceptsrc]) <= 0){
					printf("Error in IPv6 Source Address (accept) filter number %u.\n", nacceptsrc+1);
					exit(1);
				}
		
				if((charptr = strtok_r(NULL, " ", &lasts)) == NULL){
					acceptsrclen[nacceptsrc] = 128;
				}
				else{
					acceptsrclen[nacceptsrc] = atoi(charptr);
		
					if(acceptsrclen[nacceptsrc]>128){
						printf("Length error in IPv6 Source Address (accept) filter number %u.\n", nacceptsrc+1);
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
					printf("Error in IPv6 Destination Address (accept) filter number %u.\n", nacceptdst+1);
					exit(1);
				}

				if ( inet_pton(AF_INET6, pref, &acceptdst[nacceptdst]) <= 0){
					printf("Error in IPv6 Source Address (accept) filter number %u.\n", nacceptdst+1);
					exit(1);
				}

				if((charptr = strtok_r(NULL, " ", &lasts)) == NULL){
					acceptdstlen[nacceptdst] = 128;
				}
				else{
					acceptdstlen[nacceptdst] = atoi(charptr);
		
					if(acceptdstlen[nacceptdst]>128){
						printf("Length error in IPv6 Source Address (accept) filter number %u.\n", nacceptdst+1);
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
					printf("Error in link-layer Source Address (accept) filter number %u.\n", nacceptlinksrc+1);
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
					printf("Error in link-layer Destination Address (accept) filter number %u.\n", nacceptlinkdst+1);
					exit(1);
				}
		
				nacceptlinkdst++;
				acceptfilters_f=1;
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
		puts("ra6 needs root privileges to run.");
		exit(1);
	}

	if(!iface_f){
		puts("Must specify the network interface with the -i option");
		exit(1);
	}

	if( (pfd= pcap_open_live(iface, PCAP_SNAP_LEN, PCAP_PROMISC, PCAP_TIMEOUT, errbuf)) == NULL){
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
    
	if( pcap_datalink(pfd) != DLT_EN10MB){
		printf("Error: Interface %s is not an Ethernet interface", iface);
		exit(1);
	}

	if(pcap_compile(pfd, &pcap_filter, PCAP_ICMPV6_RS_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
		printf("pcap_compile(): %s", pcap_geterr(pfd));
		exit(1);
	}
    
	if(pcap_setfilter(pfd, &pcap_filter) == -1){
		printf("pcap_setfilter(): %s", pcap_geterr(pfd));
		exit(1);
	}

	pcap_freecode(&pcap_filter);

    /* 
       If the IPv6 Source Address has not been specified, and the "-F" (flood) option has
       not been specified, select a random link-local unicast address.
     */
    if(!srcaddr_f && !floods_f){
		/* When randomizing a link-local IPv6 address, select addresses that belong to the
		   prefix fe80::/64 (that's what a link-local address looks-like in legitimate cases).
		   The KAME implementation discards addresses in which the second high-order 16 bits
		   (srcaddr.s6_addr16[1] in our case) are not zero.
		 */  
		srcaddr.s6_addr16[0]= htons(0xfe80); /* Link-local unicast prefix */
	
		for(i=1;i<4;i++)
			srcaddr.s6_addr16[i]=0x0000;	
	    
		for(i=4; i<8; i++)
			srcaddr.s6_addr16[i]=random();
	}

    /*
       If the flood option ("-F") has been specified, but no prefix has been specified,
       select the random Source Addresses from the link-local unicast prefix (fe80::/64).
     */
	if(floods_f && !srcprefix_f){
		srcaddr.s6_addr16[0]= htons(0xfe80); /* Link-local unicast prefix */

		for(i=1;i<8;i++)
			srcaddr.s6_addr16[i]=0x0000;
	
		srcpreflen=64;
    }

	if(!dstaddr_f)		/* Destination Address defaults to all-nodes (ff02::1) */
		if( inet_pton(AF_INET6, ALL_NODES_MULTICAST_ADDR, &dstaddr) <= 0){
		    puts("inet_pton(): address not valid");
		    exit(1);
		}

	if(!hsrcaddr_f)		/* Source link-layer address is randomized by default */
		for(i=0; i<6; i++)
	 		hsrcaddr.a[i]= random();

	if(!hdstaddr_f)		/* Destination link-layer address defaults to all-nodes */
		if(ether_pton(ETHER_ALLNODES_LINK_ADDR, &hdstaddr, sizeof(hdstaddr)) == 0){
			puts("ether_pton(): Error converting all-nodes multicast address");
			exit(1);
		}
    
	if(sllopt_f && !sllopta_f){	/* The value of the source link-layer address option  */
		linkaddr[0]= hsrcaddr;	/* defaults to the source Ethernet address            */
		nlinkaddr++;
    }

	if(floodp_f){
		if(nfloodp == 0){
			puts("Invalid number of prefix options in option -f");
			exit(1);
		}
	
		if(!nprefixes){
		    prefixlen[0] = 64;
		    prefixflags[0]= ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO;
		    prefixpref[0] = DEFAULT_PREFIX_PREFERRED;			
		    prefixvalid[0] = DEFAULT_PREFIX_VALID;
		}
	
		nprefixes=nfloodp;
    }

	if(floodr_f){
		if(nfloodr == 0){
			puts("Invalid number of route options in option -f");
			exit(1);
		}
	
		if(!nroutes){
			routelen[0] = 64; /* By default, flood with /64s */
			routepref[0]= DEFAULT_ROUTE_OPT_PREF;
			routelife[0] = DEFAULT_ROUTE_OPT_LIFE;			
		}
	
		nroutes=nfloodr;
   	 }

	if(!floods_f)
		nsources=1;

	if(floodd_f){
		if(!nrdnss)
			rdnsslife[0]= DEFAULT_RDNSS_LIFETIME;
	    
		nrdnss=nfloodda;
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

	if(verbose_f){
		print_attack_info();
    }

    /* Set initial contents of the attack packet */
    init_packet_data();
    
    /* Fire an unsolicited Router Advertisement if a target IPv6 address or a target Ethernet
     * address were specified
     */
	if(dstaddr_f || hdstaddr_f){
		send_packet(NULL);
		if(verbose_f)    
			puts("Initial attack packet(s) sent successfully.");

		if(loop_f){
			if(verbose_f)
				printf("Now sending Router Advertisements every %u second%s...\n", nsleep, ((nsleep>1)?"s":""));

			while(loop_f){
				sleep(nsleep);
				send_packet(NULL);
		    }
	
		    exit(0);
		}
    }

	if(listen_f){
		if(verbose_f)
			puts("Listening to incoming ICMPv6 Router Solicitation messages...");

		if( (fd= pcap_fileno(pfd)) == -1){
			puts("Error obtaining descriptor number for pcap_t");
			exit(1);
		}

		FD_ZERO(&sset);
		FD_SET(fd, &sset);

		while(listen_f){
			rset= sset;

			if((sel=select(fd+1, &rset, NULL, NULL, NULL)) == -1){
				if(errno == EINTR){
					continue;
				}
				else{
					puts("Error in select()");
					exit(1);
				}
			}

			/* Read a Router Solicitation message */
			if((r=pcap_next_ex(pfd, &pkthdr, &pktdata)) == -1){
				printf("pcap_next_ex(): %s", pcap_geterr(pfd));
				exit(1);
			}
			else if(r == 0){
				continue; /* Should never happen */
			}

			pkt_ether = (struct ether_header *) pktdata;
			pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + ETHER_HDR_LEN);
			pkt_rs = (struct nd_router_solicit *) ((char *) pkt_ipv6 + MIN_IPV6_HLEN);

			accepted_f=0;

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
	
			if(nacceptlinksrc){
				if(match_ether(acceptlinksrc, nacceptlinksrc, &(pkt_ether->src)))
					accepted_f=1;
			}

			if(nacceptlinkdst && !accepted_f){
				if(match_ether(acceptlinkdst, nacceptlinkdst, &(pkt_ether->dst)))
					accepted_f= 1;
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

			if(verbose_f)
				print_filter_result(pktdata, ACCEPTED);


			/* Send a Router Advertisement */
			send_packet(pktdata);
		}
	}

	if(!(dstaddr_f || hdstaddr_f) && !listen_f){
		puts("Error: Nothing to send!");
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
    v6buffer = buffer + sizeof(struct ether_header);
    ipv6 = (struct ip6_hdr *) v6buffer;

    ethernet->src = hsrcaddr;
    ethernet->dst = hdstaddr;
    ethernet->ether_type = htons(0x86dd);

    ipv6->ip6_flow=0;
    ipv6->ip6_vfc= 0x60;
    ipv6->ip6_hlim= hoplimit;
    ipv6->ip6_src= srcaddr;
    ipv6->ip6_dst= dstaddr;
    prev_nh = (char *) &(ipv6->ip6_nxt);

    ptr = (char *) v6buffer + MIN_IPV6_HLEN;
    
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
    	if( (fragpart+sizeof(fraghdr)+nfrags) > (v6buffer+ETH_DATA_LEN)){
    		puts("Unfragmentable part too large for current MTU (1500 bytes)");
    		exit(1);
    	}

    	/* We prepare a separete Fragment Header, but we do not include it in the packet to be sent.
    	   This Fragment Header will be used (an assembled with the rest of the packet by the 
    	   send_packet() function.
    	*/
    	bzero(&fraghdr, FRAG_HDR_SIZE);
    	*prev_nh = IPPROTO_FRAGMENT;
    	prev_nh = (char *) &fraghdr;
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

    if( (ptr+sizeof(struct nd_router_advert)) > (v6buffer+max_packet_size)){
    	puts("Packet too large while inserting Router Advertisement header (should be using Frag. option?)");
    	exit(1);
    }

    ra= (struct nd_router_advert *) (ptr);
    ra->nd_ra_type = ND_ROUTER_ADVERT;
    ra->nd_ra_code = 0;

    ra->nd_ra_curhoplimit = curhop;
    ra->nd_ra_flags_reserved = managed_f | other_f | home_f | proxy_f | prefbits;
    ra->nd_ra_router_lifetime = htons(lifetime);
    ra->nd_ra_reachable = htonl(reachable);
    ra->nd_ra_retransmit = htonl(retrans);
    
    ptr += sizeof(struct nd_router_advert);
    
    /* If a single source link-layer address is specified, it is included in all packets */
    if(sllopt_f && nlinkaddr==1){
        if( (ptr+sizeof(struct nd_opt_slla)) <= (v6buffer+max_packet_size)){
        	sllaopt = (struct nd_opt_slla *) ptr;
        	sllaopt->type= ND_OPT_SOURCE_LINKADDR;
        	sllaopt->length= SLLA_OPT_LEN;
        	bcopy(linkaddr[0].a, sllaopt->address, ETH_ALEN);
        	ptr += sizeof(struct nd_opt_slla);
        }
        else{
        	puts("Packet too large while processing source link-layer addresss opt. (should be using Frag. option?)");
        	exit(1);
        }
    }
    
    startofprefixes = ptr;    

}



/*
 * Function: send_packet()
 *
 * Initialize the remaining fields of the Router Advertisement Message, and
 * send the attack packet(s).
 */
void send_packet(const u_char *pktdata){
    if(pktdata==NULL){
	sources=0;	
    }
    else{     /* Sending a response to a Router Solicitation message */
	pkt_ether = (struct ether_header *) pktdata;
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + ETHER_HDR_LEN);
	pkt_ipv6addr = &(pkt_ipv6->ip6_src);

	/* If the IPv6 Source Address of the incoming Router Solicitation is the unspecified 
	   address (::), the Router Advertisement must be directed to the IPv6 all-nodes multicast
	   address (and the Ethernet Destination address should be 33:33:33:00:00:01). Otherwise,
	   the Router Advertisement is directed to the IPv6 Source Address (and Ethernet Source
	   Address) of the incoming Router Solicitation message
	 */
	if(IN6_IS_ADDR_UNSPECIFIED(pkt_ipv6addr)){
	    if ( inet_pton(AF_INET6, ALL_NODES_MULTICAST_ADDR, &(ipv6->ip6_dst)) <= 0){
		perror("inet_pton():");
		exit(1);
	    }

	    if(ether_pton(ETHER_ALLNODES_LINK_ADDR, &(ethernet->dst), ETHER_ADDR_LEN) == 0){
		puts("ether_pton(): Error converting all-nodes link-local address");
		exit(1);
	    }
	}
	else{
	    ipv6->ip6_dst = pkt_ipv6->ip6_src;
	    ethernet->dst = pkt_ether->src;
	}

	pkt_ipv6addr = &(pkt_ipv6->ip6_dst);

	/* If the Router Solicitation message was directed to a unicast address (unlikely), the
	   IPv6 Source Address and the Ethernet Source Address of the Router Advertisement are set
	   to the IPv6 Destination Address and the Ethernet Destination Address	of the incoming
	   Router Solicitation, respectively. Otherwise, the IPv6 Source Address and the Ethernet
	   Source Address are set as specified by the command-line (or randomized).
	 */
	if(IN6_IS_ADDR_MULTICAST(pkt_ipv6addr)){
	    ipv6->ip6_src = srcaddr;
	    ethernet->src = hsrcaddr;
	    sources=0;
	    multicastdst_f=1;
	}
	else{
	    ipv6->ip6_src = pkt_ipv6->ip6_dst;
	    ethernet->src = pkt_ether->dst;
	    sources=nsources;
	    multicastdst_f=0;
	}
    }


    do{
	if(floods_f && (pktdata==NULL || (pktdata != NULL && multicastdst_f))){
	    /* 
	        Randomize the IPv6 Source address based on the specified prefix and prefix length
	        (defaults to fe80::/64).
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

		ipv6->ip6_src.s6_addr16[startrand]= ipv6->ip6_src.s6_addr16[startrand] & htons(mask);
		    
	    }

	    for(i=0; i<=(srcpreflen/16); i++)
		ipv6->ip6_src.s6_addr16[i]= ipv6->ip6_src.s6_addr16[i] | srcaddr.s6_addr16[i];

	    if(!hsrcaddr_f){
		for(i=0; i<6; i++)
		    ethernet->src.a[i]= random();

		/*
		   If the source-link layer address must be included, but no value was 
		   specified we set it to the randomized Ethernet Source Address
		 */
		if(sllopt_f && !sllopta_f){
		    bcopy(ethernet->src.a, sllaopt->address, ETH_ALEN);
		}
	    }
	}

	prefixes= 0;
	routes= 0;
	dnsopts= 0;
	mtus=0;
	    
	if(nlinkaddr==1)
	    linkaddrs=1;
	else
	    linkaddrs=0;
	    	
	do{
	    /*
	       newdata_f handles the case where it is impossible for the packet to incorporate options,
	       and hence this would result in and endless loop
	     */
	    newdata_f=0;
	    ptr = startofprefixes;

	    while(linkaddrs<nlinkaddr && (ptr+sizeof(struct nd_opt_slla)-v6buffer)<=max_packet_size){
		sllaopt = (struct nd_opt_slla *) ptr;
		sllaopt->type= ND_OPT_SOURCE_LINKADDR;
		sllaopt->length= SLLA_OPT_LEN;
		bcopy(linkaddr[linkaddrs].a, sllaopt->address, ETH_ALEN);
		ptr += sizeof(struct nd_opt_slla);
		linkaddrs++;
	        newdata_f=1;
	    }

	    while(mtus<nmtu && (ptr+sizeof(struct nd_opt_mtu)-v6buffer)<=max_packet_size){
		mtuopt= (struct nd_opt_mtu *) ptr;
		mtuopt->nd_opt_mtu_type = ND_OPT_MTU;
		mtuopt->nd_opt_mtu_len = MTU_OPT_LEN;
		mtuopt->nd_opt_mtu_reserved = 0;
		mtuopt->nd_opt_mtu_mtu = htonl(mtu[mtus]);
		ptr += sizeof(struct nd_opt_mtu);
		mtus++;
	        newdata_f=1;
	    }

	    while(prefixes<nprefixes && (((ptr+ sizeof(struct nd_opt_prefix_info)) - v6buffer)\
									     <= max_packet_size)){
		prefixopt = (struct nd_opt_prefix_info *) ptr;
		prefixopt->nd_opt_pi_type= ND_OPT_PREFIX_INFORMATION;
		prefixopt->nd_opt_pi_len= PREFIX_OPT_LEN;
		    
		if(!floodp_f){
		    prefixopt->nd_opt_pi_flags_reserved= prefixflags[prefixes];
		    prefixopt->nd_opt_pi_prefix_len= prefixlen[prefixes];
		    prefixopt->nd_opt_pi_valid_time = htonl(prefixvalid[prefixes]);
		    prefixopt->nd_opt_pi_preferred_time = htonl(prefixpref[prefixes]);
		    prefixopt->nd_opt_pi_reserved2 = 0;
		    prefixopt->nd_opt_pi_prefix = prefix[prefixes];
		}
		else{
		    prefixopt->nd_opt_pi_flags_reserved= prefixflags[0];
		    prefixopt->nd_opt_pi_prefix_len= prefixlen[0];
		    prefixopt->nd_opt_pi_valid_time = htonl(prefixvalid[0]);
		    prefixopt->nd_opt_pi_preferred_time = htonl(prefixpref[0]);
		    prefixopt->nd_opt_pi_reserved2 = 0;

		    endrand= (prefixlen[0]+15)/16;

		    for(i=0; i<endrand; i++)
			prefixopt->nd_opt_pi_prefix.s6_addr16[i]=random();

		    if(prefixlen[0]%16){
			mask=0;
			for(i=0; i<(prefixlen[0]%16); i++)
			    mask= (mask>>1) | 0x8000;
		    
			prefixopt->nd_opt_pi_prefix.s6_addr16[endrand-1]= \
				prefixopt->nd_opt_pi_prefix.s6_addr16[endrand-1] & htons(mask);
		    }
			
		    for(i=endrand;i<8;i++)
			prefixopt->nd_opt_pi_prefix.s6_addr16[i]=0;
			    
		}
		
		ptr += sizeof(struct nd_opt_prefix_info);
		prefixes++;
	        newdata_f=1;
	    }


	    while(routes < nroutes && (((ptr+ sizeof(struct nd_opt_route_info_l)) - v6buffer) \
									    <= max_packet_size)){

		routeopt = (struct nd_opt_route_info_l *) ptr;
		routeopt->nd_opt_ri_type=ND_OPT_ROUTE_INFORMATION;
		routeopt->nd_opt_ri_len= MAX_ROUTE_OPT_LEN;
		    
		if(!floodr_f){
		    routeopt->nd_opt_ri_rsvd_pref_rsvd= routepref[routes];
		    routeopt->nd_opt_ri_prefix = route[routes];
		    routeopt->nd_opt_ri_prefix_len= routelen[routes];
		    routeopt->nd_opt_ri_lifetime = htonl(routelife[routes]);
		}
		else{
		    routeopt->nd_opt_ri_rsvd_pref_rsvd= routepref[0];
		    routeopt->nd_opt_ri_prefix_len= routelen[0];
		    routeopt->nd_opt_ri_lifetime = htonl(routelife[0]);

		    endrand= (routelen[0]+15)/16;

		    for(i=0; i<endrand; i++)
			routeopt->nd_opt_ri_prefix.s6_addr16[i]=random();

		    if(routelen[0]%16){
			mask=0;
			for(i=0; i<(routelen[0]%16); i++)
			    mask= (mask>>1) | 0x8000;
		    
			routeopt->nd_opt_ri_prefix.s6_addr16[endrand-1]= \
				routeopt->nd_opt_ri_prefix.s6_addr16[endrand-1] & htons(mask);
		    }
			
		    for(i=endrand;i<8;i++)
			routeopt->nd_opt_ri_prefix.s6_addr16[i]=0;	    
		}
		
		ptr += sizeof(struct nd_opt_route_info_l);
		routes++;
	        newdata_f=1;
	    }


	    if(!floodd_f){
		while(dnsopts < nrdnss && (((ptr+ sizeof(struct nd_opt_rdnss_l)\
		    + nrdnssopt[dnsopts] * sizeof(struct in6_addr) ) - v6buffer) <= max_packet_size)){

		    dnsopt = (struct nd_opt_rdnss_l *) ptr;
		    dnsopt->nd_opt_rdnss_type= ND_OPT_RDNSS;
		    dnsopt->nd_opt_rdnss_len= (sizeof(struct nd_opt_rdnss_l) + nrdnssopt[dnsopts] \
						* sizeof(struct in6_addr))/8;

		    dnsopt->nd_opt_rdnss_lifetime= htonl(rdnsslife[dnsopts]);
		    
		    for(i=0; i< nrdnssopt[dnsopts]; i++)
			dnsopt->nd_opt_rdnss_addr[i] = rdnss[dnsopts][i];

		    ptr+= sizeof(struct nd_opt_rdnss_l) + sizeof(struct in6_addr) * nrdnssopt[dnsopts];
		    dnsopts++;
	            newdata_f=1;
		}
	    }
	    else{
		while(dnsopts < nrdnss){
		    smaxaddrs = (max_packet_size - (ptr-v6buffer) - sizeof(struct nd_opt_rdnss_l))\
								    / sizeof(struct in6_addr);
		    if(smaxaddrs>0){
			dnsopt = (struct nd_opt_rdnss_l *) ptr;
			dnsopt->nd_opt_rdnss_type= ND_OPT_RDNSS;
			dnsopt->nd_opt_rdnss_lifetime= htonl(rdnsslife[0]);

			for(i=0; i<smaxaddrs && i<nflooddoa && dnsopts<nrdnss; i++, dnsopts++)
			    for(j=0; j<8; j++)
				dnsopt->nd_opt_rdnss_addr[i].s6_addr16[j]=random();
		
			dnsopt->nd_opt_rdnss_len= (sizeof(struct nd_opt_rdnss_l) + \
							i * sizeof(struct in6_addr))/8;
			
			ptr+= sizeof(struct nd_opt_rdnss_l) + sizeof(struct in6_addr) * i;
	                newdata_f=1;
		    }
		}
	    }

	    ra->nd_ra_cksum = 0;
	    ra->nd_ra_cksum = in_chksum(v6buffer, ra, ptr-((char *)ra));

	    if(!fragh_f){
		ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);

        	if((nw=pcap_inject(pfd, buffer, ptr - buffer)) == -1){
		    printf("pcap_inject(): %s\n", pcap_geterr(pfd));
		    exit(1);
		}
    
		if(nw != (ptr-buffer)){
		    printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, (LUI) (ptr-buffer));
		    exit(1);
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
		    exit(1);
		}
		
		memcpy(fptr, (char *) &fraghdr, FRAG_HDR_SIZE);
		fh= (struct ip6_frag *) fptr;
		fh->ip6f_ident=random();
		startoffragment = fptr + FRAG_HDR_SIZE;
		/*
		 * Check that the selected fragment size is not larger than the largest fragment size
		   that can be sent
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
			printf("pcap_inject(): %s\n", pcap_geterr(pfd));
			exit(1);
		    }
    
		    if(nw != (fptr- fragbuffer)){
			printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, (LUI) (ptr-buffer));
			exit(1);
		    }
		}
		    
	    }
	}while( (linkaddrs>nlinkaddr || mtus<nmtu || prefixes<nprefixes || routes<nroutes || \
									    dnsopts < nrdnss) && newdata_f);
	    
	sources++;
    }while(sources<nsources);
}



/*
 * Function: usage()
 *
 * Print the syntax of the ra6 tool
 */

void usage(void){
    puts("usage: ra6 -i INTERFACE [-s SRC_ADDR[/LEN]] [-d DST_ADDR] [-y FRAG_SIZE] "
	 "[-u DST_OPT_HDR_SIZE] [-U DST_OPT_U_HDR_SIZE] [-H HBH_OPT_HDR_SIZE] [-S LINK_SRC_ADDR] "
	 "[-D LINK_DST_ADDR] [-c CUR_HOP] [-t ROUTER_LIFETIME] [-r REACHABLE_TIME] "
	 "[-x RETRANS_TIMER] [-m] [-o] [-a] [-q] [-p PREFERENCE] [-E LINK_ADDR] [-e] "
	 "[-P PREFIX/LEN[#FLAGS[#VALID[#PREFERRED]]]] [-M MTU] [-N [LIFETIME[#DNS_ADDR]]] "
	 "[-R PREFIX/LEN[#PREF[#LIFETIME]]] [-f N_PREFIXES] [-F N_SOURCES] [-w N_ROUTES] "
	 "[-W N_ADDRS[#ADDRSPEROPT]] [-j PREFIX[/LEN]] [-k PREFIX[/LEN]] [-J LINK_ADDR] "
	 "[-K LINK_ADDR] [-b PREFIX[/LEN]] [-g PREFIX[/LEN]] [-B LINK_ADDR] [-G LINK_ADDR] "
	 " [-L] [-v] [-h]");

}



/*
 * Function: print_help()
 *
 * Print help information for the ra6 tool
 */

void print_help(void){
	puts(SI6_TOOLKIT);
	puts("ra6: Security assessment tool for attack vectors based on RA messages\n");
	usage();

	puts("\nOPTIONS:\n"
	     "  --interface, -i            Network interface\n"
	     "  --src-address, -s          IPv6 Source Address\n"
	     "  --dst-address, -d          IPv6 Destination Address (or IPv6 prefix when flooding)\n"
	     "  --frag-hdr. -y             Fragment Header\n"
	     "  --dst-opt-hdr, -u          Destination Options Header (Fragmentable Part)\n"
	     "  --dst-opt-u-hdr, -U        Destination Options Header (Unfragmentable Part)\n"
	     "  --hbh-opt-hdr, -H          Hop by Hop Options Header\n"
	     "  --managed, -m              Set de Managed bit\n"
	     "  --other, -o                Set the Other bit\n"
	     "  --home-agent, -a           Set the Home Agent bit\n"
	     "  --nd-proxy, -q             Set the ND Proxy bit\n"
	     "  --lifetime, -t             Router Lifetime\n"
	     "  --reachable, -r            Reachable time\n"
	     "  --preference, -p           Preference\n"
	     "  --retrans, -x              Retrans Timer\n"
	     "  --curhop, -c               CurHop (advised Hop Limit)\n"
	     "  --prefix-opt, -P           Prefix option (Prefix/Len#flags#valid#preferred)\n"
	     "  --mtu-opt, -M              MTU option\n"
	     "  --src-link-opt, -E         Source link-layer address option\n"
	     "  --add-slla-opt, -e         Add Source link-layer address option\n"
	     "  --link-src-address, -S     Link-layer Source Address\n"
	     "  --link-dst-address, -D     Link-layer Destination Address\n"
	     "  --route-opt, -R            Route Information option (Prefix/Len#pref#lifetime)\n"
	     "  --rdnss-opt, -N            Recursive DNS Server option (lifetime#IPv6addr)\n"
	     "  --flood-sources, -F        Number of Source Addresses to forge randomly\n"
	     "  --flood-prefixes, -f       Number of Prefix options to forge randomly\n"
	     "  --flood-routes, -w         Number of Route Info options to forge randomly\n"
	     "  --flood-dns, -W            Number of RDNSS options to forge randomly\n"
	     "  --loop, -l                 Send periodic Router Advertisements\n"
	     "  --sleep, -z                Pause between sending RA messages\n"
	     "  --listen, -L               Listen to Router Solicitation messagres\n"
	     "  --block-src, -j            Block IPv6 Source Address prefix\n"
	     "  --block-dst, -k            Block IPv6 Destination Address prefix\n"
	     "  --block-link-src, -J       Block Ethernet Source Address\n"
	     "  --block-link-dst, -K       Block Ethernet Destination Address\n"
	     "  --accept-src, -b           Accept IPv6 Source Addres prefix\n"
	     "  --accept-dst, -g           Accept IPv6 Destination Addres prefix\n"
	     "  --accept-link-src, -B      Accept Ethernet Source Address\n"
	     "  --accept-link-dst, -G      Accept Ethernet Destination Address\n"
	     "  --verbose, -v              Be verbose\n"
	     "  --help, -h                 Print help for the ra6 tool\n"
	     "\n"
	     "Programmed by Fernando Gont for SI6 Networks <http://www.si6networks.com>\n"
	     "Please send any bug reports to <fgont@si6networks.com>"
	);
}



/* 
 * Function: in_chksum()
 *
 * Calculate the 16-bit ICMPv6 checksum
 */

u_int16_t in_chksum(void *ptr_ipv6, void *ptr_icmpv6, size_t len){
	struct ipv6pseudohdr	pseudohdr;
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
 * Print attack details (when the verbose ("-v") option is specified).
 */

void print_attack_info(void){
    if(!floods_f){
	if(ether_ntop(&hsrcaddr, plinkaddr, sizeof(plinkaddr)) == 0){
	    puts("ether_ntop(): Error converting address");
	    exit(1);
	}

	printf("Ethernet Source Address: %s%s\n", plinkaddr, ((!hsrcaddr_f)?" (randomized)":""));
    }
    else{
	if(hsrcaddr_f){
	    if(ether_ntop(&hsrcaddr, plinkaddr, sizeof(plinkaddr)) == 0){
		puts("ether_ntop(): Error converting address");
		exit(1);
	    }

	    printf("Ethernet Source Address: %s\n", plinkaddr);
	}
	else
	    puts("Ethernet Source Address: randomized for each packet");
    }

    /* Ethernet Destination Address only used if a target IPv6 address or a target Ethernet
     * address were specified
     */
    if(dstaddr_f || hdstaddr_f){
	if(ether_ntop(&hdstaddr, phdstaddr, sizeof(phdstaddr)) == 0){
	    puts("ether_ntop(): Error converting address");
	    exit(1);
	}

	printf("Ethernet Destination Address: %s%s\n", phdstaddr, \
					((!hdstaddr_f)?" (all-nodes multicast)":""));
    }


    if(inet_ntop(AF_INET6, &srcaddr, psrcaddr, sizeof(psrcaddr))<=0){
	puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
	exit(1);
    }

    if(!floods_f){
	printf("IPv6 Source Address: %s%s\n", psrcaddr, ((!srcaddr_f)?" (randomized)":""));
    }
    else{
    	printf("IPv6 Source Address: randomized, from the %s/%u prefix%s\n", psrcaddr, srcpreflen, \
    									(!srcprefix_f)?" (default)":"");
    }


    /* IPv6 Destination Address is only used if a target IPv6 address or a target Ethernet
     * address were specified
     */
    if(dstaddr_f || hdstaddr_f){
	if(inet_ntop(AF_INET6, &dstaddr, pdstaddr, sizeof(pdstaddr))<=0){
	    perror("inet_ntop()");
	    exit(1);
	}

	printf("IPv6 Destination Address: %s%s\n", pdstaddr, \
				((!dstaddr_f)?" (all-nodes link-local multicast)":""));
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
		
    printf("Cur Hop Limit: %u   Preference: %d   Flags: %s%s%s%s%s   Router Lifetime: %u\n", \
	    curhop, preference, ((managed_f)?"M":""), ((other_f)?"O":""), ((home_f)?"H":""), \
	    ((proxy_f)?"P":""), ((!managed_f && !other_f && !home_f && !proxy_f)?"none":""), \
	    lifetime);
		
    printf("Reachable Time: %u   Retrans Timer: %u\n", reachable, retrans);

    for(i=0;i<nlinkaddr;i++){
	if(ether_ntop(&linkaddr[i], plinkaddr, sizeof(plinkaddr)) == 0){
	    puts("ether_ntop(): Error converting address");
	    exit(1);
	}

	printf("Source Link-layer Address option -> Address: %s\n", \
		    ((floods_f && !sllopta_f)?"(randomized for each packet)":plinkaddr));
    }

    for(i=0;i<nmtu;i++)
	printf("MTU option -> MTU: %u\n", mtu[i]);

    if(!floodp_f){
	for(i=0; i<nprefixes; i++){
	    puts("Prefix Information option ->");		

	    if(inet_ntop(AF_INET6, &prefix[i], pprefix, sizeof(pprefix))<=0){
		perror("inet_ntop()");
		exit(1);
	    }

	    printf("Prefix: %s/%u\tFlags: %s%s%s%s   ", pprefix, prefixlen[i], \
			    ((prefixflags[i] & ND_OPT_PI_FLAG_ONLINK)?"L":""),\
			    ((prefixflags[i] & ND_OPT_PI_FLAG_AUTO)?"A":""), \
			    ((prefixflags[i] & ND_OPT_PI_FLAG_RADDR)?"R":""), \
			    ((!prefixflags[i])?"none":""));
			    
	    printf("Valid Lifetime: %u   Preferred Lifetime: %u\n", prefixvalid[i], prefixpref[i]);
	}
    }
    else{
	printf("Flooding the target with %u prefixes\n", nprefixes);
	printf("Prefix: (randomized)/%u%s   Flags: %s%s%s%s   ", prefixlen[0], (prefopt_f?"":" (default)"),\
		    ((prefixflags[0] & ND_OPT_PI_FLAG_ONLINK)?"L":""),\
		    ((prefixflags[0] & ND_OPT_PI_FLAG_AUTO)?"A":""), \
		    ((prefixflags[0] & ND_OPT_PI_FLAG_RADDR)?"R":""), \
		    ((!prefixflags[0])?"none":""));
	printf("Valid Lifetime: %u   Preferred Lifetime: %u\n", prefixvalid[0], prefixpref[0]);
    }

    if(!floodr_f){
	for(i=0; i<nroutes; i++){
	    puts("Route Information option ->");		

	    if(inet_ntop(AF_INET6, &route[i], pprefix, sizeof(pprefix))<=0){
		perror("inet_ntop()");
		exit(1);
	    }

	    printf("Prefix: %s/%u   Preference: %u   Lifetime: %u\n", pprefix, routelen[i], \
		    (routepref[i]>>3), routelife[i]);
	}
    }

    else{
	printf("Flooding the target with %u Route Information options\n", nroutes);
	printf("Prefix: (randomized)/%u   Preference: %u   Lifetime: %u\n", routelen[0], \
		(routepref[0]>>3), routelife[i]);
    }

    if(!floodd_f){
	for(i=0;i<nrdnss;i++){
	    puts("Recursive DNS Server option ->");
	    printf("Lifetime: %u   Adresses: ", rdnsslife[i]);
	    for(j=0;j<nrdnssopt[i];j++){
		if(inet_ntop(AF_INET6, &rdnss[i][j], pprefix, sizeof(pprefix))<=0){
		    perror("inet_ntop()");
		    exit(1);
		}
		printf("%s   ", pprefix);
	    }
	    printf("%s", (nrdnssopt[i]?"\n":"(empty)\n"));	    
	}
    }
    else{
        printf("Flooding with %u Recursive DNS Addresses, with a maximum of %u addresses per option. "
	     "Lifetime: %u\n", nrdnss, nflooddoa, rdnsslife[0]);
    }

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
	if( sscanf(ascii,"%x:%x:%x:%x:%x:%x", &a[0], &a[1], &a[2], &a[3], \
		    &a[4], &a[5]) == 6){ 
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
 * Convert binary Ethernet Address into printable format (an ASCII string)
 */

int ether_ntop(const struct ether_addr *ether, char *ascii, size_t s){
    unsigned int r;

    if(s < ETHER_ADDR_PLEN)
	return 0;

    r=snprintf(ascii, s, "%02x:%02x:%02x:%02x:%02x:%02x", ether->a[0], ether->a[1], \
				ether->a[2], ether->a[3], ether->a[4], ether->a[5]);

    if(r != 17)
	return 0;

    return 1;
}


/*
 * Function: inset_pad_opt()
 *
 * Insert a padding option (Pad1 or PadN) into an IPv6 extension header
 */

int insert_pad_opt(char *ptrhdr, const char *ptrhdrend, unsigned int padn){
    char *ptr;

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


/*
 * Function: print_filter_result()
 *
 * Prints infromation about an incoming Neighbor Solicitation message and whether it
 * was blocked or accepted by a filter.
 */

void print_filter_result(const u_char *pkt_data, unsigned char fresult){
	struct ip6_hdr *pkt_ipv6;
	
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_data + ETHER_HDR_LEN);

	if(inet_ntop(AF_INET6, &(pkt_ipv6->ip6_src), psrcaddr, sizeof(psrcaddr))<=0){
	    puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
	    exit(1);
	}

	if(inet_ntop(AF_INET6, &(pkt_ipv6->ip6_dst), pdstaddr, sizeof(pdstaddr))<=0){
	    puts("inet_ntop(): Error converting IPv6 Destination Address to presentation format");
	    exit(1);
	}
	
	printf("Received Router Solicitation from %s to %s (%s)\n", psrcaddr, pdstaddr, \
					    ((fresult == ACCEPTED)?"accepted":"blocked") );

}


/*
 * Function match_ipv6()
 *
 * Finds if an IPv6 address matches a prefix in a list of prefixes.
 */

unsigned int match_ipv6(struct in6_addr *prefixlist, u_int8_t *prefixlen, unsigned int nprefix, 
								struct in6_addr *ipv6addr){

    unsigned int 	i, j;
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
	unsigned int skip, i;
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

