/*
 * scan6 v1.1: An IPv6 Host Scanning Tool
 *
 * Copyright (C) 2011-2012 United Kingdom's Centre for the Protection of 
 *                         National Infrastructure (UK CPNI)
 *
 * Programmed by Fernando Gont on behalf of CPNI (http://www.cpni.gov.uk)
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
 * Build with: gcc scan6.c -Wall -lpcap -o scan6
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
#include <sys/param.h>
#include <net/if.h>
#include <ifaddrs.h>
#ifdef __linux__
	#include <netpacket/packet.h>
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
	#include <net/if_dl.h>
#endif
#include "scan6.h"

/* Function prototypes */
int					init_iface_data(struct iface_data *);
int					insert_pad_opt(unsigned char *ptrhdr, const unsigned char *, unsigned int);
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
void				generate_slaac_address(struct in6_addr *, struct ether_addr *, struct in6_addr *);
void				sig_alarm(int);
int					is_eq_in6_addr(struct in6_addr *, struct in6_addr *);
int					ipv6_to_ether(pcap_t *, struct iface_data *, struct in6_addr *, struct ether_addr *);
struct in6_addr		solicited_node(const struct in6_addr *);
struct ether_addr	ether_multicast(const struct in6_addr *);
int					match_ipv6_to_prefixes(struct in6_addr *, struct in6_addr *, unsigned char *, unsigned int);
int 				find_ipv6_router_full(pcap_t *, struct iface_data *);
int 				validate_host_entries(pcap_t *, struct iface_data *, struct host_list *, struct host_list *);
int					create_candidate_globals(struct iface_data *, struct host_list *, struct host_list *, \
											struct host_list *);
void				free_host_entries(struct host_list *);
int					print_host_entries(struct host_list *, unsigned char);
int					print_unique_host_entries(struct host_list *, unsigned char);
int					host_scan_local(pcap_t *, struct iface_data *, struct in6_addr *, unsigned char, \
									struct host_entry *);
int					multi_scan_local(pcap_t *, struct iface_data *, struct in6_addr *, unsigned char, \
									const char *, struct host_list *);
int					find_local_globals(pcap_t *, struct iface_data *, unsigned char, const char *, struct host_list *);
int					probe_node_nd(const char *, struct ether_addr *, struct in6_addr *, struct in6_addr *,\
									struct ether_addr *);
int					is_ip6_in_list(struct in6_addr *, struct host_list *);
int					is_ip6_in_prefix_list(struct in6_addr *, struct prefix_list *);
int 				send_neighbor_advert(struct iface_data *, pcap_t *,  const u_char *);
int					process_icmp6_response(struct iface_data *, struct host_list *, unsigned char , \
											struct pcap_pkthdr *, const u_char *, unsigned char *);
int					valid_icmp6_response(struct iface_data *, unsigned char, struct pcap_pkthdr *,\
									const u_char *, unsigned char *);
int					get_if_ether_addr(const char *, struct ether_addr *);
int					get_if_addrs(struct iface_data *);
struct in6_addr		*src_addr_sel(struct iface_data *, struct in6_addr *);

/* Used for multiscan */
struct host_list	host_local, host_global, host_candidate;
struct host_entry	*host_locals[MAX_IPV6_ENTRIES], *host_globals[MAX_IPV6_ENTRIES];
struct host_entry	*host_candidates[MAX_IPV6_ENTRIES];

/* Used for router discovery */
struct iface_data	idata;
struct prefix_entry	*prefix_ols[MAX_PREFIXES_ONLINK], *prefix_acs[MAX_PREFIXES_AUTO];
struct prefix_entry	*prefix_local[MAX_LOCAL_ADDRESSES];

/* Variables used for learning the default router */
struct ether_addr	router_ether, rs_ether;
struct in6_addr		router_ipv6, rs_ipv6;

struct in6_addr		randprefix;
unsigned char		randpreflen;

/* Data structures for packets read from the wire */
pcap_t				*rfd, *sfd;
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
char 				iface[IFACE_LENGTH];
    
struct ip6_hdr		*ipv6;
struct icmp6_hdr	*icmp6;

struct ether_header	*ethernet;
struct ether_addr	hsrcaddr, hdstaddr;

struct in6_addr		srcaddr, dstaddr;

char				*lasts, *rpref;
char				*charptr;

size_t				nw;
unsigned long		ul_res, ul_val;
unsigned int		i, j, startrand;
unsigned int		skip;
unsigned char		srcpreflen;

u_int16_t			mask;
u_int8_t			hoplimit;

char 				plinkaddr[ETHER_ADDR_PLEN];
char 				psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN], pv6addr[INET6_ADDRSTRLEN];
unsigned char 		verbose_f=0, iface_f=0, acceptfilters_f=0;
unsigned char 		srcaddr_f=0, srcprefix_f=0, hsrcaddr_f=0, rand_src_f=0, rand_link_src_f=0;
unsigned char 		accepted_f=0;
unsigned char		print_f=0, print_local_f=0, print_global_f=0, probe_echo_f=0, probe_unrec_f=0, probe_f=0;
unsigned char		print_type=NOT_PRINT_ETHER_ADDR, scan_local_f=0, print_unique_f=0;

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
unsigned int		nfrags, fragsize, max_packet_size;
unsigned char		*prev_nh, *startoffragment;


/* IPv6 Address Resolution */
sigjmp_buf			env;
unsigned int		canjump;

int main(int argc, char **argv){
	extern char		*optarg;	
	extern int		optind;
	uid_t			ruid;
	gid_t			rgid;
	struct passwd	*pwdptr;

	static struct option longopts[] = {
		{"interface", required_argument, 0, 'i'},
		{"src-addr", required_argument, 0, 's'},
		{"dst-opt-hdr", required_argument, 0, 'u'},
		{"dst-opt-u-hdr", required_argument, 0, 'U'},
		{"hbh-opt-hdr", required_argument, 0, 'H'},
		{"frag-hdr", required_argument, 0, 'y'},
		{"link-src-addr", required_argument, 0, 'S'},
		{"local-scan", no_argument, 0, 'l'},
		{"probe-type", required_argument, 0, 'p'},
		{"print-type", required_argument, 0, 'P'},
		{"print-unique", no_argument, 0, 'q'},
		{"print-link-addr", no_argument, 0, 'e'},
		{"retrans", required_argument, 0, 'x'},
		{"timeout", required_argument, 0, 'o'},
		{"rand-src-addr", no_argument, 0, 'r'},
		{"rand-link-src-addr", no_argument, 0, 'R'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'}
	};

	char shortopts[]= "i:s:u:U:H:y:S:lp:P:qex:o:rRvh";

	char option;

	if(argc<=1){
		usage();
		exit(1);
	}

	srandom(time(NULL));
	hoplimit=64+random()%180;

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
				if(ether_pton(optarg, &idata.ether, sizeof(idata.ether)) == 0){
					puts("Error in Source link-layer address.");
					exit(1);
				}

				idata.ether_flag=1;
				hsrcaddr_f = 1;
				break;

			case 'p':	/* Probe type */
				if(strncmp(optarg, "echo", strlen("echo")) == 0){
					probe_echo_f=1;
					probe_f=1;
				}
				else if(strncmp(optarg, "unrec", strlen("unrec")) == 0){
					probe_unrec_f=1;
					probe_f=1;
				}
				else if(strncmp(optarg, "all", strlen("all")) == 0){
					probe_echo_f=1;
					probe_unrec_f=1;
					probe_f=1;
				}
				else{
					puts("Error in '-p' option: Unknown probe type");
					exit(1);
				}

				break;

			case 'P':	/* Print type */
				if(strncmp(optarg, "local", strlen("local")) == 0){
					print_local_f=1;
					print_f=1;
				}
				else if(strncmp(optarg, "global", strlen("global")) == 0){
					print_global_f=1;
					print_f=1;
				}
				else if(strncmp(optarg, "all", strlen("all")) == 0){
					print_local_f=1;
					print_global_f=1;
					print_f=1;
				}
				else{
					puts("Error in '-P' option: Unknown address type");
					exit(1);
				}

				break;

			case 'q':
				print_unique_f=1;
				break;

			case 'e':
				print_type= PRINT_ETHER_ADDR;
				break;

			case 'x':
				idata.local_retrans=atoi(optarg);
				break;

			case 'o':
				idata.local_timeout=atoi(optarg);
				break;

			case 'l':
				scan_local_f=1;
				break;

			case 'r':
				rand_src_f=1;
				break;

			case 'R':
				rand_link_src_f=1;
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
		puts("scan6 needs superuser privileges to run");
		exit(1);
	}

	if(!iface_f){
		puts("Must specify the network interface with the -i option");
		exit(1);
	}

	if( (rfd= pcap_open_live(idata.iface, PCAP_SNAP_LEN, PCAP_PROMISC, PCAP_TIMEOUT, errbuf)) == NULL){
		printf("pcap_open_live(): %s\n", errbuf);
		return(-1);
	}

	if( pcap_datalink(rfd) != DLT_EN10MB){
		printf("Error: Interface %s is not an Ethernet interface", iface);
		return(-1);
	}

	if( (sfd= pcap_open_live(idata.iface, PCAP_SNAP_LEN, PCAP_PROMISC, PCAP_TIMEOUT, errbuf)) == NULL){
		printf("pcap_open_live(): %s\n", errbuf);
		return(-1);
	}

	if( pcap_datalink(sfd) != DLT_EN10MB){
		printf("Error: Interface %s is not an Ethernet interface", iface);
		return(-1);
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
			if(pwdptr->pw_uid && (setgid(pwdptr->pw_gid) == -1)){
				puts("Error while releasing superuser privileges (changing to nobody's group)");
				exit(1);
			}

			if(pwdptr->pw_uid && (setuid(pwdptr->pw_uid) == -1)){
				puts("Error while releasing superuser privileges (changing to 'nobody')");
				exit(1);
			}
		}
	}	

	if(!print_f){
		print_local_f=1;
		print_global_f=1;
	}

	if(!probe_f){
		probe_unrec_f=1;
		probe_echo_f=1;
	}

	if(srcaddr_f && !srcprefix_f){
		if( (srcaddr.s6_addr16[0] & htons(0xffc0)) == htons(0xfe80)){
			idata.ip6_local=srcaddr;
			idata.ip6_local_flag=1;
		}
		else{
			if( (idata.ip6_global.prefix[idata.ip6_global.nprefix] = malloc(sizeof(struct prefix_entry))) \
													== NULL){
				if(verbose_f){
					puts("Not enough memory while saving global address");
				}
				exit(1);
			}

			(idata.ip6_global.prefix[idata.ip6_global.nprefix])->ip6=srcaddr;
			idata.ip6_global.nprefix++;
			idata.ip6_global_flag=1;
		}
	}

	get_if_addrs(&idata);

	if(!idata.ether_flag || rand_link_src_f){
		randomize_ether_addr(&idata.ether);
		idata.ether_flag=1;
	}

	if(!idata.ip6_local_flag || rand_src_f){
		if( inet_pton(AF_INET6, "fe80::", &randprefix) <= 0){
			if(verbose_f)
				puts("inet_pton(): Error while randomizing IPv6 Source Address");
			exit(1);
		}
		randpreflen=64;

		randomize_ipv6_addr(&idata.ip6_local, &randprefix, randpreflen);
	}

	idata.mtu= ETH_DATA_LEN;
	find_ipv6_router_full(rfd, &idata);

	if(!idata.ip6_global_flag || rand_src_f){
		if(idata.ip6_global_flag){
			for(i=0; i < idata.ip6_global.nprefix; i++)
				for(j=4; j<8; j++)
					idata.ip6_global.prefix[i]->ip6.s6_addr16[j]= random();
		}
		else{
			if( inet_pton(AF_INET6, "::", &randprefix) <= 0){
				if(verbose_f)
					puts("inet_pton(): Error while randomizing IPv6 Source Address");

				exit(1);
			}
			randpreflen=0;

			if( (idata.ip6_global.prefix[0] = malloc(sizeof(struct prefix_entry))) == NULL){
				if(verbose_f)
					puts("Not enough memory while storing local address");

				exit(1);
			}

			randomize_ipv6_addr( &(idata.ip6_global.prefix[0]->ip6), &randprefix, randpreflen);
			idata.ip6_global.nprefix++;
			idata.ip6_global_flag=1;
		}
	}

	if(scan_local_f){
		host_local.nhosts=0;
		host_local.maxhosts= MAX_IPV6_ENTRIES;
		host_local.host= host_locals;

		if(probe_echo_f){
			if(multi_scan_local(sfd, &idata, &(idata.ip6_local), PROBE_ICMP6_ECHO, ALL_NODES_MULTICAST_ADDR,\
						&host_local) == -1){
				if(verbose_f)
					puts("Error while learning link-local addresses with ICMPv6 Echo Requests");

				exit(1);
			}
		}


		if(probe_unrec_f){
			if(multi_scan_local(sfd, &idata, &(idata.ip6_local), PROBE_UNREC_OPT, ALL_NODES_MULTICAST_ADDR,\
						 &host_local) == -1){
				if(verbose_f)
					puts("Error while learning link-local addresses with Unrecognized options");

				exit(1);
			}
		}

		if(print_local_f){
			if(verbose_f)
				puts("Link-local addresses:");

			if(print_unique_f){
				if(print_unique_host_entries(&host_local, print_type) == -1){
					if(verbose_f)
						puts("Error while printing global addresses");

					exit(1);
				}
			}
			else{
				if(print_host_entries(&host_local, print_type) == -1){
					if(verbose_f)
						puts("Error while printing global addresses");

					exit(1);
				}
			}
		}

		if(print_global_f){
			host_global.nhosts=0;
			host_global.maxhosts= MAX_IPV6_ENTRIES;
			host_global.host= host_globals;

			if(probe_echo_f){
				if(find_local_globals(sfd, &idata, PROBE_ICMP6_ECHO, ALL_NODES_MULTICAST_ADDR,\
							&host_global) == -1){
					if(verbose_f)
						puts("Error while learning link-local addresses with ICMPv6 Echo Requests");

					exit(1);
				}
			}

			if(probe_unrec_f){
				if(find_local_globals(sfd, &idata, PROBE_UNREC_OPT, ALL_NODES_MULTICAST_ADDR,\
							 &host_global) == -1){
					if(verbose_f)
						puts("Error while learning link-local addresses with Unrecognized options");

					exit(1);
				}
			}

			host_candidate.nhosts=0;
			host_candidate.maxhosts= MAX_IPV6_ENTRIES;
			host_candidate.host= host_candidates;

			if(create_candidate_globals(&idata, &host_local, &host_global, &host_candidate) == -1){
				if(verbose_f)
					puts("Error while creating candidate global addresses");

				exit(1);
			}

			if(validate_host_entries(sfd, &idata, &host_candidate, &host_global) == -1){
				if(verbose_f)
					puts("Error while validating global entries");

				exit(1);
			}

			if(verbose_f)
				puts("\nGlobal addresses:");

			if(print_unique_f){
				if(print_unique_host_entries(&host_global, print_type) == -1){
					if(verbose_f)
						puts("Error while printing global addresses");

					exit(1);
				}
			}
			else{
				if(print_host_entries(&host_global, print_type) == -1){
					if(verbose_f)
						puts("Error while printing global addresses");

					exit(1);		
				}
			}
		}
	}
	else{
		if(verbose_f)
			puts("No scanning method selected ('-l' option missing?)");

		exit(1);
	}

	exit(0);
}


/*
 * Function: usage()
 *
 * Prints the syntax of the scan6 tool
 */
void usage(void){
	puts("usage: scan6 -i INTERFACE [-s SRC_ADDR[/LEN]] [-r] [-S LINK_SRC_ADDR | -R]\n"
	     "       [-p PROBE_TYPE] [-P ADDRESS_TYPE] [-e] [-x RETRANS] [-o TIMEOUT] [-l]\n"
	     "       [-v] [-h]");
}


/*
 * Function: print_help()
 *
 * Prints help information for the scan6 tool
 */
void print_help(void){
	puts( "scan6 version 1.1\nAn IPv6 host scanning tool\n");
	usage();
    
	puts("\nOPTIONS:\n"
	     "  --interface, -i           Network interface\n"
	     "  --src-address, -s         IPv6 Source Address\n"
	     "  --link-src-address, -S    Link-layer Destination Address\n"
	     "  --probe-type, -p          Probe type {echo, unrec, all} (default: 'all')\n"
	     "  --print-type, -P          Print address type {local, global, all} (default: 'all')\n"
	     "  --print-unique, -q        Print only one IPv6 addresses per Ethernet address\n"
	     "  --print-link-addr, -e     Print link-layer addresses\n"
	     "  --retrans, -x             Number of retransmissions of each probe (default: 0)\n"
	     "  --timeout, -o             Timeout in seconds (default: 1 second)\n"
	     "  --local-scan, -l          Scan the local subnet\n"
	     "  --rand-src-addr, -r       Randomize the IPv6 Source Address\n"
	     "  --rand-link-src-addr, -R  Randomize the Ethernet Source Address\n"
	     "  --help, -h                Print help for the scan6 tool\n"
	     "  --verbose, -v             Be verbose\n"
	     "\n"
	     " Programmed by Fernando Gont on behalf of CPNI (http://www.cpni.gov.uk)\n"
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
			if(in_chksum(pkt_ipv6, pkt_na, pkt_end-((unsigned char *)pkt_na)) != 0)
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
				printf("Error: Interface %s is not an Ethernet interface", iface);

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
			if(in_chksum(pkt_ipv6, pkt_ra, pkt_end- (unsigned char *)pkt_ra) != 0)
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

								if((!idata->ip6_global_flag || rand_src_f) && \
															idata->ip6_global.nprefix < idata->ip6_global.maxprefix){
								
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
 * Compares two IPv6 addresses. Returns 1 if they are equal.
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

	ipv6addr->s6_addr16[4]=  htons(((u_int16_t)(etheraddr->a[0] | 0x02) << 8) | etheraddr->a[1]);
	ipv6addr->s6_addr16[5]=  htons( ((u_int16_t)etheraddr->a[2] << 8) | 0xff);
	ipv6addr->s6_addr16[6]=  htons((u_int16_t) 0xfe00 | etheraddr->a[3]);
	ipv6addr->s6_addr16[7]=  htons(((u_int16_t)etheraddr->a[4] << 8) | etheraddr->a[5]);
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

int match_ipv6_to_prefixes(struct in6_addr *ipv6addr, struct in6_addr *prefixes, unsigned char *preflen, \
				unsigned int nprefixes){
	unsigned int	i, j, full16, rbits;
	u_int16_t	mask;

	for(i=0; i<nprefixes; i++){
		full16= preflen[i]/16;
		for(j=0; j<full16; j++){
			if(ipv6addr->s6_addr16[j] != prefixes[i].s6_addr16[j])
				break;
		}

		if(j == full16){
			if((rbits= preflen[i]%16) == 0)
				return 1;
			else{
				mask= 0xffff;
				mask= mask<<rbits;
				if(prefixes[i].s6_addr16[full16] == (ipv6addr->s6_addr16[full16] & htons(mask)))
					return 1;
			}
		}
	}

	return 0;
}



/*
 * Function: multi_scan_local()
 *
 * Obtains the Ethernet address corresponding to an IPv6 address (by means of Neighbor Discovery)
 */

int multi_scan_local(pcap_t *pfd, struct iface_data *idata, struct in6_addr *srcaddr, unsigned char type, const char *ptargetaddr, struct host_list *hlist){
	struct bpf_program			pcap_filter;
	struct pcap_pkthdr			*pkthdr;
	const u_char				*pktdata;
	struct ip6_hdr				*pkt_ipv6;
	struct icmp6_hdr			*pkt_icmp6;
	struct nd_neighbor_solicit	*pkt_ns;
	unsigned char				*pkt_end;
	unsigned char				*ptr;

	unsigned char				buffer[65556];
	unsigned int 				icmp6_max_packet_size;
	struct ether_header			*ether;
	unsigned char 				*v6buffer;
	struct ip6_hdr				*ipv6;
	volatile unsigned int		tries=0;
	struct in6_addr				targetaddr;
	struct sigaction			new_sig, old_sig;
	struct ip6_dest				*destopth;
	struct ip6_opt				*opt;
	u_int32_t					*uint32;
	unsigned char				error_f=0, closefd_f=0, llocalsrc_f=0;
	int 						result;

	icmp6_max_packet_size = idata->mtu;
	ether = (struct ether_header *) buffer;
	v6buffer = buffer + sizeof(struct ether_header);
	ipv6 = (struct ip6_hdr *) v6buffer;


	if ( inet_pton(AF_INET6, ptargetaddr, &targetaddr) <= 0){
		if(verbose_f>1)
			puts("inet_pton(): Source Address not valid");

		return(-1);
	}

	if(IN6_IS_ADDR_LINKLOCAL(srcaddr))
		llocalsrc_f=1;

	if(pfd == NULL){
		if( (pfd= pcap_open_live(idata->iface, PCAP_SNAP_LEN, PCAP_PROMISC, PCAP_TIMEOUT, errbuf)) == NULL){
			if(verbose_f>1)
				printf("pcap_open_live(): %s\n", errbuf);

			return(-1);
		}
	    
		if( pcap_datalink(pfd) != DLT_EN10MB){
			if(verbose_f>1)
				printf("Error: Interface %s is not an Ethernet interface", iface);

			pcap_close(pfd);
			return(-1);
		}

		closefd_f=1;
	}

	switch(type){
		case PROBE_ICMP6_ECHO:
			if(pcap_compile(pfd, &pcap_filter, PCAP_ICMPV6_ERNS_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
				if(verbose_f>1)
					printf("pcap_compile(): %s", pcap_geterr(pfd));

				if(closefd_f)
					pcap_close(pfd);
				return(-1);
			}
			break;

		case PROBE_UNREC_OPT:
			if(pcap_compile(pfd, &pcap_filter, PCAP_ICMPV6_ERRORNS_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
				if(verbose_f>1)
					printf("pcap_compile(): %s", pcap_geterr(pfd));

				if(closefd_f)
					pcap_close(pfd);
				return(-1);
			}
			break;

		default:
			if(closefd_f)
				pcap_close(pfd);
			return(-1);
			break;
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

	ipv6->ip6_src= *srcaddr;
	ipv6->ip6_dst= targetaddr;

	ether->src = idata->ether;
	ether->dst = ether_multicast(&(ipv6->ip6_dst));
	ether->ether_type = htons(0x86dd);

	prev_nh = (unsigned char *) &(ipv6->ip6_nxt);

	ptr = (unsigned char *) v6buffer + MIN_IPV6_HLEN;

	switch(type){
		case PROBE_ICMP6_ECHO:
			*prev_nh = IPPROTO_ICMPV6;

			if( (ptr+sizeof(struct icmp6_hdr)+ICMPV6_ECHO_PAYLOAD_SIZE) > (v6buffer+icmp6_max_packet_size)){
				if(verbose_f>1)
					puts("Packet too large while creating ICMPv6 Echo Request Probe packet");

				if(closefd_f)
					pcap_close(pfd);

				return(-1);
			}

			icmp6 = (struct icmp6_hdr *) ptr;
			icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
			icmp6->icmp6_code = 0;
			icmp6->icmp6_cksum = random();
			icmp6->icmp6_data16[0]= htons(getpid());	/* Identifier */
			icmp6->icmp6_data16[1]= htons(random());	/* Sequence Number */

			ptr = ptr+ sizeof(struct icmp6_hdr);

			for(i=0; i<(ICMPV6_ECHO_PAYLOAD_SIZE>>2); i++){
				*(u_int32_t *)ptr = random();
				ptr += sizeof(u_int32_t);
			}
			break;

		case PROBE_UNREC_OPT:
			*prev_nh = IPPROTO_DSTOPTS;

			if( (ptr+sizeof(struct icmp6_hdr) + 8 + ICMPV6_ECHO_PAYLOAD_SIZE) > (v6buffer+icmp6_max_packet_size)){
				if(verbose_f>1)
					puts("Packet too large while creating Unrec. Opt. Probe Packet");

				if(closefd_f)
					pcap_close(pfd);

				return(-1);
			}

			destopth = (struct ip6_dest *) ptr;
			destopth->ip6d_len= 0;
			destopth->ip6d_nxt= IPPROTO_ICMPV6;

			ptr= ptr + 2;
			opt= (struct ip6_opt *) ptr;
			opt->ip6o_type= 0x80;
			opt->ip6o_len= 4;

			ptr= ptr + 2;
			uint32 = (u_int32_t *) ptr;
			*uint32 = random();

			ptr= ptr +4;
			icmp6 = (struct icmp6_hdr *) ptr;
			icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
			icmp6->icmp6_code = 0;
			icmp6->icmp6_cksum = random();
			icmp6->icmp6_data16[0]= htons(getpid());	/* Identifier */
			icmp6->icmp6_data16[1]= htons(random());	/* Sequence Number */

			ptr = ptr+ sizeof(struct icmp6_hdr);

			for(i=0; i<(ICMPV6_ECHO_PAYLOAD_SIZE>>2); i++){
				*(u_int32_t *)ptr = random();
				ptr += sizeof(u_int32_t);
			}
			break;
	}

	ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = in_chksum(v6buffer, icmp6, ptr-((unsigned char *)icmp6));

	/* We set the signal handler, and the anchor for siglongjump() */
	canjump=0;
	bzero(&new_sig, sizeof(struct sigaction));
	sigemptyset(&new_sig.sa_mask);
	new_sig.sa_handler= &sig_alarm;

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

	while(tries <= idata->local_retrans && !error_f){
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
		
		while( (hlist->nhosts < hlist->maxhosts) && !error_f){

			do{
				if((result=pcap_next_ex(pfd, &pkthdr, &pktdata)) == -1){
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
			pkt_icmp6 = (struct icmp6_hdr *) ((char *) pkt_ipv6 + sizeof(struct ip6_hdr));
			pkt_ns= (struct nd_neighbor_solicit *) pkt_icmp6;
			pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

			if( (pkt_end -  pktdata) < (ETHER_HDR_LEN + MIN_IPV6_HLEN))
				continue;

			if(pkt_ipv6->ip6_nxt == IPPROTO_ICMPV6){
				if(pkt_icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT){
					if( (pkt_end - (unsigned char *) pkt_ns) < sizeof(struct nd_neighbor_solicit))
						continue;

					if(is_eq_in6_addr(&(pkt_ns->nd_ns_target), srcaddr) || \
						is_eq_in6_addr(&(pkt_ns->nd_ns_target), &(idata->ip6_local))){
							if(send_neighbor_advert(idata, pfd, pktdata) == -1){
								error_f=1;
								break;
							}
					}
				}
				else if( (pkt_icmp6->icmp6_type == ICMP6_ECHO_REPLY) || (pkt_icmp6->icmp6_type == ICMP6_PARAM_PROB)){
					if( (pkt_end - (unsigned char *) pkt_icmp6) < sizeof(struct icmp6_hdr))
						continue;

					/*
					   If the Source Address was a link-local address, we only want link-local addresses.
					   OTOH, if the Source Address was a global address, we only want global addresses.
					 */
					if(llocalsrc_f){
						if(!IN6_IS_ADDR_LINKLOCAL(&(pkt_ipv6->ip6_src)))
							continue;
					}
					else{
						if(IN6_IS_ADDR_LINKLOCAL(&(pkt_ipv6->ip6_src)))
							continue;
					}

					if(valid_icmp6_response(idata, type, pkthdr, pktdata, buffer)){
						if(is_ip6_in_list(&(pkt_ipv6->ip6_src), hlist))
							continue;

						if( (hlist->host[hlist->nhosts]= malloc(sizeof(struct host_entry))) == NULL){
							if(verbose_f>1)
								puts("Error when allocating memory for host data");

							error_f=1;
							break;
						}

						bzero(hlist->host[hlist->nhosts], sizeof(struct host_entry));

						(hlist->host[hlist->nhosts])->ip6= pkt_ipv6->ip6_src;
						(hlist->host[hlist->nhosts])->ether= pkt_ether->src;
						(hlist->host[hlist->nhosts])->flag = VALID_MAPPING;
						(hlist->nhosts)++;
					}
				}
			}

		} /* Processing packets */

	} /* Resending Neighbor Solicitations */

	if(closefd_f)
		pcap_close(pfd);

	if( sigaction(SIGALRM, &old_sig, NULL) == -1){
		if(verbose_f>1)
			puts("Error setting up 'Alarm' signal");

		error_f=1;
	}

	if(error_f)
		return(-1);
	else
		return 0;
}



/*
 * Function: find_local_globals()
 *
 * Finds Global Unicast Addresses present on the local link
 */

int find_local_globals(pcap_t *pfd, struct iface_data *idata, unsigned char type, const char *ptargetaddr, \
						struct host_list *hlist){
	unsigned int	i;
	for(i=0; i < idata->ip6_global.nprefix; i++){
		if(multi_scan_local(pfd, idata, &((idata->ip6_global.prefix[i])->ip6), type, ALL_NODES_MULTICAST_ADDR,\
					hlist) == -1){
			return(-1);
		}
	}

	return 0;
}


/*
 * Function: host_scan_local()
 *
 * Scans a single IPv6 address
 */

int host_scan_local(pcap_t *pfd, struct iface_data *idata, struct in6_addr *srcaddr, unsigned char type, struct host_entry *host){
	struct bpf_program		pcap_filter;
	struct pcap_pkthdr		*pkthdr;
	const u_char			*pktdata;
	struct ip6_hdr			*pkt_ipv6;
	struct icmp6_hdr		*pkt_icmp6;
	struct nd_neighbor_solicit	*pkt_ns;
	unsigned char			*pkt_end;
	volatile unsigned char	*ptr;

	unsigned char			buffer[65556];
	unsigned int 			icmp6_max_packet_size;
	struct ether_header		*ether;
	unsigned char 			*v6buffer;
	struct ip6_hdr			*ipv6;
	volatile unsigned int	tries=0;
	struct in6_addr			targetaddr;
	struct sigaction		new_sig, old_sig;
	struct ip6_dest			*destopth;
	struct ip6_opt			*opt;
	u_int32_t				*uint32;
	unsigned char			foundaddr_f=0, error_f=0, closefd_f=0;
	int				result;

	icmp6_max_packet_size = idata->mtu;
	ether = (struct ether_header *) buffer;
	v6buffer = buffer + sizeof(struct ether_header);
	ipv6 = (struct ip6_hdr *) v6buffer;

	targetaddr= host->ip6;

	if(pfd == NULL){
		if( (pfd= pcap_open_live(idata->iface, PCAP_SNAP_LEN, PCAP_PROMISC, PCAP_TIMEOUT, errbuf)) == NULL){
			if(verbose_f>1)
				printf("pcap_open_live(): %s\n", errbuf);

			return(-1);
		}

		closefd_f=1;
	}

	if( pcap_datalink(pfd) != DLT_EN10MB){
		if(verbose_f>1)
			printf("Error: Interface %s is not an Ethernet interface", iface);

		if(closefd_f)
			pcap_close(pfd);

		return(-1);
	}

	switch(type){
		case PROBE_ICMP6_ECHO:
			if(pcap_compile(pfd, &pcap_filter, PCAP_ICMPV6_ERNS_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
				if(verbose_f>1)
					printf("pcap_compile(): %s", pcap_geterr(pfd));

				if(closefd_f)
					pcap_close(pfd);

				return(-1);
			}

			break;

		case PROBE_UNREC_OPT:
			if(pcap_compile(pfd, &pcap_filter, PCAP_ICMPV6_ERRORNS_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
				if(verbose_f>1)
					printf("pcap_compile(): %s", pcap_geterr(pfd));

				if(closefd_f)
					pcap_close(pfd);

				return(-1);
			}

			break;

		default:
			if(closefd_f)
				pcap_close(pfd);

			return(-1);
			break;
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
	ipv6->ip6_dst= targetaddr;
	ipv6->ip6_src= *srcaddr;

	ether->src = idata->ether;
	ether->dst = host->ether;
	ether->ether_type = htons(0x86dd);

	prev_nh = (unsigned char *) &(ipv6->ip6_nxt);

	ptr = (unsigned char *) v6buffer + MIN_IPV6_HLEN;

	switch(type){
		case PROBE_ICMP6_ECHO:
			*prev_nh = IPPROTO_ICMPV6;

			if( (ptr+sizeof(struct icmp6_hdr)+ICMPV6_ECHO_PAYLOAD_SIZE) > (v6buffer+icmp6_max_packet_size)){
				if(verbose_f>1)
					puts("Packet too large while creating ICMPv6 Echo Request Probe packet");

				if(closefd_f)
					pcap_close(pfd);

				return(-1);
			}

			icmp6 = (struct icmp6_hdr *) ptr;
			icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
			icmp6->icmp6_code = 0;
			icmp6->icmp6_cksum = random();
			icmp6->icmp6_data16[0]= htons(getpid());	/* Identifier */
			icmp6->icmp6_data16[1]= htons(random());		/* Sequence Number */

			ptr = ptr+ sizeof(struct icmp6_hdr);

			for(i=0; i<(ICMPV6_ECHO_PAYLOAD_SIZE>>2); i++){
				*(u_int32_t *)ptr = random();
				ptr += sizeof(u_int32_t);
			}
			break;

		case PROBE_UNREC_OPT:
			*prev_nh = IPPROTO_DSTOPTS;


			if( (ptr+sizeof(struct icmp6_hdr) + 8 + ICMPV6_ECHO_PAYLOAD_SIZE) > (v6buffer+icmp6_max_packet_size)){
				if(verbose_f>1)
					puts("Packet too large while creating Unrec. Opt. Probe Packet");

				if(closefd_f)
					pcap_close(pfd);

				return(-1);
			}

			destopth = (struct ip6_dest *) ptr;
			destopth->ip6d_len= 0;
			destopth->ip6d_nxt= IPPROTO_ICMPV6;

			ptr= ptr + 2;
			opt= (struct ip6_opt *) ptr;
			opt->ip6o_type= 0x80;
			opt->ip6o_len= 4;

			ptr= ptr + 2;
			uint32 = (u_int32_t *) ptr;
			*uint32 = random();

			ptr= ptr +4;
			icmp6 = (struct icmp6_hdr *) ptr;
			icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
			icmp6->icmp6_code = 0;
			icmp6->icmp6_cksum = random();
			icmp6->icmp6_data16[0]= htons(getpid());	/* Identifier */
			icmp6->icmp6_data16[1]= htons(random());	/* Sequence Number */

			ptr = ptr+ sizeof(struct icmp6_hdr);

			for(i=0; i<(ICMPV6_ECHO_PAYLOAD_SIZE>>2); i++){
				*(u_int32_t *)ptr = random();
				ptr += sizeof(u_int32_t);
			}
			break;
	}

	ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = in_chksum(v6buffer, icmp6, ptr-((unsigned char *)icmp6));

	/* We set the signal handler, and the anchor for siglongjump() */
	canjump=0;
	bzero(&new_sig, sizeof(struct sigaction));
	sigemptyset(&new_sig.sa_mask);
	new_sig.sa_handler= &sig_alarm;

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

	while(tries<= idata->local_retrans && !foundaddr_f && !error_f){
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
		
		foundaddr_f=0;

		while(!foundaddr_f && !error_f){

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
			pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

			if( (pkt_end -  pktdata) < (ETHER_HDR_LEN + MIN_IPV6_HLEN))
				continue;

			if(pkt_ipv6->ip6_nxt == IPPROTO_ICMPV6){
				pkt_icmp6 = (struct icmp6_hdr *) ((char *) pkt_ipv6 + sizeof(struct ip6_hdr));

				if(pkt_icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT){
					pkt_ns= (struct nd_neighbor_solicit *) pkt_icmp6;

					if( (pkt_end - (unsigned char *) pkt_ns) < sizeof(struct nd_neighbor_solicit))
						continue;

					if(is_eq_in6_addr(&(pkt_ns->nd_ns_target), &(idata->ip6_local)) || \
						is_eq_in6_addr(&(pkt_ns->nd_ns_target), srcaddr)){
							if(send_neighbor_advert(idata, pfd, pktdata) == -1){
								error_f=1;
								break;
							}
					}
				}
				else if( (pkt_icmp6->icmp6_type == ICMP6_ECHO_REPLY) || (pkt_icmp6->icmp6_type == ICMP6_PARAM_PROB)){

					if( (pkt_end - (unsigned char *) pkt_icmp6) < sizeof(struct icmp6_hdr))
						continue;

					if(valid_icmp6_response(idata, type, pkthdr, pktdata, buffer)){
						host->ether= pkt_ether->src;
						host->flag = VALID_MAPPING;
						foundaddr_f= 1;
						break;
					}
				}
			}

		} /* Processing packets */

	} /* Resending Probe packet */

	if(closefd_f)
		pcap_close(pfd);

	if( sigaction(SIGALRM, &old_sig, NULL) == -1){
		if(verbose_f>1)
			puts("Error setting up 'Alarm' signal");

		error_f=1;
	}

	if(error_f)
		return(-1);
	else
		return 0;

}



/*
 * Function: print_host_entries()
 *
 * Prints the IPv6 addresses (and optionally the Ethernet addresses) in a list
 */

int print_host_entries(struct host_list *hlist, unsigned char flag){
	unsigned int i;

	for(i=0; i < (hlist->nhosts); i++){
		if(inet_ntop(AF_INET6, &((hlist->host[i])->ip6), pv6addr, sizeof(pv6addr))<=0){
			if(verbose_f>1)
				puts("inet_ntop(): Error converting IPv6 address to presentation format");

			return(-1);
		}

		if(flag == PRINT_ETHER_ADDR){
			if(ether_ntop( &((hlist->host[i])->ether), plinkaddr, sizeof(plinkaddr)) == 0){
				if(verbose_f>1)
					puts("ether_ntop(): Error converting address");

				return(-1);
			}

			printf("%s @ %s\n", pv6addr, plinkaddr);
		}
		else
			printf("%s\n", pv6addr);
	}

	return 0;
}


/*
 * Function: print_unique_host_entries()
 *
 * Prints only one IPv6 address (and optionally the Ethernet addresses) per Ethernet 
 * address in a list.
 */

int print_unique_host_entries(struct host_list *hlist, unsigned char flag){
	unsigned int i, j, k;

	for(i=0; i < (hlist->nhosts); i++){

		if(i){
			for(j=0; j < i; j++){
				for(k=0; k < ETH_ALEN; k++){
					if((hlist->host[i])->ether.a[k] != (hlist->host[j])->ether.a[k])
						break;
				}

				if(k == ETH_ALEN)
					break;
			}			

			if(j < i)
				continue;
		}
			
		if(inet_ntop(AF_INET6, &((hlist->host[i])->ip6), pv6addr, sizeof(pv6addr))<=0){
			if(verbose_f>1)
				puts("inet_ntop(): Error converting IPv6 address to presentation format");

			return(-1);
		}

		if(flag == PRINT_ETHER_ADDR){
			if(ether_ntop( &((hlist->host[i])->ether), plinkaddr, sizeof(plinkaddr)) == 0){
				if(verbose_f>1)
					puts("ether_ntop(): Error converting address");

				return(-1);
			}

			printf("%s @ %s\n", pv6addr, plinkaddr);
		}
		else
			printf("%s\n", pv6addr);
	}

	return 0;
}



/*
 * Function: free_host_entries()
 *
 * Releases memory allocated for holding IPv6 addresses and Ethernet addresses
 */

void free_host_entries(struct host_list *hlist){
	unsigned int i;

	for(i=0; i< hlist->nhosts; i++)
		free(hlist->host[i]);

	hlist->nhosts=0;	/* Set the number of entries to 0, to reflect the released memory */
	return;
}


/*
 * Function: create_candidate_globals()
 *
 * Generates list of cadidate global addresses based on the local Global prefixes and Interface IDs
 */

int create_candidate_globals(struct iface_data *idata, struct host_list *local, struct host_list *global, \
				struct host_list *candidate){
	unsigned int	i, j, k;
	struct in6_addr	caddr;

	for(i=0; (i < local->nhosts) && (candidate->nhosts < candidate->maxhosts); i++){

		/* Global Address present in "local" list -- shouldn't happen, though */
		if((local->host[i])->ip6.s6_addr16[0] == htons(0xfe80)){
			/* We create one candidate address with the Interface-ID of the link-local address,
			   for each of the autoconf prefixes
			 */
			for(j=0; (j < idata->prefix_ac.nprefix) && (candidate->nhosts < candidate->maxhosts); j++){
				for(k=0; k<4; k++)
					caddr.s6_addr16[k] = (idata->prefix_ac.prefix[j])->ip6.s6_addr16[k];

				for(k=4; k<8; k++)
					caddr.s6_addr16[k] = local->host[i]->ip6.s6_addr16[k];

				/* We discard the candidate address if it is already present in the "global" list */
				if(is_ip6_in_list(&caddr, global))
					continue;

				if( (candidate->host[candidate->nhosts]=malloc(sizeof(struct host_entry))) == NULL){
					if(verbose_f>1)
						puts("Error allocating memory while creating local -> global list");

					return(-1);
				}

				bzero(candidate->host[candidate->nhosts], sizeof(struct host_entry));

				(candidate->host[candidate->nhosts])->ip6 = caddr;
				(candidate->host[candidate->nhosts])->ether = (local->host[i])->ether;
				(candidate->nhosts)++;
			}

		}
	}

	return 0;
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


/*
 * Function: validate_host_entries()
 *
 * Tests entries in a list, updates entries with invalid mappings, and removes non-existent addresses
 */

int validate_host_entries(pcap_t *pfd, struct iface_data *idata, struct host_list *candidate, struct host_list *global){
	unsigned int i;
	struct in6_addr	*srcaddrptr;

	for(i=0; i< candidate->nhosts; i++){
		if((candidate->host[i])->flag == INVALID_MAPPING){
			srcaddrptr = src_addr_sel(idata, &((candidate->host[i])->ip6));

			if(probe_unrec_f){
				if(host_scan_local(pfd, idata, srcaddrptr, PROBE_UNREC_OPT, candidate->host[i]) == -1)
					return(-1);
			}

			if( ((candidate->host[i])->flag == INVALID_MAPPING) && probe_echo_f){
				if(host_scan_local(pfd, idata, srcaddrptr, PROBE_ICMP6_ECHO, candidate->host[i]) == -1)
					return(-1);
			}
		}

		if((candidate->host[i])->flag == VALID_MAPPING){
			global->host[global->nhosts] = candidate->host[i];
			(global->nhosts)++;
		}
		else{
			free(candidate->host[i]);
		} 	
	}

	return 0;
}



/*
 * Function: is_ip6_in_list()
 *
 * Checks whether an IPv6 address is present in an address list.
 */

int is_ip6_in_list(struct in6_addr *target, struct host_list *hlist){
	unsigned int i;

	for(i=0; i < hlist->nhosts; i++)
		if(is_eq_in6_addr(target, &((hlist->host[i])->ip6)))
			return 1;

	return 0; 
}


/*
 * Function: is_ip6_in_prefix()
 *
 * Checks whether an IPv6 address is present in a prefix list.
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
	   If the Neighbor Solicitation message was directed to one of our unicast addresses, the IPv6 Source
	   Address is set to that address. Otherwise, we set the IPv6 Source Address to our link-local address.
	 */

	pkt_ipv6addr = &(pkt_ipv6->ip6_dst);

	if(IN6_IS_ADDR_MULTICAST(pkt_ipv6addr)){
		ipv6->ip6_src = idata->ip6_local;
	}
	else{
		if(is_eq_in6_addr(pkt_ipv6addr, &(idata->ip6_local))){
			ipv6->ip6_src = idata->ip6_local;	
		}
		else if(idata->ip6_global_flag){
			for(i=0; i < idata->ip6_global.nprefix; i++){
				if(is_eq_in6_addr(pkt_ipv6addr, &((idata->ip6_global.prefix[i])->ip6))){
					ipv6->ip6_src = (idata->ip6_global.prefix[i])->ip6;	
					break;
				}
			}

			if(i == idata->ip6_global.nprefix)
				return 0;
		}
		else{
			return 0;
 		}
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
				printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, \
																				(LUI) (ptr-buffer));

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
 * Function: valid_icmp6_response()
 *
 * Checks whether the response to an ICMPv6 probe is valid
 */

int valid_icmp6_response(struct iface_data *idata, unsigned char type, struct pcap_pkthdr *pkthdr,\
			const u_char *pktdata, unsigned char *pktsent){

	struct ether_header	*pkt_ether;
	struct ip6_hdr		*pkt_ipv6, *ipv6;
	struct icmp6_hdr	*pkt_icmp6, *pkt_icmp6_icmp6, *icmp6;
	unsigned char		*pkt_end;

	ipv6 = (struct ip6_hdr *) (pktsent + sizeof(struct ether_header));
	icmp6 = (struct icmp6_hdr *) ( (char *) ipv6 + sizeof(struct ip6_hdr));

	pkt_ether = (struct ether_header *) pktdata;
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + ETHER_HDR_LEN);
	pkt_icmp6 = (struct icmp6_hdr *) ((char *) pkt_ipv6 + MIN_IPV6_HLEN);
	pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

	switch(type){
		case PROBE_ICMP6_ECHO:
			pkt_icmp6 = (struct icmp6_hdr *) ((char *) pkt_ipv6 + MIN_IPV6_HLEN);

			/* The packet length is the minimum of what we capured, and what is specified in the
			   IPv6 Total Lenght field
			 */
			if( pkt_end > ((unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen) )
				pkt_end = (unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen;

			/*
			   Discard the packet if it is not of the minimum size to contain an ICMPv6 
			   header and the payload we included in the ICMPv6 Echo Request
			 */
			if( (pkt_end - (unsigned char *) pkt_icmp6) < (sizeof(struct icmp6_hdr) + \
									ICMPV6_ECHO_PAYLOAD_SIZE) )
				return 0;

			break;

		case PROBE_UNREC_OPT:
			pkt_icmp6 = (struct icmp6_hdr *) ((char *) pkt_ipv6 + MIN_IPV6_HLEN);

			/* The packet length is the minimum of what we capured, and what is specified in the
			   IPv6 Total Lenght field
			 */
			if( pkt_end > ((unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen) )
				pkt_end = (unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen;

			/*
			   Discard the packet if it is not of the minimum size to contain an ICMPv6 
			   header and the payload we included in the ICMPv6 Echo Request
			 */
			if( (pkt_end - (unsigned char *) pkt_icmp6) < (sizeof(struct icmp6_hdr) + \
						+ sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + \
						  ICMPV6_ECHO_PAYLOAD_SIZE) )
				return 0;

			break;			

	}

	/* 
	   Check that that the Destination Address of the incoming packet is the same as the one
	   we used for the Source Address of the Probe packet.
	 */
	if(!is_eq_in6_addr(&(pkt_ipv6->ip6_dst), &(ipv6->ip6_src)))
		return 0;

	/* Check that the ICMPv6 checksum is correct */
	if(in_chksum(pkt_ipv6, pkt_icmp6, pkt_end-((unsigned char *)pkt_icmp6)) != 0)
		return 0;

	switch(type){
		case PROBE_ICMP6_ECHO:
			if(pkt_icmp6->icmp6_data16[0] != icmp6->icmp6_data16[0]){
				return 0;
			}
			else if(pkt_icmp6->icmp6_data16[1] != icmp6->icmp6_data16[1]){
				return 0;
			}

			break;

		case PROBE_UNREC_OPT:
			pkt_icmp6_icmp6= (struct icmp6_hdr *) ((unsigned char *) pkt_icmp6 + \
						sizeof(struct ip6_hdr) + 8);

			if(pkt_icmp6_icmp6->icmp6_data16[0] != icmp6->icmp6_data16[0]){
				return 0;
			}
			else if(pkt_icmp6_icmp6->icmp6_data16[1] != icmp6->icmp6_data16[1]){
				return 0;
			}

			break;
	}

	return 1;
}


/*
 * Function: get_if_ether_addr()
 *
 * Gets the link-layer address of a network interface card
 */

int get_if_ether_addr(const char *iface, struct ether_addr *ether){
	struct ifaddrs	*ifptr, *ptr;
#ifdef __linux__
	struct sockaddr_ll	*sockpptr;
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
	struct sockaddr_dl	*sockpptr;
#endif

	if(getifaddrs(&ifptr) != 0){
		if(verbose_f > 1){
			printf("Error obtaining link-layer address of interface %s\n", iface);
		}
		return(-1);
	}

	for(ptr=ifptr; ptr != NULL; ptr= ptr->ifa_next){

		if(ptr->ifa_data != NULL){
#ifdef __linux__
			if((ptr->ifa_addr)->sa_family == AF_PACKET){
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
			if((ptr->ifa_addr)->sa_family == AF_LINK){
#endif
				if(strncmp(iface, ptr->ifa_name, IFACE_LENGTH-1) == 0){
#ifdef __linux__
					sockpptr = (struct sockaddr_ll *) (ptr->ifa_addr);
					if(sockpptr->sll_halen == ETHER_ADDR_LEN){
						*ether= *((struct ether_addr *)sockpptr->sll_addr);
						return 1;
					}
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
					sockpptr = (struct sockaddr_dl *) (ptr->ifa_addr);
					if(sockpptr->sdl_alen == ETHER_ADDR_LEN){
						*ether= *((struct ether_addr *)(sockpptr->sdl_data + sockpptr->sdl_nlen));
						return 1;
					}
#endif

				}
			}
		}
	}

	freeifaddrs(ifptr);
	return(0);
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
#ifdef __linux__
		if( !(idata->ether_flag) && ((ptr->ifa_addr)->sa_family == AF_PACKET) && (ptr->ifa_data != NULL)){
			if(strncmp(idata->iface, ptr->ifa_name, IFACE_LENGTH-1) == 0){
				sockpptr = (struct sockaddr_ll *) (ptr->ifa_addr);
				if(sockpptr->sll_halen == 6){
					idata->ether = *((struct ether_addr *)sockpptr->sll_addr);
					idata->ether_flag=1;
				}
			}
		}
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
		if( !(idata->ether_flag) && ((ptr->ifa_addr)->sa_family == AF_LINK) && (ptr->ifa_data != NULL)){
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

