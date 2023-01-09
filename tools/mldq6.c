/*
 * mldq6: A security assessment tool for attack vectors based on
 *       ICMPv6 Multicast Listener Discovery Query messages
 *
 * Copyright (C) 2009-2019 Fernando Gont
 * Copyright (C) 2020 Linus Lüssing
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
 * Build with: make mldq6
 *
 * The libpcap library must be previously installed on your system.
 *
 * Please send any bug reports to Fernando Gont <fgont@si6networks.com>
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include "mldq6.h"
#include "libipv6.h"
#include "ipv6toolkit.h"

void					init_packet_data(struct iface_data *);
void					send_packet(struct iface_data *);
void					print_attack_info(struct iface_data *);
void					usage(void);
void					print_help(void);


struct pcap_pkthdr		*pkthdr;
const u_char			*pktdata;
struct in6_addr			*pkt_ipv6addr;    
bpf_u_int32				my_netmask;
bpf_u_int32				my_ip;
struct bpf_program		pcap_filter;
char					dev[64], errbuf[PCAP_ERRBUF_SIZE];
char					all_nodes_addr[]= ALL_NODES_MULTICAST_ADDR;

unsigned char			buffer[65556];
unsigned char			*v6buffer, *ptr, *startofprefixes;
    
struct ip6_hdr			*ipv6, *pkt_ipv6;
struct mld_hdr			*mldq;
struct ether_header		*ethernet, *pkt_ether;
struct nd_opt_slla		*sllaopt;
char					*lasts, *endptr;
    
int 					nw;
unsigned long			ul_res, ul_val;
    
unsigned int			i, j, sources, nsources, startrand;
    
uint16_t				mask;
uint8_t				hoplimit = 1;
struct in6_addr			mldaddr;
uint32_t			mldrespdelay = 10000;


struct ether_addr		linkaddr[MAX_SLLA_OPTION];
unsigned int			nlinkaddr=0, linkaddrs;
unsigned int			nsleep;

char 					*charptr;
    
char					plinkaddr[ETHER_ADDR_PLEN], phsrcaddr[ETHER_ADDR_PLEN], phdstaddr[ETHER_ADDR_PLEN];
char		 			psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN], pprefix[INET6_ADDRSTRLEN];
unsigned char			sllopt_f=0, sllopta_f=0, loop_f = 0, sleep_f=0, floods_f=0, hoplimit_f=0;
unsigned char			mldaddr_f=0, mldrespdelay_f=0;

unsigned char			newdata_f=0;

/* Support for IPv6 extension headers */
unsigned int			dstopthdrs, dstoptuhdrs, hbhopthdrs;
unsigned char			hbhopthdr_f=0, dstoptuhdr_f=0, dstopthdr_f=0;
unsigned char			*dstopthdr[MAX_DST_OPT_HDR], *dstoptuhdr[MAX_DST_OPT_U_HDR];
unsigned char				*hbhopthdr[MAX_HBH_OPT_HDR];
unsigned int			dstopthdrlen[MAX_DST_OPT_HDR], dstoptuhdrlen[MAX_DST_OPT_U_HDR];
unsigned int			hbhopthdrlen[MAX_HBH_OPT_HDR], m, pad;

/* The Hop-by-hop option used in MLD query messages */

const struct {
	struct ip6_hbh hbh;
	struct ip6_opt_router rtr_alert;
	struct ip6_opt pad1;
} __attribute__ ((__packed__)) mld_hbh = {
	.hbh = {
		.ip6h_nxt = IPPROTO_ICMPV6,
		.ip6h_len = 0,
	},
	.rtr_alert = {
		.ip6or_type = IP6OPT_ROUTER_ALERT,
		.ip6or_len = 2,
		.ip6or_value = IP6_ALERT_MLD,
	},
	.pad1 = {
		.ip6o_type = IP6OPT_PAD1,
		.ip6o_len = 0,
	},
};


struct ip6_frag			fraghdr, *fh;
struct ip6_hdr			*fipv6;
unsigned char			fragbuffer[ETHER_HDR_LEN+MIN_IPV6_HLEN+MAX_IPV6_PAYLOAD];
unsigned char			*fragpart, *fptr, *fptrend, *ptrend, *ptrhdr, *ptrhdrend;
unsigned int			hdrlen, ndstopthdr=0, nhbhopthdr=0, ndstoptuhdr=0;
unsigned int			nfrags, fragsize;
unsigned char			*prev_nh, *startoffragment;

struct iface_data		idata;

int main(int argc, char **argv){
	extern char		*optarg;
	int				r;

	static struct option longopts[] = {
		{"interface", required_argument, 0, 'i'},
		{"src-addr", required_argument, 0, 's'},
		{"dst-addr", required_argument, 0, 'd'},
		{"hop-limit", required_argument, 0, 'A'},
		{"dst-opt-hdr", required_argument, 0, 'u'},
		{"dst-opt-u-hdr", required_argument, 0, 'U'},
		{"hbh-opt-hdr", required_argument, 0, 'H'},
		{"frag-hdr", required_argument, 0, 'y'},
		{"link-src-addr", required_argument, 0, 'S'},
		{"link-dst-addr", required_argument, 0, 'D'},
		{"add-slla-opt", no_argument, 0, 'e'},
		{"src-link-opt", required_argument, 0, 'E'},
		{"mld-addr", required_argument, 0, 'm'},
		{"mld-resp-delay", required_argument, 0, 'r'},
		{"flood-sources", required_argument, 0, 'F'},
		{"loop", no_argument, 0, 'l'},
		{"sleep", required_argument, 0, 'z'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0,  0 }
	};

	const char shortopts[]= "i:s:d:A:u:U:H:y:S:D:eE:m:r:F:lz:vh";
	char option;

	if(argc<=1){
		usage();
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
				strncpy(idata.iface, optarg, IFACE_LENGTH);
				idata.iface[IFACE_LENGTH-1]=0;
				idata.iface_f=TRUE;
				break;

			case 's':	/* IPv6 Source Address */
				if((charptr = strtok_r(optarg, "/", &lasts)) == NULL){
					puts("Error in IPv6 Source Address ('-s' option)");
					exit(EXIT_FAILURE);
				}

				if ( inet_pton(AF_INET6, charptr, &(idata.srcaddr)) <= 0){
					puts("inet_pton(): address not valid");
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

				idata.fragh_f= 1;
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
				
				if(hdrlen == 0 ){
					nhbhopthdr=0;
					hbhopthdr_f=1;
					break;
				} else if(hdrlen < 8){
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
				idata.hsrcaddr_f = 1;
				
				if(ether_pton(optarg, &(idata.hsrcaddr), sizeof(idata.hsrcaddr)) == 0){
					puts("Error in Source link-layer address.");
					exit(EXIT_FAILURE);
				}
			break;

			case 'D':	/* Destination Ethernet Address */
				idata.hdstaddr_f = 1;
				
				if(ether_pton(optarg, &(idata.hdstaddr), sizeof(idata.hdstaddr)) == 0){
					puts("Error in Source link-layer address.");
					exit(EXIT_FAILURE);
				}
			break;

			case 'E':	/* Source link-layer option */
				sllopt_f = 1;
				
				if(ether_pton(optarg, &linkaddr[nlinkaddr], sizeof(struct ether_addr)) == 0){
					puts("Error in Source link-layer address option.");
					exit(EXIT_FAILURE);
				}
				
				sllopta_f=1;
				nlinkaddr++;
				break;

			case 'e':	/* Add Source link-layer option */
				sllopt_f = 1;
				break;

			case 'm':	/* MLD Query Multicast Address */
				if( inet_pton(AF_INET6, optarg, &mldaddr) <= 0){
					puts("inet_pton(): address not valid");
					exit(EXIT_FAILURE);
				}
			
				mldaddr_f = 1;
				break;

			case 'r':	/* MLD Query Maximum Response Delay */
				mldrespdelay= atoi(optarg);
				mldrespdelay_f= 1;
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
				idata.verbose_f=1;
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
		puts("mldq6 needs root privileges to run.");
		exit(EXIT_FAILURE);
	}

	if(!idata.iface_f){
		puts("Must specify the network interface with the -i option");
		exit(EXIT_FAILURE);
	}

	if(load_dst_and_pcap(&idata, (idata.dstaddr_f?LOAD_SRC_NXT_HOP:LOAD_PCAP_ONLY)) == FAILURE){
		puts("Error while learning Source Address and Next Hop");
		exit(EXIT_FAILURE);
	}

	release_privileges();

	if( pcap_datalink(idata.pfd) != DLT_EN10MB){
		printf("Error: Interface %s is not an Ethernet interface\n", idata.iface);
		exit(EXIT_FAILURE);
	}

	if(pcap_compile(idata.pfd, &pcap_filter, PCAP_NOPACKETS_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
		printf("pcap_compile(): %s", pcap_geterr(idata.pfd));
		exit(EXIT_FAILURE);
	}
    
	if(pcap_setfilter(idata.pfd, &pcap_filter) == -1){
		printf("pcap_setfilter(): %s", pcap_geterr(idata.pfd));
		exit(EXIT_FAILURE);
	}

	pcap_freecode(&pcap_filter);

	srandom(time(NULL));

    /* 
       If the IPv6 Source Address has not been specified, and the "-F" (flood) option has
       not been specified, select a random link-local unicast address.
     */
    if(!idata.srcaddr_f && !floods_f){
		/* When randomizing a link-local IPv6 address, select addresses that belong to the
		   prefix fe80::/64 (that's what a link-local address looks-like in legitimate cases).
		   The KAME implementation discards addresses in which the second highe-order 16 bits
		   (srcaddr.s6_addr16[1] in our case) are not zero.
		 */
		if ( inet_pton(AF_INET6, "fe80::", &(idata.srcaddr)) <= 0){
			puts("inet_pton(): Error when converting address");
			exit(EXIT_FAILURE);
		}

		randomize_ipv6_addr(&(idata.srcaddr), &(idata.srcaddr), 64);
    }


    /*
       If the flood option ("-F") has been specified, but no prefix has been specified,
       select the random Source Addresses from the link-local unicast prefix (fe80::/64).
     */
	if(floods_f && !idata.srcprefix_f){
		if ( inet_pton(AF_INET6, "fe80::", &(idata.srcaddr)) <= 0){
			puts("inet_pton(): Error when converting address");
			exit(EXIT_FAILURE);
		}

		randomize_ipv6_addr(&(idata.srcaddr), &(idata.srcaddr), 64);
		idata.srcpreflen=64;
    }

	if(!idata.dstaddr_f){		/* Destination Address defaults to all-nodes (ff02::1) */
		if( inet_pton(AF_INET6, ALL_NODES_MULTICAST_ADDR, &(idata.dstaddr)) <= 0){
			puts("inet_pton(): address not valid");
			exit(EXIT_FAILURE);
		}
	}

	if(!idata.hsrcaddr_f)		/* Source link-layer address is randomized by default */
		randomize_ether_addr(&(idata.hsrcaddr));

	if(!idata.hdstaddr_f)		/* Destination link-layer address defaults to all-nodes */
		if(ether_pton(ETHER_ALLNODES_LINK_ADDR, &(idata.hdstaddr), sizeof(idata.hdstaddr)) == 0){
			puts("ether_pton(): Error converting all-nodes multicast address");
			exit(EXIT_FAILURE);
		}
    
	if(sllopt_f && !sllopta_f){	/* The value of the source link-layer address option  */
		linkaddr[0]= idata.hsrcaddr;	/* defaults to the source Ethernet address            */
		nlinkaddr++;
	}

	if(!floods_f)
		nsources=1;
	
	if(!sleep_f)
		nsleep=125;

	if( !idata.fragh_f && dstoptuhdr_f){
		puts("Dst. Options Header (Unfragmentable Part) set, but Fragmentation not specified");
		exit(EXIT_FAILURE);
	}
    
	if(idata.verbose_f){
		print_attack_info(&idata);
	}

    /* Set initial contents of the attack packet */
    init_packet_data(&idata);
    
    send_packet(&idata);
    
	if(idata.verbose_f)    
		puts("Initial attack packet(s) sent successfully.");
    
	if(loop_f && idata.verbose_f)
		printf("Now sending MLD Queries every %u second%s...\n", nsleep, \
						    ((nsleep>1)?"s":""));

	while(loop_f){
		sleep(nsleep);
		send_packet(&idata);
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
    
	/* add a non-standard Hop-by-hop header ("-H n", n >=8 ) */
	if(hbhopthdr_f && nhbhopthdr != 0){
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
	/* add standard MLD Hop-by-hop header */
	} else if (!hbhopthdr_f){
		if((ptr+ sizeof(mld_hbh)) > (v6buffer+ idata->mtu)){
			puts("Packet too large while processing HBH Opt. Header");
			exit(EXIT_FAILURE);
		}

		*prev_nh = IPPROTO_HOPOPTS;
		prev_nh = ptr;
		memcpy(ptr, &mld_hbh, sizeof(mld_hbh));
		ptr = ptr + sizeof(mld_hbh);
	} /* else: -H 0 => omit hbh header to create an invalid MLD Query */

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
			printf("Unfragmentable part too large for current MTU (%u bytes)\n", idata->mtu);
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
			if((ptr+ dstopthdrlen[dstopthdrs]) > (v6buffer+idata->max_packet_size)){
				puts("Packet too large while processing Dest. Opt. Header (U. part) (should be using the Frag. option?)");
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

	if( (ptr+sizeof(struct mld_hdr)) > (v6buffer+idata->max_packet_size)){
		puts("Packet too large while inserting MLD Query header (should be using Frag. option?)");
		exit(EXIT_FAILURE);
	}

	mldq= (struct mld_hdr *) (ptr);
	mldq->mld_type = MLD_LISTENER_QUERY;
	mldq->mld_code = 0;
	mldq->mld_maxdelay = htons(mldrespdelay);
	mldq->mld_reserved = 0;

	if (mldaddr_f)
		memcpy(&mldq->mld_addr, &mldaddr, sizeof(mldq->mld_addr));
	else
		memset(&mldq->mld_addr, 0, sizeof(mldq->mld_addr));
    
	ptr += sizeof(struct mld_hdr);
    
	/* If a single source link-layer address is specified, it is included in all packets */
	if(sllopt_f && nlinkaddr==1){
		if( (ptr+sizeof(struct nd_opt_slla)) <= (v6buffer+idata->max_packet_size)){
			sllaopt = (struct nd_opt_slla *) ptr;
			sllaopt->type= ND_OPT_SOURCE_LINKADDR;
			sllaopt->length= SLLA_OPT_LEN;
			memcpy(sllaopt->address, linkaddr[0].a, ETH_ALEN);
			ptr += sizeof(struct nd_opt_slla);
		}
		else{
			puts("Packet too large while processing source link-layer address opt. (should be using Frag. option?)");
			exit(EXIT_FAILURE);
		}
	}
    
	startofprefixes = ptr;    
}


/*
 * Function: send_packet()
 *
 * Initialize the remaining fields of the MLD Query Message, and
 * send the attack packet(s).
 */
void send_packet(struct iface_data *idata){
	sources=0;	

	do{
		if(floods_f){
		    /* 
		        Randomize the IPv6 Source address based on the specified prefix and prefix length
		        (defaults to fe80::/64).
		     */  
			randomize_ipv6_addr(&(ipv6->ip6_src), &(idata->srcaddr), idata->srcpreflen);

			if(!idata->hsrcaddr_f){
				randomize_ether_addr(&(ethernet->src));

				/*
				   If the source-link layer address must be included, but no value was 
				   specified we set it to the randomized Ethernet Source Address
				 */
				if(sllopt_f && !sllopta_f){
					memcpy(sllaopt->address, ethernet->src.a, ETH_ALEN);
				}
			}
		}

		if(nlinkaddr==1)
			linkaddrs=1;
		else
			linkaddrs=0;

		do{
			newdata_f=0;
			ptr = startofprefixes;

			while(linkaddrs<nlinkaddr && (ptr+sizeof(struct nd_opt_slla)-v6buffer)<=idata->max_packet_size){
				sllaopt = (struct nd_opt_slla *) ptr;
				sllaopt->type= ND_OPT_SOURCE_LINKADDR;
				sllaopt->length= SLLA_OPT_LEN;
				memcpy(sllaopt->address, linkaddr[linkaddrs].a, ETH_ALEN);
				ptr += sizeof(struct nd_opt_slla);
				linkaddrs++;
				newdata_f=1;
			}


			mldq->mld_cksum = 0;
			mldq->mld_cksum = in_chksum(v6buffer, mldq, ptr-((unsigned char *)mldq), IPPROTO_ICMPV6);


			if(!idata->fragh_f){
				ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);

				if((nw=pcap_inject(idata->pfd, buffer, ptr - buffer)) == -1){
					printf("pcap_inject(): %s\n", pcap_geterr(idata->pfd));
					exit(EXIT_FAILURE);
				}
    
				if(nw != (ptr-buffer)){
					printf("pcap_inject(): only wrote %d bytes (rather than %lu bytes)\n", nw, \
																				(LUI) (ptr-buffer));
					exit(EXIT_FAILURE);
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
					exit(EXIT_FAILURE);
				}

				memcpy(fptr, (char *) &fraghdr, FRAG_HDR_SIZE);
				fh= (struct ip6_frag *) fptr;
				fh->ip6f_ident=random();
				startoffragment = fptr + FRAG_HDR_SIZE;

				/*
				 * Check that the selected fragment size is not larger than the largest fragment 
				 * size that can be sent
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

					fipv6->ip6_plen = htons((fptr - fragbuffer) - MIN_IPV6_HLEN - ETHER_HDR_LEN);
		
					if((nw=pcap_inject(idata->pfd, fragbuffer, fptr - fragbuffer)) == -1){
						printf("pcap_inject(): %s\n", pcap_geterr(idata->pfd));
						exit(EXIT_FAILURE);
					}

					if(nw != (fptr- fragbuffer)){
						printf("pcap_inject(): only wrote %d bytes (rather than %lu bytes)\n", nw,\
																				(LUI) (ptr-buffer));
						exit(EXIT_FAILURE);
					}
				}
			}
		}while(linkaddrs>nlinkaddr && newdata_f);
	    
		sources++;
	}while(sources<nsources);
}



/*
 * Function: usage()
 *
 * Print the syntax of the mldq6 tool
 */
void usage(void){
    puts("usage: mldq6 -i INTERFACE [-s SRC_ADDR[/LEN]] [-d DST_ADDR] [-A HOP_LIMIT]"
	 " [-y FRAG_SIZE] [-u DST_OPT_HDR_SIZE] [-U DST_OPT_U_HDR_SIZE]"
	 " [-H HBH_OPT_HDR_SIZE] [-S LINK_SRC_ADDR] [-D LINK-DST-ADDR]"
	 " [-E LINK_ADDR] [-e] [-m MLD_ADDR] [-r MLD_RESP_DELAY ] [-F N_SOURCES]"
	 " [-z SECONDS] [-l] [-v] [-h]");
}


/*
 * Function: print_help()
 *
 * Print help information for the mldq6 tool
 */
void print_help(void){
	puts(SI6_TOOLKIT);
	puts( "mldq6: Security assessment tool for attack vectors based on MLD Query messages\n");
	usage();
    
	puts("\nOPTIONS:\n"
	     "  --interface, -i            Network interface\n"
	     "  --src-addr, -s             IPv6 Source Address\n"
	     "  --dst-addr, -d             IPv6 Destination Address\n"
	     "  --hop-limit, -A            IPv6 Hop Limit\n"
	     "  --frag-hdr. -y             Fragment Header\n"
	     "  --dst-opt-hdr, -u          Destination Options Header (Fragmentable Part)\n"
	     "  --dst-opt-u-hdr, -U        Destination Options Header (Unfragmentable Part)\n"
	     "  --hbh-opt-hdr, -H          Hop by Hop Options Header\n"
	     "  --link-src-addr, -S        Link-layer Destination Address\n"
	     "  --link-dst-addr, -D        Link-layer Source Address\n"
	     "  --src-link-opt, -E         Source link-layer address option\n"
	     "  --add-slla-opt, -e         Add Source link-layer address option\n"
	     "  --mld-addr, -m             MLD Query Multicast Address\n"
	     "  --mld-resp-delay, -r       MLD Query Maximum Response Delay [ms]\n"
	     "  --flood-sources, -F        Number of Source Addresses to forge randomly\n"
	     "  --loop, -l                 Send MLD Query periodically\n"
	     "  --sleep, -z                Pause between peiodic MLD Queries [sec]\n"
	     "  --help, -h                 Print help for the mldq6 tool\n"
	     "  --verbose, -v              Be verbose\n"
	     "\n"
	     "Programmed by Fernando Gont for SI6 Networks <https://www.si6networks.com>\n"
	     "Please send any bug reports to <fgont@si6networks.com>"
	);
}



/*
 * Function: print_attack_info()
 *
 * Print attack details (when the verbose ("-v") option is specified).
 */
void print_attack_info(struct iface_data *idata){
	if(floods_f)
		printf("Flooding the target from %u different IPv6 Source Addresses\n", nsources);

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

	if(ether_ntop(&(idata->hdstaddr), phdstaddr, sizeof(phdstaddr)) == 0){
		puts("ether_ntop(): Error converting address");
		exit(EXIT_FAILURE);
	}

    printf("Ethernet Destination Address: %s%s\n", phdstaddr, \
					((!idata->hdstaddr_f)?" (all-nodes multicast)":""));


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

	if(inet_ntop(AF_INET6, &(idata->dstaddr), pdstaddr, sizeof(pdstaddr)) == NULL){
		perror("inet_ntop()");
		exit(EXIT_FAILURE);
	}

	printf("IPv6 Destination Address: %s%s\n", pdstaddr, \
				((!idata->dstaddr_f)?" (all-nodes link-local multicast)":""));

	printf("IPv6 Hop Limit: %u%s\n", hoplimit, (hoplimit_f)?"":" (default)");

	for(i=0; i<ndstoptuhdr; i++)
		printf("Destination Options Header (Unfragmentable part): %u bytes\n", dstoptuhdrlen[i]);

	for(i=0; i<nhbhopthdr; i++)
		printf("Hop by Hop Options Header: %u bytes\n", hbhopthdrlen[i]);

	for(i=0; i<ndstopthdr; i++)
		printf("Destination Options Header: %u bytes\n", dstopthdrlen[i]);

	if(idata->fragh_f)
		printf("Sending each packet in fragments of %u bytes (plus the Unfragmentable part)\n", nfrags);
	
	for(i=0;i<nlinkaddr;i++){
		if(ether_ntop(&linkaddr[i], plinkaddr, sizeof(plinkaddr)) == 0){
			puts("ether_ntop(): Error converting address");
			exit(EXIT_FAILURE);
		}

		printf("Source Link-layer Address option -> Address: %s\n", \
				((floods_f && !sllopta_f)?"(randomized for each packet)":plinkaddr));
	}
}
