/*
 * ns6: A security assessment tool for attack vectors based on
 *      ICMPv6 Neighbor Solicitation messages
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
 * Build with: make ns6
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

#include "ns6.h"
#include "libipv6.h"
#include "ipv6toolkit.h"

void				init_packet_data(struct iface_data *);
void				send_packet(struct iface_data *);
void				print_attack_info(struct iface_data *);
void				usage(void);
void				print_help(void);

bpf_u_int32			my_netmask;
bpf_u_int32			my_ip;
struct bpf_program	pcap_filter;
char 				dev[64], errbuf[PCAP_ERRBUF_SIZE];

unsigned char		buffer[65556];
unsigned char 		*v6buffer, *ptr, *startofprefixes;
    
struct ip6_hdr		*ipv6;
struct nd_neighbor_solicit	*ns;
struct ether_header	*ethernet, *pkt_ether;
struct nd_opt_slla	*sllaopt;

struct in6_addr		targetaddr;
char				*lasts, *endptr;
    
size_t				nw;
unsigned long		ul_res, ul_val;
    
unsigned int		i, j, startrand, sources, nsources, targets, ntargets;
    
u_int16_t			mask;
u_int8_t			hoplimit;

struct ether_addr	linkaddr[MAX_SLLA_OPTION];
unsigned int		nlinkaddr=0, linkaddrs;
unsigned int		nsleep;

char 				*charptr;
    
char 				plinkaddr[ETHER_ADDR_PLEN], phsrcaddr[ETHER_ADDR_PLEN], phdstaddr[ETHER_ADDR_PLEN];
char 				psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN], pv6addr[INET6_ADDRSTRLEN];
unsigned char	 	sllopt_f=0, sllopta_f=0, targetprefix_f=0, targetaddr_f=0;
unsigned char 		loop_f = 0, sleep_f=0, floods_f=0, floodt_f=0, newdata_f=0, hoplimit_f=0;
unsigned char		targetpreflen;

/* Support for Extension Headers */
unsigned int		dstopthdrs, dstoptuhdrs, hbhopthdrs;
unsigned char		hbhopthdr_f=0, dstoptuhdr_f=0, dstopthdr_f=0;
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
struct iface_data	idata;

int main(int argc, char **argv){
	extern char	*optarg;
	int			r;

	static struct option longopts[] = {
		{"interface", required_argument, 0, 'i'},
		{"src-address", required_argument, 0, 's'},
		{"dst-address", required_argument, 0, 'd'},
		{"hop-limit", required_argument, 0, 'A'},
		{"dst-opt-hdr", required_argument, 0, 'u'},
		{"dst-opt-u-hdr", required_argument, 0, 'U'},
		{"hbh-opt-hdr", required_argument, 0, 'H'},
		{"frag-hdr", required_argument, 0, 'y'},
		{"link-src-address", required_argument, 0, 'S'},
		{"link-dst-address", required_argument, 0, 'D'},
		{"target-address", required_argument, 0, 't'},
		{"source-lla-opt", required_argument, 0, 'E'},
		{"add-slla-opt", no_argument, 0, 'e'},
		{"flood-sources", required_argument, 0, 'F'},
		{"flood-targets", required_argument, 0, 'T'},
		{"loop", no_argument, 0, 'l'},
		{"sleep", no_argument, 0, 'z'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'}
	};

	char shortopts[]= "i:s:d:A:u:U:H:y:S:D:t:eE:F:T:lz:vh";
	char option;

	if(argc<=1){
		usage();
		exit(EXIT_FAILURE);
	}

	hoplimit=255;

	if(init_iface_data(&idata) == FAILURE){
		puts("Error initializing internal data structure");
		exit(EXIT_FAILURE);
	}

	while((r=getopt_long(argc, argv, shortopts, longopts, NULL)) != -1) {
		option =r;

		switch(option) {
			case 'i':  /* Interface */
				strncpy(idata.iface, optarg, IFACE_LENGTH-1);
				idata.iface[IFACE_LENGTH-1]=0;
				idata.iface_f=1;
				break;

			case 's':	/* IPv6 Source Address */
				if((charptr = strtok_r(optarg, "/", &lasts)) == NULL){
					puts("inet_pton(): address not valid");
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
		
				nfrags = (nfrags +7) & 0xfff8;
				fragh_f= 1;
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

	    case 't':	/* NA Target address */
		if((charptr = strtok_r(optarg, "/", &lasts)) == NULL){
		    puts("Target Address not valid");
		    exit(EXIT_FAILURE);
		}

		if ( inet_pton(AF_INET6, charptr, &targetaddr) <= 0){
		    puts("inet_pton(): Target Address not valid");
		    exit(EXIT_FAILURE);
		}

		targetaddr_f = 1;
		
		if((charptr = strtok_r(NULL, " ", &lasts)) != NULL){
		    targetpreflen = atoi(charptr);
		
		    if(targetpreflen>128){
			puts("Prefix length error in Target Address");
			exit(EXIT_FAILURE);
		    }

		    sanitize_ipv6_prefix(&targetaddr, targetpreflen);
		    targetprefix_f=1;
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

	    case 'F':	/* Flood sources */
		nsources= atoi(optarg);
		if(nsources == 0){
		    puts("Invalid number of sources in option -F");
		    exit(EXIT_FAILURE);
		}
		
		floods_f= 1;
		break;

	    case 'T':	/* Flood targets */
		ntargets= atoi(optarg);
		if(ntargets == 0){
		    puts("Invalid number of Target Addresses in option -T");
		    exit(EXIT_FAILURE);
		}
		
		floodt_f= 1;
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
		puts("ns6 needs root privileges to run.");
		exit(EXIT_FAILURE);
	}

	if(!idata.iface_f){
		puts("Must specify the network interface with the -i option");
		exit(EXIT_FAILURE);
	}
    
	if(!targetaddr_f){
		puts("Must specify a ND target address with the '-t' option");
		exit(EXIT_FAILURE);
	}

	if(load_dst_and_pcap(&idata, LOAD_PCAP_ONLY) == FAILURE){
		puts("Error while learning Souce Address and Next Hop");
		exit(EXIT_FAILURE);
	}

	release_privileges();

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
		/* 
		   When randomizing a link-local IPv6 address, select addresses that belong to the
		   prefix fe80::/64 (that's what a link-local address looks-like in legitimate cases).
		   The KAME implementation discards addresses in which the second highe-order 16 bits
		   (srcaddr.s6_addr16[1] in our case) are not zero.
		 */  
		idata.srcaddr.s6_addr16[0]= htons(0xfe80); /* Link-local unicast prefix */

		for(i=1;i<4;i++)
			idata.srcaddr.s6_addr16[i]=0x0000;	
	    
		for(i=4; i<8; i++)
			idata.srcaddr.s6_addr16[i]=random();
	}


	/*
	   If the flood option ("-F") has been specified, but no prefix has been specified,
	   select the random Source Addresses from the link-local unicast prefix (fe80::/64).
	 */
	if(floods_f && !idata.srcprefix_f){
		idata.srcaddr.s6_addr16[0]= htons(0xfe80); /* Link-local unicast prefix */

		for(i=1;i<8;i++)
			idata.srcaddr.s6_addr16[i]=0x0000;
	
		idata.srcpreflen=64;
	}

	/*
	   If the flood target option ("-T") was specified, but no prefix was specified,
	   select the random Target Addresses from the link-local unicast prefix (fe80::/64).
	 */
	if(floodt_f && !targetprefix_f){
		targetaddr.s6_addr16[0]= htons(0xfe80); /* Link-local unicast prefix */

		for(i=1;i<8;i++)
			targetaddr.s6_addr16[i]=0x0000;
	
		targetpreflen=64;
	}

	if(!floodt_f)
		ntargets=1;

	if(!idata.dstaddr_f){			/* Destination Address defaults to all-nodes (ff02::1) */
		if( inet_pton(AF_INET6, ALL_NODES_MULTICAST_ADDR, &(idata.dstaddr)) <= 0){
			puts("inet_pton(): address not valid");
			exit(EXIT_FAILURE);
		}
	}

	if(!idata.hsrcaddr_f && !floods_f)	/* Source link-layer address is randomized by default */
		for(i=0; i<6; i++)
			idata.hsrcaddr.a[i]= random();

	if(sllopt_f && !sllopta_f){			/* The value of the source link-layer address option  */
		linkaddr[0]= idata.hsrcaddr;			/* defaults to the source Ethernet address            */
		nlinkaddr++;
	}

	if(!idata.hdstaddr_f)			/* Destination link-layer address defaults to all-nodes */
		if(ether_pton(ETHER_ALLNODES_LINK_ADDR, &(idata.hdstaddr), sizeof(idata.hdstaddr)) == 0){
			puts("ether_pton(): Error converting all-nodes multicast address");
			exit(EXIT_FAILURE);
		}

	if(!floods_f)
		nsources=1;
	
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

	if(idata.verbose_f){
		print_attack_info(&idata);
	}

	/* Set initial contents of the attack packet */
	init_packet_data(&idata);
    
	/* Fire a Neighbor Solicitarion message */
	send_packet(&idata);
   
	if(idata.verbose_f)    
		puts("Initial attack packet(s) sent successfully.");
    
	if(loop_f && idata.verbose_f)
		printf("Now sending Neighbor Solicitations every %u second%s...\n", nsleep, \
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
    ethernet= (struct ether_header *) buffer;
    v6buffer = buffer + idata->linkhsize;
    ipv6 = (struct ip6_hdr *) v6buffer;

	if(idata->flags != IFACE_TUNNEL && idata->flags != IFACE_LOOPBACK){
		ethernet->src = idata->hsrcaddr;
		ethernet->dst = idata->hdstaddr;
		ethernet->ether_type = htons(ETHERTYPE_IPV6);
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

    if( (ptr+sizeof(struct nd_neighbor_solicit)) > (v6buffer+max_packet_size)){
    	puts("Packet too large while inserting Neighbor Solicitation header (should be using Frag. option?)");
    	exit(EXIT_FAILURE);
    }

    ns= (struct nd_neighbor_solicit *) (ptr);

    ns->nd_ns_type = ND_NEIGHBOR_SOLICIT;
    ns->nd_ns_code = 0;
    ns->nd_ns_reserved = 0;
    ns->nd_ns_target = targetaddr;

    ptr += sizeof(struct nd_neighbor_solicit);
    sllaopt = (struct nd_opt_slla *) ptr;    

    /* If a single source link-layer address is specified, it is included in all packets */
    if(sllopt_f && nlinkaddr==1){
    	if( (ptr+sizeof(struct nd_opt_slla)) <= (v6buffer+max_packet_size)){
        	sllaopt->type= ND_OPT_SOURCE_LINKADDR;
        	sllaopt->length= SLLA_OPT_LEN;
        	bcopy(linkaddr[0].a, sllaopt->address, ETH_ALEN);
        	ptr += sizeof(struct nd_opt_slla);
        }
        else{
        	puts("Packet too large while processing source link-layer addresss opt. (should be using Frag. option?)");
        	exit(EXIT_FAILURE);
        }
    }

    startofprefixes = ptr;
}




/*
 * Function: send_packet()
 *
 * Initialize the remaining fields of the Neighbor Solicitation message, and
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
			startrand= idata->srcpreflen/16;

			for(i=0; i<startrand; i++)
				ipv6->ip6_src.s6_addr16[i]= 0;

			for(i=startrand; i<8; i++)
				ipv6->ip6_src.s6_addr16[i]=random();


			if(idata->srcpreflen%16){
				mask=0xffff;
	    
				for(i=0; i<(idata->srcpreflen%16); i++)
					mask= mask>>1;

				ipv6->ip6_src.s6_addr16[startrand]= ipv6->ip6_src.s6_addr16[startrand] & htons(mask);
			}

			for(i=0; i<=(idata->srcpreflen/16); i++)
				ipv6->ip6_src.s6_addr16[i]= ipv6->ip6_src.s6_addr16[i] | idata->srcaddr.s6_addr16[i];

			if(!idata->hsrcaddr_f){
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

		targets=0;

		do{
			if(floodt_f){
				/* 
				   Randomizing the ND Target Address based on the prefix specified by "targetaddr" 
				   and targetpreflen.
				 */  
				startrand= targetpreflen/16;

				for(i=0; i<startrand; i++)
					ns->nd_ns_target.s6_addr16[i]= 0;

				for(i=startrand; i<8; i++)
					ns->nd_ns_target.s6_addr16[i]=random();

				if(targetpreflen%16){
					mask=0xffff;

					for(i=0; i<(targetpreflen%16); i++)
						mask= mask>>1;

					ns->nd_ns_target.s6_addr16[startrand]= ns->nd_ns_target.s6_addr16[startrand] \
													& htons(mask);
				}

				for(i=0; i<=(targetpreflen/16); i++)
					ns->nd_ns_target.s6_addr16[i]= ns->nd_ns_target.s6_addr16[i] | \
										targetaddr.s6_addr16[i];

			}

			if(nlinkaddr==1)      /* If a single source link-layer address must be included, it is included */
				linkaddrs=1;  /* by init_packet_data() (rather than by send_packet()                    */
			else
				linkaddrs=0;
	    	
			do{
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

				ns->nd_ns_cksum = 0;
				ns->nd_ns_cksum = in_chksum(v6buffer, ns, ptr-((unsigned char *)ns), IPPROTO_ICMPV6);

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

			        		if((nw=pcap_inject(idata->pfd, fragbuffer, fptr - fragbuffer)) == -1){
							printf("pcap_inject(): %s\n", pcap_geterr(idata->pfd));
							exit(EXIT_FAILURE);
						}
    
						if(nw != (fptr- fragbuffer)){
							printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, \
																					(LUI) (ptr-buffer));
							exit(EXIT_FAILURE);
						}
					}
				}
	
			}while(linkaddrs<nlinkaddr && newdata_f);

			targets++;

		}while(targets<ntargets);

		sources++;

	}while(sources<nsources);
}



/*
 * Function: usage()
 *
 * Print the syntax of the ns6 tool
 */
void usage(void){
	puts("usage: ns6 -i INTERFACE [-s SRC_ADDR[/LEN]] [-d DST_ADDR] [-y FRAG_SIZE] "
	     "[-u DST_OPT_HDR_SIZE] [-U DST_OPT_U_HDR_SIZE] [-H HBH_OPT_HDR_SIZE] "
	     "[-S LINK_SRC_ADDR] [-D LINK-DST-ADDR] [-E LINK_ADDR] [-e] [-t TARGET_ADDR[/LEN]] "
	     "[-F N_SOURCES] [-T N_TARGETS] [-z SECONDS] [-l] [-v] [-h]");
}


/*
 * Function: print_help()
 *
 * Print help information for the ns6 tool
 */
void print_help(void){
	puts(SI6_TOOLKIT);
	puts("ns6: Security assessment tool for attack vectors based on NS messages\n");
	usage();
    
	puts("\nOPTIONS:\n"
	     "  --interface, -i            Network interface\n"
	     "  --src-address, -s          IPv6 Source Address\n"
	     "  --dst-address, -d          IPv6 Destination Address\n"
	     "  --frag-hdr. -y             Fragment Header\n"
	     "  --dst-opt-hdr, -u          Destination Options Header (Fragmentable Part)\n"
	     "  --dst-opt-u-hdr, -U        Destination Options Header (Unfragmentable Part)\n"
	     "  --hbh-opt-hdr, -H          Hop by Hop Options Header\n"
	     "  --link-src-address, -S     Link-layer Destination Address\n"
	     "  --link-dst-address, -D     Link-layer Source Address\n"
	     "  --target-address, -t       ND Target Address\n"
	     "  --source-lla-opt, -E       Source link-layer address option\n"
	     "  --add-slla-opt, -e         Add Source link-layer address option\n"
	     "  --flood-sources, -F        Number of Source Addresses to forge randomly\n"
	     "  --flood-targets, -T        Flood with NA's for multiple Target Addresses\n"
	     "  --loop, -l                 Send Neighbor Solicitations periodically\n"
	     "  --sleep, -z                Pause between peiodic Neighbor Solicitations\n"
	     "  --help, -h                 Print help for the ns6 tool\n"
	     "  --verbose, -v              Be verbose\n"
	     "\n"
	     "Programmed by Fernando Gont for SI6 Networks <http://www.si6networks.com>\n"
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

    if(floodt_f)
	printf("Flooding the target with %u ND Target Addresses\n", ntargets);

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
	puts("Error converting IPv6 Destination Address to presentation format");
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

    if(fragh_f)
	printf("Sending each packet in fragments of %u bytes (plus the Unfragmentable part)\n", nfrags);
		
    if(!floodt_f){
	if(targetaddr_f){
	    if(inet_ntop(AF_INET6, &targetaddr, pv6addr, sizeof(pv6addr)) == NULL){
		puts("inet_ntop(): Error converting ND IPv6 Target Address to presentation format");
		exit(EXIT_FAILURE);
	    }

	    printf("ND Target Address: %s\n", pv6addr);
	}
    }
    else{
	if(inet_ntop(AF_INET6, &targetaddr, pv6addr, sizeof(pv6addr)) == NULL){
	    puts("inet_ntop(): Error converting ND IPv6 Target Address to presentation format");
	    exit(EXIT_FAILURE);
	}

	printf("ND Target Address: randomized, from the %s/%u prefix%s\n", pv6addr, targetpreflen,\
    									(!targetprefix_f)?" (default)":"");
    }

    for(i=0;i<nlinkaddr;i++){
	if(ether_ntop(&linkaddr[i], plinkaddr, sizeof(plinkaddr)) == 0){
	    puts("ether_ntop(): Error converting address");
	    exit(EXIT_FAILURE);
	}

	printf("Source Link-layer Address option -> Address: %s\n", \
		    ((floods_f && !sllopta_f)?"(randomized for each packet)":plinkaddr));
    }
}

