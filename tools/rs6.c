/*
 * rs6: A security assessment tool for attack vectors based on
 *      ICMPv6 Router Solicitation messages
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
 * Build with: gcc rs6.c -Wall -lpcap -o rs6
 *
 * This program has been tested to compile and run on: Debian GNU/Linux 6.0,
 * FreeBSD 8.2, NetBSD 5.1, OpenBSD 5.0, and Ubuntu 11.10.
 *
 * It requires that the libpcap library be installed on your system.
 *
 * Please send any bug reports to Fernando Gont <fgont@si6networks.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
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
#include <pwd.h>
#include "rs6.h"
#include "ipv6toolkit.h"

void					init_packet_data(void);
int						insert_pad_opt(char *ptrhdr, const char *, unsigned int);
void					send_packet(void);
void					print_attack_info(void);
void					sanitize_ipv6_prefix(struct in6_addr *, u_int8_t);
void					usage(void);
void					print_help(void);
int						ether_pton(const char *, struct ether_addr *, unsigned int);
int						ether_ntop(const struct ether_addr *, char *, size_t);
u_int16_t				in_chksum(void *, void *, size_t);


pcap_t					*pfd;
struct pcap_pkthdr		*pkthdr;
const u_char			*pktdata;
struct in6_addr			*pkt_ipv6addr;    
bpf_u_int32				my_netmask;
bpf_u_int32				my_ip;
struct bpf_program		pcap_filter;
char					dev[64], errbuf[PCAP_ERRBUF_SIZE];
char					all_nodes_addr[]= ALL_NODES_MULTICAST_ADDR;

char					buffer[65556];
char					*v6buffer, *ptr, *startofprefixes;

char					iface[IFACE_LENGTH];
    
struct ip6_hdr			*ipv6, *pkt_ipv6;
struct nd_router_solicit	*rs;
struct ether_header		*ethernet, *pkt_ether;
struct ether_addr		hsrcaddr, hdstaddr;
struct nd_opt_slla		*sllaopt;

struct in6_addr			srcaddr, dstaddr;
char					*lasts, *endptr;
    
size_t					nw;
unsigned long			ul_res, ul_val;
    
unsigned int			i, j, sources, nsources, startrand;
    
u_int16_t				mask;
u_int8_t				hoplimit;

struct ether_addr		linkaddr[MAX_SLLA_OPTION];
unsigned int			nlinkaddr=0, linkaddrs;
unsigned int			nsleep;

char 					*charptr;
    
char					plinkaddr[ETHER_ADDR_PLEN], phsrcaddr[ETHER_ADDR_PLEN], phdstaddr[ETHER_ADDR_PLEN];
char		 			psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN], pprefix[INET6_ADDRSTRLEN];
unsigned char			verbose_f=0, sllopt_f=0, sllopta_f=0, iface_f=0, srcprefix_f=0;
unsigned char			srcaddr_f=0, dstaddr_f=0, hsrcaddr_f=0, hdstaddr_f=0;
unsigned char			loop_f = 0, sleep_f=0, floods_f=0, hoplimit_f=0;
unsigned char			newdata_f=0;
unsigned char			srcpreflen;


/* Support for IPv6 extension headers */
unsigned int			dstopthdrs, dstoptuhdrs, hbhopthdrs;
char					hbhopthdr_f=0, dstoptuhdr_f=0, dstopthdr_f=0;
char					*dstopthdr[MAX_DST_OPT_HDR], *dstoptuhdr[MAX_DST_OPT_U_HDR];
char					*hbhopthdr[MAX_HBH_OPT_HDR];
unsigned int			dstopthdrlen[MAX_DST_OPT_HDR], dstoptuhdrlen[MAX_DST_OPT_U_HDR];
unsigned int			hbhopthdrlen[MAX_HBH_OPT_HDR], m, pad;

struct ip6_frag			fraghdr, *fh;
struct ip6_hdr			*fipv6;
unsigned char			fragh_f=0;
char					fragbuffer[ETHER_HDR_LEN+MIN_IPV6_HLEN+MAX_IPV6_PAYLOAD];
char					*fragpart, *fptr, *fptrend, *ptrend, *ptrhdr, *ptrhdrend;
unsigned int			hdrlen, ndstopthdr=0, nhbhopthdr=0, ndstoptuhdr=0;
unsigned int			nfrags, fragsize, max_packet_size;
char					*prev_nh, *startoffragment;

int main(int argc, char **argv){
	extern char		*optarg;
	int				r;
	uid_t			ruid;
	gid_t			rgid;
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
		{"link-src-address", required_argument, 0, 'S'},
		{"link-dst-address", required_argument, 0, 'D'},
		{"add-slla-opt", no_argument, 0, 'e'},
		{"src-link-opt", required_argument, 0, 'E'},
		{"flood-sources", required_argument, 0, 'F'},
		{"loop", no_argument, 0, 'l'},
		{"sleep", no_argument, 0, 'z'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'}
	};

	char shortopts[]= "i:s:d:A:u:U:H:y:S:D:eE:F:lz:vh";
	char option;

    if(argc<=1){
	usage();
	exit(EXIT_FAILURE);
    }

    hoplimit=255;

	while((r=getopt_long(argc, argv, shortopts, longopts, NULL)) != -1) {
		option= r;

		switch(option) {
			case 'i':  /* Interface */
				strncpy(iface, optarg, IFACE_LENGTH-1);
				iface_f=1;
				break;

			case 's':	/* IPv6 Source Address */
				if((charptr = strtok_r(optarg, "/", &lasts)) == NULL){
					puts("Error in IPv6 Source Address ('-s' option)");
					exit(EXIT_FAILURE);
				}

				if ( inet_pton(AF_INET6, charptr, &srcaddr) <= 0){
					puts("inet_pton(): address not valid");
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
		hsrcaddr_f = 1;
		
		if(ether_pton(optarg, &hsrcaddr, sizeof(hsrcaddr)) == 0){
			puts("Error in Source link-layer address.");
			exit(EXIT_FAILURE);
		}
		break;

	    case 'D':	/* Destination Ethernet Address */
		hdstaddr_f = 1;
		
		if(ether_pton(optarg, &hdstaddr, sizeof(hdstaddr)) == 0){
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
		verbose_f=1;
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
		puts("rs6 needs root privileges to run.");
		exit(EXIT_FAILURE);
	}

	if(!iface_f){
		puts("Must specify the network interface with the -i option");
		exit(EXIT_FAILURE);
	}

	if( (pfd= pcap_open_live(iface, PCAP_SNAP_LEN, PCAP_PROMISC, PCAP_TIMEOUT, errbuf)) == NULL){
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

	if( pcap_datalink(pfd) != DLT_EN10MB){
		printf("Error: Interface %s is not an Ethernet interface\n", iface);
		exit(EXIT_FAILURE);
	}

	if(pcap_compile(pfd, &pcap_filter, ICMPV6_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
		printf("pcap_compile(): %s", pcap_geterr(pfd));
		exit(EXIT_FAILURE);
	}
    
	if(pcap_setfilter(pfd, &pcap_filter) == -1){
		printf("pcap_setfilter(): %s", pcap_geterr(pfd));
		exit(EXIT_FAILURE);
	}

	pcap_freecode(&pcap_filter);

	srandom(time(NULL));

    /* 
       If the IPv6 Source Address has not been specified, and the "-F" (flood) option has
       not been specified, select a random link-local unicast address.
     */
    if(!srcaddr_f && !floods_f){
		/* When randomizing a link-local IPv6 address, select addresses that belong to the
		   prefix fe80::/64 (that's what a link-local address looks-like in legitimate cases).
		   The KAME implementation discards addresses in which the second highe-order 16 bits
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

	if(!dstaddr_f){		/* Destination Address defaults to all-nodes (ff02::1) */
		if( inet_pton(AF_INET6, ALL_ROUTERS_MULTICAST_ADDR, &dstaddr) <= 0){
			puts("inet_pton(): address not valid");
			exit(EXIT_FAILURE);
		}
	}

	if(!hsrcaddr_f)		/* Source link-layer address is randomized by default */
		for(i=0; i<6; i++)
			hsrcaddr.a[i]= random();

	if(!hdstaddr_f)		/* Destination link-layer address defaults to all-nodes */
		if(ether_pton(ETHER_ALL_ROUTERS_LINK_ADDR, &hdstaddr, sizeof(hdstaddr)) == 0){
			puts("ether_pton(): Error converting all-nodes multicast address");
			exit(EXIT_FAILURE);
		}
    
	if(sllopt_f && !sllopta_f){	/* The value of the source link-layer address option  */
		linkaddr[0]= hsrcaddr;	/* defaults to the source Ethernet address            */
		nlinkaddr++;
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

	if(verbose_f){
		print_attack_info();
	}

    /* Set initial contents of the attack packet */
    init_packet_data();
    
    send_packet();
    
	if(verbose_f)    
		puts("Initial attack packet(s) sent successfully.");
    
	if(loop_f && verbose_f)
		printf("Now sending Router Solicitations every %u second%s...\n", nsleep, \
						    ((nsleep>1)?"s":""));

	while(loop_f){
		sleep(nsleep);
		send_packet();
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
    	prev_nh = (char *) &fraghdr;
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

    if( (ptr+sizeof(struct nd_router_solicit)) > (v6buffer+max_packet_size)){
    	puts("Packet too large while inserting Router Solicitation header (should be using Frag. option?)");
    	exit(EXIT_FAILURE);
    }

    rs= (struct nd_router_solicit *) (ptr);
    rs->nd_rs_type = ND_ROUTER_SOLICIT;
    rs->nd_rs_code = 0;
    
    ptr += sizeof(struct nd_router_solicit);
    
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
        	exit(EXIT_FAILURE);
        }
    }
    
    startofprefixes = ptr;    

}


/*
 * Function: send_packet()
 *
 * Initialize the remaining fields of the Router Solicitation Message, and
 * send the attack apcket(s).
 */
void send_packet(void){
	sources=0;	

	do{
		if(floods_f){
		/* 
		   When randomizing a link-local IPv6 address, select addresses that belong to
		   the prefix fe80::/64 (that's what a link-local address looks-like in legitimate
		   cases). The KAME implementation discards addresses in which the second highest-order
		   16 bits (srcaddr.s6_addr16[1] in our case) are not zero.
		*/
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

		if(nlinkaddr==1)
			linkaddrs=1;
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


			rs->nd_rs_cksum = 0;
			rs->nd_rs_cksum = in_chksum(v6buffer, rs, ptr-((char *)rs));


			if(!fragh_f){
				ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);

				if((nw=pcap_inject(pfd, buffer, ptr - buffer)) == -1){
					printf("pcap_inject(): %s\n", pcap_geterr(pfd));
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
				 * Check that the selected fragment size is not larger than the largest fragment 
				 * size that can be sent
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
						exit(EXIT_FAILURE);
					}

					if(nw != (fptr- fragbuffer)){
						printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw,\
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
 * Print the syntax of the rs6 tool
 */
void usage(void){
    puts("usage: rs6 -i INTERFACE [-s SRC_ADDR[/LEN]] [-d DST_ADDR] [-y FRAG_SIZE]"
	 " [-u DST_OPT_HDR_SIZE] [-U DST_OPT_U_HDR_SIZE] [-H HBH_OPT_HDR_SIZE]"
	 " [-S LINK_SRC_ADDR] [-D LINK-DST-ADDR] [-E LINK_ADDR] [-e] [-F N_SOURCES]"
	 " [-z SECONDS] [-l] [-v] [-h]");
}


/*
 * Function: print_help()
 *
 * Print help information for the rs6 tool
 */
void print_help(void){
	puts(SI6_TOOLKIT);
	puts( "rs6: Security assessment tool for attack vectors based on RS messages\n");
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
	     "  --src-link-opt, -E         Source link-layer address option\n"
	     "  --add-slla-opt, -e         Add Source link-layer address option\n"
	     "  --flood-sources, -F        Number of Source Addresses to forge randomly\n"
	     "  --loop, -l                 Send Router Solicitations periodically\n"
	     "  --sleep, -z                Pause between peiodic Router Solicitations\n"
	     "  --help, -h                 Print help for the rs6 tool\n"
	     "  --verbose, -v              Be verbose\n"
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
	if(floods_f)
		printf("Flooding the target from %u different IPv6 Source Addresses\n", nsources);

	if(!floods_f){
		if(ether_ntop(&hsrcaddr, plinkaddr, sizeof(plinkaddr)) == 0){
			puts("ether_ntop(): Error converting address");
			exit(EXIT_FAILURE);
		}

		printf("Ethernet Source Address: %s%s\n", plinkaddr, ((!hsrcaddr_f)?" (randomized)":""));
	}
    else{
		if(hsrcaddr_f){
			if(ether_ntop(&hsrcaddr, plinkaddr, sizeof(plinkaddr)) == 0){
				puts("ether_ntop(): Error converting address");
				exit(EXIT_FAILURE);
			}

			printf("Ethernet Source Address: %s\n", plinkaddr);
		}
		else
			puts("Ethernet Source Address: randomized for each packet");
	}

	if(ether_ntop(&hdstaddr, phdstaddr, sizeof(phdstaddr)) == 0){
		puts("ether_ntop(): Error converting address");
		exit(EXIT_FAILURE);
	}

    printf("Ethernet Destination Address: %s%s\n", phdstaddr, \
					((!hdstaddr_f)?" (all-routers multicast)":""));


	if(inet_ntop(AF_INET6, &srcaddr, psrcaddr, sizeof(psrcaddr)) == NULL){
		puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
		exit(EXIT_FAILURE);
	}

    if(!floods_f){
	printf("IPv6 Source Address: %s%s\n", psrcaddr, ((!srcaddr_f)?" (randomized)":""));
    }
    else{
    	printf("IPv6 Source Address: randomized, from the %s/%u prefix%s\n", psrcaddr, srcpreflen, \
    									(!srcprefix_f)?" (default)":"");
    }

	if(inet_ntop(AF_INET6, &dstaddr, pdstaddr, sizeof(pdstaddr)) == NULL){
		perror("inet_ntop()");
		exit(EXIT_FAILURE);
	}

	printf("IPv6 Destination Address: %s%s\n", pdstaddr, \
				((!dstaddr_f)?" (all-routers link-local multicast)":""));

	printf("IPv6 Hop Limit: %u%s\n", hoplimit, (hoplimit_f)?"":" (default)");

	for(i=0; i<ndstoptuhdr; i++)
		printf("Destination Options Header (Unfragmentable part): %u bytes\n", dstoptuhdrlen[i]);

	for(i=0; i<nhbhopthdr; i++)
		printf("Hop by Hop Options Header: %u bytes\n", hbhopthdrlen[i]);

	for(i=0; i<ndstopthdr; i++)
		printf("Destination Options Header: %u bytes\n", dstopthdrlen[i]);

	if(fragh_f)
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

    r=snprintf(ascii, s, "%02x:%02x:%02x:%02x:%02x:%02x", ether->a[0], ether->a[1], ether->a[2], ether->a[3], ether->a[4], ether->a[5]);

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

