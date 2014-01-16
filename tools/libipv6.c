#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/select.h>

#ifndef __FAVOR_BSD
	#define __FAVOR_BSD		/* This causes Linux to use the BSD definition of the TCP and UDP header fields */
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <ifaddrs.h>
#ifdef __linux__
	#include <asm/types.h>
	#include <linux/netlink.h>
	#include <linux/rtnetlink.h>
	#include <netpacket/packet.h>   /* For datalink structure */
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__) || defined(__FreeBSD_kernel__)
	#include <net/if_dl.h>
	#include <net/route.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <math.h>
#include <pcap.h>
#include <setjmp.h>
#include <pwd.h>

#include "libipv6.h"
#include "ipv6toolkit.h"


/* IPv6 Address Resolution */
sigjmp_buf			env;
unsigned int		canjump;

/* pcap variables */
char				errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program	pcap_filter;

#ifdef __linux__
/* Netlink requests */
struct nlrequest{
    struct nlmsghdr nl;
    struct rtmsg    rt;
    char   buf[MAX_NLPAYLOAD];
};
#endif

/*
 * Function: dns_decode()
 *
 * Decode a domain name from DNS wire format to an ASCII string
 */

int dns_decode(unsigned char *start, unsigned int size, unsigned char *ptr, \
				char *out, unsigned int outsize, unsigned char **next){
	unsigned char *end;
	char *w;
	unsigned int clabels=0, nlabels=0;
	end= start+size;
	w= out;

	while(nlabels <= MAX_DNS_LABELS){
		switch((*ptr & 0xc0)){
			case 0x00:
				/* No compression */

				/* Check wether the label spans past the end of the packet */
				if((ptr + *ptr) >= end)
					return(-1);

				/* Check whether there is room to write this label */
				if( (w+ *ptr + 1) >=(out+outsize))
					return(-1);

				/* Check whether this is a zero-label */
				if(*ptr == 0){
					ptr++;

					/* Check whether there is a single-label domain */
					if(ptr < end){
						if(*ptr == 0)
							ptr++;
					}

					if(w == out){
						*w='.';
						w++;
					}

					*w=0x00; /* null-terminate the string */

					/* If we're past a compressed label, '*next' already contains the right value */
					if(!clabels){
						if(ptr >= end)
							*next= NULL;
						else
							*next=ptr;
					}

					return(0);
				}
				else{
					bcopy( (ptr+1), w, *ptr);
					w= w + *ptr;
					*w= '.';
					w++;
					ptr= ptr+ (*ptr + 1);

					if(ptr >= end)
						return(-1);
				}

				break;

			case 0xc0:
				/* Compression */

				/* A compressed label ocuppies two bytes */
				if( (ptr+1) >= end)
					return(-1);

				/* The next domain is the one follong the two-byte compressed label */
				if(!clabels){
					*next= ptr+2;

					if(*next >= end)
						*next= NULL;
				}

				clabels++;

				if(clabels > MAX_DNS_CLABELS){
					return(-1);	
				}

				ptr= start + ((((unsigned short int)(*ptr & 0x3c))<< 8) + *(ptr+1));
				break;

			default:
				return(-1);
		}
	}

	return(0);
}



/*
 * dns_str2wire()
 *
 * Converts a DNS name to DNS wire format (uncompressed)
 */

int dns_str2wire(char *str, unsigned int slen, char *wire, unsigned int wlen){
	char *label, *src, *dst;
	unsigned int llen;

	if(wlen < slen)
		return(-1);

	src= str;
	dst= wire;

	while(1){

		llen=0;
		label= src;

		while(*src != 0 && *src != '.' && src < (str + slen)){
			src++;
			llen++;
		}
		
		*dst= llen;
		dst++;
		bcopy(label, dst, llen);
		dst+= llen;		

		if(*src == 0){
			*dst= 0;
			dst++;
			break;
		}
		else if(src >= (str + slen)){
			return(-1);
		}
		else{
			src++;
		}
	}

	return(dst-wire);
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
 * Function: find_ipv6_router_full()
 *
 * Finds a local router (by means of Neighbor Discovery)
 */

int find_ipv6_router_full(pcap_t *pfd, struct iface_data *idata){
	struct pcap_pkthdr			*pkthdr;
	const u_char				*pktdata;
	struct ether_header			*pkt_ether;
	struct ip6_hdr				*pkt_ipv6;
	struct nd_router_advert 	*pkt_ra;
	unsigned char				*pkt_end;
	unsigned char				*prev_nh;
	volatile unsigned char		*ptr;
	volatile unsigned char		*p;
	size_t						nw;

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
	unsigned char				error_f=0;
	int							result;

	rs_max_packet_size = idata->mtu;
	ether = (struct ether_header *) buffer;
	v6buffer = buffer + sizeof(struct ether_header);
	ipv6 = (struct ip6_hdr *) v6buffer;

	if(pcap_compile(pfd, &pcap_filter, PCAP_ICMPV6_RANS_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
		if(idata->verbose_f>1)
			printf("pcap_compile(): %s", pcap_geterr(pfd));

		return(-1);
	}
    
	if(pcap_setfilter(pfd, &pcap_filter) == -1){
		if(idata->verbose_f > 1)
			printf("pcap_setfilter(): %s", pcap_geterr(pfd));

		return(-1);
	}

	pcap_freecode(&pcap_filter);

	ipv6->ip6_flow=0;
	ipv6->ip6_vfc= 0x60;
	ipv6->ip6_hlim= 255;
	ipv6->ip6_src= idata->ip6_local;

	if ( inet_pton(AF_INET6, ALL_ROUTERS_MULTICAST_ADDR, &(ipv6->ip6_dst)) <= 0){
		if(idata->verbose_f>1)
			puts("inet_pton(): Error converting All Routers address from presentation to network format");

		return(-1);
	}

	ether->src = idata->ether;

	if(ether_pton(ETHER_ALLROUTERS_LINK_ADDR, &(ether->dst), sizeof(struct ether_addr)) == 0){
		if(idata->verbose_f>1)
			puts("ether_pton(): Error converting all-nodes multicast address");

		return(-1);
	}

	ether->ether_type = htons(ETHERTYPE_IPV6);

	prev_nh = (unsigned char *) &(ipv6->ip6_nxt);
	*prev_nh = IPPROTO_ICMPV6;

	ptr = (unsigned char *) v6buffer + MIN_IPV6_HLEN;

	if( (ptr+sizeof(struct nd_router_solicit)) > (v6buffer+rs_max_packet_size)){
		if(idata->verbose_f>1)
			puts("Packet too large while inserting Router Solicitation header");

		return(-1);
	}

	rs= (struct nd_router_solicit *) (ptr);

	rs->nd_rs_type = ND_ROUTER_SOLICIT;
	rs->nd_rs_code = 0;
	rs->nd_rs_reserved = 0;

	ptr += sizeof(struct nd_router_solicit);
	sllaopt = (struct nd_opt_slla *) ptr;    

	if( (ptr+sizeof(struct nd_opt_slla)) > (v6buffer+rs_max_packet_size)){
		if(idata->verbose_f>1)
			puts("RS message too large while processing source link-layer addresss opt.");

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
		if(idata->verbose_f>1)
			puts("Error setting up 'Alarm' signal");

		return(-1);
	}

	if(sigsetjmp(env, 1) != 0)
		tries++;

	canjump=1;

	while(tries<3 && !foundrouter && !error_f){
		if((nw=pcap_inject(pfd, buffer, ptr - buffer)) == -1){
			if(idata->verbose_f>1)
				printf("pcap_inject(): %s\n", pcap_geterr(pfd));

			error_f=1;
			break;
		}

		if(nw != (ptr-buffer)){
			if(idata->verbose_f>1)
				printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, \
												(LUI) (ptr-buffer));

			error_f=1;
			break;
		}

		alarm(idata->local_timeout + 1);
		
		while(!foundrouter && !error_f){

			do{
				if( (result=pcap_next_ex(pfd, &pkthdr, &pktdata)) == -1){
					if(idata->verbose_f>1)
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
			   Discard the packet if it is not of the minimum size to contain a Router Advertisement
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
			   and we compute the checksum over the received packet (including the Checksum field)
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
									if(idata->verbose_f>1)
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

						/*
						   We expect the autoconfiguration prefix to have a length between 32 and 64 bits.
						   We used to require it to be 64-bits long, but some routers have been found to advertise
						   48-bit long prefixes. Hence, we have relaxed the allowed length.
						 */
						if(idata->prefix_ac.nprefix < idata->prefix_ac.maxprefix){
							if( (pio->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_AUTO) && \
								(pio->nd_opt_pi_prefix_len >= 32 && pio->nd_opt_pi_prefix_len <= 64) && \
								!is_ip6_in_prefix_list(&(pio->nd_opt_pi_prefix), &(idata->prefix_ac))){

								if((idata->prefix_ac.prefix[idata->prefix_ac.nprefix] = \
																		malloc(sizeof(struct prefix_entry))) == NULL){
									if(idata->verbose_f>1)
										puts("Error in malloc() while learning prefixes");

									error_f=1;
									break;
								}

								(idata->prefix_ac.prefix[idata->prefix_ac.nprefix])->ip6= \
												pio->nd_opt_pi_prefix;

								/*
								   If the prefix is valid, we assume it to be 64-bit long. In the past, we used
								   the length advertised by pio->nd_opt_pi_prefix_len.
								 */
								(idata->prefix_ac.prefix[idata->prefix_ac.nprefix])->len= 64;

								sanitize_ipv6_prefix(&((idata->prefix_ac.prefix[idata->prefix_ac.nprefix])->ip6), \
														(idata->prefix_ac.prefix[idata->prefix_ac.nprefix])->len);

								if(!idata->ip6_global_flag && idata->ip6_global.nprefix < idata->ip6_global.maxprefix){
								
									if( (idata->ip6_global.prefix[idata->ip6_global.nprefix] = \
																	malloc(sizeof(struct prefix_entry))) == NULL){
										if(idata->verbose_f>1)
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

					default:
						break;
				}

				p= p + *(p+1) * 8;
			} /* Processing options */

		} /* Processing packets */

	} /* Resending Router Solicitations */

	/* If we added at least one global address, we set the corresponding flag to 1 */
	if(idata->ip6_global.nprefix)
		idata->ip6_global_flag=1;

	if( sigaction(SIGALRM, &old_sig, NULL) == -1){
		if(idata->verbose_f>1)
			puts("Error setting up 'Alarm' signal");

		return(-1);
	}

	if(foundrouter)
		return 1;
	else
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
 * Function: ether_to_ipv6_linklocal()
 *
 * Generates an IPv6 link-local address (with modified EUI-64 identifiers) based on
 * an Ethernet address.
 */

void ether_to_ipv6_linklocal(struct ether_addr *etheraddr, struct in6_addr *ipv6addr){
	unsigned int i;
	ipv6addr->s6_addr16[0]= htons(0xfe80); /* Link-local unicast prefix */

	for(i=1;i<4;i++)
		ipv6addr->s6_addr16[i]=0x0000;

	ipv6addr->s6_addr16[4]=  htons(((u_int16_t)etheraddr->a[0] << 8) | etheraddr->a[1]);
	ipv6addr->s6_addr16[5]=  htons( ((u_int16_t)etheraddr->a[2] << 8) | 0xff);
	ipv6addr->s6_addr16[6]=  htons((u_int16_t) 0xfe00 | etheraddr->a[3]);
	ipv6addr->s6_addr16[7]=  htons(((u_int16_t)etheraddr->a[4] << 8) | etheraddr->a[5]);
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
	struct bpf_program			pcap_filter;
	struct pcap_pkthdr			*pkthdr;
	const u_char				*pktdata;
	struct ether_header			*pkt_ether;
	struct ip6_hdr				*pkt_ipv6;
	struct nd_neighbor_advert 	*pkt_na;
	unsigned char				*pkt_end, *prev_nh;
	volatile unsigned char		*ptr, *p;

	unsigned char				buffer[65556];
	unsigned int 				ns_max_packet_size;
	struct ether_header			*ether;
	unsigned char 				*v6buffer;
	struct ip6_hdr				*ipv6;
	struct nd_neighbor_solicit	*ns;
	struct nd_opt_slla			*sllaopt;
	volatile unsigned int		tries=0;
	unsigned int				foundaddr=0;
	struct sigaction			new_sig, old_sig;
	int							result;
	unsigned char				error_f=0;
	size_t						nw;

	ns_max_packet_size = idata->mtu;

	ether = (struct ether_header *) buffer;
	v6buffer = buffer + sizeof(struct ether_header);
	ipv6 = (struct ip6_hdr *) v6buffer;

	if(pcap_compile(idata->pfd, &pcap_filter, PCAP_ICMPV6_NA_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
		if(idata->verbose_f>1)
			printf("pcap_compile(): %s", pcap_geterr(idata->pfd));

		return(-1);
	}
    
	if(pcap_setfilter(idata->pfd, &pcap_filter) == -1){
		if(idata->verbose_f>1)
			printf("pcap_setfilter(): %s", pcap_geterr(idata->pfd));

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
	ether->ether_type = htons(ETHERTYPE_IPV6);

	prev_nh = (unsigned char *) &(ipv6->ip6_nxt);
	*prev_nh = IPPROTO_ICMPV6;

	ptr = (unsigned char *) v6buffer + MIN_IPV6_HLEN;

	if( (ptr+sizeof(struct nd_neighbor_solicit)) > (v6buffer+ns_max_packet_size)){
		if(idata->verbose_f>1)
			puts("Packet too large while inserting Neighbor Solicitation header");

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
		if(idata->verbose_f>1)
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

	/* We set the signal handler, and the anchor for siglongjump() */
	canjump=0;
	bzero(&new_sig, sizeof(struct sigaction));
	sigemptyset(&new_sig.sa_mask);
	new_sig.sa_handler= &sig_alarm;

	alarm(0);

	if( sigaction(SIGALRM, &new_sig, &old_sig) == -1){
		if(idata->verbose_f>1)
			puts("Error setting up 'Alarm' signal");

		return(-1);
	}

	if(sigsetjmp(env, 1) != 0)
		tries++;

	canjump=1;

	while(tries<3 && !foundaddr && !error_f){
		if((nw=pcap_inject(idata->pfd, buffer, ptr - buffer)) == -1){
			if(idata->verbose_f>1)
				printf("pcap_inject(): %s\n", pcap_geterr(idata->pfd));

			error_f=1;
			break;
		}

		if(nw != (ptr-buffer)){
			if(idata->verbose_f>1)
				printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, \
												(LUI) (ptr-buffer));
			error_f=1;
			break;
		}

		alarm(idata->local_timeout);
		
		while(!foundaddr && !error_f){
			do{
				if( (result=pcap_next_ex(idata->pfd, &pkthdr, &pktdata)) == -1){
					if(idata->verbose_f>1)
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

	if( sigaction(SIGALRM, &old_sig, NULL) == -1){
		if(idata->verbose_f>1)
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
 * Function: generate_slaac_address()
 *
 * Generates an IPv6 address (with modified EUI-64 identifiers) based on
 * a IPv6 prefix and an Ethernet address.
 */

void generate_slaac_address(struct in6_addr *prefix, struct ether_addr *etheraddr, struct in6_addr *ipv6addr){
	unsigned int	i;
	ipv6addr->s6_addr16[0]= htons(0xfe80); /* Link-local unicast prefix */

	for(i=0;i<4;i++)
		ipv6addr->s6_addr16[i]= prefix->s6_addr16[i];

	ipv6addr->s6_addr16[4]=  htons(((u_int16_t) (etheraddr->a[0] | 0x02) << 8) | etheraddr->a[1]);
	ipv6addr->s6_addr16[5]=  htons( ((u_int16_t)etheraddr->a[2] << 8) | 0xff);
	ipv6addr->s6_addr16[6]=  htons((u_int16_t) 0xfe00 | etheraddr->a[3]);
	ipv6addr->s6_addr16[7]=  htons(((u_int16_t)etheraddr->a[4] << 8) | etheraddr->a[5]);
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
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__) || defined(__FreeBSD_kernel__)
	struct sockaddr_dl	*sockpptr;
#endif

	if(getifaddrs(&ifptr) != 0){
		if(idata->verbose_f > 1){
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
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__) || defined(__FreeBSD_kernel__)
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
#if defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__) || defined(__FreeBSD_kernel__)
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
								if(idata->verbose_f > 1)
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
 * Function: is_ip6_in_address_list()
 *
 * Checks whether an IPv6 address is present in an address list.
 */

int is_ip6_in_address_list(struct prefix_list *plist, struct in6_addr *target){
	unsigned int i, j;

	for(i=0; i < plist->nprefix; i++){
		for(j=0; j < 8; j++){
			if(target->s6_addr16[j] != (plist->prefix[i])->ip6.s6_addr16[j])
				break;
		}

		if(j == 8)
			return 1;
	}

	return 0;
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

		if(j == full16){
			if(rest16 == 0)
				return 1;
			else{
				mask16 = mask16 << (16 - rest16);

				if( (target->s6_addr16[full16] & mask16) == ((plist->prefix[i])->ip6.s6_addr16[full16] & mask16))
					return 1;
			}
		}
	}

	return 0;
}


/*
 * Function: is_time_elapsed()
 *
 * Checks whether a specific amount of time has elapsed. (i.e., whether curtime >= lastprobe + delta
 */

int is_time_elapsed(struct timeval *curtime, struct timeval *lastprobe, unsigned long delta){
		if( curtime->tv_sec > (lastprobe->tv_sec + delta / 1000000) ){
			return(1);
		}else if( curtime->tv_sec == (lastprobe->tv_sec + delta / 1000000)){
			if( curtime->tv_usec > (lastprobe->tv_usec + delta % 1000000) ){
				return(1);
			}
		}

		return(0);

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
 * Function: print_filters()
 *
 * Prints the filters that will be applied to incoming packets.
 */

void print_filters(struct iface_data *idata, struct filters *filters){
	unsigned int	i;
	char 			plinkaddr[ETHER_ADDR_PLEN];
	char			pv6addr[INET6_ADDRSTRLEN];

	if(filters->nblocksrc){
		printf("Block filter for IPv6 Source Addresss: ");
	
		for(i=0; i< filters->nblocksrc; i++){
			if(inet_ntop(AF_INET6, &(filters->blocksrc[i]), pv6addr, sizeof(pv6addr)) == NULL){
				puts("inet_ntop(): Error converting IPv6 Src. Addr. filter to presentation format");
				exit(EXIT_FAILURE);
			}

			printf("%s/%u   ", pv6addr, filters->blocksrclen[i]);
		}
		printf("\n");
	}

	if(filters->nblockdst){
		printf("Block filter for IPv6 Destination Address: ");
	
		for(i=0; i< filters->nblockdst; i++){
			if(inet_ntop(AF_INET6, &(filters->blockdst[i]), pv6addr, sizeof(pv6addr)) == NULL){
				puts("inet_ntop(): Error converting IPv6 Dst. Addr. filter to presentation format");
				exit(EXIT_FAILURE);
			}

			printf("%s/%u   ", pv6addr, filters->blockdstlen[i]);
		}
		printf("\n");
	}

	if(filters->nblocktarget){
		printf("Block filter for Target Address: ");
	
		for(i=0; i< filters->nblocktarget; i++){
			if(inet_ntop(AF_INET6, &(filters->blocktarget[i]), pv6addr, sizeof(pv6addr)) == NULL){
				puts("inet_ntop(): Error converting Target Addr. filter to presentation format");
				exit(EXIT_FAILURE);
			}

			printf("%s/%u   ", pv6addr, filters->blocktargetlen[i]);
		}
		printf("\n");
	}

	if(idata->type == DLT_EN10MB && idata->flags != IFACE_LOOPBACK){
		if(filters->nblocklinksrc){
			printf("Block filter for link-layer Source Address: ");
	
			for(i=0; i < filters->nblocklinksrc; i++){
				if(ether_ntop(&(filters->blocklinksrc[i]), plinkaddr, sizeof(plinkaddr)) == 0){
					puts("ether_ntop(): Error converting address");
					exit(EXIT_FAILURE);
				}
			
				printf("%s   ", plinkaddr);
			}
			printf("\n");
		}

		if(filters->nblocklinkdst){
			printf("Block filter for link-layer Destination Address: ");
	
			for(i=0; i < filters->nblocklinkdst; i++){
				if(ether_ntop(&(filters->blocklinkdst[i]), plinkaddr, sizeof(plinkaddr)) == 0){
					puts("ether_ntop(): Error converting address");
					exit(EXIT_FAILURE);
				}
		
				printf("%s   ", plinkaddr);
			}
			printf("\n");
		}
	}

	if(filters->nacceptsrc){
		printf("Accept filter for IPv6 Source Addresss: ");

		for(i=0; i < filters->nacceptsrc; i++){
			if(inet_ntop(AF_INET6, &(filters->acceptsrc[i]), pv6addr, sizeof(pv6addr)) == NULL){
				puts("inet_ntop(): Error converting IPv6 Src. Addr. filter to presentation format");
				exit(EXIT_FAILURE);
			}

			printf("%s/%u   ", pv6addr, filters->acceptsrclen[i]);
		}
		printf("\n");
	}

	if(filters->nacceptdst){
		printf("Accept filter for IPv6 Destination Address: ");
	
		for(i=0; i < filters->nacceptdst; i++){
			if(inet_ntop(AF_INET6, &(filters->acceptdst[i]), pv6addr, sizeof(pv6addr)) == NULL){
				puts("inet_ntop(): Error converting IPv6 Dst. Addr. filter to presentation format");
				exit(EXIT_FAILURE);
			}

			printf("%s/%u   ", pv6addr, filters->acceptdstlen[i]);
		}
		printf("\n");
	}

	if(filters->naccepttarget){
		printf("Accept filter for Target Address: ");
	
		for(i=0; i < filters->naccepttarget; i++){
			if(inet_ntop(AF_INET6, &(filters->accepttarget[i]), pv6addr, sizeof(pv6addr)) == NULL){
				puts("inet_ntop(): Error converting Target Addr. filter to presentation format");
				exit(EXIT_FAILURE);
			}

			printf("%s/%u   ", pv6addr, filters->accepttargetlen[i]);
		}
		printf("\n");
	}

	if(idata->type == DLT_EN10MB && idata->flags != IFACE_LOOPBACK){
		if(filters->nacceptlinksrc){
			printf("Accept filter for link-layer Source Address: ");

			for(i=0; i < filters->nacceptlinksrc; i++){
				if(ether_ntop(&(filters->acceptlinksrc[i]), plinkaddr, sizeof(plinkaddr)) == 0){
					puts("ether_ntop(): Error converting address");
					exit(EXIT_FAILURE);
				}
		
				printf("%s   ", plinkaddr);
			}
			printf("\n");
		}

		if(filters->nacceptlinkdst){
			printf("Accept filter for link-layer Destination Address: ");
	
			for(i=0; i < filters->nacceptlinkdst; i++){
				if(ether_ntop(&(filters->acceptlinkdst[i]), plinkaddr, sizeof(plinkaddr)) == 0){
					puts("ether_ntop(): Error converting address");
					exit(EXIT_FAILURE);
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
 * Prints infromation about an incoming packet and whether it was blocked or
 * accepted by a filter.
 */

void print_filter_result(struct iface_data *idata, const u_char *pkt_data, unsigned char fresult){
	struct ip6_hdr *pkt_ipv6;
	char		psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN];
	
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_data + idata->linkhsize);

	if(inet_ntop(AF_INET6, &(pkt_ipv6->ip6_src), psrcaddr, sizeof(psrcaddr)) == NULL){
	    puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
	    exit(EXIT_FAILURE);
	}

	if(inet_ntop(AF_INET6, &(pkt_ipv6->ip6_dst), pdstaddr, sizeof(pdstaddr)) == NULL){
	    puts("inet_ntop(): Error converting IPv6 Destination Address to presentation format");
	    exit(EXIT_FAILURE);
	}

	printf("Received IPv6 packet from %s to %s (%s)\n", psrcaddr, pdstaddr, \
					    ((fresult == ACCEPTED)?"accepted":"blocked") );

}



/*
 * randomize_ether_addr()
 *
 * Select a random Ethernet address.
 */

void randomize_ether_addr(struct ether_addr *ethaddr){
	unsigned int i;

	for(i=0; i<6; i++)
		ethaddr->a[i]= random();

	ethaddr->a[0]= (ethaddr->a[0] & 0xfc) | 0x02;
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
 * release_privileges()
 *
 * Releases superuser privileges by switching to the real uid and gid, or to nobody
 */

void release_privileges(void){
	uid_t			ruid;
	gid_t			rgid;
	struct passwd	*pwdptr;

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
 * Function: src_addr_sel2()
 *
 * Selects a Source Address for a given Destination Address (old function)
 */

struct in6_addr *sel_src_addr_ra(struct iface_data *idata, struct in6_addr *dst){
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
	unsigned int				i;
	size_t						nw;
	struct ether_header			*pkt_ether;
	struct ip6_hdr				*pkt_ipv6;
	struct nd_neighbor_solicit	*pkt_ns;
	unsigned char				*ptr;
	struct ether_header			*ethernet;
	unsigned char 				*v6buffer;
	struct ip6_hdr				*ipv6;
	struct nd_neighbor_advert	*na;
	struct nd_opt_tlla			*tllaopt;
	struct in6_addr				*pkt_ipv6addr;
	unsigned char				wbuffer[2500];

	if(idata->mtu > sizeof(wbuffer)){
		if(idata->verbose_f)
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

	ethernet->ether_type = htons(ETHERTYPE_IPV6);
	ipv6->ip6_flow=0;
	ipv6->ip6_vfc= 0x60;
	ipv6->ip6_hlim= 255;
	ipv6->ip6_nxt= IPPROTO_ICMPV6;

	if( (ptr+sizeof(struct nd_neighbor_advert)) > (v6buffer+idata->mtu)){
		if(idata->verbose_f)
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
		if(idata->verbose_f)
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
			if(idata->verbose_f)
				puts("send_neighbor_advert(): Error converting all-nodes multicast address");

			return(-1);
		}

		if(ether_pton(ETHER_ALLNODES_LINK_ADDR, &(ethernet->dst), ETHER_ADDR_LEN) == 0){
			if(idata->verbose_f)
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
		if(idata->verbose_f)
			printf("send_neighbor_advert(): pcap_inject(): %s", pcap_geterr(pfd));

		return(-1);
	}

	if(nw != (ptr-wbuffer)){
		if(idata->verbose_f)
			printf("send_neighbor_advert(): pcap_inject(): only wrote %lu bytes "
							"(rather than %lu bytes)\n", (LUI) nw, (LUI) (ptr-wbuffer));

		return(-1);
	}

	return 0;
}


/*
 * Function: string_escapes()
 *
 * Replace some escape sequences in a string
 */

int string_escapes(char *data, unsigned int *datalen, unsigned int maxlen){
	char *org, *dst;
	org=data;
	dst=data;

	while(org < (data+ *datalen) && dst <= (data+maxlen)){
		if(*org == '\\'){
			if((org+1) < (data+ *datalen)){
				org++;

				switch(*org){
					case '\\':
						*dst= '\\';
						break;

					case 'n':
						*dst= CHAR_LF;
						break;

					case 'r':
						*dst= CHAR_CR;
						break;

					default:
						return 0;
				}
			}
			else
				*dst= *org;
		}
		else{
			if(org != dst)
				*dst = *org;
		}

		org++;
		dst++;
	}

	*datalen= dst - data;
	return 1;
}



/*
 * Function: Strnlen()
 *
 * Our own version of strnlen(), since some OSes do not support it.
 */

size_t Strnlen(const char *s, size_t maxlen){
	size_t i=0;

	while(s[i] != 0 && i < maxlen)
		i++;

	if(i < maxlen)
		return(i);
	else
		return(maxlen);
}


/*
 * Function: init_iface_data()
 *
 * Initializes the contents of "iface_data" structure
 */

int init_iface_data(struct iface_data *idata){
	unsigned int i;

	memset(idata, 0, sizeof(struct iface_data));

	idata->mtu= ETH_DATA_LEN;
	idata->local_retrans = 0;
	idata->local_timeout = 1;

	if( (idata->ip6_global.prefix= malloc(MAX_LOCAL_ADDRESSES * sizeof(struct prefix_entry *))) == NULL)
		return(FAILURE);

	idata->ip6_global.nprefix=0;
	idata->ip6_global.maxprefix= MAX_LOCAL_ADDRESSES;

	if( (idata->prefix_ol.prefix= malloc(MAX_PREFIXES_ONLINK * sizeof(struct prefix_entry *))) == NULL)
		return(FAILURE);

	idata->prefix_ol.nprefix= 0;
	idata->prefix_ol.maxprefix= MAX_PREFIXES_ONLINK;

	if( (idata->prefix_ac.prefix= malloc(MAX_PREFIXES_AUTO * sizeof(struct prefix_entry *))) == NULL)
		return(FAILURE);

	idata->prefix_ac.nprefix= 0;
	idata->prefix_ac.maxprefix= MAX_PREFIXES_AUTO;

	if( ((idata->iflist).ifaces= malloc(sizeof(struct iface_entry) * MAX_IFACES)) == NULL)
		return(FAILURE);

	memset((idata->iflist).ifaces, 0, sizeof(struct iface_entry) * MAX_IFACES);

	idata->iflist.nifaces=0;
	idata->iflist.maxifaces= MAX_IFACES;

	for(i=0; i<MAX_IFACES; i++){
		if(( (idata->iflist).ifaces[i].ip6_global.prefix= malloc( sizeof(struct prefix_entry *) * MAX_LOCAL_ADDRESSES)) == NULL){
			return(FAILURE);
		}

		(idata->iflist).ifaces[i].ip6_global.maxprefix= MAX_LOCAL_ADDRESSES;

		if( ((idata->iflist).ifaces[i].ip6_local.prefix= malloc( sizeof(struct prefix_entry *) * MAX_LOCAL_ADDRESSES)) == NULL){
			return(FAILURE);
		}

		(idata->iflist).ifaces[i].ip6_local.maxprefix= MAX_LOCAL_ADDRESSES;
	}

	return SUCCESS;
}




/*
 * Function: init_filters()
 *
 * Initializes a filters structure, and allocates memory for the filter data.
 */

int init_filters(struct filters *filters){
	memset(filters, 0, sizeof(struct filters));

	if( (filters->blocksrc= malloc(sizeof(struct in6_addr) * MAX_BLOCK_SRC)) == NULL)
		return(-1);

	if( (filters->blockdst= malloc(sizeof(struct in6_addr) * MAX_BLOCK_DST)) == NULL)
		return(-1);

	if( (filters->blocktarget= malloc(sizeof(struct in6_addr) * MAX_BLOCK_TARGET)) == NULL)
		return(-1);

	if( (filters->blocklinksrc= malloc(sizeof(struct ether_addr) * MAX_BLOCK_LINK_SRC)) == NULL)
		return(-1);

	if( (filters->blocklinkdst= malloc(sizeof(struct ether_addr) * MAX_BLOCK_LINK_DST)) == NULL)
		return(-1);

	if( (filters->blocksrclen= malloc(sizeof(u_int8_t) * MAX_BLOCK_SRC)) == NULL)
		return(-1);

	if( (filters->blockdstlen= malloc(sizeof(u_int8_t) * MAX_BLOCK_DST)) == NULL)
		return(-1);

	if( (filters->blocktargetlen= malloc(sizeof(u_int8_t) * MAX_BLOCK_TARGET)) == NULL)
		return(-1);

	if( (filters->acceptsrc= malloc(sizeof(struct in6_addr) * MAX_ACCEPT_SRC)) == NULL)
		return(-1);

	if( (filters->acceptdst= malloc(sizeof(struct in6_addr) * MAX_ACCEPT_DST)) == NULL)
		return(-1);

	if( (filters->accepttarget= malloc(sizeof(struct in6_addr) * MAX_ACCEPT_TARGET)) == NULL)
		return(-1);

	if( (filters->acceptlinksrc= malloc(sizeof(struct ether_addr) * MAX_ACCEPT_LINK_SRC)) == NULL)
		return(-1);

	if( (filters->acceptlinkdst= malloc(sizeof(struct ether_addr) * MAX_ACCEPT_LINK_DST)) == NULL)
		return(-1);

	if( (filters->acceptsrclen= malloc(sizeof(u_int8_t) * MAX_ACCEPT_SRC)) == NULL)
		return(-1);

	if( (filters->acceptdstlen= malloc(sizeof(u_int8_t) * MAX_ACCEPT_DST)) == NULL)
		return(-1);

	if( (filters->accepttargetlen= malloc(sizeof(u_int8_t) * MAX_ACCEPT_TARGET)) == NULL)
		return(-1);

	return(0);
}



/*
 * Function: sel_next_hop_ra()
 *
 * Performs next hop determination by sending the necessary packets
 *
 */

int sel_next_hop_ra(struct iface_data *idata){
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
	if((idata->type == DLT_EN10MB && (idata->flags != IFACE_LOOPBACK && idata->flags != IFACE_TUNNEL)) && \
													(!(idata->hdstaddr_f) && idata->dstaddr_f)){
		if(IN6_IS_ADDR_LINKLOCAL(&(idata->dstaddr))){
			/*
			   If the IPv6 Destination Address is a multicast address, there is no need
			   to perform Neighbor Discovery
			 */
			if(IN6_IS_ADDR_MC_LINKLOCAL(&(idata->dstaddr))){
				idata->hdstaddr= ether_multicast(&(idata->dstaddr));
			}
			else if(ipv6_to_ether(idata->pfd, idata, &(idata->dstaddr), &(idata->hdstaddr)) != 1){
				if(idata->verbose_f)
					puts("Error while performing Neighbor Discovery for the Destination Address");

				return(-1);
			}
		}
		else if(find_ipv6_router_full(idata->pfd, idata) == 1){
			if(match_ipv6_to_prefixes(&(idata->dstaddr), &(idata->prefix_ol))){
				/* If address is on-link, we must perform Neighbor Discovery */
				if(ipv6_to_ether(idata->pfd, idata, &(idata->dstaddr), &(idata->hdstaddr)) != 1){
					if(idata->verbose_f)
						puts("Error while performing Neighbor Discovery for the Destination Address");

					return(-1);
				}
			}
			else{
				idata->hdstaddr= idata->router_ether;
			}
		}
		else{
			if(idata->verbose_f)
				puts("Couldn't find local router. Now trying Neighbor Discovery for the target node");
			/*
			 * If we were not able to find a local router, we assume the destination is "on-link" (as
			 * a last ressort), and thus perform Neighbor Discovery for that destination
			 */
			if(ipv6_to_ether(idata->pfd, idata, &(idata->dstaddr), &(idata->hdstaddr)) != 1){
				if(idata->verbose_f)
					puts("Error while performing Neighbor Discovery for the Destination Address");

				return(-1);
			}
		}
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


/*
 * Function: send_neighbor_solicit()
 *
 * Sends a Neighbor Advertisement message for a target address
*/
int send_neighbor_solicit(struct iface_data *idata, struct in6_addr *target){
	unsigned char			*ptr, *prev_nh;
	unsigned char			buffer[65556];
	unsigned int 			ns_max_packet_size;
	struct ether_header		*ether;
	unsigned char 			*v6buffer;
	size_t					nw;
	struct ip6_hdr			*ipv6;
	struct nd_neighbor_solicit	*ns;
	struct nd_opt_slla		*sllaopt;

	ns_max_packet_size = idata->mtu;

	ether = (struct ether_header *) buffer;
	v6buffer = buffer + idata->linkhsize;
	ipv6 = (struct ip6_hdr *) v6buffer;

	ether->src = idata->ether;
	ether->dst = ether_multicast(&(ipv6->ip6_dst));
	ether->ether_type = htons(ETHERTYPE_IPV6);

	ipv6->ip6_flow=0;
	ipv6->ip6_vfc= 0x60;
	ipv6->ip6_hlim= 255;
	ipv6->ip6_src= idata->srcaddr;
	ipv6->ip6_dst= solicited_node(&(idata->dstaddr));

	prev_nh = (unsigned char *) &(ipv6->ip6_nxt);
	*prev_nh = IPPROTO_ICMPV6;

	ptr = (unsigned char *) v6buffer + MIN_IPV6_HLEN;

	if( (ptr+sizeof(struct nd_neighbor_solicit)) > (v6buffer+ns_max_packet_size)){
		if(idata->verbose_f>1)
			puts("Packet too large while inserting Neighbor Solicitation header");

		return(-1);
	}

	ns= (struct nd_neighbor_solicit *) (ptr);

	ns->nd_ns_type = ND_NEIGHBOR_SOLICIT;
	ns->nd_ns_code = 0;
	ns->nd_ns_reserved = 0;
	ns->nd_ns_target = *target;

	ptr += sizeof(struct nd_neighbor_solicit);
	sllaopt = (struct nd_opt_slla *) ptr;    

	if( (ptr+sizeof(struct nd_opt_slla)) > (v6buffer+ns_max_packet_size)){
		if(idata->verbose_f>1)
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

	if((nw=pcap_inject(idata->pfd, buffer, ptr - buffer)) == -1){
		if(idata->verbose_f>1)
			printf("pcap_inject(): %s\n", pcap_geterr(idata->pfd));

		return(-1);
	}

	if(nw != (ptr-buffer)){
		if(idata->verbose_f > 1)
			printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, \
											(LUI) (ptr-buffer));
		return(-1);
	}

	return 0;
}


#ifdef __linux__
/*
 * Function: sel_next_hop()
 *
 * Find the next hop for a target destination
*/
int sel_next_hop(struct iface_data *idata){
	int 				sockfd;
	struct sockaddr_nl	addr, them;
	int 				ret;
	pid_t				pid;
	char				reply[MAX_NLPAYLOAD];
	struct msghdr		msg;
	struct iovec		iov;
	struct nlrequest	req;
	struct nlmsghdr		*nlp;
	struct rtmsg		*rtp;
	struct rtattr		*rtap;
	int					nll,rtl;
	unsigned char		skip_f;

	if( (sockfd=socket(AF_NETLINK,SOCK_RAW,NETLINK_ROUTE)) == -1){
		if(idata->verbose_f)
			puts("Error in socket()");

		return(FAILURE);
	}

	memset((void *)&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = pid= getpid();
	addr.nl_groups = RTMGRP_IPV6_ROUTE;

	if(bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0){
		if(idata->verbose_f)
			puts("Error in bind()");

		close(sockfd);
		return(FAILURE);
	}

	memset(&req, 0, sizeof(req));
	req.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nl.nlmsg_flags = NLM_F_REQUEST;
	req.nl.nlmsg_type = RTM_GETROUTE;
	req.rt.rtm_family= AF_INET6;

	rtap = (struct rtattr *) req.buf;

	/* Destination Address */
	if(idata->dstaddr_f){
		rtap->rta_type = RTA_DST;
		rtap->rta_len = RTA_SPACE(sizeof(idata->dstaddr));
		memcpy(RTA_DATA(rtap), &(idata->dstaddr), sizeof(idata->dstaddr));
		req.nl.nlmsg_len += rtap->rta_len;
	}

	/* Source Address */
	if(idata->srcaddr_f){
		rtap = (struct rtattr *)((char *)rtap + (rtap->rta_len));
		rtap->rta_type = RTA_SRC;
		rtap->rta_len = RTA_SPACE(sizeof(idata->srcaddr));
		memcpy(RTA_DATA(rtap), &(idata->srcaddr), sizeof(idata->srcaddr));
		req.nl.nlmsg_len += rtap->rta_len;
	}

	/* address it */
	memset(&them, 0, sizeof(them));
	them.nl_family = AF_NETLINK;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&them;
	msg.msg_namelen = sizeof(them);

	iov.iov_base = (void *) &req.nl;
	iov.iov_len  = req.nl.nlmsg_len;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/* send it */
	if( (ret = sendmsg(sockfd, &msg, 0)) < 0){
		if(idata->verbose_f)
			puts("Error in send()");

		close(sockfd);
		return(FAILURE);
	}

	memset(reply, 0, sizeof(reply));

	if( (ret = recv(sockfd, reply, sizeof(reply), 0)) < 0){
		if(idata->verbose_f)
			puts("Error in recv()");

		close(sockfd);
		return(FAILURE);
	}

	nll = ret;


	/*
	   This should eventually be improved to handle the case where messages are lost, since Netlink messages
	   reliable.
	 */
	for(nlp = (struct nlmsghdr *)reply; NLMSG_OK(nlp,nll); nlp = NLMSG_NEXT(nlp, nll)){
		rtp = (struct rtmsg *) NLMSG_DATA(nlp);

		skip_f=0;

		if(rtp->rtm_family == AF_INET6){
			for(rtap = (struct rtattr *) RTM_RTA(rtp), rtl = RTM_PAYLOAD(nlp); RTA_OK(rtap, rtl); rtap = RTA_NEXT(rtap,rtl)) {
				switch(rtap->rta_type){
					case RTA_DST:
						/* XXX
						   If Destination is different from Destination Address, this just means that we need to send
						   our packets to a local router

						if(!is_eq_in6_addr(&(idata->dstaddr), (struct in6_addr *) RTA_DATA(rtap)))
							skip_f=1;
						*/

						break;

					case RTA_OIF:
						idata->nhifindex= *((int *) RTA_DATA(rtap));
						if(if_indextoname(idata->nhifindex, idata->nhiface) == NULL){
							if(idata->verbose_f)
								puts("Error calling if_indextoname() from sel_next_hop()");
						}
						idata->nhifindex_f= 1;
						break;

					case RTA_GATEWAY:
						idata->nhaddr= *( (struct in6_addr *) RTA_DATA(rtap));
						idata->nhaddr_f= 1;
						break;
				}

				if(skip_f)
					break;
			}

			if(skip_f)
				continue;
		}
	}

	close(sockfd);

	if(idata->nhifindex_f){
		idata->nh_f=TRUE;
		return(SUCCESS);
	}
	else
		return(FAILURE);
}
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__) || defined(__FreeBSD_kernel__)
/*
 * Function: sel_next_hop()
 *
 * Find the next hop for a target destination
*/
int sel_next_hop(struct iface_data *idata){
	int					sockfd;
	pid_t				pid;
	int					seq;
	unsigned int		queries=0;
	char				reply[MAX_RTPAYLOAD];
	struct rt_msghdr	*rtm;
	struct sockaddr_in6	*sin6;
	struct	sockaddr_dl	*sockpptr;
	struct sockaddr		*sa;
	unsigned char		onlink_f=FALSE;

	if( (sockfd=socket(AF_ROUTE, SOCK_RAW, 0)) == -1){
		if(idata->verbose_f)
			puts("Error in socket() call from sel_next_hop()");

		return(FAILURE);
	}

	idata->nhaddr= idata->dstaddr;

	do{
		rtm= (struct rt_msghdr *) reply;
		memset(rtm, 0, sizeof(struct rt_msghdr));
		rtm->rtm_msglen= sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in6);
		rtm->rtm_version= RTM_VERSION;
		rtm->rtm_type= RTM_GET;
		rtm->rtm_addrs= RTA_DST;
		rtm->rtm_pid= pid= getpid();
		rtm->rtm_seq= seq= random();

		sin6= (struct sockaddr_in6 *) (rtm + 1);
		memset(sin6, 0, sizeof(struct sockaddr_in6));
		sin6->sin6_len= sizeof(struct sockaddr_in6);
		sin6->sin6_family= AF_INET6;
		sin6->sin6_addr= idata->nhaddr;

		if(write(sockfd, rtm, rtm->rtm_msglen) == -1){
			if(idata->verbose_f)
				puts("No route to the intenteded destination in the local routing table");

			return(FAILURE);
		}

		do{
			if( (read(sockfd, rtm, MAX_RTPAYLOAD)) < 0){
				puts("Error in read() call from sel_next_hop()");
				exit(1);
			}
		}while( rtm->rtm_type != RTM_GET || rtm->rtm_pid != pid || rtm->rtm_seq != seq);

		queries++;

		/* The rt_msghdr{} structure is fllowed by sockaddr structures */
		sa= (struct sockaddr *) (rtm+1);

		if(rtm->rtm_addrs & RTA_DST)
			SA_NEXT(sa);

		if(rtm->rtm_addrs & RTA_GATEWAY){
			if(sa->sa_family == AF_INET6){
				idata->nhaddr= ((struct sockaddr_in6 *) sa)->sin6_addr;
				idata->nhaddr_f=TRUE;
			}
			else if(sa->sa_family == AF_LINK){
				sockpptr = (struct sockaddr_dl *) (sa);
				idata->nhifindex= sockpptr->sdl_index;
				idata->nhifindex_f=TRUE;

				if(if_indextoname(idata->nhifindex, idata->nhiface) == NULL){
					puts("Error calling if_indextoname() from sel_next_hop()");
				}

				onlink_f=TRUE;
			}
		}
	}while(!onlink_f && queries < 2);

	close(sockfd);

	if(idata->nhifindex_f){
		if(IN6_IS_ADDR_LINKLOCAL(&(idata->nhaddr))){
			/* BSDs store the interface index in s6_addr16[1], so we must clear it */
			idata->nhaddr.s6_addr16[1] =0;
			idata->nhaddr.s6_addr16[2] =0;
			idata->nhaddr.s6_addr16[3] =0;
		}

		return(SUCCESS);
	}
	else
		return(FAILURE);
}
#endif




/*
 * Function: get_local_addrs()
 *
 * Obtains all local addresses (Ethernet and IPv6 addresses for all interfaces)
 */

int get_local_addrs(struct iface_data *idata){
	struct iface_entry		*cif;
	struct ifaddrs			*ifptr, *ptr;
	struct sockaddr_in6		*sockin6ptr;

#ifdef __linux__
	struct sockaddr_ll	*sockpptr;
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__) || defined(__FreeBSD_kernel__)
	struct sockaddr_dl	*sockpptr;
#endif

	if(getifaddrs(&ifptr) != 0){
		if(idata->verbose_f > 1){
			puts("Error in call to getifaddrs()");
		}
		return(FAILURE);
	}

	for(ptr=ifptr; ptr != NULL; ptr= ptr->ifa_next){
		if(ptr->ifa_addr == NULL)
			continue;

		if( (cif = find_iface_by_name( &(idata->iflist), ptr->ifa_name)) == NULL){
			if(idata->iflist.nifaces >= MAX_IFACES)
				continue;
			else{
				cif= &(idata->iflist.ifaces[idata->iflist.nifaces]);
				strncpy(cif->iface, ptr->ifa_name, IFACE_LENGTH-1);
				cif->iface[IFACE_LENGTH-1]=0;
				idata->iflist.nifaces++;
			}
		}

#ifdef __linux__
		if((ptr->ifa_addr)->sa_family == AF_PACKET){
			sockpptr = (struct sockaddr_ll *) (ptr->ifa_addr);

			if(sockpptr->sll_halen == ETHER_ADDR_LEN){
				memcpy(&(cif->ether), sockpptr->sll_addr, ETHER_ADDR_LEN);
			}

			cif->ifindex= sockpptr->sll_ifindex;
		}
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__) || defined(__FreeBSD_kernel__)
		if((ptr->ifa_addr)->sa_family == AF_LINK){
			sockpptr = (struct sockaddr_dl *) (ptr->ifa_addr);
			if(sockpptr->sdl_alen == ETHER_ADDR_LEN){
				memcpy(&(cif->ether), (sockpptr->sdl_data + sockpptr->sdl_nlen), ETHER_ADDR_LEN);
			}

			cif->ifindex= sockpptr->sdl_index;
		}
#endif
		else if((ptr->ifa_addr)->sa_family == AF_INET6){
			sockin6ptr= (struct sockaddr_in6 *) (ptr->ifa_addr);

			if(IN6_IS_ADDR_LINKLOCAL( &(sockin6ptr->sin6_addr))){
				if(cif->ip6_local.nprefix >= cif->ip6_local.maxprefix)
					continue;

				if(is_ip6_in_prefix_list( &(sockin6ptr->sin6_addr), &(cif->ip6_local)) == TRUE)
					continue;

				if( (cif->ip6_local.prefix[cif->ip6_local.nprefix] = malloc(sizeof(struct prefix_entry))) == NULL){
					if(idata->verbose_f > 1)
						puts("Error while storing Source Address");

					freeifaddrs(ifptr);
					return(FAILURE);
				}

				(cif->ip6_local.prefix[cif->ip6_local.nprefix])->len = 128;
				(cif->ip6_local.prefix[cif->ip6_local.nprefix])->ip6 = sockin6ptr->sin6_addr;

#if defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__) || defined(__FreeBSD_kernel__)
					/* BSDs store the interface index in s6_addr16[1], so we must clear it */
				(cif->ip6_local.prefix[cif->ip6_local.nprefix])->ip6.s6_addr16[1] =0;
				(cif->ip6_local.prefix[cif->ip6_local.nprefix])->ip6.s6_addr16[2] =0;
				(cif->ip6_local.prefix[cif->ip6_local.nprefix])->ip6.s6_addr16[3] =0;					
#endif

				cif->ip6_local.nprefix++;
			}
			else if(!IN6_IS_ADDR_LINKLOCAL( &(sockin6ptr->sin6_addr))){
				if(is_ip6_in_prefix_list( &(sockin6ptr->sin6_addr), &(cif->ip6_global)))
					continue;

				if(IN6_IS_ADDR_LOOPBACK(&(sockin6ptr->sin6_addr)))
					cif->flags= IFACE_LOOPBACK;

				if(cif->ip6_global.nprefix >= cif->ip6_global.maxprefix)
					continue;

				if( (cif->ip6_global.prefix[cif->ip6_global.nprefix] = \
												malloc(sizeof(struct prefix_entry))) == NULL){
					if(idata->verbose_f > 1)
						puts("Error while storing Source Address");

					freeifaddrs(ifptr);
					return(FAILURE);
				}

				(cif->ip6_global.prefix[cif->ip6_global.nprefix])->len = 128;
				(cif->ip6_global.prefix[cif->ip6_global.nprefix])->ip6 = sockin6ptr->sin6_addr;
				cif->ip6_global.nprefix++;
			}
		}
	}

	freeifaddrs(ifptr);
	return(SUCCESS);
}



/*
 * Function: find_iface_by_name()
 *
 * Finds an Interface (by name) in an Interface list
 */

void *find_iface_by_name(struct iface_list *iflist, char *iface){
	unsigned int i;

	for(i=0; i < iflist->nifaces; i++){
		if(strncmp((iflist->ifaces[i]).iface, iface, IFACE_LENGTH) == 0)
			return(&(iflist->ifaces[i]));
	}

	return(NULL);
}


/*
 * Function: find_iface_by_index()
 *
 * Finds an Interface (by index) in an Interface list
 */

void *find_iface_by_index(struct iface_list *iflist, int ifindex){
	unsigned int i;

	for(i=0; i < iflist->nifaces; i++){
		if((iflist->ifaces[i]).ifindex == ifindex)
			return(&(iflist->ifaces[i]));
	}

	return(NULL);
}


/*
 * Function: is_in6addr_iniface_list()
 *
 * Finds an Interface (by name) in an Interface list
 */

int is_ip6_in_iface_entry(struct iface_list *iflist, int ifindex, struct in6_addr *addr){
	unsigned int i;

	for(i=0; i < iflist->nifaces; i++){
		if(iflist->ifaces[i].ifindex == ifindex){
			if(is_ip6_in_prefix_list(addr, &(iflist->ifaces[i].ip6_global)))
				return(TRUE);
			else if(is_ip6_in_prefix_list(addr, &(iflist->ifaces[i].ip6_local)))
				return(TRUE);
		}
	}

	return(FALSE);
}


/*
 * Function: find_matching_address()
 *
 * Finds the longest matching address in an Interface list
 */

struct iface_entry *find_matching_address(struct iface_data *idata, struct iface_list *iflist, struct in6_addr *dst, struct in6_addr *match){
	unsigned int i, j, mlen, len;
	struct iface_entry	*cif=NULL;  /* Not needed, but avoids warning in OpenBSD/gcc */
	mlen= 0;

	for(i=0; i < iflist->nifaces; i++){
		if(idata->iface_f && (idata->ifindex != (iflist->ifaces[i]).ifindex))
			continue;

		for(j=0; j < (iflist->ifaces[i]).ip6_local.nprefix; j++){
			if( (len= ip6_longest_match( &((iflist->ifaces[i].ip6_local.prefix[j])->ip6), dst)) >= mlen){
				cif= &(iflist->ifaces[i]);
				*match= (iflist->ifaces[i].ip6_local.prefix[j])->ip6;
				mlen= len;
			}

			if(mlen >= 64){
				return(cif);
			}
		}

		for(j=0; j < (iflist->ifaces[i]).ip6_global.nprefix; j++){
			if( (len= ip6_longest_match( &((iflist->ifaces[i].ip6_global.prefix[j])->ip6), dst)) >= mlen){
				cif= &(iflist->ifaces[i]);
				*match= (iflist->ifaces[i].ip6_global.prefix[j])->ip6;
				mlen= len;
			}

			if(mlen >= 64){
				return(cif);
			}
		}
	}

	return(cif);
}


/*
 * Function: ip6_longest_match()
 *
 * Finds the mask that two IPv6 addresses have in common
 */
unsigned int ip6_longest_match(struct in6_addr *addr1, struct in6_addr *addr2){
	unsigned int mask, step=8;
	struct in6_addr a1, a2;

	for(mask=0; mask <= 64; mask=mask+step){
		a1= *addr1;
		a2= *addr2;
		sanitize_ipv6_prefix(&a1, mask);
		sanitize_ipv6_prefix(&a2, mask);

		if(!is_eq_in6_addr(&a1, &a2))
			return(mask - step);
	}

	return(64);
}


/*
 * Function: sel_src_addr()
 *
 * Selects a Source Address for a given Destination
 */
int sel_src_addr(struct iface_data *idata){
	struct in6_addr		match;
	struct iface_entry	*cif;

	/*
	   If the packet is directed to a link-local addresses, the ourgoing interface should have been specified.
	   If not, that's a failure. If specified, we give higher priority to link-local addresses
	 */
	if(IN6_IS_ADDR_LINKLOCAL(&(idata->dstaddr))){
		if(!idata->iface_f){
			return(FAILURE);
		}
		else{
			if( (cif=find_iface_by_index( &(idata->iflist), idata->ifindex)) == NULL){
				return(FAILURE);
			}
			else{
				idata->ether= cif->ether;
				idata->ether_flag= TRUE;
				idata->flags= cif->flags;

				if((cif->ip6_local).nprefix){
					idata->ip6_local= (cif->ip6_local).prefix[0]->ip6;
					idata->ip6_local_flag= TRUE;
				}

				idata->ip6_global= cif->ip6_global;
				if((idata->ip6_global).nprefix)
					idata->ip6_global_flag= TRUE;

				if(idata->ip6_local_flag == TRUE){
					idata->srcaddr= (cif->ip6_local.prefix[0])->ip6;
					return(SUCCESS);
				}
				else if(idata->ip6_global_flag == TRUE){
					idata->srcaddr= (cif->ip6_local.prefix[0])->ip6;
					return(SUCCESS);
				}
			}
		}
	}
	else{
		/*
		   If the destination address is not a link-local address, then:

		   1) If the interface has been specified, we select an IPv6 address assigned to that interface
		      (prioritizing "global" addresses)

		   2) If an interface has not been specified, we select the longest-matching address for that
		      destination
		 */
		if(idata->iface_f){
			if( (cif=find_iface_by_index( &(idata->iflist), idata->ifindex)) == NULL){
				return(FAILURE);
			}
			else{
				idata->ether= cif->ether;
				idata->ether_flag= TRUE;
				idata->flags= cif->flags;

				idata->ip6_global= cif->ip6_global;
				if(cif->ip6_global.nprefix){
					idata->ip6_global_flag= TRUE;
				}

				if((cif->ip6_local).nprefix){
					idata->ip6_local= (cif->ip6_local).prefix[0]->ip6;
					idata->ip6_local_flag= TRUE;
				}

				if(idata->ip6_global_flag){
					/* XXX This should be replaced with "find the longest match for this list */
					idata->srcaddr= (idata->ip6_global).prefix[0]->ip6;
					return(SUCCESS);
				}
				else if(idata->ip6_local_flag){
					idata->srcaddr= idata->ip6_local;
					return(SUCCESS);
				}
			}
		}
		else{
			if( (cif=find_matching_address(idata, &(idata->iflist), &(idata->dstaddr), &match)) != NULL){
				idata->srcaddr= match;
				strncpy(idata->iface, cif->iface, IFACE_LENGTH-1);
				idata->iface[IFACE_LENGTH-1]= 0;
				idata->ifindex= cif->ifindex;
				idata->ifindex_f= TRUE;
				idata->flags= cif->flags;

				/*
				   We know check whether the selected address belongs to the outgoing
				   interface -- otherwise packets might be filtered
				 */

				if(sel_next_hop(idata) == SUCCESS){
					if(is_ip6_in_iface_entry(&(idata->iflist), idata->nhifindex, &(idata->srcaddr)) == TRUE){
						if((cif->ip6_local).nprefix){
							idata->ip6_local= (cif->ip6_local).prefix[0]->ip6;
							idata->ip6_local_flag= TRUE;
						}

						idata->ip6_global= cif->ip6_global;
						if((idata->ip6_global).nprefix)
							idata->ip6_global_flag= TRUE;

						idata->ether= cif->ether;
						idata->ether_flag= TRUE;
						return(SUCCESS);
					}
					else{
						/*
						   If the seleted address doesn't correspond to the outgoing interface, throw away
						   the previously-selected IPv6 Address, and select one that is assigned to the
						   outgoing interface.
						 */
						if( (cif= find_iface_by_index(&(idata->iflist), idata->nhifindex)) == NULL){
							return(FAILURE);
						}
						else{
							idata->ether= cif->ether;
							idata->ether_flag= TRUE;
							idata->ifindex= idata->nhifindex;
							idata->flags= cif->flags;
							strncpy(idata->iface, idata->nhiface, IFACE_LENGTH-1);

							if((cif->ip6_local).nprefix){
								idata->ip6_local= (cif->ip6_local).prefix[0]->ip6;
								idata->ip6_local_flag= TRUE;
							}

							idata->ip6_global= cif->ip6_global;
							if((idata->ip6_global).nprefix)
								idata->ip6_global_flag= TRUE;

							if(!IN6_IS_ADDR_LINKLOCAL(&(idata->dstaddr))){
								if(idata->ip6_global_flag == TRUE){
									idata->srcaddr= (cif->ip6_global.prefix[0])->ip6;
									return(SUCCESS);
								}
								else if(idata->ip6_local_flag){
									idata->srcaddr= idata->ip6_local;
									return(SUCCESS);
								}
							}
							else{
								if(idata->ip6_local_flag){
									idata->srcaddr= idata->ip6_local;
									return(SUCCESS);
								}
								else if(idata->ip6_global_flag){
									idata->srcaddr= (cif->ip6_global.prefix[0])->ip6;
									return(SUCCESS);
								}
							}
						}
					}
				}
			}
		}
	}

	return(FAILURE);
}



/*
 * Function: load_dst_and_pcap()
 *
 * Finds the Sorurce Address, Next-Hop, and outgoing interface for a given Destination Address
 */
int load_dst_and_pcap(struct iface_data *idata, unsigned int mode){
	struct iface_entry	*cif;
	struct in6_addr		randprefix;
	unsigned char		randpreflen;
	char				errbuf[PCAP_ERRBUF_SIZE];

	if(mode != LOAD_PCAP_ONLY){
		if(idata->srcprefix_f){
			randprefix= idata->srcaddr;
			randpreflen= idata->srcpreflen;
			randomize_ipv6_addr(&(idata->srcaddr), &randprefix, randpreflen);
			idata->srcaddr_f=1;
		}

		if(!idata->srcaddr_f){
			if(get_local_addrs(idata) == FAILURE){
				puts("Error while obtaining local addresses");
				return(FAILURE);
			}

			/*
			   If no source address or prefix have been specified, then we need to automatically learn our IPv6
			   address. This is our appraoch:

			   * Firstly, assume that our host has IPv6 connectivity:
				+ If an interface has been specified, select an IPv6 address from one of the configures addresses
				      of such interface.

				* If an interface has not been specified, select a source address taking into consideration
				  all configured addresses.

			   * If that doesn't succeed, try sending RAs

			 */

			if(sel_src_addr(idata) == SUCCESS){
				if(sel_next_hop(idata) == SUCCESS){
					idata->nh_f= TRUE;
				}
			}

			if(idata->nh_f == FALSE){
				/* XXX Should really free the memory allocated by the other functions, since they are of no further use */
				idata->ip6_local_flag= FALSE;
				idata->ip6_global.nprefix=0;
				idata->ip6_global_flag= FALSE;

				if(!idata->iface_f){
					if(idata->verbose_f)
						puts("Could not determine next hop address");
	
					return(FAILURE);
				}

				/* This sends an RA, populates the local addresses and prefixes, and the local router */
				if(sel_next_hop_ra(idata) == -1){
					puts("Could not learn a local router");
					return(FAILURE);
				}

				if(sel_src_addr_ra(idata, &(idata->dstaddr)) == FAILURE || !idata->ether_flag || !idata->ip6_global_flag || !idata->ip6_local_flag){
					puts("Could not obtain local address **");
					return(FAILURE);
				}

				idata->ifindex= if_nametoindex(idata->iface);
				idata->ifindex_f= TRUE;
			}
		}
		else{
			if(get_local_addrs(idata) == FAILURE){
				if(idata->verbose_f)
					puts("Error while obtaining local addresses");
				return(FAILURE);
			}

			if(sel_next_hop(idata) == SUCCESS){
				idata->ifindex= idata->nhifindex;
				idata->nh_f= TRUE;
				strncpy(idata->iface, idata->nhiface, IFACE_LENGTH-1);
				idata->iface[IFACE_LENGTH-1]=0;

				if( (cif=find_iface_by_index(&(idata->iflist), idata->ifindex)) != NULL){
					idata->ether= cif->ether;
					idata->ether_flag= TRUE;
				}
			}
			else{
				/* This sends an RA, populates the local addresses and prefixes, and the local router */
				if(sel_next_hop_ra(idata) == -1){
					puts("Could not learn a local router");
					return(FAILURE);
				}
			}
		}
	}
	else{
		if(!idata->iface_f){
			if(idata->verbose_f){
				puts("Error opening pcap socket because interface was not specified");
			}

			return(FAILURE);
		}

		idata->ifindex= if_nametoindex(idata->iface);
		idata->ifindex_f= TRUE;

		if(get_if_addrs(idata) == -1){
			if(idata->verbose_f){
				puts("Error while obtaining local interface data");
			}

			return(FAILURE);
		}
	}


	if(!(idata->hsrcaddr_f)){
		if(idata->ether_flag)
			idata->hsrcaddr=idata->ether;
		else
			randomize_ether_addr(&(idata->hsrcaddr));
	}

	if(!idata->ip6_local_flag){
		ether_to_ipv6_linklocal(&idata->ether, &idata->ip6_local);
	}

	if( (idata->pfd= pcap_open_live(idata->iface, PCAP_SNAP_LEN, PCAP_PROMISC, PCAP_TIMEOUT, errbuf)) == NULL){
		printf("pcap_open_live(%s): %s\n", idata->iface, errbuf);
		return(FAILURE);
	}

	if( (idata->fd= pcap_fileno(idata->pfd)) == -1){
		if(idata->verbose_f)
			puts("Error obtaining descriptor number for pcap_t");

		return(FAILURE);
	}

	if( (idata->type = pcap_datalink(idata->pfd)) == DLT_EN10MB){
		idata->linkhsize= ETH_HLEN;
		idata->mtu= ETH_DATA_LEN;
	}
	else if( idata->type == DLT_RAW){
		idata->linkhsize=0;
		idata->mtu= MIN_IPV6_MTU;
		idata->flags= IFACE_TUNNEL;
	}
	else if(idata->type == DLT_NULL){
		idata->linkhsize=4;
		idata->mtu= MIN_IPV6_MTU;
		idata->flags= IFACE_TUNNEL;
	}
	else{
		printf("Error: Interface %s is not an Ethernet or tunnel interface", idata->iface);
		return(FAILURE);
	}

	if(mode == LOAD_PCAP_ONLY)
		return(SUCCESS);

	if(idata->flags != IFACE_TUNNEL && idata->flags != IFACE_LOOPBACK){
		if(ipv6_to_ether(idata->pfd, idata, &(idata->nhaddr), &(idata->nhhaddr)) != 1){
			puts("Error while performing Neighbor Discovery for the Destination Address");
			return(FAILURE);
		}
	}

	idata->hdstaddr= idata->nhhaddr;

	return(SUCCESS);
}



/*
 * sanitize_ipv4_prefix()
 *
 * Clears those bits in an IPv4 address that are not within a prefix length.
 */

void sanitize_ipv4_prefix(struct prefix4_entry *prefix4){
	unsigned int	clear, i;
	in_addr_t    	mask=0xffffffff;

	clear= 32-prefix4->len;

	for(i=0; i<clear; i++)
		mask= mask>>1;

	for(i=0; i<clear; i++)
		mask= mask<<1;

	prefix4->ip.s_addr= prefix4->ip.s_addr & htonl(mask);
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
 * Function: dec_to_hex()
 *
 * Convert a decimal number into a number that has the same representation in hexadecimal
 */
u_int16_t dec_to_hex(u_int16_t n){
	u_int16_t	r=0;
	unsigned int	d, i;

	/* The source number is truncated to the first four digits */
	n= n%10000;
	d=1000;

	for(i=0; i<4; i++){
		r= (r << 4) | (n/d);
		n= n%d;
		d=d/10;
	}

	return(r);
}


/*
 * Function: keyval()
 *
 * Obtains a (variable, value) pair from a line of text in "variable=value # comments" format
 */

int keyval(char *line, unsigned int len, char **key, char **val){
	char *ptr;
	ptr= line;

	/* Skip initial spaces (e.g. "   variable=value") */
	while( (*ptr==' ' || *ptr=='\t') && ptr < (line+len))
		ptr++;

	/* If we got to end of line or there is a comment or equal sign, there is no (variable, value) pair) */
	if(ptr==(line+len) || *ptr=='#' || *ptr=='=' || *ptr=='\r' || *ptr=='\n')
		return 0;

	*key=ptr;

	/* The variable name is everything till (and excluding) the first separator character (e.g., space or tab) */
	while( (*ptr!=' ' && *ptr!='\t' && *ptr!='\r' && *ptr!='\n' && *ptr!='#' && *ptr!='=') && ptr < (line+len))
		ptr++;

	/*
	   If the variable name is followed by a comment sign, or occupies the entire line, there's an error
	   in the config file (i.e., there is no "variable=value" pair)
	 */
	if(ptr==(line+len) || *ptr=='#' || *ptr=='\r' || *ptr=='\n')
		return -1;


	if(*ptr==' ' || *ptr=='\t'){
		/* The variable name is followed by spaces -- skip them, and find the "equal to" sign */
		*ptr=0; /* NULL-terminate the key */
		ptr++;

		while(ptr<(line+len) &&  (*ptr==' ' || *ptr=='\t'))
			ptr++;

		if(ptr==(line+len) || *ptr!='=')
			return -1;

		ptr++;
	}else{
		/* The variable name is followed by the "equal to" sign */
		*ptr=0; 
		ptr++;
	}

	/*
	   If the equal sign is followed by spaces, skip them
	 */
	while( (*ptr==' ' || *ptr=='\t') && ptr<(line+len))
		ptr++;

	/* We found the "value" in the "variable=value" pair */
	*val=ptr;

	/* The value is everthing till (and excluding) the first separator character */
	while( (*ptr!='#' && *ptr!='\r' && *ptr!='\n' && *ptr!='\t' && *ptr!='=' && *ptr!=' ') && ptr < (line+len))
		ptr++;

	/* If the value string was actually "empty", we return an error */
	if(ptr == *val)
		return(-1);

	*ptr=0;
	return(1);
}


/*
 * Function: address_contains_ranges()
 *
 * Checks whether a string contains ranges in the form YYYY-ZZZZ. A string that contains both ranges and a
 * /length prefix is considered invalid.
 */

int address_contains_ranges(char *ptr){
	unsigned char slash_f=0, dash_f=0;
	unsigned int i=0;

	while(i <= (MAX_RANGE_STR_LEN) && *ptr){
		if(*ptr == '-')
			dash_f=1;

		if(*ptr=='/')
			slash_f=1;

		ptr++;
		i++;
	}

	/* If the string contains both slashes and dashes, it is an error */
	if(dash_f){
		if(slash_f)
			return(-1);
		else
			return(1);
	}
	else{
		return(0);
	}
}


/*
 * Function: read_prefix()
 *
 * Obtain a pointer to the beginning of non-blank text, and zero-terminate that text upon space or comment.
 */
int read_prefix(char *line, unsigned int len, char **start){
	char *end;

	*start=line;

	while( (*start < (line + len)) && (**start==' ' || **start=='\t' || **start=='\r' || **start=='\n')){
		(*start)++;
	}

	if( *start == (line + len))
		return(0);

	if( **start == '#')
		return(0);

	end= *start;

	while( (end < (line + len)) && !(*end==' ' || *end=='\t' || *end=='#' || *end=='\r' || *end=='\n'))
		end++;

	*end=0;
	return(1);
}


/*
 * Function: read_ipv6_address()
 *
 * Obtains an IPv6 address (struct in6_addr) from a line of text in "IPv6_address # comments" format
 */

int read_ipv6_address(char *line, unsigned int len, struct in6_addr *iid){
	char *ptr, *ipv6addr;
	ptr= line;

	/* Skip initial spaces (e.g. "   IPv6_address") */
	while( (*ptr==' ' || *ptr=='\t') && ptr < (line+len))
		ptr++;

	/* If we got to end of line or there is a comment or equal sign, there is no IPv6 address */
	if(ptr==(line+len) || *ptr=='#' || *ptr=='=' || *ptr=='\r' || *ptr=='\n')
		return 0;

	ipv6addr=ptr;

	/* The IPv6 address is everything till (and excluding) the first separator character (e.g., space or tab) */
	while( (*ptr!=' ' && *ptr!='\t' && *ptr!='\r' && *ptr!='\n' && *ptr!='#' && *ptr!='=') && ptr < (line+len))
		ptr++;

	/* NULL-terminate the ASCII-encoded IPv6 address */
	*ptr=0; 

	if ( inet_pton(AF_INET6, ipv6addr, iid) <= 0){
		return(-1);
	}

	return(1);
}


/*
 * Function: print_local_addrs()
 *
 * Debugging function to print all local addresses (starting from a struct iface_data *)
 */

int print_local_addrs(struct iface_data *idata){
	unsigned int		i, j;
	char				pv6addr[INET6_ADDRSTRLEN];
	char 				plinkaddr[ETHER_ADDR_PLEN];

	puts("List of local interfaces/addresses");

	for(i=0; i < idata->iflist.nifaces; i++){
		if(ether_ntop(&((idata->iflist).ifaces[i].ether), plinkaddr, sizeof(plinkaddr)) == 0){
			puts("ether_ntop(): Error converting address");
			exit(EXIT_FAILURE);
		}

		printf("Name: %s\tIndex: %d\t Address: %s\n", (idata->iflist.ifaces[i]).iface, (idata->iflist.ifaces[i]).ifindex, plinkaddr);
		puts("Link-local addresses:");

		for(j=0; j < idata->iflist.ifaces[i].ip6_local.nprefix; j++){
			if(inet_ntop(AF_INET6, idata->iflist.ifaces[i].ip6_local.prefix[j], pv6addr, sizeof(pv6addr)) == NULL){
				puts("inet_ntop(): Error converting IPv6 address to presentation format");
				exit(EXIT_FAILURE);
			}

			printf("\t%s\n", pv6addr);
		}

		puts("Global addresses:");

		for(j=0; j < idata->iflist.ifaces[i].ip6_global.nprefix; j++){
			if(inet_ntop(AF_INET6, idata->iflist.ifaces[i].ip6_global.prefix[j], pv6addr, sizeof(pv6addr)) == NULL){
				puts("inet_ntop(): Error converting IPv6 address to presentation format");
				exit(EXIT_FAILURE);
			}

			printf("\t%s\n", pv6addr);
		}

		puts("");
	}

	return(SUCCESS);
}


/*
 * Function: find_ipv6_router()
 *
 * Finds a local router (by means of Neighbor Discovery)
 */

int find_ipv6_router(pcap_t *pfd, struct ether_addr *hsrcaddr, struct in6_addr *srcaddr, \
					struct ether_addr *result_ether, struct in6_addr *result_ipv6){

	struct pcap_pkthdr			*pkthdr;
	const u_char				*pktdata;
	struct ether_header			*pkt_ether;
	struct ip6_hdr				*pkt_ipv6;
	struct nd_router_advert 	*pkt_ra;
	unsigned char				*pkt_end;
	unsigned char				*ptr, *prev_nh;
	int							r;
	size_t						nw;

	unsigned char				buffer[65556];
	unsigned int 				rs_max_packet_size;
	struct ether_header 		*ether;
	unsigned char 				*v6buffer;
	struct ip6_hdr 				*ipv6;
	struct nd_router_solicit	*rs;
	struct nd_opt_slla 			*sllaopt;
	volatile unsigned int 		tries=0;
	volatile unsigned int 		foundrouter=0;
	struct sigaction 			new_sig, old_sig;

	rs_max_packet_size = ETH_DATA_LEN;

	ether = (struct ether_header *) buffer;
	v6buffer = buffer + sizeof(struct ether_header);
	ipv6 = (struct ip6_hdr *) v6buffer;

	if(pcap_compile(pfd, &pcap_filter, PCAP_ICMPV6_RA_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
		printf("pcap_compile(): %s", pcap_geterr(pfd));
		return(-1);
	}
    
	if(pcap_setfilter(pfd, &pcap_filter) == -1){
		printf("pcap_setfilter(): %s", pcap_geterr(pfd));
		return(-1);
	}

	pcap_freecode(&pcap_filter);

	ipv6->ip6_flow=0;
	ipv6->ip6_vfc= 0x60;
	ipv6->ip6_hlim= 255;
	ipv6->ip6_src= *srcaddr;

	if ( inet_pton(AF_INET6, ALL_ROUTERS_MULTICAST_ADDR, &(ipv6->ip6_dst)) <= 0){
		puts("inet_pton(): Error converting All Routers address from presentation to network format");
		return(-1);
	}

	ether->src = *hsrcaddr;

	if(ether_pton(ETHER_ALLROUTERS_LINK_ADDR, &(ether->dst), sizeof(struct ether_addr)) == 0){
	    puts("ether_pton(): Error converting all-nodes multicast address");
	    return(-1);
	}

	ether->ether_type = htons(ETHERTYPE_IPV6);

	prev_nh = (unsigned char *) &(ipv6->ip6_nxt);
	*prev_nh = IPPROTO_ICMPV6;

	ptr = (unsigned char *) v6buffer + MIN_IPV6_HLEN;

	if( (ptr+sizeof(struct nd_router_solicit)) > (v6buffer+rs_max_packet_size)){
		puts("Packet too large while inserting Router Solicitation header");
		return(-1);
	}

	rs= (struct nd_router_solicit *) (ptr);

	rs->nd_rs_type = ND_ROUTER_SOLICIT;
	rs->nd_rs_code = 0;
	rs->nd_rs_reserved = 0;

	ptr += sizeof(struct nd_router_solicit);
	sllaopt = (struct nd_opt_slla *) ptr;    

	if( (ptr+sizeof(struct nd_opt_slla)) > (v6buffer+rs_max_packet_size)){
		puts("RS message too large while processing source link-layer addresss opt.");
		return(-1);
	}

	sllaopt->type= ND_OPT_SOURCE_LINKADDR;
	sllaopt->length= SLLA_OPT_LEN;
	bcopy( &(hsrcaddr->a), sllaopt->address, ETH_ALEN);
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
		puts("Error setting up 'Alarm' signal");
		return(-1);
	}

	if(sigsetjmp(env, 1) != 0)
		tries++;

	canjump=1;

	while(tries<3 && !foundrouter){
		if((nw=pcap_inject(pfd, buffer, ptr - buffer)) == -1){
			printf("pcap_inject(): %s\n", pcap_geterr(pfd));
			return(-1);
		}

		if(nw != (ptr-buffer)){
			printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, \
																			(LUI) (ptr-buffer));
			return(-1);
		}

		alarm(1);
		
		while(!foundrouter){
			if( (r=pcap_next_ex(pfd, &pkthdr, &pktdata)) == -1){
				printf("pcap_next_ex(): %s", pcap_geterr(pfd));
				exit(EXIT_FAILURE);
			}
			else if(r == 0){
				continue; /* Should never happen */
			}
			
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
			   Check that the IPv6 packet encapsulates an ICMPv6 message
			 */
			if(pkt_ipv6->ip6_nxt != IPPROTO_ICMPV6)
				continue;

			/*
			   Check that the ICMPv6 type corresponds to RA
			 */
			if(pkt_ra->nd_ra_type != ND_ROUTER_ADVERT)
				continue;

			/*
			   Check that the ICMPv6 code is 0
			 */
			if(pkt_ra->nd_ra_code != 0)
				continue;

			/*
			   Check that the IPv6 Source Address of the Router Advertisement is an IPv6 link-local
			   address.
			 */
			if( (pkt_ipv6->ip6_src.s6_addr16[0] & htons(0xffc0)) != htons(0xfe80))
				continue;

			/* 
			   Check that that the Destination Address of the Router Advertisement is either the one
			   that we used for sending the Router Solicitation message or a multicast address (typically the all-nodes)
			 */
			if(!is_eq_in6_addr(&(pkt_ipv6->ip6_dst), &(ipv6->ip6_src)) && !IN6_IS_ADDR_MULTICAST(&(pkt_ipv6->ip6_dst)))
				continue;

			/* Check that the ICMPv6 checksum is correct. If the received checksum is valid,
			   and we compute the checksum over the received packet (including the Checkdum field)
			   the result is 0. Otherwise, the packet has been corrupted.
			*/
			if(in_chksum(pkt_ipv6, pkt_ra, pkt_end- (unsigned char *)pkt_ra, IPPROTO_ICMPV6) != 0)
				continue;

			ptr= (unsigned char *) pkt_ra + sizeof(struct nd_router_advert);

			/* Process Router Advertisement options */
			while( (ptr+sizeof(struct nd_opt_slla)) <= pkt_end && (*(ptr+1) != 0)){
				if(*ptr == ND_OPT_SOURCE_LINKADDR){
					if( (*(ptr+1) * 8) != sizeof(struct nd_opt_tlla))
						break;

					/* Got a response, so we shouln't time out */
					alarm(0);

					/* Save the link-layer address */
					*result_ether= *(struct ether_addr *) (ptr+2);
					*result_ipv6= pkt_ipv6->ip6_src;
					foundrouter=1;
					break;
				}

				ptr= ptr + *(ptr+1) * 8;
			} /* Processing options */

		} /* Processing packets */

	} /* Resending Router Solicitations */

	if( sigaction(SIGALRM, &old_sig, NULL) == -1){
		puts("Error setting up 'Alarm' signal");
		return(-1);
	}

	if(foundrouter)
		return 0;
	else
		return -1;
}

