/*
 * flow6: A security assessment tool that determines the Flow Label
 *        generation policy of a target node
 *
 * Copyright (C) 2011-2013 Fernando Gont <fgont@si6networks.com>
 *
 * Programmed by Fernando Gont for SI6 Networks (www.si6networks.com)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warrsi6networks.allanty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * 
 * Build with: make flow6
 * 
 * This program has been tested to compile and run on: Debian GNU/Linux 6.0,
 * FreeBSD 9.0, NetBSD 5.1, OpenBSD 5.0, Ubuntu 11.10, and Mac OS X.
 *
 * It requires that the libpcap library be installed on your system.
 *
 * Please send any bug reports to Fernando Gont <fgont@si6networks.com>
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/select.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <ifaddrs.h>
#ifdef __linux__
	#include <netpacket/packet.h>
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__) || ( !defined(__FreeBSD__) && defined(__FreeBSD_kernel__))
	#include <net/if_dl.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <pcap.h>

#include "flow6.h"
#include "ipv6toolkit.h"
#include "libipv6.h"


/* Function prototypes */
void				print_attack_info(void);
void				usage(void);
void				print_help(void);
int					send_fid_probe(void);
int					predict_flow_id(u_int32_t *, unsigned int, u_int32_t *, unsigned int);


/* Used for router discovery */
struct iface_data	idata;
struct in6_addr		randprefix;
unsigned char		randpreflen;

/* Data structures for packets read from the wire */
struct pcap_pkthdr	*pkthdr;
const u_char		*pktdata;
unsigned char		*pkt_end, *pkt_ptr;
struct ether_header	*pkt_ether;
struct ip6_hdr		*pkt_ipv6;
struct tcp_hdr		*pkt_tcp;
struct udp_hdr		*pkt_udp;
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
unsigned char		srcpreflen;

u_int16_t			mask, ip6length;
u_int8_t			hoplimit;

char 				plinkaddr[ETHER_ADDR_PLEN];
char 				psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN], pv6addr[INET6_ADDRSTRLEN];
unsigned char 		localaddr_f=0;
unsigned char		srcprefix_f=0, hoplimit_f=0, flowidp_f=0, dstport_f=0, protocol_f=0;

/* Support for Extension Headers */
unsigned int		dstopthdrs, dstoptuhdrs, hbhopthdrs;
char				hbhopthdr_f=0, dstoptuhdr_f=0, dstopthdr_f=0;
unsigned char		*dstopthdr[MAX_DST_OPT_HDR], *dstoptuhdr[MAX_DST_OPT_U_HDR];
unsigned char		*hbhopthdr[MAX_HBH_OPT_HDR];
unsigned int		dstopthdrlen[MAX_DST_OPT_HDR], dstoptuhdrlen[MAX_DST_OPT_U_HDR];
unsigned int		hbhopthdrlen[MAX_HBH_OPT_HDR], m, pad;

struct ip6_frag		*fh;
struct ip6_hdr		*fipv6;
unsigned char		fragh_f=0;

unsigned char		*fragpart, *ptrend, *ptrhdr, *ptrhdrend;
unsigned int		hdrlen, ndstopthdr=0, nhbhopthdr=0, ndstoptuhdr=0;
unsigned int		nfrags, fragsize;
unsigned char		*prev_nh, *startoffragment;


/* For the sampling of Flow Label values */
u_int16_t			baseport, lastport, dstport, tcpwin, addr_sig, addr_key;
u_int32_t			tcpseq;
u_int8_t			protocol;


int main(int argc, char **argv){
	extern char			*optarg;	
	fd_set				sset, rset;
	struct timeval		timeout;
	int					r, sel;
	time_t				curtime, start, lastfrag1=0;

	/* Arrays for storing the Flow ID samples */
	u_int32_t		test1[NSAMPLES], test2[NSAMPLES];
	unsigned int	ntest1=0, ntest2=0;
	unsigned char	testtype;

	static struct option longopts[] = {
		{"interface", required_argument, 0, 'i'},
		{"src-address", required_argument, 0, 's'},
		{"dst-address", required_argument, 0, 'd'},
		{"hop-limit", required_argument, 0, 'A'},
		{"link-src-addr", required_argument, 0, 'S'},
		{"link-dst-addr", required_argument, 0, 'D'},
		{"protocol", required_argument, 0, 'P'},
		{"dst-port", no_argument, 0, 'p'},
		{"flow-label-policy", no_argument, 0, 'W'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'}
	};

	char shortopts[]= "i:s:d:A:S:D:P:p:Wvh";

	char option;

	if(argc<=1){
		usage();
		exit(EXIT_FAILURE);
	}


	srandom(time(NULL));
	hoplimit=64+random()%180;

	if(init_iface_data(&idata) == FAILURE){
		puts("Error initializing internal data structure");
		exit(EXIT_FAILURE);
	}

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
					srcpreflen = atoi(charptr);
		
					if(srcpreflen>128){
						puts("Prefix length error in IPv6 Source Address");
						exit(EXIT_FAILURE);
					}

					sanitize_ipv6_prefix(&(idata.srcaddr), srcpreflen);
					srcprefix_f=1;
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

			case 'P':	/* Protocol */
				if(strncmp(optarg, "tcp", MAX_STRING_SIZE) == 0 || \
					strncmp(optarg, "TCP", MAX_STRING_SIZE) == 0){
					protocol= IPPROTO_TCP;
				}
				else if(strncmp(optarg, "udp", MAX_STRING_SIZE) == 0 || \
					strncmp(optarg, "UDP", MAX_STRING_SIZE) == 0){
					protocol= IPPROTO_UDP;
				}
				else{
					puts("Unknown protocol type (valid types: 'tcp', 'udp')");
					exit(EXIT_FAILURE);
				}

				protocol_f= 1;
				break;

			case 'p':	/* Destination port */
				dstport= atoi(optarg);
				dstport_f=1;
				break;

			case 'W':	/* Assess the Flow Label generation policy of the target */
				flowidp_f= 1;
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
		puts("flow6 needs root privileges to run.");
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

	if( !fragh_f && dstoptuhdr_f){
		puts("Dst. Options Header (Unfragmentable Part) set, but Fragmentation not specified");
		exit(EXIT_FAILURE);
	}
    
	if(fragh_f)
		idata.max_packet_size = MAX_IPV6_PAYLOAD + MIN_IPV6_HLEN;
	else
		idata.max_packet_size = ETH_DATA_LEN;

	if(idata.verbose_f){
		print_attack_info();
	}

	if(!idata.dstaddr_f){
		puts("Error: Nothing to send! (Destination Address left unspecified)");
		exit(EXIT_FAILURE);
	}

	/* Assess the Flow ID generation policy */
	if(flowidp_f){
		if(dstport_f && !protocol_f){
			puts("Error: Must specify a protocol if the port number is specified");
			exit(EXIT_FAILURE);
		}

		if(!protocol_f){
			protocol= IPPROTO_TCP;
			dstport= 80;
		}
		else if(!dstport_f){
			if(protocol == IPPROTO_TCP)
				dstport= 80;
			else
				dstport= 53;
		}

		puts("Identifying the 'Flow ID' generation policy of the target node....");

		if(protocol == IPPROTO_TCP){
			tcpwin= ((u_int16_t) random() + 1500) & (u_int16_t)0x7f00;
			tcpseq= random();
			baseport= 50000+ random()%10000;
			lastport= baseport;
		}

		/*
		   Set filter for receiving Neighbor Solicitations, and TCP segments
		 */
		if(pcap_compile(idata.pfd, &pcap_filter, PCAP_NSTCP_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
			printf("pcap_compile(): %s", pcap_geterr(idata.pfd));
			exit(EXIT_FAILURE);
		}
		
		if(pcap_setfilter(idata.pfd, &pcap_filter) == -1){
			printf("pcap_setfilter(): %s", pcap_geterr(idata.pfd));
			exit(EXIT_FAILURE);
		}

		pcap_freecode(&pcap_filter);

		if( (idata.fd= pcap_fileno(idata.pfd)) == -1){
			puts("Error obtaining descriptor number for pcap_t");
			exit(EXIT_FAILURE);
		}

		FD_ZERO(&sset);
		FD_SET(idata.fd, &sset);
		start= time(NULL);
		lastfrag1=0;		
		ntest1=0;
		ntest2=0;
		testtype= FIXED_ORIGIN;

		if(srcprefix_f){
			randprefix= idata.srcaddr;
			randpreflen=srcpreflen;
		}
		else{
			randprefix= idata.srcaddr;
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
					for(i=0; i<NSAMPLES; i++){
						if(send_fid_probe() == -1){
							puts("Error while sending packet");
							exit(EXIT_FAILURE);
						}

						lastport++;
					}
				}
				else{
					for(i=0; i<NSAMPLES; i++){
						randomize_ipv6_addr(&(idata.srcaddr), &randprefix, randpreflen);

						/*
						 * Two words of the Source IPv6 Address are specially encoded such that we only respond
						 * to Neighbor Solicitations that target those addresses, and accept ICMPv6 Echo Replies
						 * only if they are destined to those addresses
						 */
						idata.srcaddr.s6_addr16[5]= addr_sig;
						idata.srcaddr.s6_addr16[7] =  idata.srcaddr.s6_addr16[6] ^ addr_key;

						if(send_neighbor_solicit(&idata, &(idata.dstaddr)) == -1){
							puts("Error while sending Neighbor Solicitation");
							exit(EXIT_FAILURE);
						}

						if(send_fid_probe() == -1){
							puts("Error while sending packet");
							exit(EXIT_FAILURE);
						}

						lastport++;
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

			if(pkt_ipv6->ip6_nxt == IPPROTO_ICMPV6 && pkt_icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT){
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
					if(!localaddr_f && is_eq_in6_addr(&(pkt_ns->nd_ns_target), &(idata.srcaddr))){
						if(send_neighbor_advert(&idata, idata.pfd, pktdata) == -1){
							puts("Error sending Neighbor Advertisement");
							exit(EXIT_FAILURE);
						}
					}
				}
				else{
					if(pkt_ns->nd_ns_target.s6_addr16[5] != addr_sig || \
						pkt_ns->nd_ns_target.s6_addr16[7] !=  (pkt_ns->nd_ns_target.s6_addr16[6] ^ addr_key))
						continue;

					if(send_neighbor_advert(&idata, idata.pfd, pktdata) == -1){
						puts("Error sending Neighbor Advertisement");
						exit(EXIT_FAILURE);
					}
				}				
			}
			else if(pkt_ipv6->ip6_nxt == protocol){

				/* Perform TCP-specific validation checks */
				if(protocol == IPPROTO_TCP){
					if( (pkt_end - (unsigned char *) pkt_ipv6) < \
							(sizeof(struct ip6_hdr) + sizeof(struct tcp_hdr)))
						continue;

					pkt_tcp= (struct tcp_hdr *) ((unsigned char *)pkt_ipv6 + sizeof(struct ip6_hdr));

					/*
					 * The TCP Destination Port must correspond to one of the ports that we have used as
					 * TCP Source Port
					 */
					if(ntohs(pkt_tcp->th_dport) < baseport || ntohs(pkt_tcp->th_dport) > lastport)
						continue;

					/* The Source Port must be that to which we're sending our TCP segments */
					if(ntohs(pkt_tcp->th_sport) != dstport)
						continue;

					/* The TCP Acknowledgement Number must ack our SYN */
					if(ntohl(pkt_tcp->th_ack) != tcpseq+1)
						continue;

					/* We sample Flow ID's only on SYN/ACKs */
					if( (pkt_tcp->th_flags & ~TH_SYN) == 0 || (pkt_tcp->th_flags & TH_ACK) == 0)
						continue;

					/* The TCP checksum must be valid */
					if(in_chksum(pkt_ipv6, pkt_tcp, pkt_end-((unsigned char *)pkt_tcp), IPPROTO_TCP) != 0)
						continue;
				}
				/* Perform UDP-specific validation checks */
				else if(protocol == IPPROTO_UDP){
					if( (pkt_end - (unsigned char *) pkt_ipv6) < \
							(sizeof(struct ip6_hdr) + sizeof(struct udp_hdr)))
						continue;

					pkt_udp= (struct udp_hdr *) ((unsigned char *)pkt_ipv6 + sizeof(struct ip6_hdr));

					/*
					 * The UDP Destination Port must correspond to one of the ports that we have used as
					 * the UDP Source Port
					 */
					if(ntohs(pkt_udp->uh_dport) < baseport || ntohs(pkt_udp->uh_dport) > lastport)
						continue;

					/* The Source Port must be that to which we're sending our UDP datagrams */
					if(ntohs(pkt_udp->uh_sport) != dstport)
						continue;

					/* The UDP checksum must be valid */
					if(in_chksum(pkt_ipv6, pkt_udp, pkt_end-((unsigned char *)pkt_udp), IPPROTO_UDP) != 0)
						continue;
				}

				if(testtype==FIXED_ORIGIN){
					if(!is_eq_in6_addr(&(pkt_ipv6->ip6_dst), &(idata.srcaddr))){
						continue;
					}

					if(ntest1 >= NSAMPLES)
						continue;

					test1[ntest1]= ntohl(pkt_ipv6->ip6_flow) & 0x000fffff;
					ntest1++;
				}
				else{
					if(pkt_ipv6->ip6_dst.s6_addr16[5] != addr_sig || \
						pkt_ipv6->ip6_dst.s6_addr16[7] !=  (pkt_ipv6->ip6_dst.s6_addr16[6] ^ addr_key)){
						continue;
					}

					if(ntest2 >= NSAMPLES)
						continue;

					test2[ntest2]= ntohl(pkt_ipv6->ip6_flow) & 0x000fffff;
					ntest2++;
				}
			}
		}

		if(idata.verbose_f > 1){
			printf("Sampled %u Flow Labels from single-origin probes\n", ntest1);

			for(i=0; i<ntest1; i++)
				printf("#%02u: %05x\n", (i+1), test1[i]);

			printf("\nSampled %u Flow Labels from multi-origin probes\n", ntest2);

			for(i=0; i<ntest2; i++)
				printf("#%02u: %05x\n", (i+1), test2[i]);

			puts("");
		}

		if(ntest1 < 10 || ntest2 < 10){
			puts("Error: Didn't receive enough response packets");
			exit(EXIT_FAILURE);
		}

		if(predict_flow_id(test1, ntest1, test2, ntest2) == -1){
			puts("Error in predict_flow_id()");
			exit(EXIT_FAILURE);
		}

		exit(EXIT_SUCCESS);
	}

	exit(EXIT_SUCCESS);
}


/*
 * Function: send_fid_probe()
 *
 * Send a TCP segment or UDP datagram used for sampling the Flow Label
 * values sent by the target
 */
int send_fid_probe(void){
	struct ether_header	*ethernet;
	struct dlt_null		*dlt_null;
	struct ip6_hdr		*ipv6;
	struct tcp_hdr		*tcp;
	struct udp_hdr		*udp;
	unsigned char		*ptr;

	ethernet= (struct ether_header *) buffer;
	dlt_null= (struct dlt_null *) buffer;
	v6buffer = buffer + idata.linkhsize;
	ipv6 = (struct ip6_hdr *) v6buffer;

	if(idata.type == DLT_EN10MB && idata.flags != IFACE_LOOPBACK){
		ethernet->src = idata.hsrcaddr;
		ethernet->dst = idata.hdstaddr;
		ethernet->ether_type = htons(ETHERTYPE_IPV6);
	}
	else if(idata.type == DLT_NULL){
		dlt_null->family= PF_INET6;
	}

	ipv6->ip6_flow=0;
	ipv6->ip6_vfc= 0x60;
	ipv6->ip6_hlim= hoplimit;
	ipv6->ip6_src= idata.srcaddr;
	ipv6->ip6_dst= idata.dstaddr;
	ipv6->ip6_nxt= protocol;

	if(protocol == IPPROTO_TCP){
		tcp= (struct tcp_hdr *) ( (unsigned char *) ipv6 + sizeof(struct ip6_hdr));
		ptr= (unsigned char *) tcp + sizeof(struct tcp_hdr);
		bzero(tcp, sizeof(struct tcp_hdr));
		tcp->th_sport= htons(lastport);
		tcp->th_dport= htons(dstport);
		tcp->th_seq = htonl(tcpseq);
		tcp->th_ack= htonl(0);
		tcp->th_flags= TH_SYN;;
		tcp->th_urp= htons(0);
		tcp->th_win= htons(tcpwin);
		tcp->th_off= sizeof(struct tcp_hdr) >> 2;
		ipv6->ip6_plen= htons(ptr - (unsigned char *) tcp);
		tcp->th_sum = in_chksum(ipv6, tcp, (ptr - (unsigned char *) tcp), IPPROTO_TCP);
	}
	else{
		udp= (struct udp_hdr *) ( (unsigned char *) ipv6 + sizeof(struct ip6_hdr));
		ptr= (unsigned char *) udp + sizeof(struct udp_hdr);
		bzero(udp, sizeof(struct udp_hdr));
		udp->uh_sport= htons(lastport);
		udp->uh_dport= htons(dstport);
		ipv6->ip6_plen= htons(ptr - (unsigned char *) udp);
		udp->uh_sum = in_chksum(ipv6, udp, (ptr - (unsigned char *) udp), IPPROTO_TCP);
	}

	if((nw=pcap_inject(idata.pfd, buffer, ptr - buffer)) == -1){
		if(idata.verbose_f)
			printf("pcap_inject(): %s\n", pcap_geterr(idata.pfd));

		return(-1);
	}

	if(nw != (ptr- buffer)){
		if(idata.verbose_f)
			printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, (LUI) (ptr-buffer));

		return(-1);
	}

	return(0);
}


/*
 * Function: usage()
 *
 * Prints the syntax of the flow6 tool
 */
void usage(void){
	puts("usage: flow6 -i INTERFACE -d DST_ADDR [-S LINK_SRC_ADDR] [-D LINK-DST-ADDR]\n"
	     "       [-s SRC_ADDR[/LEN]] [-A HOP_LIMIT] [-P PROTOCOL] [-p PORT]\n"
	     "       [-W] [-v] [-h]");
}


/*
 * Function: print_help()
 *
 * Prints help information for the flow6 tool
 */
void print_help(void){
	puts(SI6_TOOLKIT);
	puts("flow6: Security assessment tool for the IPv6 Flow Label field\n");
	usage();
    
	puts("\nOPTIONS:\n"
	"  --interface, -i           Network interface\n"
	"  --link-src-address, -S    Link-layer Destination Address\n"
	"  --link-dst-address, -D    Link-layer Source Address\n"
	"  --src-address, -s         IPv6 Source Address\n"
	"  --dst-address, -d         IPv6 Destination Address\n"
	"  --hop-limit, -A           IPv6 Hop Limit\n"
	"  --protocol, -P            IPv6 Payload protocol (valid: TCP, UDP)\n"
	"  --dst-port, -p            Transport Protocol Destination Port\n"
	"  --flow-label-policy, -W   Assess the Flow Label generation policy\n"
	"  --help, -h                Print help for the flow6 tool\n"
	"  --verbose, -v             Be verbose\n"
	"\n"
	"Programmed by Fernando Gont on behalf of SI6 Networks <http://www.si6networks.com>\n"
	"Please send any bug reports to <fgont@si6networks.com>\n"
	);
}




/*
 * Function: print_attack_info()
 *
 * Prints attack details (when the verbose ("-v") option is specified).
 */
 
void print_attack_info(void){
	if(ether_ntop(&(idata.hsrcaddr), plinkaddr, sizeof(plinkaddr)) == 0){
		puts("ether_ntop(): Error converting address");
		exit(EXIT_FAILURE);
	}

	printf("Ethernet Source Address: %s%s\n", plinkaddr, (!idata.hsrcaddr_f)?" (automatically selected)":"");

	/* 
	   Ethernet Destination Address only used if a IPv6 Destination Address or an
	   Ethernet Destination Address were specified.
	 */
	if(ether_ntop(&(idata.hdstaddr), plinkaddr, sizeof(plinkaddr)) == 0){
		puts("ether_ntop(): Error converting address");
		exit(EXIT_FAILURE);
	}

	printf("Ethernet Destination Address: %s%s\n", plinkaddr, (!idata.hdstaddr_f)?" (automatically selected)":"");

	if(inet_ntop(AF_INET6, &(idata.srcaddr), psrcaddr, sizeof(psrcaddr)) == NULL){
		puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
		exit(EXIT_FAILURE);
	}

	if(idata.dstaddr_f){
		printf("IPv6 Source Address: %s%s\n", psrcaddr, ((!idata.srcaddr_f)?" (automatically selected)":""));
	}

	if(inet_ntop(AF_INET6, &(idata.dstaddr), pdstaddr, sizeof(pdstaddr)) == NULL){
		puts("inet_ntop(): Error converting IPv6 Destination Address to presentation format");
		exit(EXIT_FAILURE);
	}

	printf("IPv6 Destination Address: %s\n", pdstaddr);

	printf("IPv6 Hop Limit: %u%s\n", hoplimit, (hoplimit_f)?"":" (randomized)");

	printf("Protocol: %s\tDestination Port: %u\n", (protocol==IPPROTO_TCP)?"TCP":"UDP", dstport);
}



/*
 * Function: predict_flow_id()
 *
 * Identifies and prints the Flow Label generation policy
*/
int predict_flow_id(u_int32_t *s1, unsigned int n1, u_int32_t *s2, unsigned int n2){
	u_int32_t		diff1_avg, diff2_avg;
	double			diff1_sdev, diff2_sdev;

	if(inc_sdev(s1, n1, &diff1_avg, &diff1_sdev) == -1){
		if(idata.verbose_f)
			puts("Error while allocating memory in inc_sdev()");

		return(-1);
	}

	if(inc_sdev(s2, n2, &diff2_avg, &diff2_sdev) == -1){
		if(idata.verbose_f)
			puts("Error while allocating memory in inc_sdev()");

		return(-1);
	}
	
	if(diff1_sdev == 0 && diff1_avg == 0){
		if(diff2_sdev == 0 && diff2_avg == 0){
			printf("Flow Label policy: Global (predictable) constant labels, set to %05lu\n", (LUI) s1[0]);
		}
		else{
			printf("Flow Label policy: Per-destination constant labels with increments of %lu (sdev: %f)\n", \
					(LUI) diff2_avg, diff2_sdev);
		}
	}

	else if(diff1_sdev <= 100){
		if(diff2_sdev <= 100){
			printf("Flow Label policy: Global (predictable) labels with increments of %lu (sdev: %f)\n", \
					(LUI) diff1_avg, diff1_sdev);
		}
		else{
			printf("Flow Label policy: Per-destination labels with increments of %lu (sdev: %f)\n", \
					(LUI) diff1_avg, diff1_sdev);
			printf("                   Global policy: Avg. inc.: %lu, sdev: %f\n", (LUI) diff2_avg, diff2_sdev);
		}
	}
	else{
		puts("Flow Label policy: Randomized labels");
		printf("    Per-destination: Avg. inc.: %lu, sdev: %f\n"
		       "    Global:          Avg. inc.: %lu, sdev: %f\n", \
				(LUI) diff1_avg, diff1_sdev, (LUI) diff2_avg, diff2_sdev);
	}

	return(0);
}


