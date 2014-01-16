/*
 * scan6: An IPv6 Address Scanning Tool
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
 * Build with: make scan6
 *
 * It requires that the libpcap library be installed on your system.
 *
 * Please send any bug reports to Fernando Gont <fgont@si6networks.com>
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <unistd.h>

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <ifaddrs.h>
#ifdef __linux__
	#include <netpacket/packet.h>
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__) || ( !defined(__FreeBSD__) && defined(__FreeBSD_kernel__))
	#include <net/if_dl.h>
#endif
#include "scan6.h"
#include "ipv6toolkit.h"
#include "libipv6.h"


/* Function prototypes */
int					create_candidate_globals(struct iface_data *, struct host_list *, struct host_list *, \
											struct host_list *);
int					find_local_globals(pcap_t *, struct iface_data *, unsigned char, const char *, struct host_list *);
void				free_host_entries(struct host_list *);
int					host_scan_local(pcap_t *, struct iface_data *, struct in6_addr *, unsigned char, \
									struct host_entry *);
int					multi_scan_local(pcap_t *, struct iface_data *, struct in6_addr *, unsigned char, \
									const char *, struct host_list *);
void				print_help(void);
int					print_host_entries(struct host_list *, unsigned char);
int					print_unique_host_entries(struct host_list *, unsigned char);
void				local_sig_alarm(int);
void				usage(void);
int 				validate_host_entries(pcap_t *, struct iface_data *, struct host_list *, struct host_list *);

int					probe_node_nd(const char *, struct ether_addr *, struct in6_addr *, struct in6_addr *,\
									struct ether_addr *);
int					process_icmp6_response(struct iface_data *, struct host_list *, unsigned char , \
											struct pcap_pkthdr *, const u_char *, unsigned char *);
int					valid_icmp6_response(struct iface_data *, unsigned char, struct pcap_pkthdr *,\
									const u_char *, unsigned char *);
int					valid_icmp6_response_remote(struct iface_data *, struct scan_list *, unsigned char, \
									struct pcap_pkthdr *, const u_char *, unsigned char *);
int					print_scan_entries(struct scan_list *);
int					load_ipv4mapped32_entries(struct scan_list *, struct scan_entry *, struct prefix4_entry *);
int					load_ipv4mapped64_entries(struct scan_list *, struct scan_entry *, struct prefix4_entry *);
int					load_embeddedport_entries(struct scan_list *, struct scan_entry *);
int					load_lowbyte_entries(struct scan_list *, struct scan_entry *);
int					load_oui_entries(struct scan_list *, struct scan_entry *, struct ether_addr *);
int					load_vm_entries(struct scan_list *, struct scan_entry *, struct prefix4_entry *);
int					load_vendor_entries(struct scan_list *, struct scan_entry *, char *);
int					load_knownprefix_entries(struct scan_list *, struct scan_list *, FILE *);
int					load_knowniid_entries(struct scan_list *, struct scan_list *, struct prefix_list *);
int					load_knowniidfile_entries(struct scan_list *, struct scan_list *, FILE *);
int					match_strings(char *, char *);
int					load_bruteforce_entries(struct scan_list *, struct scan_entry *);
void				prefix_to_scan(struct prefix_entry *, struct scan_entry *);
int					get_next_target(struct scan_list *);
int					is_target_in_range(struct scan_entry *);
int					send_probe_remote(struct iface_data *, struct scan_list *, struct in6_addr *, unsigned char);
void				reset_scan_list(struct scan_list *);
int					process_config_file(const char *);
int					is_ip6_in_scan_list(struct scan_list *, struct in6_addr *);


/* Used for multiscan */
struct host_list			host_local, host_global, host_candidate;
struct host_entry			*host_locals[MAX_IPV6_ENTRIES], *host_globals[MAX_IPV6_ENTRIES];
struct host_entry			*host_candidates[MAX_IPV6_ENTRIES];

/* Used for router discovery */
struct iface_data			idata;

/* Variables used for learning the default router */
struct ether_addr			router_ether, rs_ether;
struct in6_addr				router_ipv6, rs_ipv6;

struct in6_addr				randprefix;
unsigned char				randpreflen;

/* Data structures for packets read from the wire */
struct pcap_pkthdr			*pkthdr;
const u_char				*pktdata;
unsigned char				*pkt_end;
struct ether_header			*pkt_ether;
struct ip6_hdr				*pkt_ipv6;
struct in6_addr				*pkt_ipv6addr;
unsigned int				pktbytes;
struct icmp6_hdr			*pkt_icmp6;
struct nd_neighbor_solicit	*pkt_ns;
struct tcp_hdr				*pkt_tcp;
int							result;
unsigned char				error_f;


bpf_u_int32				my_netmask;
bpf_u_int32				my_ip;
struct bpf_program		pcap_filter;
char 					dev[64], errbuf[PCAP_ERRBUF_SIZE];
unsigned char			buffer[BUFFER_SIZE], buffrh[MIN_IPV6_HLEN + MIN_TCP_HLEN];
char					line[LINE_BUFFER_SIZE];
unsigned char			*v6buffer, *ptr, *startofprefixes;
char					*pref;
    
struct ip6_hdr			*ipv6;
struct icmp6_hdr		*icmp6;

struct ether_header		*ethernet;
unsigned int			ndst=0;

char					*lasts, *rpref;
char					*charptr;

size_t					nw;
unsigned long			ul_res, ul_val;
unsigned int			i, j, startrand;
unsigned int			skip;
unsigned char			dstpreflen;

u_int16_t				mask;
u_int8_t				hoplimit;

char 					plinkaddr[ETHER_ADDR_PLEN], pv4addr[INET_ADDRSTRLEN];
char 					psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN], pv6addr[INET6_ADDRSTRLEN];
unsigned char 			verbose_f=FALSE;
unsigned char 			rand_src_f=FALSE, rand_link_src_f=FALSE;
unsigned char 			accepted_f=FALSE, configfile_f=FALSE, dstaddr_f=FALSE, hdstaddr_f=FALSE, dstprefix_f=FALSE;
unsigned char			print_f=FALSE, print_local_f=FALSE, print_global_f=FALSE, probe_echo_f=FALSE, probe_unrec_f=FALSE, probe_f=FALSE;
unsigned char			print_type=NOT_PRINT_ETHER_ADDR, scan_local_f=FALSE, print_unique_f=FALSE, localaddr_f=FALSE;
unsigned char			tunnel_f=FALSE, loopback_f=FALSE, timestamps_f=FALSE;

/* Support for Extension Headers */
unsigned int			dstopthdrs, dstoptuhdrs, hbhopthdrs;
char					hbhopthdr_f=FALSE, dstoptuhdr_f=FALSE, dstopthdr_f=FALSE;
unsigned char			*dstopthdr[MAX_DST_OPT_HDR], *dstoptuhdr[MAX_DST_OPT_U_HDR];
unsigned char			*hbhopthdr[MAX_HBH_OPT_HDR];
unsigned int			dstopthdrlen[MAX_DST_OPT_HDR], dstoptuhdrlen[MAX_DST_OPT_U_HDR];
unsigned int			hbhopthdrlen[MAX_HBH_OPT_HDR], m, pad;

struct ip6_frag			fraghdr, *fh;
struct ip6_hdr			*fipv6;
unsigned char			fragh_f=FALSE;
unsigned char			fragbuffer[ETHER_HDR_LEN+MIN_IPV6_HLEN+MAX_IPV6_PAYLOAD];
unsigned char			*fragpart, *fptr, *fptrend, *ptrend, *ptrhdr, *ptrhdrend;
unsigned int			hdrlen, ndstopthdr=0, nhbhopthdr=0, ndstoptuhdr=0;
unsigned int			nfrags, fragsize, max_packet_size;
unsigned char			*prev_nh, *startoffragment;

/* Remote scans */
unsigned int			inc=1;
int						ranges;
struct	scan_list		scan_list, prefix_list;
struct scan_entry		*target_list[MAX_SCAN_ENTRIES];
struct	scan_entry		*tgt_pref_list[MAX_PREF_ENTRIES];
struct prefix_list		iid_list;
struct prefix_entry		*tgt_iid_list[MAX_IID_ENTRIES];
unsigned char			dst_f=FALSE, tgt_ipv4mapped32_f=FALSE, tgt_ipv4mapped64_f=FALSE, tgt_lowbyte_f=FALSE, tgt_oui_f=FALSE;
unsigned char			tgt_vendor_f=FALSE, tgt_vm_f=FALSE, tgt_bruteforce_f=FALSE, tgt_range_f=FALSE, tgt_portembedded_f=FALSE;
unsigned char			tgt_knowniids_f=FALSE, tgt_knowniidsfile_f=FALSE, knownprefixes_f=FALSE;
unsigned char			vm_vbox_f=FALSE, vm_vmware_f=FALSE, vm_vmwarem_f=FALSE, v4hostaddr_f=FALSE;
unsigned char			v4hostprefix_f=FALSE, sort_ouis_f=FALSE, rnd_probes_f=FALSE, inc_f=FALSE, end_f=FALSE, donesending_f=FALSE;
unsigned char			onlink_f=FALSE, pps_f=FALSE, bps_f=FALSE, tcpflags_f=FALSE, rhbytes_f=FALSE, srcport_f=FALSE, dstport_f=FALSE, probetype;
unsigned char			loop_f=FALSE, sleep_f=FALSE;
u_int16_t				srcport, dstport;
u_int8_t				tcpflags=0;
unsigned long			pktinterval, rate;
unsigned int			packetsize, rhbytes;
struct prefix4_entry	v4host;
struct prefix_entry		prefix;
struct ether_addr		oui;
char					*charstart, *charend, *lastcolon;
char					rangestart[MAX_RANGE_STR_LEN+1], rangeend[MAX_RANGE_STR_LEN+1];
char 					fname[MAX_FILENAME_SIZE], fname_f=FALSE, configfile[MAX_FILENAME_SIZE], knowniidsfile[MAX_FILENAME_SIZE];
char					knownprefixesfile[MAX_FILENAME_SIZE];
FILE					*knowniids_fp, *knownprefixes_fp;
char 					*oui_end=":00:00:00";
char 					oui_ascii[ETHER_ADDR_PLEN];
char					vendor[MAX_IEEE_OUIS_LINE_SIZE];
unsigned int			nsleep;
int						sel;
fd_set					sset, rset, wset, eset;
struct timeval			curtime, pcurtime, lastprobe;
struct tm				pcurtimetm;
u_int16_t				service_ports_hex[]={0x21, 0x22, 0x23, 0x25, 0x49, 0x53, 0x80, 0x110, 0x123, 0x179, 0x220, 0x389, \
						                 0x443, 0x547, 0x993, 0x995, 0x1194, 0x3306, 0x5060, 0x5061, 0x5432, 0x6446, 0x8080};
u_int16_t				service_ports_dec[]={21, 22, 23, 25, 49, 53, 80, 110, 123, 179, 220, 389, \
						                 443, 547, 993, 995, 1194, 3306, 5060, 5061, 5432, 6446, 8080};


/* IPv6 Address Resolution */
sigjmp_buf				env;
unsigned int			canjump;

int main(int argc, char **argv){
	extern char		*optarg;
	int			r;
	struct timeval	timeout;
	char			date[DATE_STR_LEN];

	static struct option longopts[] = {
		{"interface", required_argument, 0, 'i'},
		{"src-address", required_argument, 0, 's'},
		{"dst-address", required_argument, 0, 'd'},
		{"dst-opt-hdr", required_argument, 0, 'u'},
		{"dst-opt-u-hdr", required_argument, 0, 'U'},
		{"hbh-opt-hdr", required_argument, 0, 'H'},
		{"frag-hdr", required_argument, 0, 'y'},
		{"link-src-addr", required_argument, 0, 'S'},
		{"link-dst-addr", required_argument, 0, 'D'},
		{"local-scan", no_argument, 0, 'L'},
		{"probe-type", required_argument, 0, 'p'},
		{"payload-size", required_argument, 0, 'Z'},
		{"src-port", required_argument, 0, 'o'},
		{"dst-port", required_argument, 0, 'a'},
		{"tcp-flags", required_argument, 0, 'X'},
		{"print-type", required_argument, 0, 'P'},
		{"print-unique", no_argument, 0, 'q'},
		{"print-link-addr", no_argument, 0, 'e'},
		{"print-timestamp", no_argument, 0, 't'},
		{"retrans", required_argument, 0, 'x'},
		{"timeout", required_argument, 0, 'O'},
		{"rand-src-addr", no_argument, 0, 'f'},
		{"rand-link-src-addr", no_argument, 0, 'F'},
		{"tgt-virtual-machines", required_argument, 0, 'V'},
		{"tgt-low-byte", no_argument, 0, 'b'},
		{"tgt-ipv4", required_argument, 0, 'B'},
		{"tgt-ipv4-embedded", required_argument, 0, 'B'},
		{"tgt-port", no_argument, 0, 'g'},
		{"tgt-port-embedded", no_argument, 0, 'g'},
		{"tgt-ieee-oui", required_argument, 0, 'k'},
		{"tgt-vendor", required_argument, 0, 'K'},
		{"tgt-iids-file", required_argument, 0, 'w'},
		{"tgt-iid", required_argument, 0, 'W'},
		{"prefixes-file", required_argument, 0, 'm'},
		{"ipv4-host", required_argument, 0, 'Q'},
		{"sort-ouis", no_argument, 0, 'T'},
		{"random-probes", no_argument, 0, 'N'},
		{"inc-size", required_argument, 0, 'I'},
		{"rate-limit", required_argument, 0, 'r'},
		{"loop", no_argument, 0, 'l'},
		{"sleep", required_argument, 0, 'z'},
		{"config-file", required_argument, 0, 'c'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'}
	};

	char shortopts[]= "i:s:d:u:U:H:y:S:D:Lp:Z:o:a:X:P:qetx:O:fFV:bB:gk:K:w:W:m:Q:TNI:r:lz:c:vh";

	char option;

	if(argc<=1){
		usage();
		exit(EXIT_FAILURE);
	}

	srandom(time(NULL));
	hoplimit=64+random()%180;

	init_iface_data(&idata);

	/* Initialize the scan_list structure (for remote scans) */
	scan_list.target=target_list;
	scan_list.ntarget=0;
	scan_list.maxtarget= MAX_SCAN_ENTRIES;

	/* Initialize the prefix_list structure (for remote scans) */
	prefix_list.target= tgt_pref_list;
	prefix_list.ntarget=0;
	prefix_list.maxtarget= MAX_PREF_ENTRIES;

	/* Initialize the iid_list structure (for remote scans/tracking) */
	iid_list.prefix= tgt_iid_list;
	iid_list.nprefix=0;
	iid_list.maxprefix= MAX_IID_ENTRIES;

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

				if ( inet_pton(AF_INET6, charptr, &idata.srcaddr) <= 0){
					puts("inet_pton(): Source Address not valid");
					exit(EXIT_FAILURE);
				}

				idata.srcaddr_f=TRUE;
		
				if((charptr = strtok_r(NULL, " ", &lasts)) != NULL){
					idata.srcpreflen = atoi(charptr);
		
					if(idata.srcpreflen>128){
						puts("Prefix length error in IPv6 Source Address");
						exit(EXIT_FAILURE);
					}

					sanitize_ipv6_prefix(&(idata.srcaddr), idata.srcpreflen);
					idata.srcprefix_f=TRUE;
				}

				break;

			case 'd':	/* IPv6 Destination Address/Prefix */

				if( (ranges= address_contains_ranges(optarg)) == 1){
					charptr= optarg;
					charstart= rangestart;
					charend= rangeend;
					lastcolon= charend;

					while(*charptr && (optarg - charptr) <= MAX_RANGE_STR_LEN){
						if(*charptr != '-'){
							/* If we do not find a dash, just copy this 16-bit word to both the range start and the range end */
							*charstart= *charptr;
							*charend= *charptr;
							charstart++;
							charend++;

							/*
							    Record the address of the byte following the colon (in the range end), so that we know what to
							   "overwrite when we find a "range
							 */
							if(*charptr==':')
								lastcolon= charend;

							charptr++;
						}
						else{
							/* If we found a dash, we must "overwrite" the range end with what follows the dash */
							charend= lastcolon;
							charptr++;

							while(*charptr && (optarg - charptr) <= MAX_RANGE_STR_LEN && *charptr !=':' && *charptr !='-'){
								*charend= *charptr;
								charend++;
								charptr++;
							}
						}
					}

					/* Zero-terminate the strings that we have generated from the option arguements */
					*charstart=0;
					*charend=0;
					tgt_range_f=TRUE;

					if(scan_list.ntarget <= scan_list.maxtarget){
						if( (scan_list.target[scan_list.ntarget] = malloc(sizeof(struct scan_entry))) == NULL){
							if(idata.verbose_f)
								puts("scan6: Not enough memory");

							exit(EXIT_FAILURE);
						}

						if ( inet_pton(AF_INET6, rangestart, &(scan_list.target[scan_list.ntarget]->start)) <= 0){
							if(idata.verbose_f>1)
								puts("inet_pton(): Error converting IPv6 address from presentation to network format");

							exit(EXIT_FAILURE);
						}

						if ( inet_pton(AF_INET6, rangeend, &(scan_list.target[scan_list.ntarget]->end)) <= 0){
							if(idata.verbose_f>1)
								puts("inet_pton(): Error converting IPv6 address from presentation to network format");

							exit(EXIT_FAILURE);
						}

						scan_list.target[scan_list.ntarget]->cur= scan_list.target[scan_list.ntarget]->start;

						/* Check whether the start address is smaller than the end address */
						for(i=0;i<7; i++)
							if( ntohs(scan_list.target[scan_list.ntarget]->start.s6_addr16[i]) > 
								ntohs(scan_list.target[scan_list.ntarget]->end.s6_addr16[i])){
								if(idata.verbose_f)
									puts("Error in Destination Address range: Start address larger than end address!");

								exit(EXIT_FAILURE);
							}

						if(IN6_IS_ADDR_MULTICAST(&(scan_list.target[scan_list.ntarget]->start))){
							if(idata.verbose_f)
								puts("scan6: Remote scan cannot target a multicast address");

							exit(EXIT_FAILURE);
						}

						if(IN6_IS_ADDR_MULTICAST(&(scan_list.target[scan_list.ntarget]->end))){
							if(idata.verbose_f)
								puts("scan6: Remote scan cannot target a multicast address");

							exit(EXIT_FAILURE);
						}

						scan_list.ntarget++;
					}
					else{
						/*
						   If the number of "targets" has already been exceeded, it doesn't make sense to continue further,
						   since there wouldn't be space for any specific target types
						 */
						if(idata.verbose_f)
							puts("Too many targets!");

						exit(EXIT_FAILURE);
					}

					if(prefix_list.ntarget <= prefix_list.maxtarget){
						if( (prefix_list.target[prefix_list.ntarget] = malloc(sizeof(struct scan_entry))) == NULL){
							if(idata.verbose_f)
								puts("scan6: Not enough memory");

							exit(EXIT_FAILURE);
						}

						/* Copy the recently added target to our prefix list */
						*prefix_list.target[prefix_list.ntarget]= *scan_list.target[scan_list.ntarget - 1];
						prefix_list.ntarget++;
					}
					else{
						/*
						   If the number of "targets" has already been exceeded, it doesn't make sense to continue further,
						   since there wouldn't be space for any specific target types
						 */
						if(idata.verbose_f)
							puts("Too many targets!");

						exit(EXIT_FAILURE);
					}
				}
				else if(ranges == 0){
					if((charptr = strtok_r(optarg, "/", &lasts)) == NULL){
						puts("Error in Destination Address");
						exit(EXIT_FAILURE);
					}

					if ( inet_pton(AF_INET6, charptr, &(prefix.ip6)) <= 0){
						puts("inet_pton(): Destination Address not valid");
						exit(EXIT_FAILURE);
					}

					if((charptr = strtok_r(NULL, " ", &lasts)) != NULL){
						prefix.len = atoi(charptr);
		
						if(prefix.len>128){
							puts("Prefix length error in IPv6 Destination Address");
							exit(EXIT_FAILURE);
						}

						sanitize_ipv6_prefix(&(prefix.ip6), prefix.len);
					}
					else{
						prefix.len= 128;
					}

					if(prefix_list.ntarget <= prefix_list.maxtarget){
						if( (prefix_list.target[prefix_list.ntarget] = malloc(sizeof(struct scan_entry))) == NULL){
							if(idata.verbose_f)
								puts("scan6: Not enough memory");

							exit(EXIT_FAILURE);
						}

						prefix_to_scan(&prefix, prefix_list.target[prefix_list.ntarget]);

						if(IN6_IS_ADDR_MULTICAST(&(prefix_list.target[prefix_list.ntarget]->start))){
							if(idata.verbose_f)
								puts("scan6: Remote scan cannot target a multicast address");

							exit(EXIT_FAILURE);
						}

						if(IN6_IS_ADDR_MULTICAST(&(prefix_list.target[prefix_list.ntarget]->end))){
							if(idata.verbose_f)
								puts("scan6: Remote scan cannot target a multicast address");

							exit(EXIT_FAILURE);
						}

						prefix_list.ntarget++;
					}
					else{
						/*
						   If the number of "targets" has already been exceeded, it doesn't make sense to continue further,
						   since there wouldn't be space for any specific target types
						 */
						if(idata.verbose_f)
							puts("Too many targets!");

						exit(EXIT_FAILURE);
					}
				}

				idata.dstaddr= prefix_list.target[0]->start;
				dst_f=TRUE;
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
				dstopthdr_f=TRUE;
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
				dstoptuhdr_f=TRUE;
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
				hbhopthdr_f=TRUE;
				break;

			case 'y':	/* Fragment header */
				nfrags= atoi(optarg);
				if(nfrags < 8){
					puts("Error in Fragmentation option: Fragment Size must be at least 8 bytes");
					exit(EXIT_FAILURE);
				}
		
				nfrags = (nfrags +7) & 0xfff8;
				fragh_f=TRUE;
				break;

			case 'S':	/* Source Ethernet address */
				if(ether_pton(optarg, &(idata.hsrcaddr), sizeof(idata.hsrcaddr)) == 0){
					puts("Error in Source link-layer address.");
					exit(EXIT_FAILURE);
				}

				idata.hsrcaddr_f=TRUE;
				break;

			case 'D':	/* Destination Ethernet address */
				if(ether_pton(optarg, &(idata.hdstaddr), sizeof(idata.hdstaddr)) == 0){
					puts("Error in Destination Ethernet address.");
					exit(EXIT_FAILURE);
				}

				idata.hdstaddr_f=TRUE;
				break;

			case 'L':
				scan_local_f=TRUE;
				break;

			case 'p':	/* Probe type */
				if(strncmp(optarg, "echo", strlen("echo")) == 0){
					probe_echo_f=TRUE;
					probetype= PROBE_ICMP6_ECHO;
					probe_f=TRUE;
				}
				else if(strncmp(optarg, "unrec", strlen("unrec")) == 0){
					probe_unrec_f=TRUE;
					probetype= PROBE_UNREC_OPT;
					probe_f=TRUE;
				}
				else if(strncmp(optarg, "all", strlen("all")) == 0){
					probe_echo_f=TRUE;
					probe_unrec_f=TRUE;

					/* For reote scans, we use a single probe type */
					probetype= PROBE_ICMP6_ECHO;
					probe_f=TRUE;
				}
				else if(strncmp(optarg, "tcp", strlen("tcp")) == 0){
					probetype= PROBE_TCP;
					probe_f=TRUE;
				}
				else{
					puts("Error in '-p' option: Unknown probe type");
					exit(EXIT_FAILURE);
				}

				break;

			case 'Z':	/* Payload Size*/
				rhbytes= atoi(optarg);
				rhbytes_f=TRUE;
				break;

			case 'o':	/* TCP/UDP Source Port */
				srcport= atoi(optarg);
				srcport_f=TRUE;
				break;

			case 'a':	/* TCP/UDP Destination Port */
				dstport= atoi(optarg);
				dstport_f=TRUE;
				break;

			case 'X':
				charptr = optarg;
				while(*charptr){
					switch(*charptr){
						case 'F':
							tcpflags= tcpflags | TH_FIN;
							break;

						case 'S':
							tcpflags= tcpflags | TH_SYN;
							break;

						case 'R':
							tcpflags= tcpflags | TH_RST;
							break;

						case 'P':
							tcpflags= tcpflags | TH_PUSH;
							break;

						case 'A':
							tcpflags= tcpflags | TH_ACK;
							break;

						case 'U':
							tcpflags= tcpflags | TH_URG;
							break;

						case 'X': /* No TCP flags */
							break;

						default:
							printf("Unknown TCP flag '%c'\n", *charptr);
							exit(EXIT_FAILURE);
							break;
					}

					if(*charptr == 'X')
						break;

					charptr++;
				}

				tcpflags_f=TRUE;
				break;

			case 'P':	/* Print type */
				if(strncmp(optarg, "local", strlen("local")) == 0){
					print_local_f=TRUE;
					print_f=TRUE;
				}
				else if(strncmp(optarg, "global", strlen("global")) == 0){
					print_global_f=TRUE;
					print_f=TRUE;
				}
				else if(strncmp(optarg, "all", strlen("all")) == 0){
					print_local_f=TRUE;
					print_global_f=TRUE;
					print_f=TRUE;
				}
				else{
					puts("Error in '-P' option: Unknown address type");
					exit(EXIT_FAILURE);
				}

				break;

			case 'q':
				print_unique_f=TRUE;
				break;

			case 'e':
				print_type= PRINT_ETHER_ADDR;
				break;

			case 't':
				timestamps_f=TRUE;
				break;

			case 'x':
				idata.local_retrans=atoi(optarg);
				break;

			case 'O':
				idata.local_timeout=atoi(optarg);
				break;

			case 'f':
				rand_src_f=TRUE;
				break;

			case 'F':
				rand_link_src_f=TRUE;
				break;

			case 'V':
				if(strncmp(optarg, "vbox", strlen("vbox")) == 0){
					tgt_vm_f=TRUE;
					vm_vbox_f=TRUE;
				}
				else if(strncmp(optarg, "vmware", strlen("vmware")) == 0){
					tgt_vm_f=TRUE;
					vm_vmware_f=TRUE;
				}
				else if(strncmp(optarg, "vmwarem", strlen("vmwarem")) == 0){
					tgt_vm_f=TRUE;
					vm_vmwarem_f=TRUE;
				}
				else if(strncmp(optarg, "all", strlen("all")) == 0){
					tgt_vm_f=TRUE;
					vm_vbox_f=TRUE;
					vm_vmware_f=TRUE;
					vm_vmwarem_f=TRUE;
				}
				else{
					puts("Error in '-V' option: Unknown Virtualization Technology");
					exit(EXIT_FAILURE);
				}

				break;

			case 'b':
				tgt_lowbyte_f=TRUE;
				break;

			case 'B':
				if(strncmp("ipv4-all", optarg, MAX_LINE_SIZE) == 0){
					tgt_ipv4mapped32_f=TRUE;
					tgt_ipv4mapped64_f=TRUE;
				}
				else if(strncmp("ipv4-32", optarg, MAX_LINE_SIZE) == 0){
					tgt_ipv4mapped32_f=TRUE;
				}
				else if(strncmp("ipv4-64", optarg, MAX_LINE_SIZE) == 0){
					tgt_ipv4mapped64_f=TRUE;
				}
				else{
					puts("Unknown encoding of IPv4-embedded IPv6 addresses in '-B' option");
					exit(EXIT_FAILURE);
				}

				break;

			case 'g':
				tgt_portembedded_f=TRUE;
				break;

			case 'k':	/* Target OUI */
				/*
				   In case the user entered an OUI as OO:UU:II:00:00:00, just copy the first 8 bytes of input 
				   (the OUI part)
				  */
				strncpy(oui_ascii, optarg, 8);
				oui_ascii[8]= 0;
				strncat(oui_ascii, oui_end, ETHER_ADDR_PLEN-Strnlen(oui_ascii, sizeof(oui_ascii))-1);

				if(ether_pton(oui_ascii, &oui, sizeof(oui)) == 0){
					puts("Error in vendor IEEE OUI");
					exit(EXIT_FAILURE);
				}
		
				tgt_oui_f=TRUE;
				break;

			case 'K':	/* Target vendor */
				/*
				   In case the user entered an OUI as OO:UU:II:00:00:00, just copy the first 8 bytes of input 
				   (the OUI part)
				 */

				strncpy(vendor, optarg, MAX_IEEE_OUIS_LINE_SIZE-1);
				vendor[MAX_IEEE_OUIS_LINE_SIZE-1]= 0;
		
				tgt_vendor_f=TRUE;
				break;

			case 'w':	/* Target known Interface Identifiers (IIDs) */
				strncpy(knowniidsfile, optarg, MAX_FILENAME_SIZE-1);
				knowniidsfile[MAX_FILENAME_SIZE-1]=0;

				tgt_knowniidsfile_f=TRUE;
				break;


			case 'W':	/* Target Interface Identifier (IIDs) */
				if(iid_list.nprefix >= iid_list.maxprefix){
					puts("Too many INterface Identifiers");
					exit(EXIT_FAILURE);
				}

				if( (iid_list.prefix[iid_list.nprefix] = malloc(sizeof(struct prefix_entry))) == NULL){
					puts("Not enough memory while storing Interface ID");
					exit(EXIT_FAILURE);
				}

				if ( inet_pton(AF_INET6, optarg, &((iid_list.prefix[iid_list.nprefix])->ip6)) <= 0){
					puts("inet_pton(): Source Address not valid");
					exit(EXIT_FAILURE);
				}

				iid_list.prefix[iid_list.nprefix]->len=128;
				iid_list.nprefix++;

				tgt_knowniids_f=TRUE;
				break;

			case 'm':	/* Known prefixes file */
				strncpy(knownprefixesfile, optarg, MAX_FILENAME_SIZE-1);
				knownprefixesfile[MAX_FILENAME_SIZE-1]=0;

				knownprefixes_f=TRUE;
				break;

			case 'Q':
				if((charptr = strtok_r(optarg, "/", &lasts)) == NULL){
					puts("Error in Source Address");
					exit(EXIT_FAILURE);
				}

				if(inet_pton(AF_INET, charptr, &(v4host.ip)) != 1){
					puts("Error in Host IPv4 Address");
					exit(EXIT_FAILURE);
				}

				v4hostaddr_f=TRUE;
		
				if((charptr = strtok_r(NULL, " ", &lasts)) != NULL){
					v4host.len = atoi(charptr);

					if(v4host.len>32){
						puts("Prefix length error in Host IPv4 address");
						exit(EXIT_FAILURE);
					}

					sanitize_ipv4_prefix(&v4host);
					v4hostprefix_f=TRUE;
				}
				else{
					v4host.len=32;
				}

				break;

			case 'T':
				sort_ouis_f=TRUE;
				break;

			case 'N':
				rnd_probes_f=TRUE;
				break;

			case 'I':
				inc = atoi(optarg);
				inc_f=TRUE;
				break;

			case 'r':
				if( Strnlen(optarg, LINE_BUFFER_SIZE-1) >= (LINE_BUFFER_SIZE-1)){
					puts("scan6: -r option is too long");
					exit(EXIT_FAILURE);
				}

				sscanf(optarg, "%lu%s", &rate, line);

				line[LINE_BUFFER_SIZE-1]=0;

				if(strncmp(line, "pps", 3) == 0)
					pps_f=TRUE;
				else if(strncmp(line, "bps", 3) == 0)
					bps_f=TRUE;
				else{
					puts("scan6: Unknown unit of for the rate limit ('-r' option). Unit should be 'bps' or 'pps'");
					exit(EXIT_FAILURE);
				}

				break;

			case 'l':	/* "Loop mode */
				loop_f=TRUE;
				break;

			case 'z':	/* Sleep option */
				nsleep=atoi(optarg);
				if(nsleep==0){
					puts("Invalid number of seconds in '-z' option");
					exit(EXIT_FAILURE);
				}
	
				sleep_f=TRUE;
				break;

			case 'v':	/* Be verbose */
				idata.verbose_f++;
				break;
		
			case 'h':	/* Help */
				print_help();
				exit(EXIT_FAILURE);
				break;

			case 'c':	/* Configuration file */
				strncpy(configfile, optarg, MAX_FILENAME_SIZE-1);
				configfile[MAX_FILENAME_SIZE-1]=0;
				configfile_f=TRUE;
				break;

			default:
				usage();
				exit(EXIT_FAILURE);
				break;
		
		} /* switch */
	} /* while(getopt) */

	/*
	    XXX: This is rather ugly, but some local functions need to check for verbosity, and it was not warranted
	    to pass &idata as an argument
	 */
	verbose_f= idata.verbose_f;

	if(geteuid()){
		puts("scan6 needs superuser privileges to run");
		exit(EXIT_FAILURE);
	}

	if(scan_local_f && !idata.iface_f){
		puts("Must specify the network interface with the -i option when a local scan is selected");
		exit(EXIT_FAILURE);
	}

	/* Must open the "Known IIDs" file now, since it might be non-readable for the unprivileged user */
	if(tgt_knowniidsfile_f){
		if( (knowniids_fp=fopen(knowniidsfile, "r")) == NULL){
			perror("Error opening known IIDs file");
			exit(EXIT_FAILURE);
		}
	}

	/* Must open the "Known IIDs" file now, since it might be non-readable for the unprivileged user */
	if(knownprefixes_f){
		if( (knownprefixes_fp=fopen(knownprefixesfile, "r")) == NULL){
			perror("Error opening known prefixes file");
			exit(EXIT_FAILURE);
		}

		dst_f=TRUE;
	}

	if(!dst_f && !scan_local_f){
		if(idata.verbose_f)
			puts("Must specify either a destination prefix ('-d'), or a local scan ('-L')");

		exit(EXIT_FAILURE);
	}

	if(!scan_local_f){
		if(load_dst_and_pcap(&idata, LOAD_SRC_NXT_HOP) == FAILURE){
			puts("Error while learning Souce Address and Next Hop");
			exit(EXIT_FAILURE);
		}
	}
	else{
		if(load_dst_and_pcap(&idata, LOAD_PCAP_ONLY) == FAILURE){
			puts("Error while learning Souce Address and Next Hop");
			exit(EXIT_FAILURE);
		}
	}

	release_privileges();

	/* This loads prefixes, but not scan entries */
	if(knownprefixes_f){
		if(!load_knownprefix_entries(&scan_list, &prefix_list, knownprefixes_fp)){
			puts("Couldn't load known IPv6 prefixes");
			exit(EXIT_FAILURE);
		}			
	}

	if(!inc_f)
		scan_list.inc=1;

	if(pps_f && bps_f){
		puts("Cannot specify a rate-limit in bps and pps at the same time");
		exit(EXIT_FAILURE);
	}

	if(pps_f){
		if(rate < 1)
			rate=1;

		pktinterval= 1000000/rate;
	}

	if(bps_f){
		switch(probetype){
			case PROBE_UNREC_OPT:
				packetsize= MIN_IPV6_HLEN + sizeof(struct icmp6_hdr) + ICMPV6_ECHO_PAYLOAD_SIZE;
				break;

			case PROBE_ICMP6_ECHO:
				packetsize= MIN_IPV6_HLEN + MIN_DST_OPT_HDR_SIZE + sizeof(struct icmp6_hdr) + ICMPV6_ECHO_PAYLOAD_SIZE;
				break;

			case PROBE_TCP:
				packetsize= MIN_IPV6_HLEN + sizeof(struct tcp_hdr) + rhbytes;
				break;
		}

		if(rate == 0 || ((packetsize * 8)/rate) <= 0)
			pktinterval= 1000000;
		else
			pktinterval= ((packetsize * 8)/rate) * 1000000;
	}

	/* We Default to 1000 pps */
	if(!pps_f && !bps_f)
		pktinterval= 1000;


	if(!configfile_f){
		strncpy(configfile, "/etc/ipv6toolkit.conf", MAX_FILENAME_SIZE);
	}

	if(tgt_vendor_f){
		if(!process_config_file(configfile)){
			puts("Error while processing configuration file");
			exit(EXIT_FAILURE);
		}
	}

	if(loop_f && !dst_f){
		puts("Loop mode '-l' set, but no targets ('-d') specified!");
		puts("Note: '-l' option changed since IPv6 toolkit v1.3.4!");
	}

	if(dst_f && !(tgt_ipv4mapped32_f || tgt_ipv4mapped64_f || tgt_lowbyte_f || tgt_oui_f || tgt_vendor_f || \
			tgt_vm_f || tgt_range_f || tgt_portembedded_f || tgt_knowniids_f || tgt_knowniidsfile_f)){

		tgt_bruteforce_f=TRUE;
	}

	if( (tgt_ipv4mapped32_f || tgt_ipv4mapped64_f) && !v4hostaddr_f){
		puts("Error: Must IPv4 host address/prefix (with '--ipv4-host') if '--tgt-ipv4-embedded' is set");
		exit(EXIT_FAILURE);
	}

	if(scan_local_f && (idata.type != DLT_EN10MB || loopback_f)){
		puts("Error cannot apply local scan on a loopback or tunnel interface");
		exit(EXIT_FAILURE);
	}

	if(!print_f){
		print_local_f=TRUE;
		print_global_f=TRUE;
	}

	if(!probe_f){
		probe_unrec_f=TRUE;
		probe_echo_f=TRUE;

		/* For remote scans we use a single probe type */
		probetype=PROBE_ICMP6_ECHO;
	}

	/*
	   If a Source Address (and *not* a "source prefix") has been specified, we need to incorporate such address
	   in our iface_data structure.
	 */
	if(idata.srcaddr_f && !idata.srcprefix_f){
		if( (idata.srcaddr.s6_addr16[0] & htons(0xffc0)) == htons(0xfe80)){
			idata.ip6_local=idata.srcaddr;
			idata.ip6_local_flag=TRUE;
		}
		else{
			if( (idata.ip6_global.prefix[idata.ip6_global.nprefix] = malloc(sizeof(struct prefix_entry))) \
													== NULL){
				if(idata.verbose_f){
					puts("Not enough memory while saving global address");
				}
				exit(EXIT_FAILURE);
			}

			(idata.ip6_global.prefix[idata.ip6_global.nprefix])->ip6=idata.srcaddr;
			idata.ip6_global.nprefix++;
			idata.ip6_global_flag=1;
		}
	}

	if((idata.ip6_local_flag && idata.ip6_global_flag) && !idata.srcaddr_f)
		localaddr_f=TRUE;

	if(scan_local_f){
		host_local.nhosts=0;
		host_local.maxhosts= MAX_IPV6_ENTRIES;
		host_local.host= host_locals;

		if(probe_echo_f){
			if(multi_scan_local(idata.pfd, &idata, &(idata.ip6_local), PROBE_ICMP6_ECHO, ALL_NODES_MULTICAST_ADDR,\
						&host_local) == -1){
				if(idata.verbose_f)
					puts("Error while learning link-local addresses with ICMPv6 Echo Requests");

				exit(EXIT_FAILURE);
			}
		}


		if(probe_unrec_f){
			if(multi_scan_local(idata.pfd, &idata, &(idata.ip6_local), PROBE_UNREC_OPT, ALL_NODES_MULTICAST_ADDR,\
						 &host_local) == -1){
				if(idata.verbose_f)
					puts("Error while learning link-local addresses with Unrecognized options");

				exit(EXIT_FAILURE);
			}
		}

		if(print_local_f){
			if(idata.verbose_f)
				puts("Link-local addresses:");

			if(print_unique_f){
				if(print_unique_host_entries(&host_local, print_type) == -1){
					if(idata.verbose_f)
						puts("Error while printing global addresses");

					exit(EXIT_FAILURE);
				}
			}
			else{
				if(print_host_entries(&host_local, print_type) == -1){
					if(idata.verbose_f)
						puts("Error while printing global addresses");

					exit(EXIT_FAILURE);
				}
			}
		}

		if(print_global_f){
			host_global.nhosts=0;
			host_global.maxhosts= MAX_IPV6_ENTRIES;
			host_global.host= host_globals;

			if(probe_echo_f){
				if(find_local_globals(idata.pfd, &idata, PROBE_ICMP6_ECHO, ALL_NODES_MULTICAST_ADDR,\
							&host_global) == -1){
					if(idata.verbose_f)
						puts("Error while learning link-local addresses with ICMPv6 Echo Requests");

					exit(EXIT_FAILURE);
				}
			}

			if(probe_unrec_f){
				if(find_local_globals(idata.pfd, &idata, PROBE_UNREC_OPT, ALL_NODES_MULTICAST_ADDR,\
							 &host_global) == -1){
					if(idata.verbose_f)
						puts("Error while learning link-local addresses with Unrecognized options");

					exit(EXIT_FAILURE);
				}
			}

			host_candidate.nhosts=0;
			host_candidate.maxhosts= MAX_IPV6_ENTRIES;
			host_candidate.host= host_candidates;

			if(create_candidate_globals(&idata, &host_local, &host_global, &host_candidate) == -1){
				if(idata.verbose_f)
					puts("Error while creating candidate global addresses");

				exit(EXIT_FAILURE);
			}

			if(validate_host_entries(idata.pfd, &idata, &host_candidate, &host_global) == -1){
				if(idata.verbose_f)
					puts("Error while validating global entries");

				exit(EXIT_FAILURE);
			}

			if(idata.verbose_f)
				puts("\nGlobal addresses:");

			if(print_unique_f){
				if(print_unique_host_entries(&host_global, print_type) == -1){
					if(idata.verbose_f)
						puts("Error while printing global addresses");

					exit(EXIT_FAILURE);
				}
			}
			else{
				if(print_host_entries(&host_global, print_type) == -1){
					if(idata.verbose_f)
						puts("Error while printing global addresses");

					exit(EXIT_FAILURE);		
				}
			}
		}
	}

	/* Remote scan */
	else{
		if(tgt_knowniids_f){
			if(!load_knowniid_entries(&scan_list, &prefix_list, &iid_list)){
				puts("Couldn't load known IID IPv6 addresses");
				exit(EXIT_FAILURE);
			}
		}

		if(tgt_knowniidsfile_f){
			if(!load_knowniidfile_entries(&scan_list, &prefix_list, knowniids_fp)){
				puts("Couldn't load known IID IPv6 addresses");
				exit(EXIT_FAILURE);
			}

			fclose(knowniids_fp);
		}

		if(tgt_portembedded_f){
			for(i=0; i < prefix_list.ntarget; i++){
				if(!load_embeddedport_entries(&scan_list, prefix_list.target[i])){
					puts("Couldn't load embedded-port IPv6 addresses");
					exit(EXIT_FAILURE);
				}
			}
		}

		if(tgt_lowbyte_f){
			for(i=0; i < prefix_list.ntarget; i++){
				if(!load_lowbyte_entries(&scan_list, prefix_list.target[i])){
					puts("Couldn't load prefixes for low-byte IPv6 addresses");
					exit(EXIT_FAILURE);
				}
			}
		}

		if(tgt_ipv4mapped32_f){
			for(i=0; i < prefix_list.ntarget; i++){
				if(!load_ipv4mapped32_entries(&scan_list, prefix_list.target[i], &v4host)){
					puts("Couldn't load prefixes for IPv4-embeded (32-bit) IPv6 addresses");
					exit(EXIT_FAILURE);
				}
			}
		}

		if(tgt_ipv4mapped64_f){
			for(i=0; i < prefix_list.ntarget; i++){
				if(!load_ipv4mapped64_entries(&scan_list, prefix_list.target[i], &v4host)){
					puts("Couldn't load prefixes for IPv4-embeded (64-bit) IPv6 addresses");
					exit(EXIT_FAILURE);
				}
			}
		}

		if(tgt_vm_f){
			for(i=0; i < prefix_list.ntarget; i++){
				if(!load_vm_entries(&scan_list, prefix_list.target[i], &v4host)){
					puts("Couldn't load prefix for IEEE OUI");
					exit(EXIT_FAILURE);
				}
			}
		}

		if(tgt_oui_f){
			for(i=0; i < prefix_list.ntarget; i++){
				if(!load_oui_entries(&scan_list, prefix_list.target[i], &oui)){
					puts("Couldn't load prefix for IEEE OUI");
					exit(EXIT_FAILURE);
				}
			}			
		}

		if(tgt_vendor_f){
			for(i=0; i < prefix_list.ntarget; i++){
				if(!load_vendor_entries(&scan_list, prefix_list.target[i], vendor)){
					puts("Couldn't load prefixes for the specified vendor");
					exit(EXIT_FAILURE);
				}
			}
		}

		if(tgt_bruteforce_f){
			for(i=0; i < prefix_list.ntarget; i++){
				if(!load_bruteforce_entries(&scan_list, prefix_list.target[i])){
					puts("Couldn't load prefixes for the specified destination prefix");
					exit(EXIT_FAILURE);
				}
			}
		}

		if(idata.verbose_f){
			printf("Target address ranges (%d)\n", scan_list.ntarget);

			if(!print_scan_entries(&scan_list)){
				puts("Error while printing target address ranges");
				exit(EXIT_FAILURE);
			}
		}

		if(!scan_local_f && !idata.ip6_global_flag){
			if(idata.verbose_f)
				puts("Cannot obtain a global address to scan remote network");

			exit(EXIT_FAILURE);
		}

		switch(probetype){
			case PROBE_ICMP6_ECHO:
				if(pcap_compile(idata.pfd, &pcap_filter, PCAP_ICMPV6_ERQNSNA_FILTER, 0, PCAP_NETMASK_UNKNOWN) == -1){
					if(idata.verbose_f>1)
						printf("pcap_compile(): %s\n", pcap_geterr(idata.pfd));

					exit(EXIT_FAILURE);
				}
				break;

			case PROBE_UNREC_OPT:
				if(pcap_compile(idata.pfd, &pcap_filter, PCAP_ICMPV6_ERRORNSNA_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
					if(idata.verbose_f>1)
						printf("pcap_compile(): %s\n", pcap_geterr(idata.pfd));

					exit(EXIT_FAILURE);
				}
				break;

			case PROBE_TCP:
				if(pcap_compile(idata.pfd, &pcap_filter, PCAP_TCP_NSNA_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
					if(idata.verbose_f>1)
						printf("pcap_compile(): %s\n", pcap_geterr(idata.pfd));

					exit(EXIT_FAILURE);
				}
				break;
		}

		if(pcap_setfilter(idata.pfd, &pcap_filter) == -1){
			if(idata.verbose_f>1)
				printf("pcap_setfilter(): %s\n", pcap_geterr(idata.pfd));

			exit(EXIT_FAILURE);
		}

		pcap_freecode(&pcap_filter);

		if(idata.verbose_f)
			puts("\nAlive nodes:");

		FD_ZERO(&sset);
		FD_SET(idata.fd, &sset);

		lastprobe.tv_sec= 0;	
		lastprobe.tv_usec=0;
		idata.pending_write_f=TRUE;		

		while(!end_f){
			rset= sset;
			wset= sset;
			eset= sset;

			if(!donesending_f){
				timeout.tv_sec= pktinterval / 1000000 ;	
				timeout.tv_usec= pktinterval % 1000000;
			}
			else{
				timeout.tv_usec=0;
				timeout.tv_sec= SELECT_TIMEOUT;
			}

			/*
				Check for readability and exceptions. We only check for writeability if there is pending data
				to send (the pcap descriptor will usually be writeable!).
			 */
			if((sel=select(idata.fd+1, &rset, (idata.pending_write_f?&wset:NULL), &eset, &timeout)) == -1){
				if(errno == EINTR){
					continue;
				}
				else{
					perror("scan6:");
					exit(EXIT_FAILURE);
				}
			}

			if(gettimeofday(&curtime, NULL) == -1){
				if(idata.verbose_f)
					perror("scan6");

				exit(EXIT_FAILURE);
			}

			/* Check whether we have finished probing all targets */
			if(donesending_f){
				/*
				   If we're not looping, just wait for SELECT_TIMEOUT seconds for any incoming responses.
				   If we are looping (most likely because we're doing host-tracking, wait for nsleep seconds, and
				   reset the targets.
				*/
				if(!loop_f){
					if(is_time_elapsed(&curtime, &lastprobe, SELECT_TIMEOUT * 1000000)){
						end_f=TRUE;
					}
				}
				else{
					if(is_time_elapsed(&curtime, &lastprobe, nsleep * 1000000)){
						reset_scan_list(&scan_list);
						donesending_f=FALSE;
						continue;
					}
				}
			}

			/*
			   If we didn't check for writeability in the previous call to select(), we must do it now. Otherwise, we might
			   block when trying to send a packet.
			 */
			if(!donesending_f && !idata.pending_write_f){
				wset= sset;

				timeout.tv_usec=0;
				timeout.tv_sec= 0;

				if( (sel=select(idata.fd+1, NULL, &wset, NULL, &timeout)) == -1){
					if(errno == EINTR){
						continue;
					}
					else{
						perror("scan6:");
						exit(EXIT_FAILURE);
					}
				}
			}

			if(FD_ISSET(idata.fd, &rset)){
				error_f=FALSE;

				if((result=pcap_next_ex(idata.pfd, &pkthdr, &pktdata)) == -1){
					if(idata.verbose_f)
						printf("Error while reading packet in main loop: pcap_next_ex(): %s", pcap_geterr(idata.pfd));

					exit(EXIT_FAILURE);
				}

				if(result == 1){
					pkt_ether = (struct ether_header *) pktdata;
					pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata.linkhsize);
					pkt_icmp6 = (struct icmp6_hdr *) ((char *) pkt_ipv6 + sizeof(struct ip6_hdr));
					pkt_tcp = (struct tcp_hdr *) ((char *) pkt_ipv6 + sizeof(struct ip6_hdr));
					pkt_ns= (struct nd_neighbor_solicit *) pkt_icmp6;
					pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

					if( (pkt_end -  pktdata) < (idata.linkhsize + MIN_IPV6_HLEN))
						continue;

					if(pkt_ipv6->ip6_nxt == IPPROTO_ICMPV6){
						if( idata.type == DLT_EN10MB && !loopback_f && pkt_icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT){
							if( (pkt_end - (unsigned char *) pkt_ns) < sizeof(struct nd_neighbor_solicit))
								continue;

							/* 
								If the addresses that we're using are not actually configured on the local system
								(i.e., they are "spoofed", we must check whether it is a Neighbor Solicitation for 
								one of our addresses, and respond with a Neighbor Advertisement. Otherwise, the kernel
								will take care of that.
							 */
							if(is_ip6_in_address_list(&(idata.ip6_global), &(pkt_ns->nd_ns_target)) || \
								is_eq_in6_addr(&(pkt_ns->nd_ns_target), &(idata.ip6_local))){
									if(send_neighbor_advert(&idata, idata.pfd, pktdata) == -1){
										if(idata.verbose_f)
											puts("Error sending Neighbor Advertisement message");

										exit(EXIT_FAILURE);
									}
							}
						}
						else if( (probetype == PROBE_ICMP6_ECHO && pkt_icmp6->icmp6_type == ICMP6_ECHO_REPLY) ||\
								 (probetype == PROBE_UNREC_OPT && pkt_icmp6->icmp6_type == ICMP6_PARAM_PROB)){
							if(!is_ip6_in_scan_list(&scan_list, &(pkt_ipv6->ip6_src)))
								continue;

							if( (pkt_end - (unsigned char *) pkt_icmp6) < sizeof(struct icmp6_hdr))
								continue;

							if(valid_icmp6_response_remote(&idata, &scan_list, probetype, pkthdr, pktdata, buffer)){
								/* Print the Source Address of the incoming packet */
								if(inet_ntop(AF_INET6, &(pkt_ipv6->ip6_src), pv6addr, sizeof(pv6addr)) == NULL){
									if(idata.verbose_f>1)
										puts("inet_ntop(): Error converting IPv6 address to presentation format");

									exit(EXIT_FAILURE);
								}

								if(timestamps_f){
									if(gettimeofday(&pcurtime, NULL) == -1){
										if(idata.verbose_f)
											perror("scan6");

										exit(EXIT_FAILURE);
									}

									if(localtime_r( (time_t *) &(pcurtime.tv_sec), &pcurtimetm) == NULL){
										if(idata.verbose_f>1)
											puts("localtime_r(): Error obtaining local time.");

										exit(EXIT_FAILURE);
									}

									if(strftime(date, DATE_STR_LEN, "%a %b %d %T %Y", &pcurtimetm) == 0){
										if(idata.verbose_f>1)
											puts("strftime(): Error converting current time to text");

										exit(EXIT_FAILURE);
									}

									printf("%s (%s)\n", pv6addr, date);
								}
								else{
									printf("%s\n", pv6addr);
								}
							}
						}
					}
					else if(probetype == PROBE_TCP && pkt_ipv6->ip6_nxt == IPPROTO_TCP){
						if(!is_ip6_in_scan_list(&scan_list, &(pkt_ipv6->ip6_src)))
							continue;

						if(srcport_f)
							if(pkt_tcp->th_dport != htons(srcport))
								continue;

						if(dstport_f)
							if(pkt_tcp->th_sport != htons(dstport))
								continue;

						if(in_chksum(pkt_ipv6, pkt_tcp, pkt_end-((unsigned char *)pkt_tcp), IPPROTO_TCP) != 0)
							continue;

						if(inet_ntop(AF_INET6, &(pkt_ipv6->ip6_src), pv6addr, sizeof(pv6addr)) == NULL){
							if(idata.verbose_f>1)
								puts("inet_ntop(): Error converting IPv6 address to presentation format");

							exit(EXIT_FAILURE);
						}

						if(timestamps_f){
							if(gettimeofday(&pcurtime, NULL) == -1){
								if(idata.verbose_f)
									perror("scan6");

								exit(EXIT_FAILURE);
							}

							if(localtime_r((time_t *) &(pcurtime.tv_sec), &pcurtimetm) == NULL){
								if(idata.verbose_f>1)
									puts("localtime_r(): Error obtaining local time.");

								exit(EXIT_FAILURE);
								}

							if(strftime(date, DATE_STR_LEN, "%a %b %d %T %Y", &pcurtimetm) == 0){
								if(idata.verbose_f>1)
									puts("strftime(): Error converting current time to text");

								exit(EXIT_FAILURE);
							}

							printf("%s (%s)\n", pv6addr, date);
						}
						else{
							printf("%s\n", pv6addr);
						}
					}
				}
			}

			if(!donesending_f && !idata.pending_write_f && is_time_elapsed(&curtime, &lastprobe, pktinterval)){
				idata.pending_write_f=TRUE;
				continue;
			}

			if(!donesending_f && FD_ISSET(idata.fd, &wset)){
				idata.pending_write_f=FALSE;

				/* Check whether the current scan_entry is within range. Otherwise, get the next target */
				if( !is_target_in_range(scan_list.target[scan_list.ctarget])){
					if(!get_next_target(&scan_list)){
						if(gettimeofday(&lastprobe, NULL) == -1){
							if(idata.verbose_f)
								perror("scan6");

							exit(EXIT_FAILURE);
						}

						donesending_f=TRUE;
						continue;
					}
				}

				if(!send_probe_remote(&idata, &scan_list, &(idata.srcaddr), probetype)){
						exit(EXIT_FAILURE);
				}

				if(gettimeofday(&lastprobe, NULL) == -1){
					if(idata.verbose_f)
						perror("scan6");

					exit(EXIT_FAILURE);
				}

				if(!get_next_target(&scan_list)){
					donesending_f=TRUE;
					continue;
				}

			}

			if(FD_ISSET(idata.fd, &eset)){
				if(idata.verbose_f)
					puts("scan6: Found exception on libpcap descriptor");

				exit(EXIT_FAILURE);
			}
		}

	}

	exit(EXIT_SUCCESS);
}


/*
 * Function: reset_scan_list()
 *
 * Resets each scan_list.target[]->cur to scan_list.target[]->start.
 */

void reset_scan_list(struct scan_list *scan){
	unsigned int i;

	for(i=0; i < scan->ntarget; i++)
		(scan->target[i])->cur = (scan->target[i])->start;

	scan->ctarget=0;

	return;
}



/*
 * Function: is_target_in_range()
 *
 * Checks whether a scan_entry->cur is >= scan_entry->start && <= scan_entry->end
 */

int is_target_in_range(struct scan_entry *scan_entry){
	unsigned int i;

	if(scan_list.ctarget >=scan_list.ntarget || scan_list.ctarget >= scan_list.maxtarget){
		return(0);
	}

	for(i=0; i<=7; i++){
		if( ntohs((scan_entry->cur).s6_addr16[i]) < ntohs((scan_entry->start).s6_addr16[i]) || \
			( ntohs((scan_entry->cur).s6_addr16[i]) > ntohs((scan_entry->end).s6_addr16[i])) )
				return(0);
	}

	return(1);
}


/*
 * Function: get_next_target()
 *
 * "Increments" a scan_entry structure to obtain the next target to scan.
 */

int get_next_target(struct scan_list *scan_list){
	int i;
	unsigned int	cind;


	for(i=7; i>=0; i--){
		/*
			Increment scan_entry according to scan_entry->start and scan_entry->end, starting with the low-order word
		 */

		if( ntohs((scan_list->target[scan_list->ctarget])->cur.s6_addr16[i]) >= \
								ntohs((scan_list->target[scan_list->ctarget])->end.s6_addr16[i])){
			if(i==0){
				scan_list->ctarget++;

				if(scan_list->ctarget < scan_list->ntarget && scan_list->ctarget < scan_list->maxtarget){
					return(1);
				}
				else{
					return(0);
				}
			}

			(scan_list->target[scan_list->ctarget])->cur.s6_addr16[i]= (scan_list->target[scan_list->ctarget])->start.s6_addr16[i];

		}
		else{
			/* We must increment the current word */

			cind= scan_list->ctarget;

			/*
				If we're incrementing the lowest-order word, and the scan range is larger than MIN_INC_RANGE, we increment
				the word by scan_list->inc. Otherwise, we increment the word by 1.
			 */
			if(i==7 && ( ntohs((scan_list->target[cind])->end.s6_addr16[7]) - ntohs( (scan_list->target[cind])->start.s6_addr16[7]) ) \
																	>= MIN_INC_RANGE ){

				/* If the increment would exceed scan_entry->end, we make it "wrap around" */
				if( ((unsigned int) ntohs((scan_list->target[cind])->cur.s6_addr16[7]) + scan_list->inc) > \
							ntohs((scan_list->target[scan_list->ctarget])->end.s6_addr16[7]) ){

						(scan_list->target[cind])->cur.s6_addr16[i]= htons((u_int16_t)((unsigned int)
																ntohs((scan_list->target[cind])->start.s6_addr16[i]) + \
																( (unsigned int) ntohs((scan_list->target[cind])->cur.s6_addr16[i]) + \
																 scan_list->inc - ntohs((scan_list->target[cind])->start.s6_addr16[i])) % \
																( ntohs((scan_list->target[cind])->end.s6_addr16[i]) - \
																ntohs((scan_list->target[cind])->start.s6_addr16[i]))));
				}
				else{
					/* Otherwise we simply increment the word with scan_list->inc */
					scan_list->target[cind]->cur.s6_addr16[i] = htons(ntohs(scan_list->target[cind]->cur.s6_addr16[i]) + scan_list->inc);
					return(1);
				}
			}
			else{
				/*
				   If the scan range is smaller than MIN_IN_RANGE, or we are incrementing a word other than the lowest-order one,
				   we try to increment in by 1. If this would exceed scan_entry->end, we set it to scan_entry->start and cause the
				   next word to be incremented
				 */
				if( ((unsigned int) ntohs((scan_list->target[cind])->cur.s6_addr16[i]) + 1) > ntohs(scan_list->target[cind]->end.s6_addr16[i])){
					(scan_list->target[cind])->cur.s6_addr16[i]= (scan_list->target[cind])->start.s6_addr16[i];
				}
				else{
					scan_list->target[cind]->cur.s6_addr16[i] = htons(ntohs(scan_list->target[cind]->cur.s6_addr16[i]) + 1);
					return(1);
				}
			}
		}
	}

	return(1);
}



/*
 * Function: print_scan_entries()
 *
 * Print address ranges to scan
 */

int print_scan_entries(struct scan_list *scan){
	unsigned int i, j;

	for(i=0; i< scan->ntarget; i++){
		for(j=0; j<8; j++){
			if((scan->target[i])->start.s6_addr16[j] == (scan->target[i])->end.s6_addr16[j])
				printf("%x", ntohs((scan->target[i])->start.s6_addr16[j]));
			else
				printf("%x-%x", ntohs((scan->target[i])->start.s6_addr16[j]), ntohs((scan->target[i])->end.s6_addr16[j]));

			if(j<7)
				printf(":");
			else
				puts("");
		}
	}

	return(1);
}


/*
 * Function: load_ipv4mapped32_prefixes()
 *
 * Generate scan_entry's for IPv4-mapped (32-bits) addresses
 */

int load_ipv4mapped32_entries(struct scan_list *scan, struct scan_entry *dst, struct prefix4_entry *v4host){
	unsigned int i;
	u_int32_t	mask32;

	if(scan->ntarget >= scan->maxtarget){
		return(0);
	}

	if( (scan->target[scan->ntarget] = malloc(sizeof(struct scan_entry))) == NULL)
		return(0);

	(scan->target[scan->ntarget])->start= dst->start;

	for(i=4; i<=5; i++)
		(scan->target[scan->ntarget])->start.s6_addr16[i]= htons(0);

	(scan->target[scan->ntarget])->start.s6_addr16[6]= htons( (u_int16_t) (ntohl(v4host->ip.s_addr) >> 16));
	(scan->target[scan->ntarget])->start.s6_addr16[7]= htons( (u_int16_t) (ntohl(v4host->ip.s_addr) & 0x0000ffff));
	(scan->target[scan->ntarget])->cur= (scan->target[scan->ntarget])->start;

	(scan->target[scan->ntarget])->end= dst->end;

	for(i=4; i<=7; i++)
		(scan->target[scan->ntarget])->end.s6_addr16[i]= (scan->target[scan->ntarget])->start.s6_addr16[i];

	mask32= 0xffffffff;

	for(i=0; i< v4host->len; i++)
		mask32=mask32<<1;

	for(i=0; i< v4host->len; i++)
		mask32=mask32>>1;

	(scan->target[scan->ntarget])->end.s6_addr16[6]= (scan->target[scan->ntarget])->end.s6_addr16[6] | htons( (u_int16_t)(mask32>>16));
	(scan->target[scan->ntarget])->end.s6_addr16[7]= (scan->target[scan->ntarget])->end.s6_addr16[7] | htons((u_int16_t)(mask32 & 0x0000ffff));

	scan->ntarget++;

	return(1);
}


/*
 * Function: load_ipv4mapped64_prefixes()
 *
 * Generate scan_entry's for IPv4-mapped (64-bits) addresses
 */

int load_ipv4mapped64_entries(struct scan_list *scan, struct scan_entry *dst, struct prefix4_entry *v4host){
	unsigned int i;
	u_int32_t	mask32;

	if(scan->ntarget >= scan->maxtarget){
		return(0);
	}

	if( (scan->target[scan->ntarget] = malloc(sizeof(struct scan_entry))) == NULL)
		return(0);

	(scan->target[scan->ntarget])->start= dst->start;

	(scan->target[scan->ntarget])->start.s6_addr16[4]= htons( (u_int16_t) (ntohl(v4host->ip.s_addr) >> 24));
	(scan->target[scan->ntarget])->start.s6_addr16[5]= htons( ((u_int16_t) (ntohl(v4host->ip.s_addr) >> 16)) & 0x00ff);
	(scan->target[scan->ntarget])->start.s6_addr16[6]= htons( (u_int16_t) ((ntohl(v4host->ip.s_addr) >> 8) & 0x000000ff));
	(scan->target[scan->ntarget])->start.s6_addr16[7]= htons( (u_int16_t) (ntohl(v4host->ip.s_addr) & 0x000000ff));
	(scan->target[scan->ntarget])->cur= (scan->target[scan->ntarget])->start;

	(scan->target[scan->ntarget])->end= dst->end;

	for(i=4; i<=7; i++)
		(scan->target[scan->ntarget])->end.s6_addr16[i]= (scan->target[scan->ntarget])->start.s6_addr16[i];

	mask32= 0xffffffff;

	for(i=0; i< v4host->len; i++)
		mask32=mask32<<1;

	for(i=0; i< v4host->len; i++)
		mask32=mask32>>1;

	(scan->target[scan->ntarget])->end.s6_addr16[4]= (scan->target[scan->ntarget])->end.s6_addr16[4] | htons( (u_int16_t)(mask32>>24));
	(scan->target[scan->ntarget])->end.s6_addr16[5]= (scan->target[scan->ntarget])->end.s6_addr16[5] | htons( (u_int16_t)(mask32>>16 & 0x000000ff));
	(scan->target[scan->ntarget])->end.s6_addr16[6]= (scan->target[scan->ntarget])->end.s6_addr16[6] | htons( (u_int16_t)(mask32>>8 & 0x000000ff));
	(scan->target[scan->ntarget])->end.s6_addr16[7]= (scan->target[scan->ntarget])->end.s6_addr16[7] | htons((u_int16_t)(mask32 & 0x000000ff));

	for(i=4; i<=7; i++){
		(scan->target[scan->ntarget])->start.s6_addr16[i]= htons( dec_to_hex(ntohs((scan->target[scan->ntarget])->start.s6_addr16[i])));
		(scan->target[scan->ntarget])->end.s6_addr16[i]= htons( dec_to_hex(ntohs((scan->target[scan->ntarget])->end.s6_addr16[i])));
	}

	scan->ntarget++;

	return(1);
}


/*
 * Function: load_knownprefix_entries()
 *
 * Generate prefix_entry's for known prefixes (populate the prefix_list)
 */

int load_knownprefix_entries(struct scan_list *scan_list, struct scan_list *prefix_list, FILE *fp){
	unsigned int i;
	int	r;
	char line[MAX_LINE_SIZE], *ptr, *charptr, *charstart, *charend, *lastcolon;
	char rangestart[MAX_RANGE_STR_LEN+1], rangeend[MAX_RANGE_STR_LEN+1];
	struct prefix_entry		prefix;

	while(fgets(line, sizeof(line),  fp) != NULL){
		r= read_prefix(line, Strnlen(line, MAX_LINE_SIZE), &ptr);

		if(r == 1){
			if( (ranges= address_contains_ranges(ptr)) == 1){
				charptr= ptr;
				charstart= rangestart;
				charend= rangeend;
				lastcolon= charend;

				while(*charptr && (ptr - charptr) <= MAX_RANGE_STR_LEN){
					if(*charptr != '-'){
						*charstart= *charptr;
						*charend= *charptr;
						charstart++;
						charend++;

						if(*charptr==':')
							lastcolon= charend;

						charptr++;
					}
					else{
						charend= lastcolon;
						charptr++;

						while(*charptr && (ptr - charptr) <= MAX_RANGE_STR_LEN && *charptr !=':' && *charptr !='-'){
							*charend= *charptr;
							charend++;
							charptr++;
						}
					}
				}

				*charstart=0;
				*charend=0;
				tgt_range_f=TRUE;

				if(scan_list->ntarget <= scan_list->maxtarget){
					if( (scan_list->target[scan_list->ntarget] = malloc(sizeof(struct scan_entry))) == NULL){
						if(verbose_f > 1)
							puts("scan6: Not enough memory");

						return(0);
					}

					if ( inet_pton(AF_INET6, rangestart, &((scan_list->target[scan_list->ntarget])->start)) <= 0){
						if(verbose_f>1)
							puts("inet_pton(): Error converting IPv6 address from presentation to network format");

						return(0);
					}

					if ( inet_pton(AF_INET6, rangeend, &((scan_list->target[scan_list->ntarget])->end)) <= 0){
						if(verbose_f>1)
							puts("inet_pton(): Error converting IPv6 address from presentation to network format");

						return(0);
					}

					(scan_list->target[scan_list->ntarget])->cur= (scan_list->target[scan_list->ntarget])->start;

					/* Check whether the start address is smaller than the end address */
					for(i=0;i<7; i++)
						if( ntohs((scan_list->target[scan_list->ntarget])->start.s6_addr16[i]) > 
							ntohs((scan_list->target[scan_list->ntarget])->end.s6_addr16[i])){
							if(verbose_f > 1)
								puts("Error in Destination Address range: Start address larger than end address!");

							return(0);
						}

					if(IN6_IS_ADDR_MULTICAST(&((scan_list->target[scan_list->ntarget])->start))){
						if(verbose_f > 1)
							puts("scan6: Remote scan cannot target a multicast address");

						return(0);
					}

					if(IN6_IS_ADDR_MULTICAST(&((scan_list->target[scan_list->ntarget])->end))){
						if(verbose_f > 1)
							puts("scan6: Remote scan cannot target a multicast address");

						return(0);
					}

					scan_list->ntarget++;
				}
				else{
					/*
					   If the number of "targets" has already been exceeded, it doesn't make sense to continue further,
					   since there wouldn't be space for any specific target types
					 */
					if(verbose_f > 1)
						puts("Too many targets!");

					return(0);
				}

				if(prefix_list->ntarget <= prefix_list->maxtarget){
					if( (prefix_list->target[prefix_list->ntarget] = malloc(sizeof(struct scan_entry))) == NULL){
						if(verbose_f > 1)
							puts("scan6: Not enough memory");

						return(0);
					}

					/* Copy the recently added target to our prefix list */
					*(prefix_list->target[prefix_list->ntarget])= *(scan_list->target[scan_list->ntarget - 1]);
					prefix_list->ntarget++;
				}
				else{
					/*
					   If the number of "targets" has already been exceeded, it doesn't make sense to continue further,
					   since there wouldn't be space for any specific target types
					 */
					if(verbose_f > 1)
						puts("Too many targets!");

					return(0);
				}
			}
			else if(ranges == 0){
				if((charptr = strtok_r(ptr, "/", &lasts)) == NULL){
					if(verbose_f > 1)
						puts("Error in Destination Address");

					return(0);
				}

				if ( inet_pton(AF_INET6, charptr, &(prefix.ip6)) <= 0){
					if(verbose_f > 1)
						puts("inet_pton(): Destination Address not valid");

					return(0);
				}

				if((charptr = strtok_r(NULL, " ", &lasts)) != NULL){
					prefix.len = atoi(charptr);
		
					if(prefix.len>128){
						if(verbose_f > 1)
							puts("Prefix length error in IPv6 Destination Address");

						return(0);
					}

					sanitize_ipv6_prefix(&(prefix.ip6), prefix.len);
				}
				else{
					prefix.len= 128;
				}

				if(prefix_list->ntarget <= prefix_list->maxtarget){
					if( (prefix_list->target[prefix_list->ntarget] = malloc(sizeof(struct scan_entry))) == NULL){
						if(verbose_f)
							puts("scan6: Not enough memory");

						return(0);
					}

					prefix_to_scan(&prefix, prefix_list->target[prefix_list->ntarget]);

					if(IN6_IS_ADDR_MULTICAST(&((prefix_list->target[prefix_list->ntarget])->start))){
						if(verbose_f > 1)
							puts("scan6: Remote scan cannot target a multicast address");

						return(0);
					}

					if(IN6_IS_ADDR_MULTICAST(&((prefix_list->target[prefix_list->ntarget])->end))){
						if(verbose_f > 1)
							puts("scan6: Remote scan cannot target a multicast address");

						return(0);
					}

					prefix_list->ntarget++;
				}
				else{
					/*
					   If the number of "targets" has already been exceeded, it doesn't make sense to continue further,
					   since there wouldn't be space for any specific target types
					 */
					if(verbose_f > 1)
						puts("Too many targets!");

					return(0);
				}
			}

			dst_f=TRUE;
		}
		else if(r == -1){
			if(verbose_f){
				printf("Error in 'known prefixes' file %s\n", knownprefixesfile);
			}

			fclose(fp);
			return(0);
		}
	}

	return(1);
}


/*
 * Function: load_knowniid_entries()
 *
 * Generate scan_entry's for known Interface IDs
 */

int load_knowniid_entries(struct scan_list *scan, struct scan_list *prefix, struct prefix_list *iid){
	unsigned int i, j, k;

	for(i=0; i< iid->nprefix; i++){
		for(j=0; j < prefix->ntarget; j++){
			if(scan->ntarget >= scan->maxtarget){
				return(0);
			}

			if( (scan->target[scan->ntarget] = malloc(sizeof(struct scan_entry))) == NULL)
				return(0);

			(scan->target[scan->ntarget])->start= (prefix->target[j])->start;

			for(k=4; k<=7; k++)
				(scan->target[scan->ntarget])->start.s6_addr16[k]= (iid->prefix[i])->ip6.s6_addr16[k];

			(scan->target[scan->ntarget])->cur= (scan->target[scan->ntarget])->start;

			(scan->target[scan->ntarget])->end= (prefix->target[j])->end;

			for(k=4; k<=7; k++)
				(scan->target[scan->ntarget])->end.s6_addr16[k]= (iid->prefix[i])->ip6.s6_addr16[k];

			scan->ntarget++;
		}
	}

	return(1);
}



/*
 * Function: load_knowniidfile_entries()
 *
 * Generate scan_entry's for known Interface IDs
 */

int load_knowniidfile_entries(struct scan_list *scan, struct scan_list *prefix, FILE *fp){
	unsigned int i;
	int	r;
	char line[MAX_LINE_SIZE];
	struct in6_addr	iid;

	while(fgets(line, sizeof(line),  fp) != NULL){
		r= read_ipv6_address(line, Strnlen(line, MAX_LINE_SIZE), &iid);

		if(r == 1){
			for(i=0; i< prefix->ntarget; i++){
				if(scan->ntarget >= scan->maxtarget){
					return(0);
				}

				if( (scan->target[scan->ntarget] = malloc(sizeof(struct scan_entry))) == NULL)
					return(0);

				(scan->target[scan->ntarget])->start= (prefix->target[i])->start;

				for(j=4; j<=7; j++)
					(scan->target[scan->ntarget])->start.s6_addr16[j]= iid.s6_addr16[j];

				(scan->target[scan->ntarget])->cur= (scan->target[scan->ntarget])->start;

				(scan->target[scan->ntarget])->end= (prefix->target[i])->end;

				for(j=4; j<=7; j++)
					(scan->target[scan->ntarget])->end.s6_addr16[j]= iid.s6_addr16[j];

				scan->ntarget++;
			}

		}
		else if(r == -1){
			if(verbose_f){
				printf("Error in 'known IIDs' file %s\n", knowniidsfile);
			}

			fclose(fp);
			return(0);
		}

	}

	return(1);
}


/*
 * Function: load_embeddedport_entries()
 *
 * Generate scan_entry's for IPv6 addresses with embedded service ports
 */

int load_embeddedport_entries(struct scan_list *scan, struct scan_entry *dst){
	unsigned int	i;

	for(i=0; i < (sizeof(service_ports_hex)/sizeof(u_int16_t)); i++){
		if(scan->ntarget >= scan->maxtarget){
			return(0);
		}

		if( (scan->target[scan->ntarget] = malloc(sizeof(struct scan_entry))) == NULL)
			return(0);

		(scan->target[scan->ntarget])->start= dst->start;
		(scan->target[scan->ntarget])->start.s6_addr16[4]= htons(0);
		(scan->target[scan->ntarget])->start.s6_addr16[5]= htons(0);
		(scan->target[scan->ntarget])->start.s6_addr16[6]= htons(0);
		(scan->target[scan->ntarget])->start.s6_addr16[7]= htons(service_ports_hex[i]);
		(scan->target[scan->ntarget])->cur= (scan->target[scan->ntarget])->start;

		(scan->target[scan->ntarget])->end= dst->end;
		(scan->target[scan->ntarget])->end.s6_addr16[4]= htons(0);
		(scan->target[scan->ntarget])->end.s6_addr16[5]= htons(0);
		(scan->target[scan->ntarget])->end.s6_addr16[6]= htons(EMBEDDED_PORT_2ND_WORD);
		(scan->target[scan->ntarget])->end.s6_addr16[7]= htons(service_ports_hex[i]);
		scan->ntarget++;

		if(scan->ntarget >= scan->maxtarget){
			return(0);
		}

		if( (scan->target[scan->ntarget] = malloc(sizeof(struct scan_entry))) == NULL)
			return(0);

		(scan->target[scan->ntarget])->start= dst->start;
		(scan->target[scan->ntarget])->start.s6_addr16[4]= htons(0);
		(scan->target[scan->ntarget])->start.s6_addr16[5]= htons(0);
		(scan->target[scan->ntarget])->start.s6_addr16[6]= htons(service_ports_hex[i]);
		(scan->target[scan->ntarget])->start.s6_addr16[7]= htons(0);
		(scan->target[scan->ntarget])->cur= (scan->target[scan->ntarget])->start;

		(scan->target[scan->ntarget])->end= dst->end;
		(scan->target[scan->ntarget])->end.s6_addr16[4]= htons(0);
		(scan->target[scan->ntarget])->end.s6_addr16[5]= htons(0);
		(scan->target[scan->ntarget])->end.s6_addr16[6]= htons(service_ports_hex[i]);
		(scan->target[scan->ntarget])->end.s6_addr16[7]= htons(EMBEDDED_PORT_2ND_WORD);
		scan->ntarget++;
	}

	for(i=0; i < (sizeof(service_ports_dec)/sizeof(u_int16_t)); i++){
		if(scan->ntarget >= scan->maxtarget){
			return(0);
		}

		if( (scan->target[scan->ntarget] = malloc(sizeof(struct scan_entry))) == NULL)
			return(0);

		(scan->target[scan->ntarget])->start= dst->start;
		(scan->target[scan->ntarget])->start.s6_addr16[4]= htons(0);
		(scan->target[scan->ntarget])->start.s6_addr16[5]= htons(0);
		(scan->target[scan->ntarget])->start.s6_addr16[6]= htons(0);
		(scan->target[scan->ntarget])->start.s6_addr16[7]= htons(service_ports_dec[i]);
		(scan->target[scan->ntarget])->cur= (scan->target[scan->ntarget])->start;

		(scan->target[scan->ntarget])->end= dst->end;
		(scan->target[scan->ntarget])->end.s6_addr16[4]= htons(0);
		(scan->target[scan->ntarget])->end.s6_addr16[5]= htons(0);
		(scan->target[scan->ntarget])->end.s6_addr16[6]= htons(EMBEDDED_PORT_2ND_WORD);
		(scan->target[scan->ntarget])->end.s6_addr16[7]= htons(service_ports_dec[i]);
		scan->ntarget++;

		if(scan->ntarget >= scan->maxtarget){
			return(0);
		}

		if( (scan->target[scan->ntarget] = malloc(sizeof(struct scan_entry))) == NULL)
			return(0);

		(scan->target[scan->ntarget])->start= dst->start;
		(scan->target[scan->ntarget])->start.s6_addr16[4]= htons(0);
		(scan->target[scan->ntarget])->start.s6_addr16[5]= htons(0);
		(scan->target[scan->ntarget])->start.s6_addr16[6]= htons(service_ports_dec[i]);
		(scan->target[scan->ntarget])->start.s6_addr16[7]= htons(0);
		(scan->target[scan->ntarget])->cur= (scan->target[scan->ntarget])->start;

		(scan->target[scan->ntarget])->end= dst->end;
		(scan->target[scan->ntarget])->end.s6_addr16[4]= htons(0);
		(scan->target[scan->ntarget])->end.s6_addr16[5]= htons(0);
		(scan->target[scan->ntarget])->end.s6_addr16[6]= htons(service_ports_dec[i]);
		(scan->target[scan->ntarget])->end.s6_addr16[7]= htons(EMBEDDED_PORT_2ND_WORD);
		scan->ntarget++;
	}

	return(1);
}


/*
 * Function: load_lowbyte_entries()
 *
 * Generate scan_entry's for low-byte addresses
 */

int load_lowbyte_entries(struct scan_list *scan, struct scan_entry *dst){
	unsigned int	i;

	if(scan->ntarget >= scan->maxtarget){
		return(0);
	}

	if( (scan->target[scan->ntarget] = malloc(sizeof(struct scan_entry))) == NULL)
		return(0);

	(scan->target[scan->ntarget])->start= dst->start;

	for(i=4; i<=7; i++)
		(scan->target[scan->ntarget])->start.s6_addr16[i]= htons(0);

	(scan->target[scan->ntarget])->cur= (scan->target[scan->ntarget])->start;
	(scan->target[scan->ntarget])->end= dst->end;

	for(i=4; i<=5; i++)
		(scan->target[scan->ntarget])->end.s6_addr16[i]= htons(0);

	(scan->target[scan->ntarget])->end.s6_addr16[6]= htons(LOW_BYTE_2ND_WORD_UPPER);
	(scan->target[scan->ntarget])->end.s6_addr16[7]= htons(LOW_BYTE_1ST_WORD_UPPER);
	scan->ntarget++;

	return(1);
}



/*
 * Function: load_oui_entries()
 *
 * Generate scan_entry's based on a specific IEEE OUI
 */

int load_oui_entries(struct scan_list *scan, struct scan_entry *dst, struct ether_addr *oui){
	unsigned int i;

	if(scan->ntarget >= scan->maxtarget)
		return(0);

	if( (scan->target[scan->ntarget]= malloc(sizeof(struct scan_entry))) == NULL){
		if(verbose_f)
			puts("scans: malloc(): Not enough memory");
		return(0);
	}

	generate_slaac_address(&(dst->start), oui, &((scan->target[scan->ntarget])->start));
	(scan->target[scan->ntarget])->cur= (scan->target[scan->ntarget])->start;

	for(i=0; i<4; i++)
		(scan->target[scan->ntarget])->end.s6_addr16[i]= dst->end.s6_addr16[i];

	for(i=4; i<=7; i++)
		(scan->target[scan->ntarget])->end.s6_addr16[i]= (scan->target[scan->ntarget])->start.s6_addr16[i];

	/*
	   The three low-order bytes must vary from 0x000000 to 0xffffff
	 */
	(scan->target[scan->ntarget])->end.s6_addr16[6]= (scan->target[scan->ntarget])->end.s6_addr16[6] | htons(0x00ff);
	(scan->target[scan->ntarget])->end.s6_addr16[7]= (scan->target[scan->ntarget])->end.s6_addr16[7] | htons(0xffff);

	scan->ntarget++;
	return(1);
}


/*
 * Function: load_vm_entries()
 *
 * Generate scan_entry's based on virtualization prefixes, and scan modes
 */

int load_vm_entries(struct scan_list *scan, struct scan_entry *dst, struct prefix4_entry *v4host){
	unsigned int 		i;
	u_int32_t			mask32;
	struct ether_addr 	ether;

	/* VirtualBOX */
	if(vm_vbox_f){
		if(scan->ntarget >= scan->maxtarget)
			return(0);

		if(ether_pton("08:00:27:00:00:00", &ether, sizeof(ether)) == 0){
			if(verbose_f)
				puts("scan6: ether_pton(): Error converting Ethernet Address to presentation format");

			return(0);
		}

		if( (scan->target[scan->ntarget]= malloc(sizeof(struct scan_entry))) == NULL){
			if(verbose_f)
				puts("scans: malloc(): Not enough memory");

			return(0);
		}

		generate_slaac_address(&(dst->start), &ether, &((scan->target[scan->ntarget])->start));
		(scan->target[scan->ntarget])->cur= (scan->target[scan->ntarget])->start;
		(scan->target[scan->ntarget])->end= dst->end;

		for(i=4; i<=7; i++)
			(scan->target[scan->ntarget])->end.s6_addr16[i]= (scan->target[scan->ntarget])->start.s6_addr16[i];

		/*
		   The three low-order bytes must vary from 0x000000 to 0xffffff
		 */
		(scan->target[scan->ntarget])->end.s6_addr16[6]= (scan->target[scan->ntarget])->end.s6_addr16[6] | htons(0x00ff);
		(scan->target[scan->ntarget])->end.s6_addr16[7]= (scan->target[scan->ntarget])->end.s6_addr16[7] | htons(0xffff);
		scan->ntarget++;
	}

	if(vm_vmware_f){
		if(scan->ntarget >= scan->maxtarget)
			return(0);

		if(ether_pton("00:05:69:00:00:00", &ether, sizeof(ether)) == 0){
			if(verbose_f)
				puts("scan6: ether_pton(): Error converting Ethernet Address to presentation format");

			return(0);
		}

		if( (scan->target[scan->ntarget]= malloc(sizeof(struct scan_entry))) == NULL){
			if(verbose_f)
				puts("scans: malloc(): Not enough memory");

			return(0);
		}

		generate_slaac_address(&(dst->start), &ether, &((scan->target[scan->ntarget])->start));
		(scan->target[scan->ntarget])->cur= (scan->target[scan->ntarget])->start;
		(scan->target[scan->ntarget])->end= dst->end;

		for(i=4; i<=7; i++)
			(scan->target[scan->ntarget])->end.s6_addr16[i]= (scan->target[scan->ntarget])->start.s6_addr16[i];


		/*
		   If we know the host system IPv4 address, we can narrow down the search space. Otherwise
		   the three low-order bytes must vary in the range 0x000000 to 0xffffff
		 */
		if(v4hostaddr_f){
			if(v4hostprefix_f){
				mask32= 0xffffffff;

				for(i=0; i< v4host->len; i++)
					mask32=mask32>>1;
			}
			else{
				mask32= 0;
			}

			(scan->target[scan->ntarget])->start.s6_addr16[6]= (scan->target[scan->ntarget])->start.s6_addr16[6] | \
															htons((ntohl(v4host->ip.s_addr) & 0x0000ff00)>>8);
			(scan->target[scan->ntarget])->start.s6_addr16[7]= (scan->target[scan->ntarget])->start.s6_addr16[7] | \
															htons((ntohl(v4host->ip.s_addr) & 0x000000ff)<<8);

			(scan->target[scan->ntarget])->end.s6_addr16[6]= (scan->target[scan->ntarget])->end.s6_addr16[6] | \
															htons((ntohl(v4host->ip.s_addr) & 0x0000ff00)>>8) | \
															htonl((mask32 & 0x0000ff00)>>8);
			(scan->target[scan->ntarget])->end.s6_addr16[7]= (scan->target[scan->ntarget])->end.s6_addr16[7] | \
															htons((ntohl(v4host->ip.s_addr) & 0x000000ff)<<8) | \
															htonl((mask32 & 0x000000ff)<<8) | htons(0x00ff);
		}
		else{
			(scan->target[scan->ntarget])->end.s6_addr16[6]= (scan->target[scan->ntarget])->end.s6_addr16[6] | htons(0x00ff);
			(scan->target[scan->ntarget])->end.s6_addr16[7]= (scan->target[scan->ntarget])->end.s6_addr16[7] | htons(0xffff);
		}

		scan->ntarget++;
	}

	if(vm_vmwarem_f){
		if(scan->ntarget >= scan->maxtarget)
			return(0);

		if(ether_pton("00:50:56:00:00:00", &ether, sizeof(ether)) == 0){
			if(verbose_f)
				puts("scan6: ether_pton(): Error converting Ethernet Address to presentation format");

			return(0);
		}

		if( (scan->target[scan->ntarget]= malloc(sizeof(struct scan_entry))) == NULL){
			if(verbose_f)
				puts("scans: malloc(): Not enough memory");

			return(0);
		}

		generate_slaac_address(&(dst->start), &ether, &((scan->target[scan->ntarget])->start));
		(scan->target[scan->ntarget])->cur= (scan->target[scan->ntarget])->start;
		(scan->target[scan->ntarget])->end= dst->end;

		for(i=4; i<=7; i++)
			(scan->target[scan->ntarget])->end.s6_addr16[i]= (scan->target[scan->ntarget])->start.s6_addr16[i];

		/*
		   The three low-order bytes must vary from 0x000000 to 0x3fffff
		 */
		(scan->target[scan->ntarget])->end.s6_addr16[6]= (scan->target[scan->ntarget])->end.s6_addr16[6] | htons(0x003f);
		(scan->target[scan->ntarget])->end.s6_addr16[7]= (scan->target[scan->ntarget])->end.s6_addr16[6] | htons(0xffff);

		scan->ntarget++;
	}

	return(1);
}


/*
 * Function: load_vendor_entries()
 *
 * Lookup vendor's IEEE OUIs
 */

int load_vendor_entries(struct scan_list *scan, struct scan_entry *dst, char *vendor){
	FILE 				*fp;
	struct ether_addr	aux_oui, oui_list[MAX_IEEE_OUIS];
	char 				oui_ascii[ETHER_ADDR_PLEN];
	char 				*oui_end=":00:00:00";
	char				*oui_hex_string="(hex)";
	char				line[MAX_IEEE_OUIS_LINE_SIZE];
	char				*charptr;
	unsigned int		lines=0, ouis;
	int					i;

	ouis=0;
	
	if( (fp=fopen(fname, "r")) == NULL){
		perror("scan6:");
		return(0);
	}

	while( ouis <= MAX_IEEE_OUIS && fgets(line, MAX_IEEE_OUIS_LINE_SIZE, fp) != NULL){
		/*
		   We ship a minimalistic IEEE OUI "database" containing only the first "line" for each IEEE OUI.
		   However, in order to handle the case of users employing the OUI database directly downloaded
		   from the IEEE site, we perform a simple check to skip those lines that do not start with
		   the pattern XX-XX-XX
		 */

		if( (lines=Strnlen(line, MAX_IEEE_OUIS_LINE_SIZE)) <= 9)
			continue;

		if(line[2] != '-' || line[5] != '-' || line[8] != ' ')
			continue;

		charptr= (char *)line + 9;

		/* Skip any whitespaces */
		while(charptr < ( (char *)line + lines) && *charptr == ' ')
			charptr++;

		/*
		   The database we ship contains the complete first line for each OUI, which includes the string "(hex)".
		   If we find that string, we should skip it.
		 */

		if( (( (char *)line + lines) - charptr) >= OUI_HEX_STRING_SIZE){

			/* If we find the "(hex)" string, we must skip it */
			if( bcmp(oui_hex_string, charptr, OUI_HEX_STRING_SIZE) == 0)
				charptr+= OUI_HEX_STRING_SIZE;

			/* Now we mst skip any whitespaces between the "(hex)" string and the vendor name */
			while(charptr < ( (char *)line + lines) && *charptr == ' ')
				charptr++;

			if(charptr >= ( (char *)line + lines))
				continue;
		}


		if(match_strings(vendor, charptr)){
			/* Copy the actual OUI to our array */
			bcopy(line, oui_ascii, 8);

			/* Patch the dashes with colons (i.e., s/-/:/ */
			oui_ascii[2]=':';
			oui_ascii[5]=':';

			/* zero-terminate the string */
			oui_ascii[8]= 0;

			strncat(oui_ascii, oui_end, ETHER_ADDR_PLEN-Strnlen(oui_ascii, sizeof(oui_ascii))-1);

			if(ether_pton(oui_ascii, &oui_list[ouis], sizeof(oui_list[ouis])) == 0){
				if(verbose_f)
					puts("scan6: ether_pton(): Error converting Ethernet Address to presentation format");

				return(0);
			}

			ouis++;
		}
	}


	if(ferror(fp)){
		if(verbose_f)
			perror("scan6:");

		return(0);
	}

	fclose(fp);

	/*
	 * If the target is a list of IEEE OUIs, we want to start trying from the newest OUIs,
	 * to the older OUIs. The older OUIs are left for the end, since they have probably been
	 * used for NICs used by legacy systems that are no longer online. Similarly, the very 
	 * newest OUI is left for the end, since it has probably not been used (yet) for any 
	 * commercialized Network Interface cards.
	 */

	if(sort_ouis_f && ouis >= 4){
		aux_oui= oui_list[ouis-1];

		for(i=ouis-2; i>=1; i--){
			oui_list[i+1]= oui_list[i];
		}

		oui_list[1] = aux_oui;
	}

	if(ouis == 0){
		if(verbose_f)
			puts("scan6: Couldn't find any IEEE OUI for the target vendor");

		return(0);
	}


	/* We walk the IEEE OUI list backwards: from newer to older OUIs */
	for(i=ouis-1; i>=0; i--){
		if(scan->ntarget >= scan->maxtarget)
			return(0);

		if( (scan->target[scan->ntarget]= malloc(sizeof(struct scan_entry))) == NULL){
			if(verbose_f)
				puts("scans: malloc(): Not enough memory");

			return(0);
		}

		generate_slaac_address(&(dst->start), &oui_list[i], &((scan->target[scan->ntarget])->start));
		(scan->target[scan->ntarget])->cur= (scan->target[scan->ntarget])->start;
		generate_slaac_address(&(dst->end), &oui_list[i], &((scan->target[scan->ntarget])->end));

		/*
		   The three low-order bytes must vary from 0x000000 to 0xffffff
		 */
		(scan->target[scan->ntarget])->end.s6_addr16[6]= (scan->target[scan->ntarget])->end.s6_addr16[6] | htons(0x00ff);
		(scan->target[scan->ntarget])->end.s6_addr16[7]= (scan->target[scan->ntarget])->end.s6_addr16[6] | htons(0xffff);

		scan->ntarget++;
	}

	return(1);
}


/*
 * Function: match_strings()
 *
 * Checks whether one string "matches" within another string
 */

int match_strings(char *buscar, char *buffer){
	unsigned int buscars, buffers;
	unsigned int i=0, j=0;

	buscars= Strnlen(buscar, MAX_IEEE_OUIS_LINE_SIZE);
	buffers= Strnlen(buffer, MAX_IEEE_OUIS_LINE_SIZE);

	if(buscars > buffers)
		return(0);

	while(i <= (buffers - buscars)){
		j=0;

		while(j < buscars){
			if(toupper((int) ((unsigned char)buscar[j])) != toupper((int) ((unsigned char)buffer[i+j])))
				break;

			j++;
		}

		if(j >= buscars)
			return(1);

		i++;
	}

	return(0);
}


/*
 * Function: load_bruteforce_entries()
 *
 * Converts a target prefix to scan_entry format
 */

int load_bruteforce_entries(struct scan_list *scan, struct scan_entry *dst){
	if(scan->ntarget >= scan->maxtarget)
		return(0);

	if( (scan->target[scan->ntarget]= malloc(sizeof(struct scan_entry))) == NULL){
		if(verbose_f)
			puts("scans: malloc(): Not enough memory");

		return(0);
	}

	*scan->target[scan->ntarget]= *dst;
	scan->ntarget++;

	return(1);
}


/*
 * Function: prefix_to_scan()
 *
 * Converts a target prefix to scan_entry format
 */

void prefix_to_scan(struct prefix_entry *pref, struct scan_entry *scan){
	u_int16_t mask;
	u_int8_t words;	
	unsigned int i;

	sanitize_ipv6_prefix(&(pref->ip6), pref->len);
	scan->start= pref->ip6;
	scan->cur= scan->start;

	words= pref->len/16;

	for(i=0; i< words; i++)
		(scan->end).s6_addr16[i]= (pref->ip6).s6_addr16[i];

	for(i= (words+1); i<8; i++){
		(scan->end).s6_addr16[i]= htons(0xffff);
	}

	mask=0xffff;

	for(i=0; i< (pref->len % 16); i++)
		mask= mask>>1;

	(scan->end).s6_addr16[words]= (scan->start).s6_addr16[words] | htons(mask);
}




/*
 * Function: usage()
 *
 * Prints the syntax of the scan6 tool
 */

void usage(void){
	puts("usage: scan6 -i INTERFACE (-L | -d) [-s SRC_ADDR[/LEN] | -f] \n"
	     "       [-S LINK_SRC_ADDR | -F] [-p PROBE_TYPE] [-Z PAYLOAD_SIZE] [-o SRC_PORT]\n"
	     "       [-a DST_PORT] [-X TCP_FLAGS] [-P ADDRESS_TYPE] [-q] [-e] [-t]\n"
	     "       [-x RETRANS] [-o TIMEOUT] [-V VM_TYPE] [-b] [-B ENCODING] [-g]\n"
	     "       [-k IEEE_OUI] [-K VENDOR] [-m PREFIXES_FILE] [-w IIDS_FILE] [-W IID]\n"
	     "       [-Q IPV4_PREFIX[/LEN]] [-T] [-I INC_SIZE] [-r RATE(bps|pps)] [-l]\n"
	     "       [-z SECONDS] [-c CONFIG_FILE] [-v] [-h]");
}


/*
 * Function: print_help()
 *
 * Prints help information for the scan6 tool
 */

void print_help(void){
	puts(SI6_TOOLKIT);
	puts( "scan6: An advanced IPv6 Address Scanning tool\n");
	usage();
    
	puts("\nOPTIONS:\n"
	     "  --interface, -i             Network interface\n"
	     "  --src-address, -s           IPv6 Source Address\n"
	     "  --dst-address, -d           IPv6 Destination Range or Prefix\n"
	     "  --prefixes-file, -m         Prefixes file\n"
	     "  --link-src-address, -S      Link-layer Destination Address\n"
	     "  --probe-type, -p            Probe type {echo, unrec, all}\n"
	     "  --payload-size, -Z          TCP/UDP Payload Size\n"
	     "  --src-port, -o              TCP/UDP Source Port\n"
	     "  --dst-port, -a              TCP/UDP Destination Port\n"
	     "  --tcp-flags, -X             TCP Flags\n"
	     "  --print-type, -P            Print address type {local, global, all}\n"
	     "  --print-unique, -q          Print only one IPv6 addresses per Ethernet address\n"
	     "  --print-link-addr, -e       Print link-layer addresses\n"
	     "  --print-timestamp, -t       Print timestamp for each alive node\n"
	     "  --retrans, -x               Number of retransmissions of each probe\n"
	     "  --timeout, -O               Timeout in seconds (default: 1 second)\n"
	     "  --local-scan, -L            Scan the local subnet\n"
	     "  --rand-src-addr, -f         Randomize the IPv6 Source Address\n"
	     "  --rand-link-src-addr, -F    Randomize the Ethernet Source Address\n"
	     "  --tgt-virtual-machines, -V  Target virtual machines\n"
	     "  --tgt-low-byte, -b          Target low-byte addresses\n"
	     "  --tgt-ipv4, -B              Target embedded-IPv4 addresses\n"
	     "  --tgt-port, -g              Target embedded-port addresses\n"
	     "  --tgt-ieee-oui, -k          Target IPv6 addresses embedding IEEE OUI\n"
	     "  --tgt-vendor, -K            Target IPv6 addresses for vendor's IEEE OUIs\n"
	     "  --tgt-iids-file, -w         Target Interface IDs (IIDs) in specified file\n"
	     "  --tgt-iid, -W               Target Interface IDs (IIDs)\n"
	     "  --ipv4-host, -Q             Host IPv4 Address/Prefix\n"
	     "  --sort-ouis, -T             Sort IEEE OUIs\n"
	     "  --inc-size, -I              Increments size\n"
	     "  --rate-limit, -r            Rate limit the address scan to specified rate\n"
	     "  --loop, -l                  Send periodic probes to the specified targets\n"
	     "  --sleep, -z                 Pause between periodic probes\n"
	     "  --config-file, -c           Use alternate configuration file\n"
	     "  --help, -h                  Print help for the scan6 tool\n"
	     "  --verbose, -v               Be verbose\n"
	     "\n"
	     " Programmed by Fernando Gont for SI6 Networks <http://www.si6networks.com>\n"
	     " Please send any bug reports to <fgont@si6networks.com>\n"
	);
}



/*
 * Function: send_probe_remote()
 *
 * Sends a probe packet to a remote target
 */

int send_probe_remote(struct iface_data *idata, struct scan_list *scan, struct in6_addr *srcaddr, unsigned char type){
	unsigned char				*ptr;
	unsigned int 				i;
	struct ether_header			*ether;
	struct dlt_null				*dlt_null;
	unsigned char 				*v6buffer;
	struct ip6_hdr				*ipv6;
	struct tcp_hdr				*tcp;
	struct ip6_dest				*destopth;
	struct ip6_option			*opt;
	u_int32_t					*uint32;

	/* max_packet_size holds is equal to the link MTU, since the tool doesn't support packets larger than the link MTU */
	max_packet_size = idata->mtu;
	ether = (struct ether_header *) buffer;
	dlt_null= (struct dlt_null *) buffer;
	v6buffer = buffer + idata->linkhsize;
	ipv6 = (struct ip6_hdr *) v6buffer;

	if(idata->type == DLT_EN10MB && !loopback_f){
		ether->src = idata->ether;

		if(!onlink_f){
			ether->dst = idata->nhhaddr;
		}else{
			if(ipv6_to_ether(idata->pfd, idata, &(scan->target[scan->ctarget])->cur, &(idata->hdstaddr)) != 1){
				return(1);
			}
		}

		ether->ether_type = htons(ETHERTYPE_IPV6);
	}
	else if(idata->type == DLT_NULL){
		dlt_null->family= PF_INET6;
	}

	ipv6->ip6_flow=0;
	ipv6->ip6_vfc= 0x60;
	ipv6->ip6_hlim= 255;

	ipv6->ip6_src= idata->srcaddr_f?(*srcaddr):*sel_src_addr_ra(idata, &((scan->target[scan->ctarget])->cur));
	ipv6->ip6_dst= (scan->target[scan->ctarget])->cur;

	prev_nh = (unsigned char *) &(ipv6->ip6_nxt);

	ptr = (unsigned char *) v6buffer + MIN_IPV6_HLEN;

	switch(type){
		case PROBE_ICMP6_ECHO:
			*prev_nh = IPPROTO_ICMPV6;

			if( (ptr+sizeof(struct icmp6_hdr)+ICMPV6_ECHO_PAYLOAD_SIZE) > (v6buffer+idata->mtu)){
				if(idata->verbose_f>1)
					puts("Packet too large while creating ICMPv6 Echo Request Probe packet");

				return(-1);
			}

			icmp6 = (struct icmp6_hdr *) ptr;
			icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
			icmp6->icmp6_code = 0;
			icmp6->icmp6_data16[0]= htons(getpid());	/* Identifier */
			icmp6->icmp6_data16[1]= htons(0);			/* Sequence Number */

			ptr = ptr+ sizeof(struct icmp6_hdr);

			for(i=0; i<(ICMPV6_ECHO_PAYLOAD_SIZE>>2); i++){
				*(u_int32_t *)ptr = random();
				ptr += sizeof(u_int32_t);
			}

			ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);
			icmp6->icmp6_cksum = 0;
			icmp6->icmp6_cksum = in_chksum(v6buffer, icmp6, ptr-((unsigned char *)icmp6), IPPROTO_ICMPV6);
			break;

		case PROBE_UNREC_OPT:
			*prev_nh = IPPROTO_DSTOPTS;

			if( (ptr+sizeof(struct icmp6_hdr) + 8 + ICMPV6_ECHO_PAYLOAD_SIZE) > (v6buffer+idata->mtu)){
				if(idata->verbose_f>1)
					puts("Packet too large while creating Unrec. Opt. Probe Packet");

				return(-1);
			}

			destopth = (struct ip6_dest *) ptr;
			destopth->ip6d_len= 0;
			destopth->ip6d_nxt= IPPROTO_ICMPV6;

			ptr= ptr + 2;
			opt= (struct ip6_option *) ptr;
			opt->ip6o_type= 0x80;
			opt->ip6o_len= 4;

			ptr= ptr + 2;
			uint32 = (u_int32_t *) ptr;
			*uint32 = random();

			ptr= ptr +4;
			icmp6 = (struct icmp6_hdr *) ptr;
			icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
			icmp6->icmp6_code = 0;
			icmp6->icmp6_data16[0]= htons(getpid());	/* Identifier */
			icmp6->icmp6_data16[1]= htons(0);			/* Sequence Number */

			ptr = ptr+ sizeof(struct icmp6_hdr);

			for(i=0; i<(ICMPV6_ECHO_PAYLOAD_SIZE>>2); i++){
				*(u_int32_t *)ptr = random();
				ptr += sizeof(u_int32_t);
			}

			ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);
			icmp6->icmp6_cksum = 0;
			icmp6->icmp6_cksum = in_chksum(v6buffer, icmp6, ptr-((unsigned char *)icmp6), IPPROTO_ICMPV6);
			break;

		case PROBE_TCP:
			*prev_nh = IPPROTO_TCP;

			if( (ptr+sizeof(struct tcp_hdr)) > (v6buffer + max_packet_size)){
				if(idata->verbose_f)
					puts("Packet Too Large while inserting TCP header");

				return(0);
			}

			tcp = (struct tcp_hdr *) ptr;
			bzero(tcp, sizeof(struct tcp_hdr));

			if(srcport_f)
				tcp->th_sport= htons(srcport);
			else
				tcp->th_sport= htons(1024+ rand() % 64512);

			if(dstport_f)
				tcp->th_dport= htons(dstport);
			else
				tcp->th_dport= htons(1+ rand() % 1024);

			if(tcpflags_f)
				tcp->th_flags= tcpflags;
			else
				tcp->th_flags= TH_ACK;

			if(tcpflags & TH_ACK)
				tcp->th_ack= htonl(rand());
			else
				tcp->th_ack= htonl(0);

			tcp->th_win= htons( 4096 * (rand() % 9 + 1));

			/* Current version of tcp6 does not support sending TCP options */
			tcp->th_off= sizeof(struct tcp_hdr) >> 2;
			ptr+= tcp->th_off << 2;

			if( (ptr + rhbytes) > v6buffer+max_packet_size){
				puts("Packet Too Large while inserting TCP segment");
				exit(EXIT_FAILURE);
			}

			while(rhbytes>=4){
				*(u_int32_t *)ptr = random();
				ptr += sizeof(u_int32_t);
				rhbytes -= sizeof(u_int32_t);
			}

			while(rhbytes>0){
				*(u_int8_t *) ptr= (u_int8_t) random();
				ptr++;
				rhbytes--;
			}

			ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);
			tcp->th_sum = 0;
			tcp->th_sum = in_chksum(v6buffer, tcp, ptr-((unsigned char *)tcp), IPPROTO_TCP);
			break;
	}

	if((nw=pcap_inject(idata->pfd, buffer, ptr - buffer)) ==  -1){
		if(idata->verbose_f>1)
			printf("pcap_inject(): %s\n", pcap_geterr(idata->pfd));

		return(0);
	}

	if(nw != (ptr-buffer)){
		if(idata->verbose_f>1)
			printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, \
																			(LUI) (ptr-buffer));
		return(0);
	}

	return(1);
}



/*
 * Function: multi_scan_local()
 *
 * Performs an IPv6 address scan on a local link
 */

int multi_scan_local(pcap_t *pfd, struct iface_data *idata, struct in6_addr *srcaddr, unsigned char type, \
                     const char *ptargetaddr, struct host_list *hlist){

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
	struct ip6_option			*opt;
	u_int32_t					*uint32;
	unsigned char				error_f=FALSE, llocalsrc_f=FALSE;
	int 						result;

	icmp6_max_packet_size = idata->mtu;
	ether = (struct ether_header *) buffer;
	v6buffer = buffer + sizeof(struct ether_header);
	ipv6 = (struct ip6_hdr *) v6buffer;

	if ( inet_pton(AF_INET6, ptargetaddr, &targetaddr) <= 0){
		if(idata->verbose_f>1)
			puts("inet_pton(): Source Address not valid");

		return(-1);
	}

	if(IN6_IS_ADDR_LINKLOCAL(srcaddr))
		llocalsrc_f=TRUE;

	if(pfd == NULL)
		return(-1);

	switch(type){
		case PROBE_ICMP6_ECHO:
			if(pcap_compile(pfd, &pcap_filter, PCAP_ICMPV6_ERNS_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
				if(idata->verbose_f>1)
					printf("pcap_compile(): %s", pcap_geterr(pfd));

				return(-1);
			}
			break;

		case PROBE_UNREC_OPT:
			if(pcap_compile(pfd, &pcap_filter, PCAP_ICMPV6_ERRORNS_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
				if(idata->verbose_f>1)
					printf("pcap_compile(): %s", pcap_geterr(pfd));

				return(-1);
			}
			break;

		default:
			return(-1);
			break;
	}

	if(pcap_setfilter(pfd, &pcap_filter) == -1){
		if(idata->verbose_f>1)
			printf("pcap_setfilter(): %s", pcap_geterr(pfd));

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
	ether->ether_type = htons(ETHERTYPE_IPV6);

	prev_nh = (unsigned char *) &(ipv6->ip6_nxt);

	ptr = (unsigned char *) v6buffer + MIN_IPV6_HLEN;

	switch(type){
		case PROBE_ICMP6_ECHO:
			*prev_nh = IPPROTO_ICMPV6;

			if( (ptr+sizeof(struct icmp6_hdr)+ICMPV6_ECHO_PAYLOAD_SIZE) > (v6buffer+icmp6_max_packet_size)){
				if(idata->verbose_f>1)
					puts("Packet too large while creating ICMPv6 Echo Request Probe packet");

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
				if(idata->verbose_f>1)
					puts("Packet too large while creating Unrec. Opt. Probe Packet");

				return(-1);
			}

			destopth = (struct ip6_dest *) ptr;
			destopth->ip6d_len= 0;
			destopth->ip6d_nxt= IPPROTO_ICMPV6;

			ptr= ptr + 2;
			opt= (struct ip6_option *) ptr;
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
	icmp6->icmp6_cksum = in_chksum(v6buffer, icmp6, ptr-((unsigned char *)icmp6), IPPROTO_ICMPV6);

	/* We set the signal handler, and the anchor for siglongjump() */
	canjump=0;
	bzero(&new_sig, sizeof(struct sigaction));
	sigemptyset(&new_sig.sa_mask);
	new_sig.sa_handler= &local_sig_alarm;

	if( sigaction(SIGALRM, &new_sig, &old_sig) == -1){
		if(idata->verbose_f>1)
			puts("Error setting up 'Alarm' signal");

		return(-1);
	}

	if(sigsetjmp(env, 1) != 0)
		tries++;

	canjump=1;

	while(tries <= idata->local_retrans && !error_f){
		if((nw=pcap_inject(pfd, buffer, ptr - buffer)) == -1){
			if(idata->verbose_f>1)
				printf("pcap_inject(): %s\n", pcap_geterr(pfd));

			error_f=TRUE;
			break;
		}

		if(nw != (ptr-buffer)){
			if(idata->verbose_f>1)
				printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, \
																			(LUI) (ptr-buffer));

			error_f=TRUE;
			break;
		}

		alarm(idata->local_timeout);
		
		while( (hlist->nhosts < hlist->maxhosts) && !error_f){

			do{
				if((result=pcap_next_ex(pfd, &pkthdr, &pktdata)) == -1){
					if(idata->verbose_f>1)
						printf("pcap_next_ex(): %s", pcap_geterr(pfd));

					error_f=TRUE;
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
								error_f=TRUE;
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
							if(idata->verbose_f>1)
								puts("Error when allocating memory for host data");

							error_f=TRUE;
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


	if( sigaction(SIGALRM, &old_sig, NULL) == -1){
		if(idata->verbose_f>1)
			puts("Error setting up 'Alarm' signal");

		error_f=TRUE;
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
	struct ip6_option		*opt;
	u_int32_t				*uint32;
	unsigned char			foundaddr_f=FALSE, error_f=FALSE;
	int				result;

	icmp6_max_packet_size = idata->mtu;
	ether = (struct ether_header *) buffer;
	v6buffer = buffer + sizeof(struct ether_header);
	ipv6 = (struct ip6_hdr *) v6buffer;

	targetaddr= host->ip6;

	if( pcap_datalink(pfd) != DLT_EN10MB){
		if(idata->verbose_f>1)
			printf("Error: Interface %s is not an Ethernet interface", idata->iface);

		return(-1);
	}

	switch(type){
		case PROBE_ICMP6_ECHO:
			if(pcap_compile(pfd, &pcap_filter, PCAP_ICMPV6_ERNS_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
				if(idata->verbose_f>1)
					printf("pcap_compile(): %s", pcap_geterr(pfd));

				return(-1);
			}

			break;

		case PROBE_UNREC_OPT:
			if(pcap_compile(pfd, &pcap_filter, PCAP_ICMPV6_ERRORNS_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
				if(idata->verbose_f>1)
					printf("pcap_compile(): %s", pcap_geterr(pfd));

				return(-1);
			}

			break;

		default:
			return(-1);
			break;
	}

	if(pcap_setfilter(pfd, &pcap_filter) == -1){
		if(idata->verbose_f>1)
			printf("pcap_setfilter(): %s", pcap_geterr(pfd));

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
	ether->ether_type = htons(ETHERTYPE_IPV6);

	prev_nh = (unsigned char *) &(ipv6->ip6_nxt);

	ptr = (unsigned char *) v6buffer + MIN_IPV6_HLEN;

	switch(type){
		case PROBE_ICMP6_ECHO:
			*prev_nh = IPPROTO_ICMPV6;

			if( (ptr+sizeof(struct icmp6_hdr)+ICMPV6_ECHO_PAYLOAD_SIZE) > (v6buffer+icmp6_max_packet_size)){
				if(idata->verbose_f>1)
					puts("Packet too large while creating ICMPv6 Echo Request Probe packet");

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
				if(idata->verbose_f>1)
					puts("Packet too large while creating Unrec. Opt. Probe Packet");

				return(-1);
			}

			destopth = (struct ip6_dest *) ptr;
			destopth->ip6d_len= 0;
			destopth->ip6d_nxt= IPPROTO_ICMPV6;

			ptr= ptr + 2;
			opt= (struct ip6_option *) ptr;
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
	icmp6->icmp6_cksum = in_chksum(v6buffer, icmp6, ptr-((unsigned char *)icmp6), IPPROTO_ICMPV6);

	/* We set the signal handler, and the anchor for siglongjump() */
	canjump=0;
	bzero(&new_sig, sizeof(struct sigaction));
	sigemptyset(&new_sig.sa_mask);
	new_sig.sa_handler= &local_sig_alarm;

	if( sigaction(SIGALRM, &new_sig, &old_sig) == -1){
		if(idata->verbose_f>1)
			puts("Error setting up 'Alarm' signal");

		return(-1);
	}

	if(sigsetjmp(env, 1) != 0)
		tries++;

	canjump=1;

	while(tries<= idata->local_retrans && !foundaddr_f && !error_f){
		if((nw=pcap_inject(pfd, buffer, ptr - buffer)) == -1){
			if(idata->verbose_f>1)
				printf("pcap_inject(): %s\n", pcap_geterr(pfd));

			error_f=TRUE;
			break;
		}

		if(nw != (ptr-buffer)){
			if(idata->verbose_f>1)
				printf("pcap_inject(): only wrote %lu bytes (rather than %lu bytes)\n", (LUI) nw, \
																		(LUI) (ptr-buffer));

			error_f=TRUE;
			break;
		}

		alarm(idata->local_timeout);
		
		foundaddr_f=FALSE;

		while(!foundaddr_f && !error_f){

			do{
				if( (result=pcap_next_ex(pfd, &pkthdr, &pktdata)) == -1){
					if(idata->verbose_f>1)
						printf("pcap_next_ex(): %s", pcap_geterr(pfd));

					error_f=TRUE;
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
								error_f=TRUE;
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
						foundaddr_f=TRUE;
						break;
					}
				}
			}

		} /* Processing packets */

	} /* Resending Probe packet */

	if( sigaction(SIGALRM, &old_sig, NULL) == -1){
		if(idata->verbose_f>1)
			puts("Error setting up 'Alarm' signal");

		error_f=TRUE;
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
		if(inet_ntop(AF_INET6, &((hlist->host[i])->ip6), pv6addr, sizeof(pv6addr)) == NULL){
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
			
		if(inet_ntop(AF_INET6, &((hlist->host[i])->ip6), pv6addr, sizeof(pv6addr)) == NULL){
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
 * Function: validate_host_entries()
 *
 * Tests entries in a list, updates entries with invalid mappings, and removes non-existent addresses
 */

int validate_host_entries(pcap_t *pfd, struct iface_data *idata, struct host_list *candidate, struct host_list *global){
	unsigned int i;
	struct in6_addr	*srcaddrptr;

	for(i=0; i< candidate->nhosts; i++){
		if((candidate->host[i])->flag == INVALID_MAPPING){
			srcaddrptr = sel_src_addr_ra(idata, &((candidate->host[i])->ip6));

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

	if(type == PROBE_UNREC_OPT)
		icmp6 = (struct icmp6_hdr *) ( (char *) ipv6 + sizeof(struct ip6_hdr) + MIN_DST_OPT_HDR_SIZE);
	else
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
			   header and the embedded payload
			 */
			if( (pkt_end - (unsigned char *) pkt_icmp6) < (sizeof(struct icmp6_hdr) + \
						+ sizeof(struct ip6_hdr) + MIN_DST_OPT_HDR_SIZE + sizeof(struct icmp6_hdr) + \
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
	if(in_chksum(pkt_ipv6, pkt_icmp6, pkt_end-((unsigned char *)pkt_icmp6), IPPROTO_ICMPV6) != 0)
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
			pkt_icmp6_icmp6= (struct icmp6_hdr *) ((unsigned char *) pkt_icmp6 + sizeof(struct icmp6_hdr) +\
						sizeof(struct ip6_hdr) + MIN_DST_OPT_HDR_SIZE);

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
 * Function: valid_icmp6_response_remote()
 *
 * Checks whether the response to an ICMPv6 probe is valid
 */

int valid_icmp6_response_remote(struct iface_data *idata, struct scan_list *scan, unsigned char type, struct pcap_pkthdr *pkthdr,\
			const u_char *pktdata, unsigned char *pktsent){

	struct ether_header	*pkt_ether;
	struct ip6_hdr		*pkt_ipv6, *ipv6;
	struct icmp6_hdr	*pkt_icmp6, *pkt_icmp6_icmp6, *icmp6;
	unsigned char		*pkt_end;

	ipv6 = (struct ip6_hdr *) (pktsent + idata->linkhsize);

	if(type == PROBE_UNREC_OPT)
		icmp6 = (struct icmp6_hdr *) ( (char *) ipv6 + sizeof(struct ip6_hdr) + MIN_DST_OPT_HDR_SIZE);
	else
		icmp6 = (struct icmp6_hdr *) ( (char *) ipv6 + sizeof(struct ip6_hdr));

	pkt_ether = (struct ether_header *) pktdata;
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + idata->linkhsize);
	pkt_icmp6 = (struct icmp6_hdr *) ((char *) pkt_ipv6 + sizeof(struct ip6_hdr));
	pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

	switch(type){
		case PROBE_ICMP6_ECHO:
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
			/* The packet length is the minimum of what we capured, and what is specified in the
			   IPv6 Total Lenght field
			 */
			if( pkt_end > ((unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen) )
				pkt_end = (unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen;

			/*
			   Discard the packet if it is not of the minimum size to contain an ICMPv6 
			   header and the empedded payload
			 */
			if( (pkt_end - (unsigned char *) pkt_icmp6) < (sizeof(struct icmp6_hdr) + \
						+ sizeof(struct ip6_hdr) + MIN_DST_OPT_HDR_SIZE + sizeof(struct icmp6_hdr) + \
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
	if(in_chksum(pkt_ipv6, pkt_icmp6, pkt_end-((unsigned char *)pkt_icmp6), IPPROTO_ICMPV6) != 0)
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
			pkt_icmp6_icmp6= (struct icmp6_hdr *) ((unsigned char *) pkt_icmp6 + sizeof(struct icmp6_hdr) +\
						sizeof(struct ip6_hdr) + MIN_DST_OPT_HDR_SIZE);

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
 * Function: process_config_file()
 *
 * Processes the SI6 Networks' toolkit configuration file
 */

int process_config_file(const char *path){
	FILE *fp;
	char *key, *value;
	char line[MAX_LINE_SIZE];
	int	r;
	unsigned int ln=1;

	if( (fp=fopen(path, "r")) == NULL){
		return(0);
	}

	while(fgets(line, sizeof(line),  fp) != NULL){
		r=keyval(line, Strnlen(line, MAX_LINE_SIZE), &key, &value);

		if(r == 1){
			if(strncmp(key, "OUI-Database", MAX_VAR_NAME_LEN) == 0){
				strncpy(fname, value, MAX_FILENAME_SIZE-1);
				fname[MAX_FILENAME_SIZE-1]=0;
				fname_f=TRUE;
			}


		}
		else if(r == -1){
			if(verbose_f){
				printf("Error in configuration file %s", configfile);
			}

			fclose(fp);
			return(0);
		}

		ln++;
	}

	fclose(fp);

	if(!fname_f)
		strncpy(fname, "/usr/share/ipv6toolkit/oui.txt", MAX_FILENAME_SIZE-1);

	return(1);
}



/*
 * Function: is_ip6_in_scan_list()
 *
 * Check whether an IPv6 address belongs to one of our scan ranges
 */
int	is_ip6_in_scan_list(struct scan_list *scan, struct in6_addr *ip6){
	unsigned int i, j;

	for(i=0; i< scan->ntarget; i++){
		for(j=0; j<8; j++){
			if( (ntohs(ip6->s6_addr16[j]) < ntohs((scan->target[i])->start.s6_addr16[j])) || \
					(ntohs(ip6->s6_addr16[j]) > ntohs((scan->target[i])->end.s6_addr16[j]))){
				break;
			}
		}

		if(j == 8)
			return(1);
	}

	return(0);
}



/*
 * Handler for the ALARM signal.
 *
 * Used for setting a timeout on libpcap reads
 */

void local_sig_alarm(int num){
	if(canjump == 0)
		return;

	siglongjmp(env, 1);
}

