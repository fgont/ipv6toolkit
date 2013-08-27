/*
 * addr6: A tool to decode IPv6 addresses
 *
 * Copyright (C) 2013 Fernando Gont (fgont@si6networks.com)
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
 * Build with: gcc addr6.c -Wall -o addr6
 * 
 * This program has been tested to compile and run on: Debian GNU/Linux 6.0,
 * FreeBSD 9.0, NetBSD 5.1, OpenBSD 5.0, and Ubuntu 11.10.
 *
 * It requires that the libpcap library be installed on your system.
 *
 * Please send any bug reports to Fernando Gont <fgont@si6networks.com>
 */

#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <pwd.h>
#include "addr6.h"
#include "ipv6toolkit.h"

void					usage(void);
void					print_help(void);
int						read_prefix(char *, unsigned int, char **);
size_t					Strnlen(const char *, size_t);
unsigned int			is_service_port(u_int16_t);
unsigned int			zero_byte_iid(struct in6_addr *);
void					decode_ipv6_address(struct decode6 *, struct stats6 *);
void					stat_ipv6_address(struct decode6 *, struct stats6 *);
void					print_dec_address_script(struct decode6 *);
int						init_host_list(struct host_list *);
u_int16_t				key(struct host_list *, struct in6_addr *);
struct host_entry *		add_host_entry(struct host_list *, struct in6_addr *);
unsigned int			is_ip6_in_list(struct host_list *, struct in6_addr *);
int 					is_eq_in6_addr(struct in6_addr *, struct in6_addr *);
unsigned int			match_ipv6(struct in6_addr *, u_int8_t *, unsigned int, struct in6_addr *);
void					sanitize_ipv6_prefix(struct in6_addr *, u_int8_t);
void					print_stats(struct stats6 *);

unsigned char			stdin_f=0, addr_f=0, verbose_f=0, decode_f=0, print_unique_f=0, stats_f=0, filter_f=0;
char					line[MAX_LINE_SIZE];

int main(int argc, char **argv){
	extern char			*optarg;	
	struct decode6		addr;
	struct stats6		stats;
	struct host_list	hlist;
	int					r;
	char				*ptr, *pref, *charptr, *lasts;
	char				pv6addr[INET6_ADDRSTRLEN];
	uid_t				ruid;
	gid_t				rgid;
	struct passwd		*pwdptr;
	unsigned int		accept_type=0, block_type=0, accept_scope=0, block_scope=0, accept_itype=0, block_itype=0;
	unsigned int		accept_utype=0, block_utype=0;

	unsigned char		accepted_f=0, acceptfilters_f=0;

	/* Block Filters */
	struct in6_addr 	block[MAX_BLOCK];
	u_int8_t			blocklen[MAX_BLOCK];
	unsigned int		nblock=0;

	/* Accept Filters */
	struct in6_addr		accept[MAX_ACCEPT];
	u_int8_t			acceptlen[MAX_ACCEPT];
	unsigned int		naccept=0;

	static struct option longopts[] = {
		{"address", required_argument, 0, 'a'},
		{"stdin", no_argument, 0, 'i'},
		{"print-decode", no_argument, 0, 'd'},
		{"print-stats", no_argument, 0, 's'},
		{"print-unique", no_argument, 0, 'q'},
		{"accept", required_argument, 0, 'j'},
		{"accept-type", required_argument, 0, 'b'},
		{"accept-scope", required_argument, 0, 'k'},
		{"accept-utype", required_argument, 0, 'w'},
		{"accept-iid", required_argument, 0, 'g'},
		{"block", required_argument, 0, 'J'},
		{"block-type", required_argument, 0, 'B'},
		{"block-scope", required_argument, 0, 'K'},
		{"block-utype", required_argument, 0, 'W'},
		{"block-iid", required_argument, 0, 'G'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'}
	};

	char shortopts[]= "a:idsqj:b:k:w:g:J:B:K:W:G:vh";

	char option;

	if(argc<=1){
		usage();
		exit(EXIT_FAILURE);
	}

	/* 
	   addr6 does not need superuser privileges. But since most of the other tools in the toolkit do,
	   the user might unnecessarily run it as such. We release any unnecessary privileges before proceeding
	   further.

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
			if(pwdptr->pw_uid && (setgid(pwdptr->pw_gid) == -1)){
				puts("Error while releasing superuser privileges (changing to nobody's group)");
				exit(EXIT_FAILURE);
			}

			if(pwdptr->pw_uid && (setuid(pwdptr->pw_uid) == -1)){
				puts("Error while releasing superuser privileges (changing to 'nobody')");
				exit(EXIT_FAILURE);
			}
		}
	}

	while((r=getopt_long(argc, argv, shortopts, longopts, NULL)) != -1) {
		option= r;

		switch(option) {
			case 'a':
				if( inet_pton(AF_INET6, optarg, &(addr.ip6)) <= 0){
					puts("inet_pton(): address not valid");
					exit(EXIT_FAILURE);
				}
		
				addr_f=1;
				break;

			case 'i':  /* Read from stdin */
				stdin_f=1;
				break;
	    
			case 'd':	/* Decode IPv6 addresses */
				decode_f=1;
				break;


			case 'j':	/* IPv6 Address (accept) filter */
				if(naccept > MAX_ACCEPT){
					puts("Too many IPv6 Address (accept) filters.");
					exit(EXIT_FAILURE);
				}

				if((pref = strtok_r(optarg, "/", &lasts)) == NULL){
					printf("Error in IPv6 Address (accept) filter number %u.\n", naccept+1);
				    exit(EXIT_FAILURE);
				}

				if ( inet_pton(AF_INET6, pref, &accept[naccept]) <= 0){
					printf("Error in IPv6 Address (accept) filter number %u.\n", naccept+1);
					exit(EXIT_FAILURE);
				}
		
				if((charptr = strtok_r(NULL, " ", &lasts)) == NULL){
					acceptlen[naccept] = 128;
				}
				else{
					acceptlen[naccept] = atoi(charptr);
		
					if(acceptlen[naccept]>128){
						printf("Length error in IPv6 Source Address (accept) filter number %u.\n", naccept+1);
						exit(EXIT_FAILURE);
					}
				}
		
				sanitize_ipv6_prefix(&accept[naccept], acceptlen[naccept]);
				naccept++;
				acceptfilters_f=1;
				filter_f=1;
				break;

			case 'J':	/* IPv6 Address (block) filter */
				if(nblock >= MAX_BLOCK){
					puts("Too many IPv6 Source Address (block) filters.");
					exit(EXIT_FAILURE);
				}
	    
				if((pref = strtok_r(optarg, "/", &lasts)) == NULL){
					printf("Error in IPv6 Address (block) filter number %u.\n", nblock+1);
					exit(EXIT_FAILURE);
				}

				if ( inet_pton(AF_INET6, pref, &block[nblock]) <= 0){
					printf("Error in IPv6 Source Address (block) filter number %u.", nblock+1);
					exit(EXIT_FAILURE);
				}

				if((charptr = strtok_r(NULL, " ", &lasts)) == NULL){
					blocklen[nblock] = 128;
				}
				else{
					blocklen[nblock] = atoi(charptr);
		
					if(blocklen[nblock]>128){
						printf("Length error in IPv6 Address (block) filter number %u.\n", nblock+1);
						exit(EXIT_FAILURE);
					}
				}

				sanitize_ipv6_prefix(&block[nblock], blocklen[nblock]);
				
				nblock++;
				filter_f=1;
				break;

			case 'b':	/* Accept type filter */
				if(strncmp(optarg, "unicast", MAX_TYPE_SIZE) == 0){
					accept_type |= IPV6_UNICAST;
				}
				else if(strncmp(optarg, "unspec", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "unspecified", MAX_TYPE_SIZE) == 0){
					accept_type |= IPV6_UNSPEC;
				}
				else if(strncmp(optarg, "multicast", MAX_TYPE_SIZE) == 0){
					accept_type |= IPV6_MULTICAST;
				}
				else{
					printf("Unknown address type '%s' in accept type filter\n", optarg);
					exit(EXIT_FAILURE);
				}

				acceptfilters_f=1;
				filter_f=1;
				break;

			case 'B':	/* Block type filter */
				if(strncmp(optarg, "unicast", MAX_TYPE_SIZE) == 0){
					block_type |= IPV6_UNICAST;
				}
				else if(strncmp(optarg, "unspec", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "unspecified", MAX_TYPE_SIZE) == 0){
					block_type |= IPV6_UNSPEC;
				}
				else if(strncmp(optarg, "multicast", MAX_TYPE_SIZE) == 0){
					block_type |= IPV6_MULTICAST;
				}
				else{
					printf("Unknown address type '%s' in block type filter\n", optarg);
					exit(EXIT_FAILURE);
				}

				filter_f=1;
				break;

			case 'k':	/* Accept scope filter */
				if(strncmp(optarg, "reserved", MAX_TYPE_SIZE) == 0){
					accept_scope |= SCOPE_RESERVED;
				}
				else if(strncmp(optarg, "interface", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "interface-local", MAX_TYPE_SIZE) == 0){
					accept_type |= SCOPE_INTERFACE;
				}
				else if(strncmp(optarg, "link", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "link-local", MAX_TYPE_SIZE) == 0){
					accept_type |= SCOPE_LINK;
				}
				else if(strncmp(optarg, "admin", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "admin-local", MAX_TYPE_SIZE) == 0){
					accept_type |= SCOPE_ADMIN;
				}
				else if(strncmp(optarg, "site", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "site-local", MAX_TYPE_SIZE) == 0){
					accept_type |= SCOPE_SITE;
				}
				else if(strncmp(optarg, "organization", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "organization-local", MAX_TYPE_SIZE) == 0){
					accept_type |= SCOPE_ORGANIZATION;
				}
				else if(strncmp(optarg, "global", MAX_TYPE_SIZE) == 0){
					accept_type |= SCOPE_GLOBAL;
				}
				else if(strncmp(optarg, "unassigned", MAX_TYPE_SIZE) == 0){
					accept_type |= SCOPE_UNASSIGNED;
				}
				else if(strncmp(optarg, "unspecified", MAX_TYPE_SIZE) == 0){
					accept_type |= SCOPE_UNSPECIFIED;
				}
				else{
					printf("Unknown address scope '%s' in accept scope filter\n", optarg);
					exit(EXIT_FAILURE);
				}

				acceptfilters_f=1;
				filter_f=1;
				break;

			case 'K':	/* Block scope filter */
				if(strncmp(optarg, "reserved", MAX_TYPE_SIZE) == 0){
					block_scope |= SCOPE_RESERVED;
				}
				else if(strncmp(optarg, "interface", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "interface-local", MAX_TYPE_SIZE) == 0){
					block_type |= SCOPE_INTERFACE;
				}
				else if(strncmp(optarg, "link", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "link-local", MAX_TYPE_SIZE) == 0){
					block_type |= SCOPE_LINK;
				}
				else if(strncmp(optarg, "admin", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "admin-local", MAX_TYPE_SIZE) == 0){
					block_type |= SCOPE_ADMIN;
				}
				else if(strncmp(optarg, "site", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "site-local", MAX_TYPE_SIZE) == 0){
					block_type |= SCOPE_SITE;
				}
				else if(strncmp(optarg, "organization", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "organization-local", MAX_TYPE_SIZE) == 0){
					block_type |= SCOPE_ORGANIZATION;
				}
				else if(strncmp(optarg, "global", MAX_TYPE_SIZE) == 0){
					block_type |= SCOPE_GLOBAL;
				}
				else if(strncmp(optarg, "unassigned", MAX_TYPE_SIZE) == 0){
					block_type |= SCOPE_UNASSIGNED;
				}
				else if(strncmp(optarg, "unspecified", MAX_TYPE_SIZE) == 0){
					block_type |= SCOPE_UNSPECIFIED;
				}
				else{
					printf("Unknown address scope '%s' in block scope filter\n", optarg);
					exit(EXIT_FAILURE);
				}

				filter_f=1;
				break;

			case 'w':	/* Accept unicast type filter */
				if(strncmp(optarg, "loopback", MAX_TYPE_SIZE) == 0){
					accept_utype |= UCAST_LOOPBACK;
				}
				else if(strncmp(optarg, "ipv4-compat", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "ipv4-compatible", MAX_TYPE_SIZE) == 0){
					accept_utype |= UCAST_V4COMPAT;
				}
				else if(strncmp(optarg, "ipv4-mapped", MAX_TYPE_SIZE) == 0){
					accept_utype |= UCAST_V4MAPPED;
				}
				else if(strncmp(optarg, "link-local", MAX_TYPE_SIZE) == 0){
					accept_utype |= UCAST_LINKLOCAL;
				}
				else if(strncmp(optarg, "site-local", MAX_TYPE_SIZE) == 0){
					accept_utype |= UCAST_SITELOCAL;
				}
				else if(strncmp(optarg, "unique-local", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "ula", MAX_TYPE_SIZE) == 0){
					accept_utype |= UCAST_UNIQUELOCAL;
				}
				else if(strncmp(optarg, "6to4", MAX_TYPE_SIZE) == 0){
					accept_utype |= UCAST_6TO4;
				}
				else if(strncmp(optarg, "teredo", MAX_TYPE_SIZE) == 0){
					accept_utype |= UCAST_TEREDO;
				}
				else if(strncmp(optarg, "global", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "normal", MAX_TYPE_SIZE) == 0){
					accept_utype |= UCAST_GLOBAL;
				}
				else{
					printf("Unknown unicast address type '%s' in accept unicast address type filter\n", optarg);
					exit(EXIT_FAILURE);
				}

				acceptfilters_f=1;
				filter_f=1;
				break;


			case 'W':	/* Block unicast type filter */
				if(strncmp(optarg, "loopback", MAX_TYPE_SIZE) == 0){
					block_utype |= UCAST_LOOPBACK;
				}
				else if(strncmp(optarg, "ipv4-compat", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "ipv4-compatible", MAX_TYPE_SIZE) == 0){
					block_utype |= UCAST_V4COMPAT;
				}
				else if(strncmp(optarg, "ipv4-mapped", MAX_TYPE_SIZE) == 0){
					block_utype |= UCAST_V4MAPPED;
				}
				else if(strncmp(optarg, "link-local", MAX_TYPE_SIZE) == 0){
					block_utype |= UCAST_LINKLOCAL;
				}
				else if(strncmp(optarg, "site-local", MAX_TYPE_SIZE) == 0){
					block_utype |= UCAST_SITELOCAL;
				}
				else if(strncmp(optarg, "unique-local", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "ula", MAX_TYPE_SIZE) == 0){
					block_utype |= UCAST_UNIQUELOCAL;
				}
				else if(strncmp(optarg, "6to4", MAX_TYPE_SIZE) == 0){
					block_utype |= UCAST_6TO4;
				}
				else if(strncmp(optarg, "teredo", MAX_TYPE_SIZE) == 0){
					block_utype |= UCAST_TEREDO;
				}
				else if(strncmp(optarg, "global", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "normal", MAX_TYPE_SIZE) == 0){
					block_utype |= UCAST_GLOBAL;
				}
				else{
					printf("Unknown unicast address type '%s' in block unicast address type filter\n", optarg);
					exit(EXIT_FAILURE);
				}

				filter_f=1;
				break;

			case 'g':	/* Accept IID filter */
				if(strncmp(optarg, "ieee", MAX_TYPE_SIZE) == 0){
					accept_itype |= IID_MACDERIVED;
				}
				else if(strncmp(optarg, "isatap", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "ISATAP", MAX_TYPE_SIZE) == 0){
					accept_itype |= IID_ISATAP;
				}
				else if(strncmp(optarg, "ipv4-32", MAX_TYPE_SIZE) == 0){
					accept_itype |= IID_EMBEDDEDIPV4;
				}
				else if(strncmp(optarg, "ipv4-64", MAX_TYPE_SIZE) == 0){
					accept_itype |= IID_EMBEDDEDIPV4_64;
				}
				else if(strncmp(optarg, "ipv4-all", MAX_TYPE_SIZE) == 0){
					accept_itype |= IID_EMBEDDEDIPV4;
					accept_itype |= IID_EMBEDDEDIPV4_64;
				}
				else if(strncmp(optarg, "embed-port", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "port", MAX_TYPE_SIZE) == 0){
					accept_itype |= IID_EMBEDDEDPORT;
				}
				else if(strncmp(optarg, "embed-port-rev", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "port-rev", MAX_TYPE_SIZE) == 0){
					accept_itype |= IID_EMBEDDEDPORTREV;
				}
				else if(strncmp(optarg, "embed-port-all", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "port-all", MAX_TYPE_SIZE) == 0){
					accept_itype |= IID_EMBEDDEDPORT;
					accept_itype |= IID_EMBEDDEDPORTREV;
				}
				else if(strncmp(optarg, "low-byte", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "lowbyte", MAX_TYPE_SIZE) == 0){
					accept_itype |= IID_LOWBYTE;
				}
				else if(strncmp(optarg, "byte-pattern", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "bytepattern", MAX_TYPE_SIZE) == 0){
					accept_itype |= IID_PATTERN_BYTES;
				}
				else if(strncmp(optarg, "random", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "randomized", MAX_TYPE_SIZE) == 0){
					accept_itype |= IID_RANDOM;
				}
				else{
					printf("Unknown IID type '%s' in accept IID type filter.\n", optarg);
					exit(EXIT_FAILURE);
				}

				acceptfilters_f=1;
				filter_f = 1;
				break;

			case 'G':	/* Block IID filter */
				if(strncmp(optarg, "ieee", MAX_TYPE_SIZE) == 0){
					block_itype |= IID_MACDERIVED;
				}
				else if(strncmp(optarg, "isatap", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "ISATAP", MAX_TYPE_SIZE) == 0){
					block_itype |= IID_ISATAP;
				}
				else if(strncmp(optarg, "ipv4-32", MAX_TYPE_SIZE) == 0){
					block_itype |= IID_EMBEDDEDIPV4;
				}
				else if(strncmp(optarg, "ipv4-64", MAX_TYPE_SIZE) == 0){
					block_itype |= IID_EMBEDDEDIPV4_64;
				}
				else if(strncmp(optarg, "ipv4-all", MAX_TYPE_SIZE) == 0){
					block_itype |= IID_EMBEDDEDIPV4;
					block_itype |= IID_EMBEDDEDIPV4_64;
				}
				else if(strncmp(optarg, "embed-port", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "port", MAX_TYPE_SIZE) == 0){
					block_itype |= IID_EMBEDDEDPORT;
				}
				else if(strncmp(optarg, "embed-port-rev", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "port-rev", MAX_TYPE_SIZE) == 0){
					block_itype |= IID_EMBEDDEDPORTREV;
				}
				else if(strncmp(optarg, "embed-port-all", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "port-all", MAX_TYPE_SIZE) == 0){
					block_itype |= IID_EMBEDDEDPORT;
					block_itype |= IID_EMBEDDEDPORTREV;
				}
				else if(strncmp(optarg, "low-byte", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "lowbyte", MAX_TYPE_SIZE) == 0){
					block_itype |= IID_LOWBYTE;
				}
				else if(strncmp(optarg, "byte-pattern", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "bytepattern", MAX_TYPE_SIZE) == 0){
					block_itype |= IID_PATTERN_BYTES;
				}
				else if(strncmp(optarg, "random", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "randomized", MAX_TYPE_SIZE) == 0){
					block_itype |= IID_RANDOM;
				}
				else{
					printf("Unknown IID type '%s' in block IID type filter.\n", optarg);
					exit(EXIT_FAILURE);
				}

				filter_f = 1;
				break;

			case 's':	/* Generate IPv6 Address Statistics */
				stats_f = 1;
				break;

			case 'q':	/* Filter duplicate addresses */
				print_unique_f = 1;
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


	if(stdin_f && addr_f){
		puts("Cannot specify both '-a' and '-s' at the same time (try only one of them at a time)");
		exit(EXIT_FAILURE);
	}

	if(!stdin_f && !addr_f){
		puts("Must specify an IPv6 address with '-a', or set '-s' to read addresses from stdin");
		exit(EXIT_FAILURE);
	}

	if(stats_f && !stdin_f){
		puts("Cannot obtain statistics based on a single IPv6 address (should be using '-i')");
		exit(EXIT_FAILURE);
	}

	/* By default, addr6 decodes IPv6 addresses */
	if(!print_unique_f && !filter_f && !stats_f)
		decode_f=1;

	if(print_unique_f){
		if(!init_host_list(&hlist)){
			puts("Not enough memory when initializing internal host list");
			exit(EXIT_FAILURE);
		}
	}

	if(stats_f){
		memset(&stats, 0, sizeof(stats));
	}

	if(stdin_f){
		while(fgets(line, MAX_LINE_SIZE, stdin) != NULL){
			r= read_prefix(line, Strnlen(line, MAX_LINE_SIZE), &ptr);

			if(r==1){
				if ( inet_pton(AF_INET6, ptr, &(addr.ip6)) <= 0){
					if(decode_f)
						puts("Error: Invalid IPv6 address");

					continue;
				}

				if(filter_f || decode_f || stats_f)
					decode_ipv6_address(&addr, &stats);


				if(nblock){
					if(match_ipv6(block, blocklen, nblock, &(addr.ip6))){
						continue;
					}
				}

				if(block_type || block_scope || block_itype || block_utype){
					if( (block_type & addr.type) || (block_utype & addr.subtype)\
						 || (block_scope & addr.scope) || (block_itype & addr.iidtype))
						continue;
				}

				accepted_f=0;

				if(naccept){
					if(match_ipv6(accept, acceptlen, naccept, &(addr.ip6)))
						accepted_f= 1;
				}

				if(!accepted_f && (accept_type || accept_scope || accept_itype || accept_utype)){
					if( (accept_type & addr.type) || (accept_utype & addr.subtype)\
						 || (accept_scope & addr.scope) || (accept_itype & addr.iidtype))
						accepted_f=1;
				}

				if(acceptfilters_f && !accepted_f)
					continue;

				if(print_unique_f){
					if(is_ip6_in_list(&hlist, &(addr.ip6))){
						continue;
					}
					else{
						if(add_host_entry(&hlist, &(addr.ip6)) == NULL){
							puts("Not enough memory (or hit internal artificial limit) when storing IPv6 address in memory");
							exit(EXIT_FAILURE);
						}
					}
				}

				if(stats_f){
					stat_ipv6_address(&addr, &stats);
				}
				else if(decode_f){
						print_dec_address_script(&addr);
				}
				else{
					if(inet_ntop(AF_INET6, &(addr.ip6), pv6addr, sizeof(pv6addr)) == NULL){
						puts("inet_ntop(): Error converting IPv6 address to presentation format");
						exit(EXIT_FAILURE);
					}

					printf("%s\n", pv6addr);
				}
			}
		}

		if(stats_f){
			print_stats(&stats);
		}
	}
	else{
		/* If we were not asked to decode the address, we should print it on stdout */
		if(decode_f){
			decode_ipv6_address(&addr, &stats);
			print_dec_address_script(&addr);
		}
	}

	exit(EXIT_SUCCESS);
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
 * Function: is_service_port()
 *
 * Check whether a short int is in the list of service ports (in hexadecmal or decimal "notations")
 */

unsigned int is_service_port(u_int16_t port){
	unsigned int 	i;
	u_int16_t		service_ports_hex[]={0x21, 0x22, 0x23, 0x25, 0x49, 0x53, 0x80, 0x110, 0x123, 0x179, 0x220, 0x389, \
						                 0x443, 0x547, 0x993, 0x995, 0x1194, 0x3306, 0x5060, 0x5061, 0x5432, 0x6446, 0x8080};
	u_int16_t		service_ports_dec[]={21, 22, 23, 25, 49, 53, 80, 110, 123, 179, 220, 389, \
						                 443, 547, 993, 995, 1194, 3306, 5060, 5061, 5432, 6446, 8080};

	
	for(i=0; i< (sizeof(service_ports_hex)/sizeof(u_int16_t)); i++){
		if(port == service_ports_hex[i])
			return(1);
	}

	for(i=0; i< (sizeof(service_ports_hex)/sizeof(u_int16_t)); i++){
		if(port == service_ports_dec[i])
			return(1);
	}

	return(0);
}

/*
 * Function: zero_byte_iid()
 *
 * Counts the number of zero-bytes in an IPv6 Interface ID
 */

unsigned int zero_byte_iid(struct in6_addr *ipv6){
	unsigned int i, nonzero=0;

	for(i=8; i<=15; i++){
		if(ipv6->s6_addr[i] == 0)
			nonzero++;
	}

	return(nonzero);
}


/*
 * Function: decode_ipv6_address()
 *
 * Decodes/analyzes an IPv6 address
 */

void decode_ipv6_address(struct decode6 *addr, struct stats6 *stats){
	u_int16_t	scope;

	if(IN6_IS_ADDR_UNSPECIFIED(&(addr->ip6))){
		addr->type= IPV6_UNSPEC;
		addr->subtype= IPV6_UNSPEC;
		addr->scope= SCOPE_UNSPECIFIED;
	}
	else if(IN6_IS_ADDR_MULTICAST(&(addr->ip6))){
		addr->type= IPV6_MULTICAST;
		addr->iidtype= IID_UNSPECIFIED;
		addr->iidsubtype= IID_UNSPECIFIED;

		if((addr->ip6.s6_addr16[0] & htons(0xff00)) == htons(0xff00)){
			if((addr->ip6.s6_addr16[0] & htons(0xfff0)) == htons(0xff00)){
				addr->subtype= MCAST_PERMANENT;
			}
			else if((addr->ip6.s6_addr16[0] & htons(0xfff0)) == htons(0xff10)){
				addr->subtype= MCAST_NONPERMANENT;
			}
			else if((addr->ip6.s6_addr16[0] & htons(0xfff0)) == htons(0xff20)){
				addr->subtype= MCAST_INVALID;
			}
			else if((addr->ip6.s6_addr16[0] & htons(0xfff0)) == htons(0xff30)){
				addr->subtype= MCAST_UNICASTBASED;
			}
			else if((addr->ip6.s6_addr16[0] & htons(0xfff0)) == htons(0xff40)){
				addr->subtype= MCAST_INVALID;
			}
			else if((addr->ip6.s6_addr16[0] & htons(0xfff0)) == htons(0xff50)){
				addr->subtype= MCAST_INVALID;
			}
			else if((addr->ip6.s6_addr16[0] & htons(0xfff0)) == htons(0xff60)){
				addr->subtype= MCAST_INVALID;
			}
			else if((addr->ip6.s6_addr16[0] & htons(0xfff0)) == htons(0xff70)){
				addr->subtype= MCAST_EMBEDRP;
			}

			scope= htons(addr->ip6.s6_addr16[0]) & 0x000f;

			switch(scope){
				case 0:
					addr->scope= SCOPE_RESERVED;
					break;

				case 1:
					addr->scope= SCOPE_INTERFACE;
					break;

				case 2:
					addr->scope= SCOPE_LINK;
					break;

				case 3:
					addr->scope= SCOPE_RESERVED;
					break;

				case 4:
					addr->scope= SCOPE_ADMIN;
					break;

				case 5:
					addr->scope= SCOPE_SITE;
					break;

				case 8:
					addr->scope= SCOPE_ORGANIZATION;
					break;

				case 0Xe:
					addr->scope= SCOPE_GLOBAL;
					break;

				default:
					addr->scope= SCOPE_UNASSIGNED;
					break;
			}
		}
		else{
			addr->subtype= MCAST_UNKNOWN;
		}
	}
	else{
		addr->type= IPV6_UNICAST;
		addr->iidtype= IID_UNSPECIFIED;
		addr->iidsubtype= IID_UNSPECIFIED;

		if(IN6_IS_ADDR_LOOPBACK(&(addr->ip6))){
			addr->subtype= UCAST_LOOPBACK;
			addr->scope= SCOPE_INTERFACE;
		}
		else if(IN6_IS_ADDR_V4MAPPED(&(addr->ip6))){
			addr->subtype= UCAST_V4MAPPED;
			addr->scope= SCOPE_UNSPECIFIED;
		}
		else if(IN6_IS_ADDR_V4COMPAT(&(addr->ip6))){
			addr->subtype= UCAST_V4COMPAT;
			addr->scope= SCOPE_UNSPECIFIED;
		}
		else if(IN6_IS_ADDR_LINKLOCAL(&(addr->ip6))){
			addr->subtype= UCAST_LINKLOCAL;
			addr->scope= SCOPE_LINK;
		}
		else if(IN6_IS_ADDR_SITELOCAL(&(addr->ip6))){
			addr->subtype= UCAST_SITELOCAL;
			addr->scope= SCOPE_SITE;
		}
		else if(IN6_IS_ADDR_UNIQUELOCAL(&(addr->ip6))){
			addr->subtype= UCAST_UNIQUELOCAL;
			addr->scope= SCOPE_GLOBAL;
		}
		else if(IN6_IS_ADDR_6TO4(&(addr->ip6))){
			addr->subtype= UCAST_6TO4;
			addr->scope= SCOPE_GLOBAL;
		}
		else if(IN6_IS_ADDR_TEREDO(&(addr->ip6)) || IN6_IS_ADDR_TEREDO_LEGACY(&(addr->ip6))){
			addr->subtype= UCAST_TEREDO;
			addr->scope= SCOPE_GLOBAL;

			/* If the U or G bytes are set, the IID type is unknown */
			if(ntohs(addr->ip6.s6_addr16[4]) & 0x0300){
				addr->iidtype= IID_TEREDO_UNKNOWN;
			}
			else if(ntohs(addr->ip6.s6_addr16[4]) & 0x3cff){
				addr->iidtype= IID_TEREDO_RFC5991;
			}
			else{
				addr->iidtype= IID_TEREDO_RFC4380;
			}
		}
		else{
			addr->subtype= UCAST_GLOBAL;
			addr->scope= SCOPE_GLOBAL;
		}

		if(addr->subtype==UCAST_GLOBAL || addr->subtype==UCAST_V4MAPPED || addr->subtype==UCAST_V4COMPAT || \
			addr->subtype==UCAST_LINKLOCAL || addr->subtype==UCAST_SITELOCAL || addr->subtype==UCAST_UNIQUELOCAL ||\
			addr->subtype == UCAST_6TO4){

			if( (addr->ip6.s6_addr32[2] & htonl(0x020000ff)) == htonl(0x020000ff) && 
				(addr->ip6.s6_addr32[3] & htonl(0xff000000)) == htonl(0xfe000000)){
				addr->iidtype= IID_MACDERIVED;
				addr->iidsubtype= (ntohl(addr->ip6.s6_addr32[2]) >> 8) & 0xfffdffff;
			}
			else if((addr->ip6.s6_addr32[2] & htonl(0xfdffffff)) == htonl(0x00005efe)){
				/* We assume the u bit can be o o 1, but the i/g bit must be 0 */
				addr->iidtype= IID_ISATAP;
			}
			else if(addr->ip6.s6_addr32[2] == 0 && (addr->ip6.s6_addr16[6] & htons(0xff00)) != 0 && addr->ip6.s6_addr16[7] != 0){
				addr->iidtype= IID_EMBEDDEDIPV4;
			}
			else if(addr->ip6.s6_addr32[2] == 0 && \
			          ((addr->ip6.s6_addr16[6] & htons(0xff00)) == 0 && is_service_port(ntohs(addr->ip6.s6_addr16[7])))){
				addr->iidtype= IID_EMBEDDEDPORT;
			}
			else if(addr->ip6.s6_addr32[2] == 0 && \
			        	         ((addr->ip6.s6_addr16[7] & htons(0xff00)) == 0 && is_service_port(ntohs(addr->ip6.s6_addr16[6])))){
				addr->iidtype= IID_EMBEDDEDPORTREV;
			}
			else if(addr->ip6.s6_addr32[2] == 0 && (addr->ip6.s6_addr16[6] & htons(0xff00)) == 0 && addr->ip6.s6_addr16[7] != 0){
				addr->iidtype= IID_LOWBYTE;
			}
			else if( ntohs(addr->ip6.s6_addr16[4]) <= 0x255 && ntohs(addr->ip6.s6_addr16[5]) <= 0x255 && \
					ntohs(addr->ip6.s6_addr16[6]) <= 0x255 && ntohs(addr->ip6.s6_addr16[7]) <= 0x255){
				addr->iidtype= IID_EMBEDDEDIPV4_64;
			}
			else if( zero_byte_iid(&(addr->ip6)) > 2 ){
				addr->iidtype= IID_PATTERN_BYTES;
			}
			else{
				addr->iidtype= IID_RANDOM;
			}
		}
	}
}


/*
 * Function: stat_ipv6_address()
 *
 * Incorporate address in IPv6 address statistics
 */

void stat_ipv6_address(struct decode6 *addr, struct stats6 *stats){
	(stats->total)++;

	switch(addr->type){
		case IPV6_UNSPEC:
			(stats->ipv6unspecified)++;
			break;

		case IPV6_MULTICAST:
			(stats->ipv6multicast)++;

			switch(addr->subtype){
				case MCAST_PERMANENT:
					(stats->mcastpermanent)++;
					break;

				case MCAST_NONPERMANENT:
					(stats->mcastnonpermanent)++;
					break;

				case MCAST_INVALID:
					(stats->mcastinvalid)++;
					break;

				case MCAST_UNICASTBASED:
					(stats->mcastunicastbased)++;
					break;

				case MCAST_EMBEDRP:
					(stats->mcastembedrp)++;
					break;

				case MCAST_UNKNOWN:
					(stats->mcastunknown)++;
					break;
			}

			if(addr->subtype != MCAST_UNKNOWN){
				switch(addr->scope){
					case SCOPE_RESERVED:
						(stats->mscopereserved)++;
						break;

					case SCOPE_INTERFACE:
						(stats->mscopeinterface)++;
						break;

					case SCOPE_LINK:
						(stats->mnscopelink)++;
						break;

					case SCOPE_ADMIN:
						(stats->mscopeadmin)++;
						break;

					case SCOPE_SITE:
						(stats->mscopesite)++;
						break;

					case SCOPE_ORGANIZATION:
						(stats->mscopeorganization)++;
						break;

					case SCOPE_GLOBAL:
						(stats->mscopeglobal)++;
						break;

					case SCOPE_UNASSIGNED:
						(stats->mscopeunassigned)++;
						break;
				}
			}

			break;

		case IPV6_UNICAST:
			(stats->ipv6unicast)++;

			switch(addr->subtype){
				case UCAST_LOOPBACK:
					(stats->ucastloopback)++;
					break;

				case UCAST_V4MAPPED:
					(stats->ucastv4mapped)++;
					break;

				case UCAST_V4COMPAT:
					(stats->ucastv4compat)++;
					break;

				case UCAST_LINKLOCAL:
					(stats->ucastlinklocal)++;
					break;

				case UCAST_SITELOCAL:
					(stats->ucastsitelocal)++;
					break;

				case UCAST_UNIQUELOCAL:
					(stats->ucastuniquelocal)++;
					break;

				case UCAST_6TO4:
					(stats->ucast6to4)++;
					break;

				case UCAST_TEREDO:
					(stats->ucastteredo)++;
					break;

				case UCAST_GLOBAL:
					(stats->ucastglobal)++;
					break;
			}


			if(addr->subtype==UCAST_GLOBAL || addr->subtype==UCAST_V4MAPPED || addr->subtype==UCAST_V4COMPAT || \
				addr->subtype==UCAST_LINKLOCAL || addr->subtype==UCAST_SITELOCAL || addr->subtype==UCAST_UNIQUELOCAL ||\
				addr->subtype == UCAST_6TO4){

				switch(addr->iidtype){
					case IID_MACDERIVED:
						(stats->iidmacderived)++;
						break;

					case IID_ISATAP:
						(stats->iidisatap)++;
						break;

					case IID_EMBEDDEDIPV4:
						(stats->iidmbeddedipv4)++;
						break;

					case IID_EMBEDDEDPORT:
						(stats->iidembeddedport)++;
						break;

					case IID_EMBEDDEDPORTREV:
						(stats->iidembeddedportrev)++;
						break;

					case IID_LOWBYTE:
						(stats->iidlowbyte)++;
						break;

					case IID_EMBEDDEDIPV4_64:
						(stats->iidembeddedipv4_64)++;
						break;

					case IID_PATTERN_BYTES:
						(stats->iidpatternbytes)++;
						break;

					case IID_RANDOM:
						(stats->iidrandom)++;
						break;
				}
			}

			break;
		
	}

}


/*
 * Function: print_dec_address_script()
 *
 * Print the IPv6 address decode obtained by decode_ipv6_address
 */

void print_dec_address_script(struct decode6 *addr){
	unsigned int r;

	char *nullstring="";
	char *unspecified="unspecified";
	char iidsubtypebuffer[9];
	char *ipv6unspec="unspecified";
	char *ipv6multicast="multicast";
	char *ipv6unicast="unicast";

	char *ucastloopback="loopback";
	char *ucastv4mapped="ipv4-mapped";
	char *ucastv4compat="ipv4-compatible";
	char *ucastlinklocal="link-local";
	char *ucastsitelocal="site-local";
	char *ucastuniquelocal="unique-local";
	char *ucast6to4="6to4";
	char *ucastteredo="teredo";
	char *ucastglobal="global";

	char *mcastpermanent="permanent";
	char *mcastnonpermanent="non-permanent";
	char *mcastinvalid="invalid";
	char *mcastunicastbased="unicast-based";
	char *mcastembedrp="embedded-rp";
	char *mcastunknown="unknown";

	char *iidmacderived="ieee-derived";
	char *iidisatap="isatap";
	char *iidmbeddedipv4="embedded-ipv4";
	char *iidembeddedport="embedded-port";
	char *iidembeddedportrev="embedded-port-rev";
	char *iidlowbyte="low-byte";
	char *iidembeddedipv4_64="embedded-ipv4-64";
	char *iidpatternbytes="pattern-bytes";
	char *iidrandom="randomized";
	char *iidteredorfc4380="rfc4380";
	char *iidteredorfc5991="rfc5991";
	char *iidteredounknown="unknown";

	char *scopereserved="reserved";
	char *scopeinterface="interface";
	char *scopelink="link";
	char *scopeadmin="admin";
	char *scopesite="site";
	char *scopeorganization="organization";
	char *scopeglobal="global";
	char *scopeunassigned="unassigned";
	char *scopeunspecified="unspecified";

	char *type, *subtype, *scope, *iidtype, *iidsubtype;

	type= nullstring;
	subtype= nullstring;
	iidtype= nullstring;
	iidsubtype= nullstring;

	switch(addr->type){
		case IPV6_UNSPEC:
			type= ipv6unspec;
			subtype= unspecified;
			iidtype= unspecified;
			iidsubtype=unspecified;
			break;

		case IPV6_UNICAST:
			type= ipv6unicast;
			iidtype= unspecified;
			iidsubtype=unspecified;

			switch(addr->subtype){
				case UCAST_LOOPBACK:
					subtype= ucastloopback;
					iidtype= iidlowbyte;
					break;

				case UCAST_GLOBAL:
					subtype= ucastglobal;
					break;

				case UCAST_V4MAPPED:
					subtype= ucastv4mapped;
					break;

				case UCAST_V4COMPAT:
					subtype= ucastv4compat;
					break;

				case UCAST_LINKLOCAL:
					subtype= ucastlinklocal;
					break;

				case UCAST_SITELOCAL:
					subtype= ucastsitelocal;
					break;

				case UCAST_UNIQUELOCAL:
					subtype= ucastuniquelocal;
					break;

				case UCAST_6TO4:
					subtype= ucast6to4;
					break;

				case UCAST_TEREDO:
					subtype= ucastteredo;
					break;
			}


			if(addr->subtype == UCAST_GLOBAL || addr->subtype == UCAST_V4MAPPED || addr->subtype == UCAST_V4COMPAT || \
			   addr->subtype == UCAST_LINKLOCAL || addr->subtype == UCAST_SITELOCAL || addr->subtype == UCAST_UNIQUELOCAL ||\
			   addr->subtype == UCAST_6TO4 || addr->subtype == UCAST_TEREDO){

				switch(addr->iidtype){
					case IID_MACDERIVED:
						iidtype= iidmacderived;
						iidsubtype= iidsubtypebuffer;

						r=snprintf(iidsubtypebuffer, sizeof(iidsubtypebuffer), "%02x-%02x-%02x", (addr->iidsubtype >> 16 & 0xff), 
									(addr->iidsubtype >> 8 & 0xff), (addr->iidsubtype & 0xff));

						if(r == 8)
							iidsubtype= iidsubtypebuffer;

						break;

					case IID_ISATAP:
						iidtype= iidisatap;
						break;

					case IID_EMBEDDEDIPV4:
						iidtype= iidmbeddedipv4;
						break;

					case IID_EMBEDDEDPORT:
						iidtype= iidembeddedport;
						break;

					case IID_EMBEDDEDPORTREV:
						iidtype= iidembeddedportrev;
						break;

					case IID_LOWBYTE:
						iidtype= iidlowbyte;
						break;

					case IID_EMBEDDEDIPV4_64:
						iidtype= iidembeddedipv4_64;
						break;

					case IID_PATTERN_BYTES:
						iidtype= iidpatternbytes;
						break;

					case IID_RANDOM:
						iidtype= iidrandom;
						break;

					case IID_TEREDO_RFC4380:
						iidtype= iidteredorfc4380;
						break;

					case IID_TEREDO_RFC5991:
						iidtype= iidteredorfc5991;
						break;

					case IID_TEREDO_UNKNOWN:
						iidtype= iidteredounknown;
						break;
				}
			}

			break;

		case IPV6_MULTICAST:
			type= ipv6multicast;
			iidtype= unspecified;
			iidsubtype= unspecified;

			switch(addr->subtype){
				case MCAST_PERMANENT:
					subtype= mcastpermanent;
					break;

				case MCAST_NONPERMANENT:
					subtype= mcastnonpermanent;
					break;

				case MCAST_INVALID:
					subtype= mcastinvalid;
					break;

				case MCAST_UNICASTBASED:
					subtype= mcastunicastbased;
					break;

				case MCAST_EMBEDRP:
					subtype= mcastembedrp;
					break;

				case MCAST_UNKNOWN:
					subtype= mcastunknown;
					break;
			}
	}


	switch(addr->scope){
		case SCOPE_RESERVED:
			scope= scopereserved;
			break;

		case SCOPE_INTERFACE:
			scope= scopeinterface;
			break;

		case SCOPE_LINK:
			scope= scopelink;
			break;

		 case SCOPE_ADMIN:
			scope= scopeadmin;
			break;

		case SCOPE_SITE:
			scope= scopesite;
			break;

		case SCOPE_ORGANIZATION:
			scope= scopeorganization;
			break;

		case SCOPE_GLOBAL:
			scope= scopeglobal;
			break;

		case SCOPE_UNSPECIFIED:
			scope= scopeunspecified;
			break;

		default:
			scope= scopeunassigned;
			break;
	}

	printf("%s=%s=%s=%s=%s\n", type, subtype, scope, iidtype, iidsubtype);
}


/*
 * Function: usage()
 *
 * Prints the syntax of the scan6 tool
 */

void usage(void){
	puts("usage: addr6 (-i | -a) [-d | -s | -q] [-v] [-h]");
}


/*
 * Function: print_help()
 *
 * Prints help information for the scan6 tool
 */

void print_help(void){
	puts(SI6_TOOLKIT);
	puts( "addr6: An IPv6 address analysis tool\n");
	usage();
    
	puts("\nOPTIONS:\n"
	     "  --address, -a             IPv6 address to be decoded\n"
	     "  --stdin, -i               Read IPv6 addresses from stdin (standard input)\n"
	     "  --print-decode, -d        Decode IPv6 addresses\n"
	     "  --print-stats, -s         Print statistics about IPv6 addresses\n"
	     "  --print-unique, -q        Discard duplicate IPv6 addresses\n"
	     "  --accept, -j              Accept IPv6 addresses from specified IPv6 prefix\n"
	     "  --accept-type, -b         Accept IPv6 addresses of specified type\n"
	     "  --accept-scope, -k        Accept IPv6 addresses of specified scope\n"
	     "  --accept-utype, -w        Accept IPv6 unicast addresses of specified type\n"
	     "  --accept-iid, -g          Accept IPv6 addresses with IIDs of specified type\n"
	     "  --block, -J               Block IPv6 addresses from specified IPv6 prefix\n"
	     "  --block-type, -B          Block IPv6 addresses of specified type\n"
	     "  --block-scope, -K         Block IPv6 addresses of specified scope\n"
	     "  --block-utype, -W         Block IPv6 unicast addresses of specified type\n"
	     "  --block-iid, -G           Block IPv6 addresses with IIDs of specified type\n"
	     "  --verbose, -v             Be verbose\n"
	     "  --help, -h                Print help for the addr6 tool\n"
	     "\n"
	     " Programmed by Fernando Gont for SI6 Networks <http://www.si6networks.com>\n"
	     " Please send any bug reports to <fgont@si6networks.com>\n"
	);
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
 * Function: init_host_list()
 *
 * Initilizes a host_list structure
 */

int init_host_list(struct host_list *hlist){
	unsigned int i;

	bzero(hlist, sizeof(struct host_list));

	if( (hlist->host = malloc(MAX_LIST_ENTRIES * sizeof(struct host_entry *))) == NULL){
		return(0);
	}

	for(i=0; i < MAX_LIST_ENTRIES; i++)
		hlist->host[i]= NULL;

	hlist->nhosts= 0;
	hlist->maxhosts= MAX_HOST_ENTRIES;
	hlist->key_l= rand();
	hlist->key_h= rand();
	return(1);
}


/*
 * Function: key()
 *
 * Compute a key for accessing the hash-table of a host_list structure
 */

u_int16_t key(struct host_list *hlist, struct in6_addr *ipv6){
		return( ((hlist->key_l ^ ipv6->s6_addr16[0] ^ ipv6->s6_addr16[7]) \
				^ (hlist->key_h ^ ipv6->s6_addr16[1] ^ ipv6->s6_addr16[6])) % MAX_LIST_ENTRIES);
}


/*
 * Function: add_host_entry()
 *
 * Add a host_entry structure to the hash table
 */

struct host_entry *add_host_entry(struct host_list *hlist, struct in6_addr *ipv6){
	struct host_entry	*hentry, *ptr;
	u_int16_t			hkey;

	hkey= key(hlist, ipv6);

	if(hlist->nhosts >= hlist->maxhosts){
		return(NULL);
	}

	if( (hentry= malloc(sizeof(struct host_entry))) == NULL){
		return(NULL);
	}

	bzero(hentry, sizeof(struct host_entry));
	hentry->ip6 = *ipv6;
	hentry->next= NULL;

	if(hlist->host[hkey] == NULL){
		/* First node in chain */
		hlist->host[hkey]= hentry;
		hentry->prev= NULL;
	}
	else{
		/* Find last node in list */
		for(ptr=hlist->host[hkey]; ptr->next != NULL; ptr= ptr->next);

		hentry->prev= ptr;
		ptr->next= hentry;
	}

	(hlist->nhosts)++;

	return(hentry);
}


/*
 * Function: is_ip6_in_list()
 *
 * Checks whether an IPv6 address is present in a host list.
 */

unsigned int is_ip6_in_list(struct host_list *hlist, struct in6_addr *target){
	u_int16_t			ckey;
	struct host_entry	*chentry;

	ckey= key(hlist, target);

	for(chentry= hlist->host[ckey]; chentry != NULL; chentry=chentry->next)
		if( is_eq_in6_addr(target, &(chentry->ip6)) )
			return 1;

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
 * Function: print_stats()
 *
 * Prints IPv6 address statistics
 */

void print_stats(struct stats6 *stats){
	unsigned int	totaliids=0;
	puts("\n** IPv6 General Address Analysis **\n");
	printf("Total IPv6 addresses: %u\n", stats->total);
	printf("Unicast: %7u (%.2f%%)\t\tMulticast: %7u (%.2f%%)\n", stats->ipv6unicast, \
			((float)(stats->ipv6unicast)/stats->total) * 100, stats->ipv6multicast, ((float)(stats->ipv6multicast)/stats->total) * 100);
	printf("Unspec.: %7u (%.2f%%)\n\n", stats->ipv6unspecified, ((float)(stats->ipv6unspecified)/stats->total) * 100);

	if(stats->ipv6unicast){
		puts("** IPv6 Unicast Addresses **\n");
		printf("Loopback:     %7u (%.2f%%)\t\tIPv4-mapped:  %7u (%.2f%%)\n",\
				stats->ucastloopback, ((float)(stats->ucastloopback)/stats->ipv6unicast) * 100, stats->ucastv4mapped, \
				((float)(stats->ucastv4mapped)/stats->ipv6unicast) * 100);

		printf("IPv4-compat.: %7u (%.2f%%)\t\tLink-local:   %7u (%.2f%%)\n", stats->ucastv4compat, \
				((float)(stats->ucastv4compat)/stats->ipv6unicast) * 100, stats->ucastlinklocal, \
				((float)(stats->ucastlinklocal)/stats->ipv6unicast) * 100);

		printf("Site-local:   %7u (%.2f%%)\t\tUnique-local: %7u (%.2f%%)\n", stats->ucastsitelocal, \
				((float)(stats->ucastsitelocal)/stats->ipv6unicast) * 100, stats->ucastuniquelocal, \
				((float)(stats->ucastuniquelocal)/stats->ipv6unicast) * 100);

		printf("6to4:         %7u (%.2f%%)\t\tTeredo:       %7u (%.2f%%)\n", stats->ucast6to4, \
				((float)(stats->ucast6to4)/stats->ipv6unicast) * 100, stats->ucastteredo, \
				((float)(stats->ucastteredo)/stats->ipv6unicast) * 100);

		printf("Global:       %7u (%.2f%%)\n\n", stats->ucastglobal, ((float)(stats->ucastglobal)/stats->ipv6unicast) * 100);
	}

	if(stats->ipv6multicast){
		puts("** IPv6 Multicast Addresses **\n");
		puts("+ Multicast Address Types +");
		printf("Permanent:   %7u (%.2f%%)\t\tNon-permanent  %7u (%.2f%%)\n",\
				stats->mcastpermanent, ((float)(stats->mcastpermanent)/stats->ipv6multicast) * 100, stats->mcastnonpermanent, \
				((float)(stats->mcastnonpermanent)/stats->ipv6multicast) * 100);

		printf("Invalid:     %7u (%.2f%%)\t\tUnicast-based: %7u (%.2f%%)\n", stats->mcastinvalid, \
				((float)(stats->mcastinvalid)/stats->ipv6multicast) * 100, stats->mcastunicastbased, \
				((float)(stats->mcastunicastbased)/stats->ipv6multicast) * 100);

		printf("Embedded-RP: %7u (%.2f%%)\t\tUnknown:       %7u (%.2f%%)\n\n", stats->mcastembedrp, \
				((float)(stats->mcastembedrp)/stats->ipv6multicast) * 100, stats->mcastunknown, \
				((float)(stats->mcastunknown)/stats->ipv6multicast) * 100);

		puts("+ Multicast Address Scopes +");

		printf("Reserved:    %7u (%.2f%%)\t\tInterface:     %7u (%.2f%%)\n",\
				stats->mscopereserved, ((float)(stats->mscopereserved)/stats->ipv6multicast) * 100, stats->mscopeinterface, \
				((float)(stats->mscopeinterface)/stats->ipv6multicast) * 100);

		printf("Link:        %7u (%.2f%%)\t\tAdmin:         %7u (%.2f%%)\n", stats->mnscopelink, \
				((float)(stats->mnscopelink)/stats->ipv6multicast) * 100, stats->mscopeadmin, \
				((float)(stats->mscopeadmin)/stats->ipv6multicast) * 100);

		printf("Site:        %7u (%.2f%%)\t\tOrganization:  %7u (%.2f%%)\n", stats->mscopesite, \
				((float)(stats->mscopesite)/stats->ipv6multicast) * 100, stats->mscopeorganization, \
				((float)(stats->mscopeorganization)/stats->ipv6multicast) * 100);

		printf("Global:      %7u (%.2f%%)\t\tUnassigned:    %7u (%.2f%%)\n\n", stats->mscopeadmin, \
				((float)(stats->mscopeadmin)/stats->ipv6multicast) * 100, stats->mscopesite, \
				((float)(stats->mscopesite)/stats->ipv6multicast) * 100);
	}

	totaliids= stats->ucastglobal + stats->ucastlinklocal + stats->ucastsitelocal + stats->ucastuniquelocal + \
	           stats->ucast6to4;

	if(totaliids){
		puts("** IPv6 Interface IDs **\n");

		printf("Total IIDs analyzed: %u\n", totaliids);
		printf("IEEE-based: %7u (%.2f%%)\t\tLow-byte:        %7u (%.2f%%)\n",\
				stats->iidmacderived, ((float)(stats->iidmacderived)/totaliids) * 100, stats->iidlowbyte, 
				((float)(stats->iidlowbyte)/totaliids) * 100);

		printf("Embed-IPv4: %7u (%.2f%%)\t\tEmbed-IPv4 (64): %7u (%.2f%%)\n", stats->iidmbeddedipv4, \
				((float)(stats->iidmbeddedipv4)/totaliids) * 100, stats->iidembeddedipv4_64, \
				((float)(stats->iidembeddedipv4_64)/totaliids) * 100);

		printf("Embed-port: %7u (%.2f%%)\t\tEmbed-port (r):  %7u (%.2f%%)\n", stats->iidembeddedport, \
				((float)(stats->iidembeddedport)/totaliids) * 100, stats->iidembeddedportrev, \
				((float)(stats->iidembeddedportrev)/totaliids) * 100);


		printf("ISATAP:     %7u (%.2f%%)\t\tByte-pattern:    %7u (%.2f%%)\n", stats->iidisatap, \
				((float)(stats->iidisatap)/totaliids) * 100, stats->iidpatternbytes, \
				((float)(stats->iidpatternbytes)/totaliids) * 100);

		printf("Randomized: %7u (%.2f%%)\n\n", stats->iidrandom, ((float)(stats->iidrandom)/totaliids) * 100);
	}
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
			
    for(i=skip; i<8; i++)
		ipv6addr->s6_addr16[i]=0;
}

