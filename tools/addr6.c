/*
 * addr6: A tool to decode IPv6 addresses
 *
 * Copyright (C) 2013-2019 Fernando Gont (fgont@si6networks.com)
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
 * Build with: make addr6
 *
 * It requires that the libpcap library be installed on your system.
 *
 * Please send any bug reports to Fernando Gont <fgont@si6networks.com>
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "addr6.h"
#include "ipv6toolkit.h"
#include "libipv6.h"

void usage(void);
void print_help(void);
void stat_ipv6_address(struct decode6 *, struct stats6 *);
void print_dec_address_script(struct decode6 *);
int init_host_list(struct hashed_host_list *);
uint16_t key(struct hashed_host_list *, struct in6_addr *);
struct hashed_host_entry *add_hashed_host_entry(struct hashed_host_list *, struct in6_addr *);
unsigned int is_ip6_in_hashed_list(struct hashed_host_list *, struct in6_addr *);
void print_stats(struct stats6 *);

unsigned char stdin_f = FALSE, addr_f = FALSE, verbose_f = FALSE, decode_f = FALSE, block_duplicate_f = FALSE;
unsigned char block_duplicate_preflen_f = FALSE, stats_f = FALSE, filter_f = FALSE, canonic_f = FALSE;
unsigned char fixed_f = FALSE, print_unique_preflen_f = FALSE, pattern_f = FALSE, response_f = FALSE;
unsigned char reverse_f = FALSE;
unsigned int pstart, pend;
unsigned int caddr = 0, naddr = 0;
char line[MAX_LINE_SIZE];

extern char *optarg;
extern int optind, opterr, optopt;

int main(int argc, char **argv) {
    struct decode6 addr;
    struct stats6 stats;
    struct hashed_host_list hlist;
    int r;
    char *ptr, *pref, *charptr, *lasts, *endptr;
    unsigned long ul_res;
    char pv6addr[INET6_ADDRSTRLEN];
    char prefstr[5]; /* Buffer to store a prefix such as /128 */
    unsigned int accept_type = 0, block_type = 0, accept_scope = 0, block_scope = 0, accept_itype = 0, block_itype = 0;
    unsigned int accept_utype = 0, block_utype = 0;

    unsigned char accepted_f = FALSE, acceptfilters_f = FALSE, duplicate_f = FALSE, flag_f = FALSE;

    /* Block Filters */
    struct in6_addr block[MAX_BLOCK], *ptable = NULL;
    struct in6_addr genaddr, randaddr;
    uint8_t genpref = 0;

    uint32_t *pcounter = NULL, pthres, pratio;
    uint8_t blocklen[MAX_BLOCK];
    unsigned int nblock = 0;

    /* Accept Filters */
    struct in6_addr accept[MAX_ACCEPT];
    uint8_t acceptlen[MAX_ACCEPT];
    unsigned int naccept = 0, i, j, k;

    /* Filter based on prefix length */
    uint8_t dpreflen = 128; /* To avoid warnings */

    pid_t pid;
    struct in6_addr dummyipv6;
    struct timeval time;

    static struct option longopts[] = {
        {"address", required_argument, 0, 'a'},
        {"gen-addr", required_argument, 0, 'A'},
        {"stdin", no_argument, 0, 'i'},
        {"print-canonic", no_argument, 0, 'c'},
        {"print-decode", no_argument, 0, 'd'},
        {"print-fixed", no_argument, 0, 'f'},
        {"print-reverse", no_argument, 0, 'r'},
        {"print-stats", no_argument, 0, 's'},
        {"print-pattern", required_argument, 0, 'x'},
        {"print-response", no_argument, 0, 'R'},
        {"block-dup", no_argument, 0, 'q'},
        {"print-unique", no_argument, 0, 'Q'},
        {"print-uni-preflen", required_argument, 0, 'P'},
        {"block-dup-preflen", required_argument, 0, 'p'},
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
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0},
    };

    const char shortopts[] = "a:A:icrdfsx:RqQP:p:j:b:k:w:g:J:B:K:W:G:vh";

    char option;

    if (argc <= 1) {
        usage();
        exit(EXIT_FAILURE);
    }

    release_privileges();

    while ((r = getopt_long(argc, argv, shortopts, longopts, NULL)) != -1 && r != '?') {
        option = r;

        switch (option) {
        case 'a':
            if (inet_pton(AF_INET6, optarg, &(addr.ip6)) <= 0) {
                puts("inet_pton(): address not valid");
                exit(EXIT_FAILURE);
            }

            addr_f = TRUE;
            break;

        case 'A':
            if ((charptr = strtok_r(optarg, "/", &lasts)) == NULL) {
                puts("Error in Prefix");
                exit(EXIT_FAILURE);
            }

            if (inet_pton(AF_INET6, charptr, &genaddr) <= 0) {
                puts("inet_pton(): Source Address not valid");
                exit(EXIT_FAILURE);
            }

            if ((charptr = strtok_r(NULL, " ", &lasts)) != NULL) {
                genpref = atoi(charptr);

                if (genpref > 128) {
                    puts("Prefix length error in IPv6 Source Address");
                    exit(EXIT_FAILURE);
                }
            }
            else {
                puts("Missing Prefix Length");
                exit(EXIT_FAILURE);
            }

            if (gettimeofday(&time, NULL) == -1) {
                perror("addr6");
                exit(EXIT_FAILURE);
            }

            pid = getpid();
            srandom((unsigned int)time.tv_sec + (unsigned int)time.tv_usec + (unsigned int)pid);
            randomize_ipv6_addr(&randaddr, &genaddr, genpref);

            if (inet_ntop(AF_INET6, &randaddr, pv6addr, sizeof(pv6addr)) == NULL) {
                puts("inet_ntop(): Error converting IPv6 address to presentation format");
                exit(EXIT_FAILURE);
            }

            puts(pv6addr);

            exit(EXIT_SUCCESS);
            break;

        case 'i': /* Read from stdin */
            stdin_f = TRUE;
            break;

        case 'c': /* Print addresses in canonic form */
            canonic_f = TRUE;
            break;

        case 'f': /* Print addresses with fixed length */
            fixed_f = TRUE;
            break;

        case 'd': /* Decode IPv6 addresses */
            decode_f = TRUE;
            break;

        case 'r': /* Print addresses in reversed form */
            reverse_f = TRUE;
            break;

        case 'j': /* IPv6 Address (accept) filter */
            if (naccept > MAX_ACCEPT) {
                puts("Too many IPv6 Address (accept) filters.");
                exit(EXIT_FAILURE);
            }

            if ((pref = strtok_r(optarg, "/", &lasts)) == NULL) {
                printf("Error in IPv6 Address (accept) filter number %u.\n", naccept + 1);
                exit(EXIT_FAILURE);
            }

            if (inet_pton(AF_INET6, pref, &accept[naccept]) <= 0) {
                printf("Error in IPv6 Address (accept) filter number %u.\n", naccept + 1);
                exit(EXIT_FAILURE);
            }

            if ((charptr = strtok_r(NULL, " ", &lasts)) == NULL) {
                acceptlen[naccept] = 128;
            }
            else {
                acceptlen[naccept] = atoi(charptr);

                if (acceptlen[naccept] > 128) {
                    printf("Length error in IPv6 Source Address (accept) filter number %u.\n", naccept + 1);
                    exit(EXIT_FAILURE);
                }
            }

            sanitize_ipv6_prefix(&accept[naccept], acceptlen[naccept]);
            naccept++;
            acceptfilters_f = TRUE;
            filter_f = TRUE;
            break;

        case 'J': /* IPv6 Address (block) filter */
            if (nblock >= MAX_BLOCK) {
                puts("Too many IPv6 Source Address (block) filters.");
                exit(EXIT_FAILURE);
            }

            if ((pref = strtok_r(optarg, "/", &lasts)) == NULL) {
                printf("Error in IPv6 Address (block) filter number %u.\n", nblock + 1);
                exit(EXIT_FAILURE);
            }

            if (inet_pton(AF_INET6, pref, &block[nblock]) <= 0) {
                printf("Error in IPv6 Source Address (block) filter number %u.", nblock + 1);
                exit(EXIT_FAILURE);
            }

            if ((charptr = strtok_r(NULL, " ", &lasts)) == NULL) {
                blocklen[nblock] = 128;
            }
            else {
                blocklen[nblock] = atoi(charptr);

                if (blocklen[nblock] > 128) {
                    printf("Length error in IPv6 Address (block) filter number %u.\n", nblock + 1);
                    exit(EXIT_FAILURE);
                }
            }

            sanitize_ipv6_prefix(&block[nblock], blocklen[nblock]);

            nblock++;
            filter_f = TRUE;
            break;

        case 'b': /* Accept type filter */
            if (strncmp(optarg, "unicast", MAX_TYPE_SIZE) == 0) {
                accept_type |= IPV6_UNICAST;
            }
            else if (strncmp(optarg, "unspec", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "unspecified", MAX_TYPE_SIZE) == 0) {
                accept_type |= IPV6_UNSPEC;
            }
            else if (strncmp(optarg, "multicast", MAX_TYPE_SIZE) == 0) {
                accept_type |= IPV6_MULTICAST;
            }
            else {
                printf("Unknown address type '%s' in accept type filter\n", optarg);
                exit(EXIT_FAILURE);
            }

            acceptfilters_f = TRUE;
            filter_f = TRUE;
            break;

        case 'B': /* Block type filter */
            if (strncmp(optarg, "unicast", MAX_TYPE_SIZE) == 0) {
                block_type |= IPV6_UNICAST;
            }
            else if (strncmp(optarg, "unspec", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "unspecified", MAX_TYPE_SIZE) == 0) {
                block_type |= IPV6_UNSPEC;
            }
            else if (strncmp(optarg, "multicast", MAX_TYPE_SIZE) == 0) {
                block_type |= IPV6_MULTICAST;
            }
            else {
                printf("Unknown address type '%s' in block type filter\n", optarg);
                exit(EXIT_FAILURE);
            }

            filter_f = TRUE;
            break;

        case 'k': /* Accept scope filter */
            if (strncmp(optarg, "reserved", MAX_TYPE_SIZE) == 0) {
                accept_scope |= SCOPE_RESERVED;
            }
            else if (strncmp(optarg, "interface", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "interface-local", MAX_TYPE_SIZE) == 0) {
                accept_scope |= SCOPE_INTERFACE;
            }
            else if (strncmp(optarg, "link", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "link-local", MAX_TYPE_SIZE) == 0) {
                accept_scope |= SCOPE_LINK;
            }
            else if (strncmp(optarg, "admin", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "admin-local", MAX_TYPE_SIZE) == 0) {
                accept_scope |= SCOPE_ADMIN;
            }
            else if (strncmp(optarg, "site", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "site-local", MAX_TYPE_SIZE) == 0) {
                accept_scope |= SCOPE_SITE;
            }
            else if (strncmp(optarg, "organization", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "organization-local", MAX_TYPE_SIZE) == 0) {
                accept_scope |= SCOPE_ORGANIZATION;
            }
            else if (strncmp(optarg, "global", MAX_TYPE_SIZE) == 0) {
                accept_scope |= SCOPE_GLOBAL;
            }
            else if (strncmp(optarg, "unassigned", MAX_TYPE_SIZE) == 0) {
                accept_scope |= SCOPE_UNASSIGNED;
            }
            else if (strncmp(optarg, "unspecified", MAX_TYPE_SIZE) == 0) {
                accept_scope |= SCOPE_UNSPECIFIED;
            }
            else {
                printf("Unknown address scope '%s' in accept scope filter\n", optarg);
                exit(EXIT_FAILURE);
            }

            acceptfilters_f = TRUE;
            filter_f = TRUE;
            break;

        case 'K': /* Block scope filter */
            if (strncmp(optarg, "reserved", MAX_TYPE_SIZE) == 0) {
                block_scope |= SCOPE_RESERVED;
            }
            else if (strncmp(optarg, "interface", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "interface-local", MAX_TYPE_SIZE) == 0) {
                block_scope |= SCOPE_INTERFACE;
            }
            else if (strncmp(optarg, "link", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "link-local", MAX_TYPE_SIZE) == 0) {
                block_scope |= SCOPE_LINK;
            }
            else if (strncmp(optarg, "admin", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "admin-local", MAX_TYPE_SIZE) == 0) {
                block_scope |= SCOPE_ADMIN;
            }
            else if (strncmp(optarg, "site", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "site-local", MAX_TYPE_SIZE) == 0) {
                block_scope |= SCOPE_SITE;
            }
            else if (strncmp(optarg, "organization", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "organization-local", MAX_TYPE_SIZE) == 0) {
                block_scope |= SCOPE_ORGANIZATION;
            }
            else if (strncmp(optarg, "global", MAX_TYPE_SIZE) == 0) {
                block_scope |= SCOPE_GLOBAL;
            }
            else if (strncmp(optarg, "unassigned", MAX_TYPE_SIZE) == 0) {
                block_scope |= SCOPE_UNASSIGNED;
            }
            else if (strncmp(optarg, "unspecified", MAX_TYPE_SIZE) == 0) {
                block_scope |= SCOPE_UNSPECIFIED;
            }
            else {
                printf("Unknown address scope '%s' in block scope filter\n", optarg);
                exit(EXIT_FAILURE);
            }

            filter_f = TRUE;
            break;

        case 'w': /* Accept unicast type filter */
            if (strncmp(optarg, "loopback", MAX_TYPE_SIZE) == 0) {
                accept_utype |= UCAST_LOOPBACK;
            }
            else if (strncmp(optarg, "ipv4-compat", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "ipv4-compatible", MAX_TYPE_SIZE) == 0) {
                accept_utype |= UCAST_V4COMPAT;
            }
            else if (strncmp(optarg, "ipv4-mapped", MAX_TYPE_SIZE) == 0) {
                accept_utype |= UCAST_V4MAPPED;
            }
            else if (strncmp(optarg, "link-local", MAX_TYPE_SIZE) == 0) {
                accept_utype |= UCAST_LINKLOCAL;
            }
            else if (strncmp(optarg, "site-local", MAX_TYPE_SIZE) == 0) {
                accept_utype |= UCAST_SITELOCAL;
            }
            else if (strncmp(optarg, "unique-local", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "ula", MAX_TYPE_SIZE) == 0) {
                accept_utype |= UCAST_UNIQUELOCAL;
            }
            else if (strncmp(optarg, "6to4", MAX_TYPE_SIZE) == 0) {
                accept_utype |= UCAST_6TO4;
            }
            else if (strncmp(optarg, "teredo", MAX_TYPE_SIZE) == 0) {
                accept_utype |= UCAST_TEREDO;
            }
            else if (strncmp(optarg, "global", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "normal", MAX_TYPE_SIZE) == 0) {
                accept_utype |= UCAST_GLOBAL;
            }
            else {
                printf("Unknown unicast address type '%s' in accept unicast address type filter\n", optarg);
                exit(EXIT_FAILURE);
            }

            acceptfilters_f = TRUE;
            filter_f = TRUE;
            break;

        case 'W': /* Block unicast type filter */
            if (strncmp(optarg, "loopback", MAX_TYPE_SIZE) == 0) {
                block_utype |= UCAST_LOOPBACK;
            }
            else if (strncmp(optarg, "ipv4-compat", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "ipv4-compatible", MAX_TYPE_SIZE) == 0) {
                block_utype |= UCAST_V4COMPAT;
            }
            else if (strncmp(optarg, "ipv4-mapped", MAX_TYPE_SIZE) == 0) {
                block_utype |= UCAST_V4MAPPED;
            }
            else if (strncmp(optarg, "link-local", MAX_TYPE_SIZE) == 0) {
                block_utype |= UCAST_LINKLOCAL;
            }
            else if (strncmp(optarg, "site-local", MAX_TYPE_SIZE) == 0) {
                block_utype |= UCAST_SITELOCAL;
            }
            else if (strncmp(optarg, "unique-local", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "ula", MAX_TYPE_SIZE) == 0) {
                block_utype |= UCAST_UNIQUELOCAL;
            }
            else if (strncmp(optarg, "6to4", MAX_TYPE_SIZE) == 0) {
                block_utype |= UCAST_6TO4;
            }
            else if (strncmp(optarg, "teredo", MAX_TYPE_SIZE) == 0) {
                block_utype |= UCAST_TEREDO;
            }
            else if (strncmp(optarg, "global", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "normal", MAX_TYPE_SIZE) == 0) {
                block_utype |= UCAST_GLOBAL;
            }
            else {
                printf("Unknown unicast address type '%s' in block unicast address type filter\n", optarg);
                exit(EXIT_FAILURE);
            }

            filter_f = TRUE;
            break;

        case 'g': /* Accept IID filter */
            if (strncmp(optarg, "ieee", MAX_TYPE_SIZE) == 0) {
                accept_itype |= IID_MACDERIVED;
            }
            else if (strncmp(optarg, "isatap", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "ISATAP", MAX_TYPE_SIZE) == 0) {
                accept_itype |= IID_ISATAP;
            }
            else if (strncmp(optarg, "ipv4-32", MAX_TYPE_SIZE) == 0) {
                accept_itype |= IID_EMBEDDEDIPV4;
            }
            else if (strncmp(optarg, "ipv4-64", MAX_TYPE_SIZE) == 0) {
                accept_itype |= IID_EMBEDDEDIPV4_64;
            }
            else if (strncmp(optarg, "ipv4-all", MAX_TYPE_SIZE) == 0) {
                accept_itype |= IID_EMBEDDEDIPV4;
                accept_itype |= IID_EMBEDDEDIPV4_64;
            }
            else if (strncmp(optarg, "embed-port", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "port", MAX_TYPE_SIZE) == 0) {
                accept_itype |= IID_EMBEDDEDPORT;
            }
            else if (strncmp(optarg, "embed-port-rev", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "port-rev", MAX_TYPE_SIZE) == 0) {
                accept_itype |= IID_EMBEDDEDPORTREV;
            }
            else if (strncmp(optarg, "embed-port-all", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "port-all", MAX_TYPE_SIZE) == 0) {
                accept_itype |= IID_EMBEDDEDPORT;
                accept_itype |= IID_EMBEDDEDPORTREV;
            }
            else if (strncmp(optarg, "low-byte", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "lowbyte", MAX_TYPE_SIZE) == 0) {
                accept_itype |= IID_LOWBYTE;
            }
            else if (strncmp(optarg, "byte-pattern", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "bytepattern", MAX_TYPE_SIZE) == 0) {
                accept_itype |= IID_PATTERN_BYTES;
            }
            else if (strncmp(optarg, "random", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "randomized", MAX_TYPE_SIZE) == 0) {
                accept_itype |= IID_RANDOM;
            }
            else {
                printf("Unknown IID type '%s' in accept IID type filter.\n", optarg);
                exit(EXIT_FAILURE);
            }

            acceptfilters_f = TRUE;
            filter_f = TRUE;
            break;

        case 'G': /* Block IID filter */
            if (strncmp(optarg, "ieee", MAX_TYPE_SIZE) == 0) {
                block_itype |= IID_MACDERIVED;
            }
            else if (strncmp(optarg, "isatap", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "ISATAP", MAX_TYPE_SIZE) == 0) {
                block_itype |= IID_ISATAP;
            }
            else if (strncmp(optarg, "ipv4-32", MAX_TYPE_SIZE) == 0) {
                block_itype |= IID_EMBEDDEDIPV4;
            }
            else if (strncmp(optarg, "ipv4-64", MAX_TYPE_SIZE) == 0) {
                block_itype |= IID_EMBEDDEDIPV4_64;
            }
            else if (strncmp(optarg, "ipv4-all", MAX_TYPE_SIZE) == 0) {
                block_itype |= IID_EMBEDDEDIPV4;
                block_itype |= IID_EMBEDDEDIPV4_64;
            }
            else if (strncmp(optarg, "embed-port", MAX_TYPE_SIZE) == 0 || strncmp(optarg, "port", MAX_TYPE_SIZE) == 0) {
                block_itype |= IID_EMBEDDEDPORT;
            }
            else if (strncmp(optarg, "embed-port-rev", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "port-rev", MAX_TYPE_SIZE) == 0) {
                block_itype |= IID_EMBEDDEDPORTREV;
            }
            else if (strncmp(optarg, "embed-port-all", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "port-all", MAX_TYPE_SIZE) == 0) {
                block_itype |= IID_EMBEDDEDPORT;
                block_itype |= IID_EMBEDDEDPORTREV;
            }
            else if (strncmp(optarg, "low-byte", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "lowbyte", MAX_TYPE_SIZE) == 0) {
                block_itype |= IID_LOWBYTE;
            }
            else if (strncmp(optarg, "byte-pattern", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "bytepattern", MAX_TYPE_SIZE) == 0) {
                block_itype |= IID_PATTERN_BYTES;
            }
            else if (strncmp(optarg, "random", MAX_TYPE_SIZE) == 0 ||
                     strncmp(optarg, "randomized", MAX_TYPE_SIZE) == 0) {
                block_itype |= IID_RANDOM;
            }
            else {
                printf("Unknown IID type '%s' in block IID type filter.\n", optarg);
                exit(EXIT_FAILURE);
            }

            filter_f = TRUE;
            break;

        case 's': /* Generate IPv6 Address Statistics */
            stats_f = TRUE;
            break;

        case 'q': /* Block duplicate addresses */
        case 'Q': /* For backwards-compatibility */
            block_duplicate_f = TRUE;
            break;

        case 'p': /* Filter duplicate addresses on a per-prefix basis */
            if (block_duplicate_preflen_f) {
                puts("Error: Cannot specify multiple --block-dup-preflen options");
                exit(EXIT_FAILURE);
            }

            if ((pref = strtok_r(optarg, "/", &lasts)) == NULL) {
                puts("Error in '--block-dup-preflen' option");
                exit(EXIT_FAILURE);
            }

            if ((ul_res = strtoul(pref, &endptr, 10)) == ULONG_MAX) {
                perror("Error in '--block-dup-preflen' option");
                exit(EXIT_FAILURE);
            }

            if (endptr != pref) {
                dpreflen = ul_res;
                block_duplicate_preflen_f = TRUE;
            }
            else {
                puts("Error in '--block-dup-preflen' option");
                exit(EXIT_FAILURE);
            }

            break;

        case 'P': /* Generate unique prefixes of specified length */
            if (print_unique_preflen_f) {
                puts("Error: Cannot specify multiple --print-unique-preflen options");
                exit(EXIT_FAILURE);
            }

            if ((pref = strtok_r(optarg, "/", &lasts)) == NULL) {
                puts("Error in '--print-unique-preflen' option");
                exit(EXIT_FAILURE);
            }

            if ((ul_res = strtoul(pref, &endptr, 10)) == ULONG_MAX) {
                perror("Error in '--print-unique-preflen' option");
                exit(EXIT_FAILURE);
            }

            if (endptr != pref) {
                dpreflen = ul_res;
                print_unique_preflen_f = TRUE;
            }
            else {
                puts("Error in '--print-unique-preflen' option");
                exit(EXIT_FAILURE);
            }

            break;

        case 'x': /* Print pattern */
            pattern_f = 1;

            if (sscanf(optarg, "/%u:/%u:%u%%", &pstart, &pend, &pratio) == 3) {
                if (pstart % 8 != 0 || pend % 8 != 0) {
                    puts("Must specify range as /n1:/n2:p% where n1 and n2 are multiples of 8, and p is percentage");
                    exit(EXIT_FAILURE);
                }

                pstart = pstart / 8;

                if (pstart > 0)
                    pstart = pstart - 1;

                pend = pend / 8;

                if (pend > 0)
                    pend = pend - 1;
            }
            else if (sscanf(optarg, "%u:%u:%u%%", &pstart, &pend, &pratio) != 3) {
                puts("Must specify range as n1:n2:, where n1 and n2 are smaller than 16, and p is a percentage");
                exit(EXIT_FAILURE);
            }

            if (pstart >= pend || pstart > 15 || pend > 15) {
                puts("Inappropriate range for prefix analysis");
                exit(EXIT_FAILURE);
            }

            if (pratio <= 0 || pratio > 100) {
                puts("Error: percentage must be larger than 0 and smaller (or equal) to 100\n");
                exit(EXIT_FAILURE);
            }

            printf("N1: %u, N2: %u\n", pstart, pend);

            if ((ptable = malloc(16 * MAX_ADDR_PATTERN)) == NULL) {
                puts("Not enough memory");
                exit(EXIT_FAILURE);
            }

            if ((pcounter = malloc(sizeof(uint32_t) * MAX_ADDR_PATTERN)) == NULL) {
                puts("Not enough memory");
                exit(EXIT_FAILURE);
            }

            break;

        case 'R': /* Be verbose */
            response_f = TRUE;
            break;

        case 'v': /* Be verbose */
            verbose_f++;
            break;

        case 'h': /* Help */
            print_help();
            exit(EXIT_FAILURE);
            break;

        default:
            usage();
            exit(EXIT_FAILURE);
            break;

        } /* switch */
    } /* while(getopt) */

    /* Catch simultaneous use of incompatible addresses */

    if (stdin_f && addr_f) {
        puts("Cannot specify both '-a' and '-i' at the same time (try only one of them at a time)");
        exit(EXIT_FAILURE);
    }

    if (!stdin_f && !addr_f) {
        puts("Must specify an IPv6 address with '-a', or set '-i' to read addresses from stdin");
        exit(EXIT_FAILURE);
    }

    if (!stdin_f) {
        if (stats_f) {
            puts("Cannot obtain statistics based on a single IPv6 address (should be using '-i')");
            exit(EXIT_FAILURE);
        }
        else if (pattern_f) {
            puts("Cannot analyze pattern based on a single IPv6 address (should be using '-i')");
            exit(EXIT_FAILURE);
        }
    }

    if (block_duplicate_f && block_duplicate_preflen_f) {
        puts("Cannot employ --block-dup and --block-dup-preflen options simultaneously");
        exit(EXIT_FAILURE);
    }

    if (print_unique_preflen_f && (block_duplicate_f || block_duplicate_preflen_f)) {
        puts("Cannot employ --print-unique-preflen with --block-dup or --block-dup-preflen options simultaneously");
        exit(EXIT_FAILURE);
    }

    if (canonic_f && fixed_f) {
        puts("Cannot employ --print-canonic and --print-fixed simultaneously");
        exit(EXIT_FAILURE);
    }

    /* By default, addr6 decodes IPv6 addresses */
    if (!block_duplicate_f && !block_duplicate_preflen_f && !print_unique_preflen_f && !filter_f && !stats_f &&
        !canonic_f && !fixed_f && !reverse_f)
        decode_f = TRUE;

    if (block_duplicate_f || block_duplicate_preflen_f || print_unique_preflen_f) {
        if (!init_host_list(&hlist)) {
            puts("Not enough memory when initializing internal host list");
            exit(EXIT_FAILURE);
        }
    }

    if (stats_f) {
        memset(&stats, 0, sizeof(stats));
    }

    if (stdin_f) {
        while (fgets(line, MAX_LINE_SIZE, stdin) != NULL) {
            r = read_prefix(line, Strnlen(line, MAX_LINE_SIZE), &ptr);

            if (r == 1) {
                if (inet_pton(AF_INET6, ptr, &(addr.ip6)) <= 0) {
                    if (decode_f)
                        puts("Error: Invalid IPv6 address");

                    continue;
                }

                if (filter_f || decode_f || stats_f)
                    decode_ipv6_address(&addr);

                if (nblock) {
                    if (match_ipv6(block, blocklen, nblock, &(addr.ip6))) {
                        if (response_f)
                            puts("REJECT");

                        continue;
                    }
                }

                if (block_type || block_scope || block_itype || block_utype) {
                    if ((block_type & addr.type) || (block_utype & addr.subtype) || (block_scope & addr.scope) ||
                        (block_itype & addr.iidtype)) {
                        if (response_f)
                            puts("REJECT");

                        continue;
                    }
                }

                if (block_duplicate_f && is_ip6_in_hashed_list(&hlist, &(addr.ip6))) {
                    if (response_f)
                        puts("REJECT");

                    continue;
                }
                else if (block_duplicate_preflen_f || print_unique_preflen_f) {
                    dummyipv6 = addr.ip6;
                    sanitize_ipv6_prefix(&dummyipv6, dpreflen);

                    if (is_ip6_in_hashed_list(&hlist, &dummyipv6)) {
                        if (response_f)
                            puts("REJECT");

                        continue;
                    }
                }

                accepted_f = 0;

                if (naccept) {
                    if (match_ipv6(accept, acceptlen, naccept, &(addr.ip6)))
                        accepted_f = TRUE;
                }

                if (!accepted_f && (accept_type || accept_scope || accept_itype || accept_utype)) {
                    if ((accept_type & addr.type) || (accept_utype & addr.subtype) || (accept_scope & addr.scope) ||
                        (accept_itype & addr.iidtype))
                        accepted_f = TRUE;
                }

                if (acceptfilters_f && !accepted_f) {
                    if (response_f)
                        puts("REJECT");

                    continue;
                }
                /*
                   If we got here, and block_duplicate_f is TRUE, then this address is unique, and we must add it to
                   the hashed list.
                 */
                if (block_duplicate_f) {
                    if (add_hashed_host_entry(&hlist, &(addr.ip6)) == NULL) {
                        puts(
                            "Not enough memory (or hit internal artificial limit) when storing IPv6 address in memory");
                        exit(EXIT_FAILURE);
                    }
                }
                else if (block_duplicate_preflen_f || print_unique_preflen_f) {
                    dummyipv6 = addr.ip6;
                    sanitize_ipv6_prefix(&dummyipv6, dpreflen);

                    if (add_hashed_host_entry(&hlist, &dummyipv6) == NULL) {
                        puts(
                            "Not enough memory (or hit internal artificial limit) when storing IPv6 address in memory");
                        exit(EXIT_FAILURE);
                    }
                }

                if (filter_f && response_f) {
                    puts("ACCEPT");
                    continue;
                }

                if (stats_f) {
                    stat_ipv6_address(&addr, &stats);
                }
                else if (decode_f) {
                    print_dec_address_script(&addr);
                }
                else if (reverse_f) {
                    print_ipv6_address_rev(&(addr.ip6));
                }
                else if (pattern_f) {
                    /* XXX  */
                    /* Analyze address pattern */
                    if (caddr >= MAX_ADDR_PATTERN) {
                        puts("Too many addresses for pattern analysis. Filter them out in smaller subsets, and retry");
                        exit(EXIT_FAILURE);
                    }

                    *(ptable + caddr) = addr.ip6;

                    /*
                                                            puts("Direcciones hasta ahora");
                                                            for(i=0; i<=caddr; i++){
                                                                    if(inet_ntof(AF_INET6, ptable+caddr, pv6addr,
                       sizeof(pv6addr)) == NULL){ puts("inet_ntof(): Error converting IPv6 address to fixed presentation
                       format"); exit(EXIT_FAILURE);
                                                                    }

                                                                    printf("Address #%u: %s\n", i, pv6addr);
                                                            }

                                                            puts("");
                    */
                    /* Initialize counters for this address to 0 */
                    for (i = 0; i < 16; i++) {
                        *(pcounter + (caddr * 16) + i) = 0;
                    }

                    /* Compute differences in bytes */
                    for (naddr = 0; naddr < caddr; naddr++) {
                        for (j = 0; j < 4; j++) {
                            for (k = 0; k < 4; k++) {

                                /*printf("Comparo: %08x con %08x\n", (ntohl((ptable+naddr)->s6_addr32[j]) &
                                 * (0xff000000>>(k*8))) , (ntohl((ptable+caddr)->s6_addr32[j]) &
                                 * (0xff000000>>(k*8))));*/
                                if ((ntohl((ptable + naddr)->s6_addr32[j]) & (0xff000000 >> (k * 8))) !=
                                    (ntohl((ptable + caddr)->s6_addr32[j]) & (0xff000000 >> (k * 8)))) {
                                    /* If the bytes were different, increment counters for both addresses */
                                    (*(pcounter + (naddr * 16) + j * 4 + k))++;
                                    (*(pcounter + (caddr * 16) + j * 4 + k))++;
                                }
                            }
                        }
                    }

                    caddr++;
                }
                else {
                    if (print_unique_preflen_f) {
                        sanitize_ipv6_prefix(&(addr.ip6), dpreflen);
                        snprintf(prefstr, sizeof(prefstr), "/%u", (unsigned int)dpreflen);
                    }
                    else {
                        prefstr[0] = 0; /* zero-terminate the prefix string, since we don't need to print a prefix */
                    }

                    if (fixed_f) {
                        if (inet_ntof(AF_INET6, &(addr.ip6), pv6addr, sizeof(pv6addr)) == NULL) {
                            puts("inet_ntof(): Error converting IPv6 address to fixed presentation format");
                            exit(EXIT_FAILURE);
                        }
                    }
                    else {
                        if (inet_ntop(AF_INET6, &(addr.ip6), pv6addr, sizeof(pv6addr)) == NULL) {
                            puts("inet_ntop(): Error converting IPv6 address to fixed format");
                            exit(EXIT_FAILURE);
                        }
                    }

                    printf("%s%s\n", pv6addr, prefstr);
                }
            }
        }

        if (stats_f) {
            print_stats(&stats);
        }

        else if (pattern_f) {
            pthres = ((unsigned long)caddr * (100 - pratio)) / 100;

            for (i = 0; i < caddr; i++) {
                flag_f = 0;

                for (j = pstart; j <= pend; j++) {
                    if (*(pcounter + i * 16 + j) <= pthres) {
                        flag_f = 1;
                    }
                }

                /*
                        If flag is set to 1, we identified some pattern -- the search space can be reduced
                   We just need to avoid specifying the same range twice
                */

                duplicate_f = 0;

                if (flag_f == 1) {
                    /* We go around comparing the current address with al the previous ones */
                    for (j = 0; (j < i) && !duplicate_f; j++) {
                        for (k = pstart; k <= pend; k++) {
                            /* In order for prefix to be duplicate:
                               Both counters must be below threshold and be equal, or both must be or threshold
                             */

                            if (*(pcounter + i * 16 + k) <= pthres) {
                                if (*(pcounter + j * 16 + k) > pthres) {
                                    break;
                                }
                                else if ((ntohl((ptable + i)->s6_addr32[k / 4]) & (0xff000000 >> ((k % 4) * 8))) !=
                                         (ntohl((ptable + j)->s6_addr32[k / 4]) & (0xff000000 >> ((k % 4) * 8)))) {
                                    break;
                                }
                            }
                            else if (*(pcounter + j * 16 + k) <= pthres) {
                                break;
                            }
                        }

                        if (k > pend) {
                            duplicate_f = 1;
                        }
                    }

                    if (!duplicate_f) {
                        /* The address in 'i' is a unique range */
                        for (k = 0; k < 16; k++) {
                            if (*(pcounter + i * 16 + k) <= pthres) {
                                /* (ntohl((ptable+i)->s6_addr32[k/4]) & (0xff000000>>((k%4)*8))) >> ( (3 - (k%4)) * 8)
                                 */
                                printf("%02x%s",
                                       ((ntohl((ptable + i)->s6_addr32[k / 4]) & (0xff000000 >> ((k % 4) * 8))) >>
                                        ((3 - (k % 4)) * 8)),
                                       (k < 15) ? ";" : "\n");
                            }
                            else {
                                printf("0x00-0xff%s", (k < 15) ? ";" : "\n");
                            }
                        }
                    }
                }
            }

            /*
                                    for(i=0; i < caddr; i++){
                                            for(j=0; j<16; j++){
                                                    if(j==0){
                                                            printf("A%08x: ", i);
                                                    }
                                                    else if(j==8){
                                                            printf("\n           ");
                                                    }


                                                    printf("%08x ", *(pcounter + i * 16 + j));

                                                    if(j==15){
                                                            printf("\n\n");
                                                    }
                                            }
                                    }
            */

            puts("");
            for (i = 0; i < caddr; i++) {
                for (j = 0; j < 16; j++) {
                    if (j == 0) {
                        printf("A%08x: ", i);
                    }
                    else if (j == 8) {
                        printf("\n           ");
                    }

                    printf("%08x ", *(pcounter + i * 16 + j));

                    if (j == 15) {
                        printf("\n\n");
                    }
                }
            }
        }
    }
    else {
        if (filter_f || decode_f)
            decode_ipv6_address(&addr);

        if (nblock) {
            if (match_ipv6(block, blocklen, nblock, &(addr.ip6))) {
                if (response_f)
                    puts("REJECT");

                exit(EXIT_SUCCESS);
            }
        }

        if (block_type || block_scope || block_itype || block_utype) {
            if ((block_type & addr.type) || (block_utype & addr.subtype) || (block_scope & addr.scope) ||
                (block_itype & addr.iidtype)) {
                if (response_f)
                    puts("REJECT");

                exit(EXIT_SUCCESS);
            }
        }

        accepted_f = FALSE;

        if (naccept) {
            if (match_ipv6(accept, acceptlen, naccept, &(addr.ip6)))
                accepted_f = TRUE;
        }

        if (!accepted_f && (accept_type || accept_scope || accept_itype || accept_utype)) {
            if ((accept_type & addr.type) || (accept_utype & addr.subtype) || (accept_scope & addr.scope) ||
                (accept_itype & addr.iidtype))
                accepted_f = TRUE;
        }

        if (acceptfilters_f && !accepted_f) {
            if (response_f)
                puts("REJECT");

            exit(EXIT_SUCCESS);
        }

        if (filter_f && accepted_f) {
            puts("ACCEPT");
            exit(EXIT_SUCCESS);
        }

        if (print_unique_preflen_f) {
            sanitize_ipv6_prefix(&(addr.ip6), dpreflen);
            snprintf(prefstr, sizeof(prefstr), "/%u", (unsigned int)dpreflen);
        }
        else {
            prefstr[0] = 0; /* zero-terminate the prefix string, since we don't need to print a prefix */
        }

        if (decode_f) {
            print_dec_address_script(&addr);
        }
        else if (reverse_f) {
            if (print_ipv6_address_rev(&(addr.ip6)) != EXIT_SUCCESS)
                exit(EXIT_FAILURE);
        }
        else if (fixed_f) {
            if (inet_ntof(AF_INET6, &(addr.ip6), pv6addr, sizeof(pv6addr)) == NULL) {
                puts("inet_ntof(): Error converting IPv6 address to fixed presentation format");
                exit(EXIT_FAILURE);
            }

            printf("%s%s\n", pv6addr, prefstr);
        }
        else {
            if (inet_ntop(AF_INET6, &(addr.ip6), pv6addr, sizeof(pv6addr)) == NULL) {
                puts("inet_ntop(): Error converting IPv6 address to fixed format");
                exit(EXIT_FAILURE);
            }

            printf("%s%s\n", pv6addr, prefstr);
        }
    }

    exit(EXIT_SUCCESS);
}

/*
 * Function: stat_ipv6_address()
 *
 * Incorporate address in IPv6 address statistics
 */

void stat_ipv6_address(struct decode6 *addr, struct stats6 *stats) {
    (stats->total)++;

    switch (addr->type) {
    case IPV6_UNSPEC:
        (stats->ipv6unspecified)++;
        break;

    case IPV6_MULTICAST:
        (stats->ipv6multicast)++;

        switch (addr->subtype) {
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

        if (addr->subtype != MCAST_UNKNOWN) {
            switch (addr->scope) {
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

        switch (addr->subtype) {
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

        /* XXX: We used to leave out some address types. Now we include all
        if(addr->subtype==UCAST_GLOBAL || addr->subtype==UCAST_V4MAPPED || addr->subtype==UCAST_V4COMPAT || \
                addr->subtype==UCAST_LINKLOCAL || addr->subtype==UCAST_SITELOCAL || addr->subtype==UCAST_UNIQUELOCAL ||\
                addr->subtype == UCAST_6TO4){
         */

        switch (addr->iidtype) {
        case IID_MACDERIVED:
            (stats->iidmacderived)++;
            break;

        case IID_ISATAP:
            (stats->iidisatap)++;
            break;

        case IID_EMBEDDEDIPV4:
            switch (addr->iidsubtype) {
            case IID_EMBEDDEDIPV4_32:
                (stats->iidembeddedipv4_32)++;
                break;

            case IID_EMBEDDEDIPV4_64:
                (stats->iidembeddedipv4_64)++;
                break;
            }
            break;

        case IID_EMBEDDEDPORT:
            switch (addr->iidsubtype) {
            case IID_EMBEDDEDPORT:
                (stats->iidembeddedportfwd)++;
                break;

            case IID_EMBEDDEDPORTREV:
                (stats->iidembeddedportrev)++;
                break;
            }

            break;

        case IID_TEREDO:
            (stats->iidteredo)++;
            break;

        case IID_PATTERN_BYTES:
            (stats->iidpatternbytes)++;
            break;

        case IID_LOWBYTE:
            (stats->iidlowbyte)++;
            break;

        case IID_RANDOM:
            (stats->iidrandom)++;
            break;
        }

        break;
    }
}

/*
 * Function: print_dec_address_script()
 *
 * Print the IPv6 address decode obtained by decode_ipv6_address
 */

void print_dec_address_script(struct decode6 *addr) {
    unsigned int r;

    char *nullstring = "";
    char *unspecified = "unspecified";
    char iidsubtypebuffer[9];
    char *ipv6unspec = "unspecified";
    char *ipv6multicast = "multicast";
    char *ipv6unicast = "unicast";

    char *ucastloopback = "loopback";
    char *ucastv4mapped = "ipv4-mapped";
    char *ucastv4compat = "ipv4-compatible";
    char *ucastlinklocal = "link-local";
    char *ucastsitelocal = "site-local";
    char *ucastuniquelocal = "unique-local";
    char *ucast6to4 = "6to4";
    char *ucastteredo = "teredo";
    char *ucastglobal = "global";

    char *mcastpermanent = "permanent";
    char *mcastnonpermanent = "non-permanent";
    char *mcastinvalid = "invalid";
    char *mcastunicastbased = "unicast-based";
    char *mcastembedrp = "embedded-rp";
    char *mcastunknown = "unknown";

    char *iidmacderived = "ieee-derived";
    char *iidisatap = "isatap";
    char *iidmbeddedipv4 = "embedded-ipv4";
    char *iidembeddedport = "embedded-port";
    char *iidembeddedportfwd = "port-fwd";
    char *iidembeddedportrev = "port-rev";
    char *iidlowbyte = "low-byte";
    char *iidembeddedipv4_32 = "embedded-ipv4-32";
    char *iidembeddedipv4_64 = "embedded-ipv4-64";
    char *iidpatternbytes = "pattern-bytes";
    char *iidrandom = "randomized";
    char *iidteredo = "teredo";
    char *iidteredorfc4380 = "rfc4380";
    char *iidteredorfc5991 = "rfc5991";
    char *iidteredounknown = "unknown";

    char *scopereserved = "reserved";
    char *scopeinterface = "interface";
    char *scopelink = "link";
    char *scopeadmin = "admin";
    char *scopesite = "site";
    char *scopeorganization = "organization";
    char *scopeglobal = "global";
    char *scopeunassigned = "unassigned";
    char *scopeunspecified = "unspecified";

    char *type, *subtype, *scope, *iidtype, *iidsubtype;

    type = nullstring;
    subtype = nullstring;
    iidtype = nullstring;
    iidsubtype = nullstring;

    switch (addr->type) {
    case IPV6_UNSPEC:
        type = ipv6unspec;
        subtype = unspecified;
        iidtype = unspecified;
        iidsubtype = unspecified;
        break;

    case IPV6_UNICAST:
        type = ipv6unicast;
        iidtype = unspecified;
        iidsubtype = unspecified;

        switch (addr->subtype) {
        case UCAST_LOOPBACK:
            subtype = ucastloopback;
            iidtype = iidlowbyte;
            break;

        case UCAST_GLOBAL:
            subtype = ucastglobal;
            break;

        case UCAST_V4MAPPED:
            subtype = ucastv4mapped;
            break;

        case UCAST_V4COMPAT:
            subtype = ucastv4compat;
            break;

        case UCAST_LINKLOCAL:
            subtype = ucastlinklocal;
            break;

        case UCAST_SITELOCAL:
            subtype = ucastsitelocal;
            break;

        case UCAST_UNIQUELOCAL:
            subtype = ucastuniquelocal;
            break;

        case UCAST_6TO4:
            subtype = ucast6to4;
            break;

        case UCAST_TEREDO:
            subtype = ucastteredo;
            break;
        }

        if (addr->subtype == UCAST_GLOBAL || addr->subtype == UCAST_V4MAPPED || addr->subtype == UCAST_V4COMPAT ||
            addr->subtype == UCAST_LINKLOCAL || addr->subtype == UCAST_SITELOCAL ||
            addr->subtype == UCAST_UNIQUELOCAL || addr->subtype == UCAST_6TO4 || addr->subtype == UCAST_TEREDO) {

            switch (addr->iidtype) {
            case IID_MACDERIVED:
                iidtype = iidmacderived;
                iidsubtype = iidsubtypebuffer;

                r = snprintf(iidsubtypebuffer, sizeof(iidsubtypebuffer), "%02x-%02x-%02x",
                             (addr->iidsubtype >> 16 & 0xff), (addr->iidsubtype >> 8 & 0xff),
                             (addr->iidsubtype & 0xff));

                if (r == 8)
                    iidsubtype = iidsubtypebuffer;

                break;

            case IID_ISATAP:
                iidtype = iidisatap;
                break;

            case IID_EMBEDDEDIPV4:
                iidtype = iidmbeddedipv4;
                switch (addr->iidsubtype) {
                case IID_EMBEDDEDIPV4_32:
                    iidsubtype = iidembeddedipv4_32;
                    break;

                case IID_EMBEDDEDIPV4_64:
                    iidsubtype = iidembeddedipv4_64;
                    break;
                }

                break;

            case IID_EMBEDDEDPORT:
                iidtype = iidembeddedport;

                switch (addr->iidsubtype) {
                case IID_EMBEDDEDPORT:
                    iidsubtype = iidembeddedportfwd;
                    break;

                case IID_EMBEDDEDPORTREV:
                    iidsubtype = iidembeddedportrev;
                    break;
                }

                break;

            case IID_LOWBYTE:
                iidtype = iidlowbyte;
                break;

            case IID_PATTERN_BYTES:
                iidtype = iidpatternbytes;
                break;

            case IID_RANDOM:
                iidtype = iidrandom;
                break;

            case IID_TEREDO:
                iidtype = iidteredo;

                switch (addr->iidsubtype) {
                case IID_TEREDO_RFC4380:
                    iidsubtype = iidteredorfc4380;
                    break;

                case IID_TEREDO_RFC5991:
                    iidsubtype = iidteredorfc5991;
                    break;

                case IID_TEREDO_UNKNOWN:
                    iidsubtype = iidteredounknown;
                    break;
                }

                break;
            }
        }

        break;

    case IPV6_MULTICAST:
        type = ipv6multicast;
        iidtype = unspecified;
        iidsubtype = unspecified;

        switch (addr->subtype) {
        case MCAST_PERMANENT:
            subtype = mcastpermanent;
            break;

        case MCAST_NONPERMANENT:
            subtype = mcastnonpermanent;
            break;

        case MCAST_INVALID:
            subtype = mcastinvalid;
            break;

        case MCAST_UNICASTBASED:
            subtype = mcastunicastbased;
            break;

        case MCAST_EMBEDRP:
            subtype = mcastembedrp;
            break;

        case MCAST_UNKNOWN:
            subtype = mcastunknown;
            break;
        }
    }

    switch (addr->scope) {
    case SCOPE_RESERVED:
        scope = scopereserved;
        break;

    case SCOPE_INTERFACE:
        scope = scopeinterface;
        break;

    case SCOPE_LINK:
        scope = scopelink;
        break;

    case SCOPE_ADMIN:
        scope = scopeadmin;
        break;

    case SCOPE_SITE:
        scope = scopesite;
        break;

    case SCOPE_ORGANIZATION:
        scope = scopeorganization;
        break;

    case SCOPE_GLOBAL:
        scope = scopeglobal;
        break;

    case SCOPE_UNSPECIFIED:
        scope = scopeunspecified;
        break;

    default:
        scope = scopeunassigned;
        break;
    }

    printf("%s=%s=%s=%s=%s\n", type, subtype, scope, iidtype, iidsubtype);
}

/*
 * Function: usage()
 *
 * Prints the syntax of the addr6 tool
 */

void usage(void) { puts("usage: addr6 (-i | -a) [-c | -d | -r | -s | -q] [-v] [-h]"); }

/*
 * Function: print_help()
 *
 * Prints help information for the scan6 tool
 */

void print_help(void) {
    puts(SI6_TOOLKIT);
    puts("addr6: An IPv6 address analysis and conversion tool\n");
    usage();

    puts("\nOPTIONS:\n"
         "  --address, -a             IPv6 address to be decoded\n"
         "  --gen-addr, -A            Generate a randmized address for the specified prefix\n"
         "  --stdin, -i               Read IPv6 addresses from stdin (standard input)\n"
         "  --print-fixed, -f         Print addresses in expanded/fixed format\n"
         "  --print-canonic, -c       Print IPv6 addresses in canonic form\n"
         "  --print-reverse, -r       Print reversed IPv6 address\n"
         "  --print-decode, -d        Decode IPv6 addresses\n"
         "  --print-stats, -s         Print statistics about IPv6 addresses\n"
         "  --print-response, -R      Print result of address filters\n"
         "  --print-pattern, -x       Analyze addresses pattern\n"
         "  --print-uni-preflen, -P   Print unique prefixes of a specified length\n"
         "  --block-dup, -q           Discard duplicate IPv6 addresses\n"
         "  --block-dup-preflen, -p   Discard duplicate prefixes of specified length\n"
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
         " Programmed by Fernando Gont for SI6 Networks <https://www.si6networks.com>\n"
         " Please send any bug reports to <fgont@si6networks.com>\n");
}

/*
 * Function: init_host_list()
 *
 * Initilizes a host_list structure
 */

int init_host_list(struct hashed_host_list *hlist) {
    unsigned int i;

    memset(hlist, 0, sizeof(struct hashed_host_list));

    if ((hlist->host = malloc(MAX_LIST_ENTRIES * sizeof(struct hashed_host_entry *))) == NULL) {
        return (0);
    }

    for (i = 0; i < MAX_LIST_ENTRIES; i++)
        hlist->host[i] = NULL;

    hlist->nhosts = 0;
    hlist->maxhosts = MAX_HOST_ENTRIES;
    hlist->key_l = random();
    hlist->key_h = random();
    return (1);
}

/*
 * Function: key()
 *
 * Compute a key for accessing the hash-table of a hashed_host_list structure
 */

uint16_t key(struct hashed_host_list *hlist, struct in6_addr *ipv6) {
    return (((hlist->key_l ^ (uint16_t)(ntohl(ipv6->s6_addr32[0]) >> 16) ^
              (uint16_t)(ntohl(ipv6->s6_addr32[3]) & 0x0000ffff)) ^
             (hlist->key_h ^ (uint16_t)(ntohl(ipv6->s6_addr32[0]) >> 16) ^ (uint16_t)(ipv6->s6_addr32[3] >> 16))) %
            MAX_LIST_ENTRIES);
}

/*
 * Function: add_hashed_host_entry()
 *
 * Add a hashed_host_entry structure to the hash table
 */

struct hashed_host_entry *add_hashed_host_entry(struct hashed_host_list *hlist, struct in6_addr *ipv6) {
    struct hashed_host_entry *hentry, *ptr;
    uint16_t hkey;

    hkey = key(hlist, ipv6);

    if (hlist->nhosts >= hlist->maxhosts) {
        return (NULL);
    }

    if ((hentry = malloc(sizeof(struct hashed_host_entry))) == NULL) {
        return (NULL);
    }

    memset(hentry, 0, sizeof(struct hashed_host_entry));
    hentry->ip6 = *ipv6;
    hentry->next = NULL;

    if (hlist->host[hkey] == NULL) {
        /* First node in chain */
        hlist->host[hkey] = hentry;
        hentry->prev = NULL;
    }
    else {
        /* Find last node in list */
        for (ptr = hlist->host[hkey]; ptr->next != NULL; ptr = ptr->next)
            ;

        hentry->prev = ptr;
        ptr->next = hentry;
    }

    (hlist->nhosts)++;

    return (hentry);
}

/*
 * Function: is_ip6_in_hashed_list()
 *
 * Checks whether an IPv6 address is present in a host list.
 */

unsigned int is_ip6_in_hashed_list(struct hashed_host_list *hlist, struct in6_addr *target) {
    uint16_t ckey;
    struct hashed_host_entry *chentry;

    ckey = key(hlist, target);

    for (chentry = hlist->host[ckey]; chentry != NULL; chentry = chentry->next)
        if (is_eq_in6_addr(target, &(chentry->ip6)))
            return 1;

    return 0;
}

/*
 * Function: print_stats()
 *
 * Prints IPv6 address statistics
 */

void print_stats(struct stats6 *stats) {
    unsigned int totaliids = 0;
    puts("\n** IPv6 General Address Analysis **\n");
    printf("Total IPv6 addresses: %lu\n", stats->total);

    if (stats->total) {
        printf("Unicast:      %11lu (%6.2f%%)\tMulticast:    %11lu (%6.2f%%)\n", stats->ipv6unicast,
               ((float)(stats->ipv6unicast) / stats->total) * 100, stats->ipv6multicast,
               ((float)(stats->ipv6multicast) / stats->total) * 100);
        printf("Unspec.:      %11lu (%6.2f%%)\n\n", stats->ipv6unspecified,
               ((float)(stats->ipv6unspecified) / stats->total) * 100);
    }

    if (stats->ipv6unicast) {
        puts("** IPv6 Unicast Addresses **\n");
        printf("Loopback:     %11lu (%6.2f%%)\tIPv4-mapped:  %11lu (%6.2f%%)\n", stats->ucastloopback,
               ((float)(stats->ucastloopback) / stats->ipv6unicast) * 100, stats->ucastv4mapped,
               ((float)(stats->ucastv4mapped) / stats->ipv6unicast) * 100);

        printf("IPv4-compat.: %11lu (%6.2f%%)\tLink-local:   %11lu (%6.2f%%)\n", stats->ucastv4compat,
               ((float)(stats->ucastv4compat) / stats->ipv6unicast) * 100, stats->ucastlinklocal,
               ((float)(stats->ucastlinklocal) / stats->ipv6unicast) * 100);

        printf("Site-local:   %11lu (%6.2f%%)\tUnique-local: %11lu (%6.2f%%)\n", stats->ucastsitelocal,
               ((float)(stats->ucastsitelocal) / stats->ipv6unicast) * 100, stats->ucastuniquelocal,
               ((float)(stats->ucastuniquelocal) / stats->ipv6unicast) * 100);

        printf("6to4:         %11lu (%6.2f%%)\tTeredo:       %11lu (%6.2f%%)\n", stats->ucast6to4,
               ((float)(stats->ucast6to4) / stats->ipv6unicast) * 100, stats->ucastteredo,
               ((float)(stats->ucastteredo) / stats->ipv6unicast) * 100);

        printf("Global:       %11lu (%6.2f%%)\n\n", stats->ucastglobal,
               ((float)(stats->ucastglobal) / stats->ipv6unicast) * 100);
    }

    /*
       XXX: We usedto exclude some of the unicast address types. Now we use all
    totaliids= stats->ucastglobal + stats->ucastlinklocal + stats->ucastsitelocal + stats->ucastuniquelocal + \
               stats->ucast6to4;
     */

    totaliids = stats->ipv6unicast;

    if (totaliids) {
        puts("+ IPv6 Unicast Interface Identifiers +\n");

        printf("Total IIDs analyzed: %u\n", totaliids);
        printf("IEEE-based: %11lu (%6.2f%%)\tLow-byte:        %11lu (%6.2f%%)\n", stats->iidmacderived,
               ((float)(stats->iidmacderived) / totaliids) * 100, stats->iidlowbyte,
               ((float)(stats->iidlowbyte) / totaliids) * 100);

        printf("Embed-IPv4: %11lu (%6.2f%%)\tEmbed-IPv4 (64): %11lu (%6.2f%%)\n", stats->iidembeddedipv4_32,
               ((float)(stats->iidembeddedipv4_32) / totaliids) * 100, stats->iidembeddedipv4_64,
               ((float)(stats->iidembeddedipv4_64) / totaliids) * 100);

        printf("Embed-port: %11lu (%6.2f%%)\tEmbed-port (r):  %11lu (%6.2f%%)\n", stats->iidembeddedport,
               ((float)(stats->iidembeddedport) / totaliids) * 100, stats->iidembeddedportrev,
               ((float)(stats->iidembeddedportrev) / totaliids) * 100);

        printf("ISATAP:     %11lu (%6.2f%%)\tTeredo:          %11lu (%6.2f%%)\n", stats->iidisatap,
               ((float)(stats->iidisatap) / totaliids) * 100, stats->iidteredo,
               ((float)(stats->iidteredo) / totaliids) * 100);

        printf("Randomized: %11lu (%6.2f%%)\tByte-pattern:    %11lu (%6.2f%%)\n\n", stats->iidrandom,
               ((float)(stats->iidrandom) / totaliids) * 100, stats->iidpatternbytes,
               ((float)(stats->iidpatternbytes) / totaliids) * 100);
    }

    if (stats->ipv6multicast) {
        puts("** IPv6 Multicast Addresses **\n");
        puts("+ Multicast Address Types +");
        printf("Permanent:   %11lu (%.2f%%)\tNon-permanent  %11lu (%.2f%%)\n", stats->mcastpermanent,
               ((float)(stats->mcastpermanent) / stats->ipv6multicast) * 100, stats->mcastnonpermanent,
               ((float)(stats->mcastnonpermanent) / stats->ipv6multicast) * 100);

        printf("Invalid:     %11lu (%.2f%%)\tUnicast-based: %11lu (%.2f%%)\n", stats->mcastinvalid,
               ((float)(stats->mcastinvalid) / stats->ipv6multicast) * 100, stats->mcastunicastbased,
               ((float)(stats->mcastunicastbased) / stats->ipv6multicast) * 100);

        printf("Embedded-RP: %11lu (%.2f%%)\tUnknown:       %11lu (%.2f%%)\n\n", stats->mcastembedrp,
               ((float)(stats->mcastembedrp) / stats->ipv6multicast) * 100, stats->mcastunknown,
               ((float)(stats->mcastunknown) / stats->ipv6multicast) * 100);

        puts("+ Multicast Address Scopes +");

        printf("Reserved:    %11lu (%.2f%%)\tInterface:     %11lu (%.2f%%)\n", stats->mscopereserved,
               ((float)(stats->mscopereserved) / stats->ipv6multicast) * 100, stats->mscopeinterface,
               ((float)(stats->mscopeinterface) / stats->ipv6multicast) * 100);

        printf("Link:        %11lu (%.2f%%)\tAdmin:         %11lu (%.2f%%)\n", stats->mnscopelink,
               ((float)(stats->mnscopelink) / stats->ipv6multicast) * 100, stats->mscopeadmin,
               ((float)(stats->mscopeadmin) / stats->ipv6multicast) * 100);

        printf("Site:        %11lu (%.2f%%)\tOrganization:  %11lu (%.2f%%)\n", stats->mscopesite,
               ((float)(stats->mscopesite) / stats->ipv6multicast) * 100, stats->mscopeorganization,
               ((float)(stats->mscopeorganization) / stats->ipv6multicast) * 100);

        printf("Global:      %11lu (%.2f%%)\tUnassigned:    %11lu (%.2f%%)\n\n", stats->mscopeadmin,
               ((float)(stats->mscopeadmin) / stats->ipv6multicast) * 100, stats->mscopesite,
               ((float)(stats->mscopesite) / stats->ipv6multicast) * 100);
    }
}
