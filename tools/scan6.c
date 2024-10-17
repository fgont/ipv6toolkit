/*
 * scan6: An IPv6 Scanning Tool
 *
 * Copyright (C) 2011-2020 Fernando Gont <fgont@si6networks.com>
 *
 * Programmed by Fernando Gont for SI6 Networks <https://www.si6networks.com>
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

#include <sys/param.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <pcap.h>

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ipv6toolkit.h"
#include "libipv6.h"
#include "scan6.h"

/* #define DEBUG */

/* Function prototypes */
void init_packet_data(struct iface_data *);
int create_candidate_globals(struct iface_data *, struct host_list *, struct host_list *, struct host_list *);
int find_local_globals(pcap_t *, struct iface_data *, unsigned char, const char *, struct host_list *);
void free_host_entries(struct host_list *);
int host_scan_local(pcap_t *, struct iface_data *, struct in6_addr *, unsigned char, struct host_entry *);
int multi_scan_local(pcap_t *, struct iface_data *, struct in6_addr *, unsigned char, const char *, struct host_list *);
void print_help(void);
void print_port_entries(struct port_list *);
int print_host_entries(struct host_list *, unsigned char);
int print_unique_host_entries(struct host_list *, unsigned char);
void local_sig_alarm(int);
void usage(void);
int validate_host_entries(pcap_t *, struct iface_data *, struct host_list *, struct host_list *);

int probe_node_nd(const char *, struct ether_addr *, struct in6_addr *, struct in6_addr *, struct ether_addr *);
int process_icmp6_response(struct iface_data *, struct host_list *, unsigned char, struct pcap_pkthdr *, const u_char *,
                           unsigned char *);
int valid_icmp6_response(struct iface_data *, unsigned char, struct pcap_pkthdr *, const u_char *, unsigned char *);
int valid_icmp6_response_remote(struct iface_data *, struct scan_list *, unsigned char, struct pcap_pkthdr *,
                                const u_char *, unsigned char *);
int print_scan_entries(struct scan_list *);
int load_ipv4mapped32_entries(struct scan_list *, struct scan_entry *, struct prefix4_entry *);
int load_ipv4mapped64_entries(struct scan_list *, struct scan_entry *, struct prefix4_entry *);
int load_embeddedport_entries(struct scan_list *, struct scan_entry *);
int load_lowbyte_entries(struct scan_list *, struct scan_entry *);
int load_oui_entries(struct scan_list *, struct scan_entry *, struct ether_addr *);
int load_port_table(struct port_table_entry *, char *, unsigned int);
int load_top_ports_entries(struct port_list *, struct port_list *, uint8_t, unsigned int);
int load_vm_entries(struct scan_list *, struct scan_entry *, struct prefix4_entry *);
int load_vendor_entries(struct scan_list *, struct scan_entry *, char *);
int load_knownprefix_entries(struct scan_list *, struct scan_list *, FILE *);
int load_knowniid_entries(struct scan_list *, struct scan_list *, struct prefix_list *);
int load_knowniidfile_entries(struct scan_list *, struct scan_list *, FILE *);
int load_smart_entries(struct scan_list *, struct scan_list *);
int match_strings(char *, char *);
int load_bruteforce_entries(struct scan_list *, struct scan_entry *);
void prefix_to_scan(struct prefix_entry *, struct scan_entry *);
void print_port_entries(struct port_list *);
void print_port_scan(struct port_list *, unsigned int *, int);
void print_port_table(struct port_table_entry *, unsigned int);
int get_next_target(struct scan_list *);

int get_next_port(struct port_list *);
int is_port_in_range(struct port_list *);
int is_target_in_range(struct scan_list *);
int send_probe_remote(struct iface_data *, struct scan_list *, struct in6_addr *, unsigned char);
int send_pscan_probe(struct iface_data *, struct scan_list *, struct port_list *, struct in6_addr *, unsigned char);
void reset_scan_list(struct scan_list *);
void reset_port_list(struct port_list *);
int process_config_file(const char *);
int is_ip6_in_scan_list(struct scan_list *, struct in6_addr *);
int add_to_scan_list(struct scan_list *, struct scan_entry *);
int is_scan_entry_duplicate(struct scan_list *, struct scan_entry *);

/* Used for multiscan */
struct host_list host_local, host_global, host_candidate;
struct host_entry *host_locals[MAX_IPV6_ENTRIES], *host_globals[MAX_IPV6_ENTRIES];
struct host_entry *host_candidates[MAX_IPV6_ENTRIES];

/* Used for router discovery */
struct iface_data idata;

/* Variables used for learning the default router */
struct ether_addr router_ether, rs_ether;
struct in6_addr router_ipv6, rs_ipv6;

struct in6_addr randprefix;
unsigned char randpreflen;

/* Data structures for packets read from the wire */
struct pcap_pkthdr *pkthdr;
const u_char *pktdata;
unsigned char *pkt_end;
struct ether_header *pkt_ether;
struct ip6_hdr *pkt_ipv6;
struct in6_addr *pkt_ipv6addr;
unsigned int pktbytes;
struct icmp6_hdr *pkt_icmp6;
struct nd_neighbor_solicit *pkt_ns;
struct tcp_hdr *pkt_tcp;
struct udp_hdr *pkt_udp;
struct ip6_eh *pkt_eh;
int result;
unsigned char error_f;

bpf_u_int32 my_netmask;
bpf_u_int32 my_ip;
struct bpf_program pcap_filter;
char dev[64], errbuf[PCAP_ERRBUF_SIZE];
unsigned char buffer[PACKET_BUFFER_SIZE], buffrh[MIN_IPV6_HLEN + MIN_TCP_HLEN];
char line[LINE_BUFFER_SIZE];
unsigned char *v6buffer, *ptr, *startofprefixes;
char *pref;

struct ip6_hdr *ipv6;
struct icmp6_hdr *icmp6;

struct ether_header *ethernet;
unsigned int ndst = 0;

char *lasts, *rpref;
char *charptr;

int nw;
unsigned long ul_res, ul_val;
unsigned int i, j, startrand;
unsigned int skip;
unsigned char dstpreflen;

uint16_t mask;
uint8_t hoplimit;

char plinkaddr[ETHER_ADDR_PLEN], pv4addr[INET_ADDRSTRLEN];
char psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN], pv6addr[INET6_ADDRSTRLEN];
unsigned char verbose_f = FALSE;
unsigned char rand_src_f = FALSE, rand_link_src_f = FALSE;
unsigned char accepted_f = FALSE, configfile_f = FALSE, dstaddr_f = FALSE, hdstaddr_f = FALSE, dstprefix_f = FALSE;
unsigned char print_f = FALSE, print_local_f = FALSE, print_global_f = FALSE, probe_echo_f = FALSE,
              probe_unrec_f = FALSE, probe_f = FALSE;
unsigned char print_type = NOT_PRINT_ETHER_ADDR, scan_local_f = FALSE, print_unique_f = FALSE, localaddr_f = FALSE;
unsigned char timestamps_f = FALSE;

/* Support for Extension Headers */
unsigned int dstopthdrs, dstoptuhdrs, hbhopthdrs;
char hbhopthdr_f = FALSE, dstoptuhdr_f = FALSE, dstopthdr_f = FALSE;
unsigned char *dstopthdr[MAX_DST_OPT_HDR], *dstoptuhdr[MAX_DST_OPT_U_HDR];
unsigned char *hbhopthdr[MAX_HBH_OPT_HDR];
unsigned int dstopthdrlen[MAX_DST_OPT_HDR], dstoptuhdrlen[MAX_DST_OPT_U_HDR];
unsigned int hbhopthdrlen[MAX_HBH_OPT_HDR], m, pad;

struct ip6_frag fraghdr, *fh;
struct ip6_hdr *fipv6;

unsigned char fragbuffer[FRAG_BUFFER_SIZE];
unsigned char *fragpart, *fptr, *fptrend, *ptrend, *ptrhdr, *ptrhdrend;
unsigned int hdrlen, ndstopthdr = 0, nhbhopthdr = 0, ndstoptuhdr = 0;
unsigned int nfrags, fragsize;
unsigned char *prev_nh, *startoffragment;

/* Remote scans */
unsigned int inc = 1;
int ranges;
struct scan_list scan_list;
struct scan_entry *target_list[MAX_SCAN_ENTRIES];
struct scan_list prefix_list, smart_list;

struct scan_entry *tgt_pref_list[MAX_PREF_ENTRIES];
struct scan_entry *smrt_pref_list[MAX_PREF_ENTRIES];
struct prefix_list iid_list;
struct prefix_entry *tgt_iid_list[MAX_IID_ENTRIES];
struct port_list tcp_port_list, udp_port_list, *port_list;

/* These tables maintain the port ranges to scan */
struct port_entry *tcp_prt_list[MAX_PORT_ENTRIES];
struct port_entry *udp_prt_list[MAX_PORT_ENTRIES];

/* These two tables maintain the port -> service name mappings */
struct port_table_entry tcp_port_table[MAX_PORT_RANGE];
struct port_table_entry udp_port_table[MAX_PORT_RANGE];

/* These arrays maintain the port scan results for a single node */
unsigned int *port_results, tcp_results[MAX_PORT_RANGE], udp_results[MAX_PORT_RANGE];

/* Load top ports */
unsigned char loadalltopports_f = FALSE, loadtcptopports_f = FALSE, loadudptopports_f = FALSE;
unsigned int nalltopports, ntcptopports, nudptopports;
uint8_t cprotocol;

uint16_t portscanl, portscanh, portscanp, portscantemp;
unsigned char dst_f = FALSE, tgt_ipv4mapped32_f = FALSE, tgt_ipv4mapped64_f = FALSE, tgt_lowbyte_f = FALSE,
              tgt_oui_f = FALSE;
unsigned char tgt_vendor_f = FALSE, tgt_vm_f = FALSE, tgt_bruteforce_f = FALSE, tgt_range_f = FALSE,
              tgt_portembedded_f = FALSE;
unsigned char tgt_knowniids_f = FALSE, tgt_knowniidsfile_f = FALSE, knownprefixes_f = FALSE;
unsigned char vm_vbox_f = FALSE, vm_vmware_f = FALSE, vm_vmware_esx_f = FALSE, vm_vmware_vsphere_f = FALSE,
              vm_vmwarem_f = FALSE, v4hostaddr_f = FALSE;
unsigned char v4hostprefix_f = FALSE, sort_ouis_f = FALSE, rnd_probes_f = FALSE, inc_f = FALSE, end_f = FALSE,
              endpscan_f = FALSE;
unsigned char donesending_f = FALSE, nomoreaddr_f = FALSE;
unsigned char onlink_f = FALSE, pps_f = FALSE, bps_f = FALSE, tcpflags_f = FALSE, rhbytes_f = FALSE, srcport_f = FALSE,
              dstport_f = FALSE, probetype;
unsigned char loop_f = FALSE, sleep_f = FALSE, smart_f = FALSE, portscan_f = FALSE, droppacket_f = FALSE, pscantype;
uint16_t srcport, dstport;
uint8_t tcpflags = 0;
unsigned long pktinterval, rate;
unsigned int packetsize, rhbytes;
struct prefix4_entry v4host;
struct prefix_entry prefix;
struct ether_addr oui;
char *charstart, *charend, *lastcolon;
char rangestart[MAX_RANGE_STR_LEN + 1], rangeend[MAX_RANGE_STR_LEN + 1];
char fname[MAX_FILENAME_SIZE], fname_f = FALSE, configfile[MAX_FILENAME_SIZE], knowniidsfile[MAX_FILENAME_SIZE];
char portsfname[MAX_FILENAME_SIZE], portsfname_f = FALSE, topportsfname[MAX_FILENAME_SIZE], topportsfname_f = FALSE;
char knownprefixesfile[MAX_FILENAME_SIZE];
FILE *knowniids_fp, *knownprefixes_fp;
char *oui_end = ":00:00:00";
char oui_ascii[ETHER_ADDR_PLEN];
char vendor[MAX_IEEE_OUIS_LINE_SIZE];
unsigned int nsleep;
int sel;
fd_set sset, rset, wset, eset;
struct timeval curtime, pcurtime, lastprobe;
struct tm pcurtimetm;
uint16_t service_ports_hex[] = {0x21,   0x22,   0x23,   0x25,   0x49,   0x53,   0x80,  0x110,
                                0x123,  0x179,  0x220,  0x389,  0x443,  0x547,  0x993, 0x995,
                                0x1194, 0x3306, 0x5060, 0x5061, 0x5432, 0x6446, 0x8080};
uint16_t service_ports_dec[] = {21,  22,  23,  25,  49,   53,   80,   110,  123,  179,  220, 389,
                                443, 547, 993, 995, 1194, 3306, 5060, 5061, 5432, 6446, 8080};

/* IPv6 Address Resolution */
static sigjmp_buf env;
static unsigned int canjump;

int main(int argc, char **argv) {
    extern char *optarg;
    int r;
    struct addrinfo hints, *res, *aiptr;
    struct target_ipv6 target;
    struct timeval timeout;
    char date[DATE_STR_LEN], *endptr;
    uint8_t ulhtype;
    struct scan_entry dummy;

    static struct option longopts[] = {{"interface", required_argument, 0, 'i'},
                                       {"src-addr", required_argument, 0, 's'},
                                       {"dst-addr", required_argument, 0, 'd'},
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
                                       {"port-scan", required_argument, 0, 'j'},
                                       {"tcp-scan-type", required_argument, 0, 'G'},
                                       {"print-unique", no_argument, 0, 'q'},
                                       {"print-link-addr", no_argument, 0, 'e'},
                                       {"print-timestamp", no_argument, 0, 't'},
                                       {"retrans", required_argument, 0, 'x'},
                                       {"timeout", required_argument, 0, 'O'},
                                       {"rand-src-addr", no_argument, 0, 'f'},
                                       {"rand-link-src-addr", no_argument, 0, 'F'},
                                       {"smart", no_argument, 0, 'A'},
                                       {"tgt-virtual-machines", required_argument, 0, 'V'},
                                       {"tgt-low-byte", no_argument, 0, 'b'},
                                       {"tgt-ipv4", required_argument, 0, 'B'},
                                       {"tgt-port", no_argument, 0, 'g'},
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
                                       {"help", no_argument, 0, 'h'},
                                       {0, 0, 0, 0}};

    const char shortopts[] = "i:s:d:u:U:H:y:S:D:Lp:Z:o:a:X:P:j:G:qetx:O:fFV:bB:gk:K:w:W:m:Q:TNI:r:lz:c:vh";

    char option;

    if (argc <= 1) {
        usage();
        exit(EXIT_FAILURE);
    }

    srandom(time(NULL));
    hoplimit = 64 + random() % 180;

    init_iface_data(&idata);

    /* Initialize the scan_list structure (for remote scans) */
    scan_list.target = target_list;
    scan_list.ntarget = 0;
    scan_list.ctarget = 0;
    scan_list.maxtarget = MAX_SCAN_ENTRIES;

    /* Initialize the prefix_list structure (for remote scans) */
    prefix_list.target = tgt_pref_list;
    prefix_list.ntarget = 0;
    prefix_list.ctarget = 0;
    prefix_list.maxtarget = MAX_PREF_ENTRIES;

    /* Initialize the smart_list structure (for remote scans) */
    smart_list.target = smrt_pref_list;
    smart_list.ntarget = 0;
    smart_list.ctarget = 0;
    smart_list.maxtarget = MAX_PREF_ENTRIES;

    /* Initialize the TCP port struture (for port scans) */
    tcp_port_list.port = tcp_prt_list;
    tcp_port_list.nport = 0;
    tcp_port_list.cport = 0;
    tcp_port_list.proto = IPPROTO_TCP;
    tcp_port_list.maxport = MAX_PORT_ENTRIES;

    /* Initialize the UDP port struture (for port scans) */
    udp_port_list.port = udp_prt_list;
    udp_port_list.nport = 0;
    udp_port_list.cport = 0;
    udp_port_list.proto = IPPROTO_UDP;
    udp_port_list.maxport = MAX_PORT_ENTRIES;

    /* Initialize the iid_list structure (for remote scans/tracking) */
    iid_list.prefix = tgt_iid_list;
    iid_list.nprefix = 0;
    iid_list.maxprefix = MAX_IID_ENTRIES;

    while ((r = getopt_long(argc, argv, shortopts, longopts, NULL)) != -1) {
        option = r;

        switch (option) {
        case 'i': /* Interface */
            strncpy(idata.iface, optarg, IFACE_LENGTH);
            idata.iface[IFACE_LENGTH - 1] = 0;
            idata.ifindex = if_nametoindex(idata.iface);
            idata.iface_f = TRUE;
            break;

        case 's': /* IPv6 Source Address */
            if ((charptr = strtok_r(optarg, "/", &lasts)) == NULL) {
                puts("Error in Source Address");
                exit(EXIT_FAILURE);
            }

            if (inet_pton(AF_INET6, charptr, &idata.srcaddr) <= 0) {
                puts("inet_pton(): Source Address not valid");
                exit(EXIT_FAILURE);
            }

            idata.srcaddr_f = TRUE;

            if ((charptr = strtok_r(NULL, " ", &lasts)) != NULL) {
                idata.srcpreflen = atoi(charptr);

                if (idata.srcpreflen > 128) {
                    puts("Prefix length error in IPv6 Source Address");
                    exit(EXIT_FAILURE);
                }

                sanitize_ipv6_prefix(&(idata.srcaddr), idata.srcpreflen);
                idata.srcprefix_f = TRUE;
            }

            break;

        case 'd': /* IPv6 Destination Address/Prefix */
            if (!address_contains_colons(optarg)) {
                /* The '-d' option contains a domain name */
                if ((charptr = strtok_r(optarg, "/", &lasts)) == NULL) {
                    puts("Error in Destination Address");
                    exit(EXIT_FAILURE);
                }

                strncpy(target.name, charptr, NI_MAXHOST);
                target.name[NI_MAXHOST - 1] = 0;

                if ((charptr = strtok_r(NULL, " ", &lasts)) != NULL) {
                    prefix.len = atoi(charptr);

                    if (prefix.len > 128) {
                        puts("Prefix length error in IPv6 Destination Address");
                        exit(EXIT_FAILURE);
                    }
                }
                else {
                    prefix.len = 128;
                }

                memset(&hints, 0, sizeof(hints));
                hints.ai_family = AF_INET6;
                hints.ai_canonname = NULL;
                hints.ai_addr = NULL;
                hints.ai_next = NULL;
                hints.ai_socktype = SOCK_DGRAM;

                if ((target.res = getaddrinfo(target.name, NULL, &hints, &res)) != 0) {
                    printf("Unknown Destination '%s': %s\n", target.name, gai_strerror(target.res));
                    exit(EXIT_FAILURE);
                }

                for (aiptr = res; aiptr != NULL; aiptr = aiptr->ai_next) {
                    if (aiptr->ai_family != AF_INET6)
                        continue;

                    if (aiptr->ai_addrlen != sizeof(struct sockaddr_in6))
                        continue;

                    if (aiptr->ai_addr == NULL)
                        continue;

                    prefix.ip6 = ((struct sockaddr_in6 *)aiptr->ai_addr)->sin6_addr;

                    /*
                       If the prefix length is 64 bits (either implicitly or explicitly), we perform a smart scan
                     */

                    if (smart_f || (prefix.len == 64 && !is_iid_null(&(prefix.ip6), 64))) {
                        if (smart_list.ntarget <= smart_list.maxtarget) {
                            if ((smart_list.target[smart_list.ntarget] = malloc(sizeof(struct scan_entry))) == NULL) {
                                if (idata.verbose_f)
                                    puts("scan6: Not enough memory");

                                exit(EXIT_FAILURE);
                            }

                            prefix_to_scan(&prefix, smart_list.target[smart_list.ntarget]);

                            if (IN6_IS_ADDR_MULTICAST(&(smart_list.target[smart_list.ntarget]->start.in6_addr))) {
                                if (idata.verbose_f)
                                    puts("scan6: Remote scan cannot target a multicast address");

                                exit(EXIT_FAILURE);
                            }

                            if (IN6_IS_ADDR_MULTICAST(&(smart_list.target[smart_list.ntarget]->end.in6_addr))) {
                                if (idata.verbose_f)
                                    puts("scan6: Remote scan cannot target a multicast address");

                                exit(EXIT_FAILURE);
                            }

                            idata.dstaddr = smart_list.target[smart_list.ntarget]->start.in6_addr;
                            smart_list.ntarget++;
                        }
                        else {
                            /*
                               If the number of "targets" has already been exceeded, it doesn't make sense to continue
                               further, since there wouldn't be space for any specific target types
                             */
                            if (idata.verbose_f)
                                puts("Too many targets!");

                            exit(EXIT_FAILURE);
                        }
                    }
                    else {
                        sanitize_ipv6_prefix(&(prefix.ip6), prefix.len);

                        if (prefix_list.ntarget <= prefix_list.maxtarget) {
                            if ((prefix_list.target[prefix_list.ntarget] = malloc(sizeof(struct scan_entry))) == NULL) {
                                if (idata.verbose_f)
                                    puts("scan6: Not enough memory");

                                exit(EXIT_FAILURE);
                            }

                            prefix_to_scan(&prefix, prefix_list.target[prefix_list.ntarget]);

                            if (IN6_IS_ADDR_MULTICAST(&(prefix_list.target[prefix_list.ntarget]->start.in6_addr))) {
                                if (idata.verbose_f)
                                    puts("scan6: Remote scan cannot target a multicast address");

                                exit(EXIT_FAILURE);
                            }

                            if (IN6_IS_ADDR_MULTICAST(&(prefix_list.target[prefix_list.ntarget]->end.in6_addr))) {
                                if (idata.verbose_f)
                                    puts("scan6: Remote scan cannot target a multicast address");

                                exit(EXIT_FAILURE);
                            }

                            idata.dstaddr = prefix_list.target[prefix_list.ntarget]->start.in6_addr;
                            prefix_list.ntarget++;
                        }
                        else {
                            /*
                               If the number of "targets" has already been exceeded, it doesn't make sense to continue
                               further, since there wouldn't be space for any specific target types
                             */
                            if (idata.verbose_f)
                                puts("Too many targets!");

                            exit(EXIT_FAILURE);
                        }
                    }
                }

                freeaddrinfo(res);
            }
            else if ((ranges = address_contains_ranges(optarg)) == 1) {
                /*
                   When an address range is specified, such address range is scanned, but the correspnding prefix is
                   also employed for generating additional addresses to be scanned (EUI-64 based, etc.)
                 */
                charptr = optarg;
                charstart = rangestart;
                charend = rangeend;
                lastcolon = charend;

                while (*charptr && (optarg - charptr) <= MAX_RANGE_STR_LEN) {
                    if (*charptr != '-') {
                        /* If we do not find a dash, just copy this 16-bit word to both the range start and the range
                         * end */
                        *charstart = *charptr;
                        *charend = *charptr;
                        charstart++;
                        charend++;

                        /*
                            Record the address of the byte following the colon (in the range end), so that we know what
                           to "overwrite when we find a "range
                         */
                        if (*charptr == ':')
                            lastcolon = charend;

                        charptr++;
                    }
                    else {
                        /* If we found a dash, we must "overwrite" the range end with what follows the dash */
                        charend = lastcolon;
                        charptr++;

                        while (*charptr && (optarg - charptr) <= MAX_RANGE_STR_LEN && *charptr != ':' &&
                               *charptr != '-') {
                            *charend = *charptr;
                            charend++;
                            charptr++;
                        }
                    }
                }

                /* Zero-terminate the strings that we have generated from the option arguments */
                *charstart = 0;
                *charend = 0;
                tgt_range_f = TRUE;

                if (scan_list.ntarget <= scan_list.maxtarget) {
                    if (inet_pton(AF_INET6, rangestart, &(dummy.start.in6_addr)) <= 0) {
                        if (idata.verbose_f > 1)
                            puts("inet_pton(): Error converting IPv6 address from presentation to network format");

                        exit(EXIT_FAILURE);
                    }

                    if (inet_pton(AF_INET6, rangeend, &(dummy.end.in6_addr)) <= 0) {
                        if (idata.verbose_f > 1)
                            puts("inet_pton(): Error converting IPv6 address from presentation to network format");

                        exit(EXIT_FAILURE);
                    }

                    dummy.cur.in6_addr = dummy.start.in6_addr;

                    /* Check whether the start address is smaller than the end address */
                    for (i = 0; i < 7; i++)
                        if (ntohs(dummy.start.s6addr16[i]) > ntohs(dummy.end.s6addr16[i])) {
                            if (idata.verbose_f)
                                puts("Error in Destination Address range: Start address larger than end address!");

                            exit(EXIT_FAILURE);
                        }

                    if (IN6_IS_ADDR_MULTICAST(&(dummy.start.in6_addr))) {
                        if (idata.verbose_f)
                            puts("scan6: Remote scan cannot target a multicast address");

                        exit(EXIT_FAILURE);
                    }

                    if (IN6_IS_ADDR_MULTICAST(&(dummy.end.in6_addr))) {
                        if (idata.verbose_f)
                            puts("scan6: Remote scan cannot target a multicast address");

                        exit(EXIT_FAILURE);
                    }

                    idata.dstaddr = dummy.start.in6_addr;
                    if (add_to_scan_list(&scan_list, &dummy) == FALSE) {
                        if (idata.verbose_f)
                            puts("Couldn't add entry to scan list");

                        exit(EXIT_FAILURE);
                    }
                }
                else {
                    /*
                       If the number of "targets" has already been exceeded, it doesn't make sense to continue further,
                       since there wouldn't be space for any specific target types
                     */
                    if (idata.verbose_f)
                        puts("Too many targets!");

                    exit(EXIT_FAILURE);
                }

                if (prefix_list.ntarget <= prefix_list.maxtarget) {
                    if ((prefix_list.target[prefix_list.ntarget] = malloc(sizeof(struct scan_entry))) == NULL) {
                        if (idata.verbose_f)
                            puts("scan6: Not enough memory");

                        exit(EXIT_FAILURE);
                    }

                    /* Copy the recently added target to our prefix list */
                    *prefix_list.target[prefix_list.ntarget] = dummy;
                    prefix_list.ntarget++;
                }
                else {
                    /*
                       If the number of "targets" has already been exceeded, it doesn't make sense to continue further,
                       since there wouldn't be space for any specific target types
                     */
                    if (idata.verbose_f)
                        puts("Too many targets!");

                    exit(EXIT_FAILURE);
                }
            }
            else if (ranges == 0) {
                /* The '-d' option contains a prefix with the slash notation */
                if ((charptr = strtok_r(optarg, "/", &lasts)) == NULL) {
                    puts("Error in Destination Address");
                    exit(EXIT_FAILURE);
                }

                if (inet_pton(AF_INET6, charptr, &(prefix.ip6)) <= 0) {
                    puts("inet_pton(): Destination Address not valid");
                    exit(EXIT_FAILURE);
                }

                if ((charptr = strtok_r(NULL, " ", &lasts)) != NULL) {
                    prefix.len = atoi(charptr);

                    if (prefix.len > 128) {
                        puts("Prefix length error in IPv6 Destination Address");
                        exit(EXIT_FAILURE);
                    }

                    sanitize_ipv6_prefix(&(prefix.ip6), prefix.len);
                }
                else {
                    prefix.len = 128;
                }

                /* If the Prefix length is /128 (explicitly set, or by omission), we do a smart scan */
                if (smart_f || (prefix.len == 64 && !is_iid_null(&(prefix.ip6), 64))) {
                    if (smart_list.ntarget <= smart_list.maxtarget) {
                        if ((smart_list.target[smart_list.ntarget] = malloc(sizeof(struct scan_entry))) == NULL) {
                            if (idata.verbose_f)
                                puts("scan6: Not enough memory");

                            exit(EXIT_FAILURE);
                        }

                        prefix_to_scan(&prefix, smart_list.target[smart_list.ntarget]);

                        if (IN6_IS_ADDR_MULTICAST(&(smart_list.target[smart_list.ntarget]->start.in6_addr))) {
                            if (idata.verbose_f)
                                puts("scan6: Remote scan cannot target a multicast address");

                            exit(EXIT_FAILURE);
                        }

                        if (IN6_IS_ADDR_MULTICAST(&(smart_list.target[smart_list.ntarget]->end.in6_addr))) {
                            if (idata.verbose_f)
                                puts("scan6: Remote scan cannot target a multicast address");

                            exit(EXIT_FAILURE);
                        }

                        idata.dstaddr = smart_list.target[smart_list.ntarget]->start.in6_addr;
                        smart_list.ntarget++;
                    }
                    else {
                        /*
                           If the number of "targets" has already been exceeded, it doesn't make sense to continue
                           further, since there wouldn't be space for any specific target types
                         */
                        if (idata.verbose_f)
                            puts("Too many targets!");

                        exit(EXIT_FAILURE);
                    }
                }
                else {
                    if (prefix_list.ntarget <= prefix_list.maxtarget) {
                        if ((prefix_list.target[prefix_list.ntarget] = malloc(sizeof(struct scan_entry))) == NULL) {
                            if (idata.verbose_f)
                                puts("scan6: Not enough memory");

                            exit(EXIT_FAILURE);
                        }

                        prefix_to_scan(&prefix, prefix_list.target[prefix_list.ntarget]);

                        if (IN6_IS_ADDR_MULTICAST(&(prefix_list.target[prefix_list.ntarget]->start.in6_addr))) {
                            if (idata.verbose_f)
                                puts("scan6: Remote scan cannot target a multicast address");

                            exit(EXIT_FAILURE);
                        }

                        if (IN6_IS_ADDR_MULTICAST(&(prefix_list.target[prefix_list.ntarget]->end.in6_addr))) {
                            if (idata.verbose_f)
                                puts("scan6: Remote scan cannot target a multicast address");

                            exit(EXIT_FAILURE);
                        }

                        prefix_list.ntarget++;
                        idata.dstaddr = prefix_list.target[0]->start.in6_addr;
                    }
                    else {
                        /*
                           If the number of "targets" has already been exceeded, it doesn't make sense to continue
                           further, since there wouldn't be space for any specific target types
                         */
                        if (idata.verbose_f)
                            puts("Too many targets!");

                        exit(EXIT_FAILURE);
                    }
                }
            }

            idata.dstaddr_f = TRUE;
            dst_f = TRUE;
            break;

        case 'u': /* Destinations Options Header */
            if (ndstopthdr >= MAX_DST_OPT_HDR) {
                puts("Too many Destination Options Headers");
                exit(EXIT_FAILURE);
            }

            hdrlen = atoi(optarg);

            if (hdrlen < 8) {
                puts("Bad length in Destination Options Header");
                exit(EXIT_FAILURE);
            }

            hdrlen = ((hdrlen + 7) / 8) * 8;
            dstopthdrlen[ndstopthdr] = hdrlen;

            if ((dstopthdr[ndstopthdr] = malloc(hdrlen)) == NULL) {
                puts("Not enough memory for Destination Options Header");
                exit(EXIT_FAILURE);
            }

            ptrhdr = dstopthdr[ndstopthdr] + 2;
            ptrhdrend = dstopthdr[ndstopthdr] + hdrlen;

            while (ptrhdr < ptrhdrend) {

                if ((ptrhdrend - ptrhdr) > 257)
                    pad = 257;
                else
                    pad = ptrhdrend - ptrhdr;

                if (!insert_pad_opt(ptrhdr, ptrhdrend, pad)) {
                    puts("Destination Options Header Too Big");
                    exit(EXIT_FAILURE);
                }

                ptrhdr = ptrhdr + pad;
            }

            *(dstopthdr[ndstopthdr] + 1) = (hdrlen / 8) - 1;
            ndstopthdr++;
            dstopthdr_f = TRUE;
            break;

        case 'U': /* Destination Options Header (Unfragmentable Part) */
            if (ndstoptuhdr >= MAX_DST_OPT_U_HDR) {
                puts("Too many Destination Options Headers (Unfragmentable Part)");
                exit(EXIT_FAILURE);
            }

            hdrlen = atoi(optarg);

            if (hdrlen < 8) {
                puts("Bad length in Destination Options Header (Unfragmentable Part)");
                exit(EXIT_FAILURE);
            }

            hdrlen = ((hdrlen + 7) / 8) * 8;
            dstoptuhdrlen[ndstoptuhdr] = hdrlen;

            if ((dstoptuhdr[ndstoptuhdr] = malloc(hdrlen)) == NULL) {
                puts("Not enough memory for Destination Options Header (Unfragmentable Part)");
                exit(EXIT_FAILURE);
            }

            ptrhdr = dstoptuhdr[ndstoptuhdr] + 2;
            ptrhdrend = dstoptuhdr[ndstoptuhdr] + hdrlen;

            while (ptrhdr < ptrhdrend) {

                if ((ptrhdrend - ptrhdr) > 257)
                    pad = 257;
                else
                    pad = ptrhdrend - ptrhdr;

                if (!insert_pad_opt(ptrhdr, ptrhdrend, pad)) {
                    puts("Destination Options Header (Unfragmentable Part) Too Big");
                    exit(EXIT_FAILURE);
                }

                ptrhdr = ptrhdr + pad;
            }

            *(dstoptuhdr[ndstoptuhdr] + 1) = (hdrlen / 8) - 1;
            ndstoptuhdr++;
            dstoptuhdr_f = TRUE;
            break;

        case 'H': /* Hop-by-Hop Options Header */
            if (nhbhopthdr >= MAX_HBH_OPT_HDR) {
                puts("Too many Hop-by-Hop Options Headers");
                exit(EXIT_FAILURE);
            }

            hdrlen = atoi(optarg);

            if (hdrlen <= 8) {
                puts("Bad length in Hop-by-Hop Options Header");
                exit(EXIT_FAILURE);
            }

            hdrlen = ((hdrlen + 7) / 8) * 8;
            hbhopthdrlen[nhbhopthdr] = hdrlen;

            if ((hbhopthdr[nhbhopthdr] = malloc(hdrlen)) == NULL) {
                puts("Not enough memory for Hop-by-Hop Options Header");
                exit(EXIT_FAILURE);
            }

            ptrhdr = hbhopthdr[nhbhopthdr] + 2;
            ptrhdrend = hbhopthdr[nhbhopthdr] + hdrlen;

            while (ptrhdr < ptrhdrend) {

                if ((ptrhdrend - ptrhdr) > 257)
                    pad = 257;
                else
                    pad = ptrhdrend - ptrhdr;

                if (!insert_pad_opt(ptrhdr, ptrhdrend, pad)) {
                    puts("Hop-by-Hop Options Header Too Big");
                    exit(EXIT_FAILURE);
                }

                ptrhdr = ptrhdr + pad;
            }

            *(hbhopthdr[nhbhopthdr] + 1) = (hdrlen / 8) - 1;
            nhbhopthdr++;
            hbhopthdr_f = TRUE;
            break;

        case 'y': /* Fragment header */
            nfrags = atoi(optarg);
            if (nfrags < 8) {
                puts("Error in Fragmentation option: Fragment Size must be at least 8 bytes");
                exit(EXIT_FAILURE);
            }

            idata.fragh_f = TRUE;

            /* XXX: To be removed when fragmentation support is added */
            puts("Error: scan6 does not currently support fragmentation");
            exit(EXIT_FAILURE);

            break;

        case 'S': /* Source Ethernet address */
            if (ether_pton(optarg, &(idata.hsrcaddr), sizeof(idata.hsrcaddr)) == FALSE) {
                puts("Error in Source link-layer address.");
                exit(EXIT_FAILURE);
            }

            idata.hsrcaddr_f = TRUE;
            break;

        case 'D': /* Destination Ethernet address */
            if (ether_pton(optarg, &(idata.hdstaddr), sizeof(idata.hdstaddr)) == FALSE) {
                puts("Error in Destination Ethernet address.");
                exit(EXIT_FAILURE);
            }

            idata.hdstaddr_f = TRUE;
            break;

        case 'L':
            scan_local_f = TRUE;
            break;

        case 'p': /* Probe type */
            if (strncmp(optarg, "echo", strlen("echo")) == 0) {
                probe_echo_f = TRUE;
                probetype = PROBE_ICMP6_ECHO;
                probe_f = TRUE;
            }
            else if (strncmp(optarg, "unrec", strlen("unrec")) == 0) {
                probe_unrec_f = TRUE;
                probetype = PROBE_UNREC_OPT;
                probe_f = TRUE;
            }
            else if (strncmp(optarg, "all", strlen("all")) == 0) {
                probe_echo_f = TRUE;
                probe_unrec_f = TRUE;

                /* For reote scans, we use a single probe type */
                probetype = PROBE_ICMP6_ECHO;
                probe_f = TRUE;
            }
            else if (strncmp(optarg, "tcp", strlen("tcp")) == 0) {
                probetype = PROBE_TCP;
                probe_f = TRUE;
            }
            else {
                puts("Error in '-p' option: Unknown probe type");
                exit(EXIT_FAILURE);
            }

            break;

        case 'Z': /* Payload Size*/
            rhbytes = atoi(optarg);
            rhbytes_f = TRUE;
            break;

        case 'o': /* TCP/UDP Source Port */
            srcport = atoi(optarg);
            srcport_f = TRUE;
            break;

        case 'a': /* TCP/UDP Destination Port */
            dstport = atoi(optarg);
            dstport_f = TRUE;
            break;

        case 'X':
            charptr = optarg;
            while (*charptr) {
                switch (*charptr) {
                case 'F':
                    tcpflags = tcpflags | TH_FIN;
                    break;

                case 'S':
                    tcpflags = tcpflags | TH_SYN;
                    break;

                case 'R':
                    tcpflags = tcpflags | TH_RST;
                    break;

                case 'P':
                    tcpflags = tcpflags | TH_PUSH;
                    break;

                case 'A':
                    tcpflags = tcpflags | TH_ACK;
                    break;

                case 'U':
                    tcpflags = tcpflags | TH_URG;
                    break;

                case 'X': /* No TCP flags */
                    break;

                default:
                    printf("Unknown TCP flag '%c'\n", *charptr);
                    exit(EXIT_FAILURE);
                    break;
                }

                if (*charptr == 'X')
                    break;

                charptr++;
            }

            tcpflags_f = TRUE;
            break;

        case 'P': /* Print type */
            if (strncmp(optarg, "local", strlen("local")) == 0) {
                print_local_f = TRUE;
                print_f = TRUE;
            }
            else if (strncmp(optarg, "global", strlen("global")) == 0) {
                print_global_f = TRUE;
                print_f = TRUE;
            }
            else if (strncmp(optarg, "all", strlen("all")) == 0) {
                print_local_f = TRUE;
                print_global_f = TRUE;
                print_f = TRUE;
            }
            else {
                puts("Error in '-P' option: Unknown address type");
                exit(EXIT_FAILURE);
            }

            break;

        case 'q':
            print_unique_f = TRUE;
            break;

        case 'e':
            print_type = PRINT_ETHER_ADDR;
            break;

        case 't':
            timestamps_f = TRUE;
            break;

        case 'x':
            idata.local_retrans = atoi(optarg);
            break;

        case 'O':
            idata.local_timeout = atoi(optarg);
            break;

        case 'f':
            rand_src_f = TRUE;
            break;

        case 'F':
            rand_link_src_f = TRUE;
            break;

        case 'A':
            smart_f = TRUE;
            break;

        case 'j':
            if ((pref = strtok_r(optarg, ":", &lasts)) == NULL) {
                printf("Error in prefix option number %u. \n", i);
                exit(EXIT_FAILURE);
            }

            if (strncmp(pref, "udp", 3) == 0 || strncmp(pref, "udp", 3) == 0) {
                port_list = &udp_port_list;
                cprotocol = IPPROTO_UDP;
            }
            else if (strncmp(pref, "tcp", 3) == 0 || strncmp(pref, "TCP", 3) == 0) {
                port_list = &tcp_port_list;
                cprotocol = IPPROTO_TCP;
            }
            else if (strncmp(pref, "all", 3) == 0 || strncmp(pref, "ALL", 3) == 0) {
                cprotocol = IPPROTO_ALL;
            }
            else {
                puts("Error unknown protocol in 'port-scan' option");
                exit(EXIT_FAILURE);
            }

            if (strncmp(lasts, "top", 3) == 0 || strncmp(lasts, "top", 3) == 0) {
                if ((charptr = strtok_r(NULL, ":", &lasts)) == NULL) {
                    printf("Error in prefix option number %u. \n", i);
                    exit(EXIT_FAILURE);
                }

                if (cprotocol == IPPROTO_ALL && (loadtcptopports_f || loadudptopports_f)) {
                    puts("Cannot specify all ports and (TCP or UDP) top ports at the same time");
                    exit(EXIT_FAILURE);
                }
                else if (cprotocol == IPPROTO_TCP && loadtcptopports_f) {
                    puts("Cannot specify TCP top ports more than once");
                    exit(EXIT_FAILURE);
                }
                else if (cprotocol == IPPROTO_UDP && loadudptopports_f) {
                    puts("Cannot specify TCP top ports more than once");
                    exit(EXIT_FAILURE);
                }

                if (strncmp(lasts, "all", 3) == 0 || strncmp(lasts, "ALL", 3) == 0) {
                    nalltopports = (MAX_PORT_RANGE + 1) * 2; /* This sets the cap for the number of entries to load */
                }
                else {
                    nalltopports = atoi(lasts);
                }

                if (nalltopports > 0) {
                    if (cprotocol == IPPROTO_TCP) {
                        loadtcptopports_f = TRUE;
                        ntcptopports = nalltopports;
                    }
                    else if (cprotocol == IPPROTO_UDP) {
                        loadudptopports_f = TRUE;
                        nudptopports = nalltopports;
                    }
                    else if (cprotocol == IPPROTO_ALL) {
                        loadalltopports_f = TRUE;
                    }
                    else {
                        /* Should never happen */
                        puts("Bad protocol");
                        exit(EXIT_FAILURE);
                    }
                }

                portscan_f = TRUE;
                break;
            }
            else if (address_contains_ranges(lasts)) {
                if ((pref = strtok_r(NULL, "-", &lasts)) == NULL) {
                    puts("Error in 'port-scan' option");
                    exit(EXIT_FAILURE);
                }

                portscanl = strtoul(pref, &endptr, 10);

                if (pref == endptr && portscanl == 0) {
                    puts("Error in port range");
                    exit(EXIT_FAILURE);
                }

                portscanh = strtoul(lasts, &endptr, 10);

                if (lasts == endptr && portscanh == 0) {
                    puts("Error in port range");
                    exit(EXIT_FAILURE);
                }
            }
            else {
                portscanl = strtoul(lasts, &endptr, 10);

                if (lasts == endptr && portscanl == 0) {
                    portscanl = DEFAULT_MIN_PORT;
                    portscanh = DEFAULT_MAX_PORT;
                }
                else {
                    portscanh = portscanl;
                }
            }

            if (portscanl > portscanh) {
                portscantemp = portscanl;
                portscanl = portscanh;
                portscanh = portscantemp;
            }

            if (port_list->nport < port_list->maxport) {
                if ((port_list->port[port_list->nport] = malloc(sizeof(struct port_entry))) == NULL) {
                    if (idata.verbose_f)
                        puts("scan6: Not enough memory");

                    exit(EXIT_FAILURE);
                }

                port_list->port[port_list->nport]->start = portscanl;
                port_list->port[port_list->nport]->end = portscanh;
                (port_list->port[port_list->nport])->cur = (port_list->port[port_list->nport])->start;
                port_list->nport++;
            }
            else {
                /*
                   If the number of "prots" has already been exceeded, it doesn't make sense to continue further,
                   since there wouldn't be space for any specific target types
                                         */
                if (idata.verbose_f)
                    puts("Too many port ranges!");

                exit(EXIT_FAILURE);
            }

            portscan_f = TRUE;
            break;

        case 'G':
            if (strncmp(optarg, "syn", strlen("syn")) == 0 || strncmp(optarg, "SYN", strlen("SYN")) == 0) {
                tcpflags = TH_SYN;
                tcpflags_f = TRUE;
            }
            else if (strncmp(optarg, "fin", strlen("fin")) == 0 || strncmp(optarg, "FIN", strlen("FIN")) == 0) {
                tcpflags = TH_FIN;
                tcpflags_f = TRUE;
            }
            else if (strncmp(optarg, "null", strlen("null")) == 0 || strncmp(optarg, "NULL", strlen("NULL")) == 0) {
                tcpflags = 0;
                tcpflags_f = TRUE;
            }
            else if (strncmp(optarg, "xmas", strlen("xmas")) == 0 || strncmp(optarg, "XMAS", strlen("XMAS")) == 0) {
                tcpflags = TH_FIN | TH_PUSH | TH_URG;
                tcpflags_f = TRUE;
            }
            else if (strncmp(optarg, "ack", strlen("ack")) == 0 || strncmp(optarg, "ACK", strlen("ACK")) == 0) {
                tcpflags = TH_ACK;
                tcpflags_f = TRUE;
            }

            break;

        case 'V':
            if (strncmp(optarg, "vbox", strlen("vbox")) == 0 ||
                strncmp(optarg, "virtualbox", strlen("virtualbox")) == 0) {
                tgt_vm_f = TRUE;
                vm_vbox_f = TRUE;
            }
            else if (strncmp(optarg, "vmware-esx", strlen("vmware-esx")) == 0) {
                tgt_vm_f = TRUE;
                vm_vmware_esx_f = TRUE;
            }
            else if (strncmp(optarg, "vmware-vsphere", strlen("vmware-vsphere")) == 0) {
                tgt_vm_f = TRUE;
                vm_vmware_vsphere_f = TRUE;
            }
            else if (strncmp(optarg, "vmwarem", strlen("vmwarem")) == 0 ||
                     strncmp(optarg, "vmware-manual", strlen("vmware-manual")) == 0) {
                tgt_vm_f = TRUE;
                vm_vmwarem_f = TRUE;
            }
            else if (strncmp(optarg, "vmware", strlen("vmware")) == 0) {
                tgt_vm_f = TRUE;
                vm_vmware_esx_f = TRUE;
                vm_vmware_vsphere_f = TRUE;
                vm_vmwarem_f = TRUE;
            }
            else if (strncmp(optarg, "all", strlen("all")) == 0) {
                tgt_vm_f = TRUE;
                vm_vbox_f = TRUE;
                vm_vmware_esx_f = TRUE;
                vm_vmware_vsphere_f = TRUE;
                vm_vmwarem_f = TRUE;
            }
            else {
                puts("Error in '-V' option: Unknown Virtualization Technology");
                exit(EXIT_FAILURE);
            }

            break;

        case 'b':
            tgt_lowbyte_f = TRUE;
            break;

        case 'B':
            if (strncmp("ipv4-all", optarg, MAX_LINE_SIZE) == 0 || strncmp("all", optarg, MAX_LINE_SIZE) == 0) {
                tgt_ipv4mapped32_f = TRUE;
                tgt_ipv4mapped64_f = TRUE;
            }
            else if (strncmp("ipv4-32", optarg, MAX_LINE_SIZE) == 0 || strncmp("32", optarg, MAX_LINE_SIZE) == 0) {
                tgt_ipv4mapped32_f = TRUE;
            }
            else if (strncmp("ipv4-64", optarg, MAX_LINE_SIZE) == 0 || strncmp("64", optarg, MAX_LINE_SIZE) == 0) {
                tgt_ipv4mapped64_f = TRUE;
            }
            else {
                puts("Unknown encoding of IPv4-embedded IPv6 addresses in '-B' option");
                exit(EXIT_FAILURE);
            }

            break;

        case 'g':
            tgt_portembedded_f = TRUE;
            break;

        case 'k': /* Target OUI */
            /*
               In case the user entered an OUI as OO:UU:II:00:00:00, just copy the first 8 bytes of input
               (the OUI part)
              */
            strncpy(oui_ascii, optarg, 8);
            oui_ascii[8] = 0;
            strncat(oui_ascii, oui_end, ETHER_ADDR_PLEN - Strnlen(oui_ascii, sizeof(oui_ascii)) - 1);

            if (ether_pton(oui_ascii, &oui, sizeof(oui)) == FALSE) {
                puts("Error in vendor IEEE OUI");
                exit(EXIT_FAILURE);
            }

            tgt_oui_f = TRUE;
            break;

        case 'K': /* Target vendor */
            /*
               In case the user entered an OUI as OO:UU:II:00:00:00, just copy the first 8 bytes of input
               (the OUI part)
             */

            strncpy(vendor, optarg, MAX_IEEE_OUIS_LINE_SIZE - 1);
            vendor[MAX_IEEE_OUIS_LINE_SIZE - 1] = 0;

            tgt_vendor_f = TRUE;
            break;

        case 'w': /* Target known Interface Identifiers (IIDs) */
            strncpy(knowniidsfile, optarg, MAX_FILENAME_SIZE - 1);
            knowniidsfile[MAX_FILENAME_SIZE - 1] = 0;

            tgt_knowniidsfile_f = TRUE;
            break;

        case 'W': /* Target Interface Identifier (IIDs) */
            if (iid_list.nprefix >= iid_list.maxprefix) {
                puts("Too many INterface Identifiers");
                exit(EXIT_FAILURE);
            }

            if ((iid_list.prefix[iid_list.nprefix] = malloc(sizeof(struct prefix_entry))) == NULL) {
                puts("Not enough memory while storing Interface ID");
                exit(EXIT_FAILURE);
            }

            if (inet_pton(AF_INET6, optarg, &((iid_list.prefix[iid_list.nprefix])->ip6)) <= 0) {
                puts("inet_pton(): Source Address not valid");
                exit(EXIT_FAILURE);
            }

            iid_list.prefix[iid_list.nprefix]->len = 128;
            iid_list.nprefix++;

            tgt_knowniids_f = TRUE;
            break;

        case 'm': /* Known prefixes file */
            strncpy(knownprefixesfile, optarg, MAX_FILENAME_SIZE - 1);
            knownprefixesfile[MAX_FILENAME_SIZE - 1] = 0;

            knownprefixes_f = TRUE;
            break;

        case 'Q':
            if ((charptr = strtok_r(optarg, "/", &lasts)) == NULL) {
                puts("Error in Source Address");
                exit(EXIT_FAILURE);
            }

            if (inet_pton(AF_INET, charptr, &(v4host.ip)) != 1) {
                puts("Error in Host IPv4 Address");
                exit(EXIT_FAILURE);
            }

            v4hostaddr_f = TRUE;

            if ((charptr = strtok_r(NULL, " ", &lasts)) != NULL) {
                v4host.len = atoi(charptr);

                if (v4host.len > 32) {
                    puts("Prefix length error in Host IPv4 address");
                    exit(EXIT_FAILURE);
                }

                sanitize_ipv4_prefix(&v4host);
                v4hostprefix_f = TRUE;
            }
            else {
                v4host.len = 32;
            }

            break;

        case 'T':
            sort_ouis_f = TRUE;
            break;

        case 'N':
            rnd_probes_f = TRUE;
            break;

        case 'I':
            inc = atoi(optarg);
            inc_f = TRUE;
            break;

        case 'r':
            if (Strnlen(optarg, LINE_BUFFER_SIZE - 1) >= (LINE_BUFFER_SIZE - 1)) {
                puts("scan6: -r option is too long");
                exit(EXIT_FAILURE);
            }

            sscanf(optarg, "%lu%s", &rate, line);

            line[LINE_BUFFER_SIZE - 1] = 0;

            if (strncmp(line, "pps", 3) == 0)
                pps_f = TRUE;
            else if (strncmp(line, "bps", 3) == 0)
                bps_f = TRUE;
            else {
                puts("scan6: Unknown unit of for the rate limit ('-r' option). Unit should be 'bps' or 'pps'");
                exit(EXIT_FAILURE);
            }

            break;

        case 'l': /* "Loop mode */
            loop_f = TRUE;
            break;

        case 'z': /* Sleep option */
            nsleep = atoi(optarg);
            if (nsleep == 0) {
                puts("Invalid number of seconds in '-z' option");
                exit(EXIT_FAILURE);
            }

            sleep_f = TRUE;
            break;

        case 'v': /* Be verbose */
            idata.verbose_f++;
            break;

        case 'h': /* Help */
            print_help();
            exit(EXIT_FAILURE);
            break;

        case 'c': /* Configuration file */
            strncpy(configfile, optarg, MAX_FILENAME_SIZE - 1);
            configfile[MAX_FILENAME_SIZE - 1] = 0;
            configfile_f = TRUE;
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
    verbose_f = idata.verbose_f;

    if (geteuid()) {
        puts("scan6 needs superuser privileges to run");
        exit(EXIT_FAILURE);
    }

    if (scan_local_f && !idata.iface_f) {
        puts("Must specify the network interface with the -i option when a local scan is selected");
        exit(EXIT_FAILURE);
    }

    /* Must open the "Known IIDs" file now, since it might be non-readable for the unprivileged user */
    if (tgt_knowniidsfile_f) {
        if ((knowniids_fp = fopen(knowniidsfile, "r")) == NULL) {
            perror("Error opening known IIDs file");
            exit(EXIT_FAILURE);
        }
    }

    /* Must open the "Known IIDs" file now, since it might be non-readable for the unprivileged user */
    if (knownprefixes_f) {
        if ((knownprefixes_fp = fopen(knownprefixesfile, "r")) == NULL) {
            perror("Error opening known prefixes file");
            exit(EXIT_FAILURE);
        }

        dst_f = TRUE;
    }

    if (!dst_f && !scan_local_f) {
        if (idata.verbose_f)
            puts("Must specify either a destination prefix ('-d'), or a local scan ('-L')");

        exit(EXIT_FAILURE);
    }

    if (!scan_local_f) {
        if (load_dst_and_pcap(&idata, LOAD_SRC_NXT_HOP) == FAILURE) {
            puts("Error while learning Source Address and Next Hop");
            exit(EXIT_FAILURE);
        }
    }
    else {
        if (load_dst_and_pcap(&idata, LOAD_PCAP_ONLY) == FAILURE) {
            puts("Error while learning Source Address and Next Hop");
            exit(EXIT_FAILURE);
        }
    }

    release_privileges();

    /* This loads prefixes, but not scan entries */
    if (knownprefixes_f) {
        if (!load_knownprefix_entries(&scan_list, &prefix_list, knownprefixes_fp)) {
            puts("Couldn't load known IPv6 prefixes");
            exit(EXIT_FAILURE);
        }
    }

    if (!inc_f)
        scan_list.inc = 1;

    if (pps_f && bps_f) {
        puts("Cannot specify a rate-limit in bps and pps at the same time");
        exit(EXIT_FAILURE);
    }

    if (pps_f) {
        if (rate < 1)
            rate = 1;

        pktinterval = 1000000 / rate;
    }

    if (bps_f) {
        switch (probetype) {
        case PROBE_UNREC_OPT:
            packetsize = MIN_IPV6_HLEN + sizeof(struct icmp6_hdr) + ICMPV6_ECHO_PAYLOAD_SIZE;
            break;

        case PROBE_ICMP6_ECHO:
            packetsize = MIN_IPV6_HLEN + MIN_DST_OPT_HDR_SIZE + sizeof(struct icmp6_hdr) + ICMPV6_ECHO_PAYLOAD_SIZE;
            break;

        case PROBE_TCP:
            packetsize = MIN_IPV6_HLEN + sizeof(struct tcp_hdr) + rhbytes;
            break;
        }

        if (rate == 0 || ((packetsize * 8) / rate) <= 0)
            pktinterval = 1000000;
        else
            pktinterval = ((packetsize * 8) / rate) * 1000000;
    }

    /* We Default to 1000 pps */
    if (!pps_f && !bps_f)
        pktinterval = 1000;

    if (!configfile_f) {
        strncpy(configfile, "/etc/ipv6toolkit.conf", MAX_FILENAME_SIZE);
    }

    if (tgt_vendor_f || portscan_f) {
        if (!process_config_file(configfile)) {
            puts("Error while processing configuration file");
            exit(EXIT_FAILURE);
        }
    }

    if (portscan_f) {
        if (loadalltopports_f) {
            if (load_top_ports_entries(&tcp_port_list, &udp_port_list, IPPROTO_ALL, nalltopports) == FALSE) {
                puts("Problem loading TCP top ports");
                exit(EXIT_FAILURE);
            }
        }
        else {
            if (loadtcptopports_f) {
                if (load_top_ports_entries(&tcp_port_list, &udp_port_list, IPPROTO_TCP, ntcptopports) == FALSE) {
                    puts("Problem loading TCP top ports");
                    exit(EXIT_FAILURE);
                }
            }
            if (loadudptopports_f) {
                if (load_top_ports_entries(&tcp_port_list, &udp_port_list, IPPROTO_UDP, nudptopports) == FALSE) {
                    puts("Problem loading UDP top ports");
                    exit(EXIT_FAILURE);
                }
            }
        }

        if (tcp_port_list.nport) {
            /* Load service names */
            if (!load_port_table(tcp_port_table, "tcp", MAX_PORT_RANGE)) {
                puts("Error while loading port number descriptions");
                exit(EXIT_FAILURE);
            }

            /* Link service names to port_list structure */
            tcp_port_list.port_table = tcp_port_table;

            /* We currently support only SYN scans for TCP */
            tcpflags_f = TRUE;
            tcpflags = TH_SYN;
        }

        if (udp_port_list.nport) {
            /* Load service names */
            if (!load_port_table(udp_port_table, "udp", MAX_PORT_RANGE)) {
                puts("Error while loading port number descriptions");
                exit(EXIT_FAILURE);
            }

            /* LInk service names to port_list structure */
            udp_port_list.port_table = udp_port_table;
        }
    }

    if (loop_f && !dst_f) {
        puts("Loop mode '-l' set, but no targets ('-d') specified!");
        puts("Note: '-l' option changed since IPv6 toolkit v1.3.4!");
    }

    if (dst_f && !(tgt_ipv4mapped32_f || tgt_ipv4mapped64_f || tgt_lowbyte_f || tgt_oui_f || tgt_vendor_f || tgt_vm_f ||
                   tgt_range_f || tgt_portembedded_f || tgt_knowniids_f || tgt_knowniidsfile_f)) {

        tgt_bruteforce_f = TRUE;
    }

    if ((tgt_ipv4mapped32_f || tgt_ipv4mapped64_f) && !v4hostaddr_f) {
        puts("Error: Must IPv4 host address/prefix (with '--ipv4-host') if '--tgt-ipv4-embedded' is set");
        exit(EXIT_FAILURE);
    }

    if (scan_local_f && (idata.type != DLT_EN10MB || (idata.flags & IFACE_TUNNEL))) {
        puts("Error cannot apply local scan on a loopback or tunnel interface");
        exit(EXIT_FAILURE);
    }

    if (!print_f) {
        print_local_f = TRUE;
        print_global_f = TRUE;
    }

    if (!probe_f) {
        probe_unrec_f = TRUE;
        probe_echo_f = TRUE;

        /* For remote scans we use a single probe type */
        probetype = PROBE_ICMP6_ECHO;
    }

    /*
       If a Source Address (and *not* a "source prefix") has been specified, we need to incorporate such address
       in our iface_data structure.
     */
    if (idata.srcaddr_f && !idata.srcprefix_f) {
        if (IN6_IS_ADDR_LINKLOCAL(&(idata.srcaddr))) {
            idata.ip6_local = idata.srcaddr;
            idata.ip6_local_flag = TRUE;
        }
        else {
            if ((idata.ip6_global.prefix[idata.ip6_global.nprefix] = malloc(sizeof(struct prefix_entry))) == NULL) {
                if (idata.verbose_f) {
                    puts("Not enough memory while saving global address");
                }
                exit(EXIT_FAILURE);
            }

            (idata.ip6_global.prefix[idata.ip6_global.nprefix])->ip6 = idata.srcaddr;
            idata.ip6_global.nprefix++;
            idata.ip6_global_flag = 1;
        }
    }

    if ((idata.ip6_local_flag && idata.ip6_global_flag) && !idata.srcaddr_f)
        localaddr_f = TRUE;

    if (scan_local_f) {
        host_local.nhosts = 0;
        host_local.maxhosts = MAX_IPV6_ENTRIES;
        host_local.host = host_locals;

        if (probe_echo_f) {
            if (multi_scan_local(idata.pfd, &idata, &(idata.ip6_local), PROBE_ICMP6_ECHO, ALL_NODES_MULTICAST_ADDR,
                                 &host_local) == -1) {
                if (idata.verbose_f)
                    puts("Error while learning link-local addresses with ICMPv6 Echo Requests");

                exit(EXIT_FAILURE);
            }
        }

        if (probe_unrec_f) {
            if (multi_scan_local(idata.pfd, &idata, &(idata.ip6_local), PROBE_UNREC_OPT, ALL_NODES_MULTICAST_ADDR,
                                 &host_local) == -1) {
                if (idata.verbose_f)
                    puts("Error while learning link-local addresses with Unrecognized options");

                exit(EXIT_FAILURE);
            }
        }

        if (print_local_f) {
            if (idata.verbose_f)
                puts("Link-local addresses:");

            if (print_unique_f) {
                if (print_unique_host_entries(&host_local, print_type) == -1) {
                    if (idata.verbose_f)
                        puts("Error while printing link-local addresses");

                    exit(EXIT_FAILURE);
                }
            }
            else {
                if (print_host_entries(&host_local, print_type) == -1) {
                    if (idata.verbose_f)
                        puts("Error while printing link-local addresses");

                    exit(EXIT_FAILURE);
                }
            }
        }

        if (print_global_f) {
            host_global.nhosts = 0;
            host_global.maxhosts = MAX_IPV6_ENTRIES;
            host_global.host = host_globals;

            if (probe_echo_f) {
                if (find_local_globals(idata.pfd, &idata, PROBE_ICMP6_ECHO, ALL_NODES_MULTICAST_ADDR, &host_global) ==
                    -1) {
                    if (idata.verbose_f)
                        puts("Error while learning link-local addresses with ICMPv6 Echo Requests");

                    exit(EXIT_FAILURE);
                }
            }

            if (probe_unrec_f) {
                if (find_local_globals(idata.pfd, &idata, PROBE_UNREC_OPT, ALL_NODES_MULTICAST_ADDR, &host_global) ==
                    -1) {
                    if (idata.verbose_f)
                        puts("Error while learning link-local addresses with Unrecognized options");

                    exit(EXIT_FAILURE);
                }
            }

            host_candidate.nhosts = 0;
            host_candidate.maxhosts = MAX_IPV6_ENTRIES;
            host_candidate.host = host_candidates;

            if (create_candidate_globals(&idata, &host_local, &host_global, &host_candidate) == -1) {
                if (idata.verbose_f)
                    puts("Error while creating candidate global addresses");

                exit(EXIT_FAILURE);
            }

            if (validate_host_entries(idata.pfd, &idata, &host_candidate, &host_global) == -1) {
                if (idata.verbose_f)
                    puts("Error while validating global entries");

                exit(EXIT_FAILURE);
            }

            if (idata.verbose_f)
                puts("\nGlobal addresses:");

            if (print_unique_f) {
                if (print_unique_host_entries(&host_global, print_type) == -1) {
                    if (idata.verbose_f)
                        puts("Error while printing global addresses");

                    exit(EXIT_FAILURE);
                }
            }
            else {
                if (print_host_entries(&host_global, print_type) == -1) {
                    if (idata.verbose_f)
                        puts("Error while printing global addresses");

                    exit(EXIT_FAILURE);
                }
            }
        }
    }

    /* Perform a port-scan */
    else if (portscan_f) {
        /* Smart entries are the first ones to be included */
        if (smart_list.ntarget) {
            if (!load_smart_entries(&scan_list, &smart_list)) {
                puts("Couldn't load smart entries");
                exit(EXIT_FAILURE);
            }
        }

        if (tgt_knowniids_f) {
            if (!load_knowniid_entries(&scan_list, &prefix_list, &iid_list)) {
                puts("Couldn't load known IID IPv6 addresses");
                exit(EXIT_FAILURE);
            }
        }

        if (tgt_knowniidsfile_f) {
            if (!load_knowniidfile_entries(&scan_list, &prefix_list, knowniids_fp)) {
                puts("Couldn't load known IID IPv6 addresses");
                exit(EXIT_FAILURE);
            }

            fclose(knowniids_fp);
        }

        if (tgt_portembedded_f) {
            for (i = 0; i < prefix_list.ntarget; i++) {
                if (!load_embeddedport_entries(&scan_list, prefix_list.target[i])) {
                    puts("Couldn't load embedded-port IPv6 addresses");
                    exit(EXIT_FAILURE);
                }
            }
        }

        if (tgt_lowbyte_f) {
            for (i = 0; i < prefix_list.ntarget; i++) {
                if (!load_lowbyte_entries(&scan_list, prefix_list.target[i])) {
                    puts("Couldn't load prefixes for low-byte IPv6 addresses");
                    exit(EXIT_FAILURE);
                }
            }
        }

        if (tgt_ipv4mapped32_f) {
            for (i = 0; i < prefix_list.ntarget; i++) {
                if (!load_ipv4mapped32_entries(&scan_list, prefix_list.target[i], &v4host)) {
                    puts("Couldn't load prefixes for IPv4-embeded (32-bit) IPv6 addresses");
                    exit(EXIT_FAILURE);
                }
            }
        }

        if (tgt_ipv4mapped64_f) {
            for (i = 0; i < prefix_list.ntarget; i++) {
                if (!load_ipv4mapped64_entries(&scan_list, prefix_list.target[i], &v4host)) {
                    puts("Couldn't load prefixes for IPv4-embeded (64-bit) IPv6 addresses");
                    exit(EXIT_FAILURE);
                }
            }
        }

        if (tgt_vm_f) {
            for (i = 0; i < prefix_list.ntarget; i++) {
                if (!load_vm_entries(&scan_list, prefix_list.target[i], &v4host)) {
                    puts("Couldn't load prefix for IEEE OUI");
                    exit(EXIT_FAILURE);
                }
            }
        }

        if (tgt_oui_f) {
            for (i = 0; i < prefix_list.ntarget; i++) {
                if (!load_oui_entries(&scan_list, prefix_list.target[i], &oui)) {
                    puts("Couldn't load prefix for IEEE OUI");
                    exit(EXIT_FAILURE);
                }
            }
        }

        if (tgt_vendor_f) {
            for (i = 0; i < prefix_list.ntarget; i++) {
                if (!load_vendor_entries(&scan_list, prefix_list.target[i], vendor)) {
                    puts("Couldn't load prefixes for the specified vendor");
                    exit(EXIT_FAILURE);
                }
            }
        }

        if (tgt_bruteforce_f) {
            for (i = 0; i < prefix_list.ntarget; i++) {
                if (!load_bruteforce_entries(&scan_list, prefix_list.target[i])) {
                    puts("Couldn't load prefixes for the specified destination prefix");
                    exit(EXIT_FAILURE);
                }
            }
        }

        /* scan_list.ctarget= scan_list.first; */

        puts(SI6_TOOLKIT);
        puts("scan6: An advanced IPv6 scanning tool\n");

        if (idata.verbose_f && !bps_f && !pps_f) {
            puts("Rate-limiting probe packets to 1000 pps (override with the '-r' option if necessary)");
        }

        if (idata.verbose_f) {
            printf("Target address ranges (%d)\n", scan_list.ntarget);

            if (!print_scan_entries(&scan_list)) {
                puts("Error while printing target address ranges");
                exit(EXIT_FAILURE);
            }
        }

        if (!scan_local_f && !idata.ip6_global_flag) {
            if (idata.verbose_f) {
                puts("Cannot obtain a global address to scan remote network");
            }

            exit(EXIT_FAILURE);
        }

        if (idata.verbose_f) {
            if (tcp_port_list.nport) {
                printf("Target TCP ports: ");
                print_port_entries(&tcp_port_list);
                puts("");
            }

            if (udp_port_list.nport) {
                printf("Target UDP ports: ");
                print_port_entries(&udp_port_list);
                puts("");
            }
        }

        if (tcp_port_list.nport) {
            if (udp_port_list.nport) {
                /* Allow both TCP and UDP packets */
                if (pcap_compile(idata.pfd, &pcap_filter, PCAP_TCP_UDP_NSNA_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) ==
                    -1) {
                    if (idata.verbose_f > 1)
                        printf("pcap_compile(): %s\n", pcap_geterr(idata.pfd));

                    exit(EXIT_FAILURE);
                }
            }
            else {
                /* Allow only TCP packets */
                if (pcap_compile(idata.pfd, &pcap_filter, PCAP_TCP_NSNA_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1) {
                    if (idata.verbose_f > 1)
                        printf("pcap_compile(): %s\n", pcap_geterr(idata.pfd));

                    exit(EXIT_FAILURE);
                }
            }
        }
        else {
            if (udp_port_list.nport) {
                /* Allow only UDP packets */
                if (pcap_compile(idata.pfd, &pcap_filter, PCAP_UDP_NSNA_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1) {
                    if (idata.verbose_f > 1)
                        printf("pcap_compile(): %s\n", pcap_geterr(idata.pfd));

                    exit(EXIT_FAILURE);
                }
            }
            /* There is no "else" here, since port scanning is triggered by specifying some proto/port */
        }

        /* Set initial contents of the attack packet */
        init_packet_data(&idata);

        /*
                        if(pcap_setfilter(idata.pfd, &pcap_filter) == -1){
                                if(idata.verbose_f>1)
                                        printf("pcap_setfilter(): %s\n", pcap_geterr(idata.pfd));

                                exit(EXIT_FAILURE);
                        }
        */
        pcap_freecode(&pcap_filter);

        FD_ZERO(&sset);
        FD_SET(idata.fd, &sset);

        /* One loop for each address */

        nomoreaddr_f = FALSE;

        while (!nomoreaddr_f) {
            if (tcp_port_list.nport) {
                pscantype = IPPROTO_TCP;
                port_list = &tcp_port_list;
                port_results = tcp_results;
            }
            else if (udp_port_list.nport) {
                pscantype = IPPROTO_UDP;
                port_list = &udp_port_list;
                port_results = udp_results;
            }
            else {
                /* Should never happen */
                puts("Error: Port scan selected, but no target TCP or UDP ports");
            }

            endpscan_f = FALSE;
            end_f = FALSE;
            donesending_f = FALSE;

            /* Check whether the current scan_entry is within range. Otherwise, get the next target */
            if (!is_target_in_range(&scan_list)) {
                if (!get_next_target(&scan_list)) {
                    /* donesending_f=TRUE; */
                    nomoreaddr_f = TRUE;
                    continue;
                }
            }

            if (tcp_port_list.nport) {
                /* Initialize port scan results for TCP (default to filtered) */
                for (i = 0; i < MAX_PORT_ENTRIES; i++)
                    tcp_results[i] = PORT_FILTERED;
            }

            if (udp_port_list.nport) {
                /* Initialize port scan results for UDP (default to open) */
                for (i = 0; i < MAX_PORT_ENTRIES; i++)
                    udp_results[i] = PORT_OPEN;
            }

            /* Reset the port entries */
            if (tcp_port_list.nport)
                reset_port_list(&tcp_port_list);

            if (udp_port_list.nport)
                reset_port_list(&udp_port_list);

            print_ipv6_address("\nPort scan report for: ", &(scan_list.target[scan_list.ctarget]->cur.in6_addr));
            puts("PORT      STATE     SERVICE");

            /* endpscan_f is set when all protocols have been scanned */
            while (!endpscan_f) {
                lastprobe.tv_sec = 0;
                lastprobe.tv_usec = 0;
                idata.pending_write_f = TRUE;

                /* end_f is set when donesending_f and proper time has elapsed */
                while (!end_f) {
                    rset = sset;
                    wset = sset;
                    eset = sset;

                    if (!donesending_f) {
                        timeout.tv_sec = pktinterval / 1000000;
                        timeout.tv_usec = pktinterval % 1000000;
                    }
                    else {
#if defined(sun) || defined(__sun) || defined(__linux__)
                        timeout.tv_sec = pktinterval / 1000000;
                        timeout.tv_usec = pktinterval % 1000000;
#else
                        timeout.tv_usec = 0;
                        timeout.tv_sec = PSCAN_TIMEOUT;
#endif
                    }

                    /*
                            Check for readability and exceptions. We only check for writeability if there is pending
                       data to send (the pcap descriptor will usually be writeable!).
                     */
                    if ((sel = select(idata.fd + 1, &rset, (idata.pending_write_f ? &wset : NULL), &eset, &timeout)) ==
                        -1) {
                        if (errno == EINTR) {
                            continue;
                        }
                        else {
                            perror("scan6:");
                            exit(EXIT_FAILURE);
                        }
                    }

                    if (gettimeofday(&curtime, NULL) == -1) {
                        if (idata.verbose_f)
                            perror("scan6");

                        exit(EXIT_FAILURE);
                    }

                    /* Check whether we have finished probing all ports */
                    if (donesending_f) {
                        if (is_time_elapsed(&curtime, &lastprobe, SELECT_TIMEOUT * 1000000)) {
                            end_f = TRUE;
                        }
                    }

#if !defined(sun) && !defined(__sun) && !defined(__linux__)
                    /*
                       If we didn't check for writeability in the previous call to select(), we must do it now.
                       Otherwise, we might block when trying to send a packet.
                     */
                    if (!donesending_f && !idata.pending_write_f) {
                        wset = sset;

                        timeout.tv_usec = 0;
                        timeout.tv_sec = 0;

                        if ((sel = select(idata.fd + 1, NULL, &wset, NULL, &timeout)) == -1) {
                            if (errno == EINTR) {
                                continue;
                            }
                            else {
                                perror("scan6:");
                                exit(EXIT_FAILURE);
                            }
                        }

                        idata.pending_write_f = TRUE;
                    }
#endif

#if defined(sun) || defined(__sun) || defined(__linux__)
                    if (TRUE) {
#else
                    if (sel && FD_ISSET(idata.fd, &rset)) {
#endif
                        /* Must process incoming packet */
                        error_f = FALSE;

                        if ((result = pcap_next_ex(idata.pfd, &pkthdr, &pktdata)) == -1) {
                            if (idata.verbose_f)
                                printf("Error while reading packet in main loop: pcap_next_ex(): %s",
                                       pcap_geterr(idata.pfd));

                            exit(EXIT_FAILURE);
                        }

                        if (result == 1 && pktdata != NULL) {
                            pkt_ether = (struct ether_header *)pktdata;
                            pkt_ipv6 = (struct ip6_hdr *)((char *)pkt_ether + idata.linkhsize);
                            pkt_end = (unsigned char *)pktdata + pkthdr->caplen;

                            if ((pkt_end - pktdata) < (idata.linkhsize + MIN_IPV6_HLEN)) {
                                continue;
                            }

                            /* Skip IPv6 EHs if present */
                            ulhtype = pkt_ipv6->ip6_nxt;
                            pkt_eh = (struct ip6_eh *)((char *)pkt_ipv6 + sizeof(struct ip6_hdr));

                            droppacket_f = FALSE;

                            while (ulhtype != IPPROTO_ICMPV6 && ulhtype != IPPROTO_TCP && ulhtype != IPPROTO_UDP &&
                                   !droppacket_f) {
                                if (ulhtype == IPPROTO_FRAGMENT) {
                                    if (((unsigned char *)pkt_eh + sizeof(struct ip6_frag)) > pkt_end) {
                                        droppacket_f = TRUE;
                                        break;
                                    }

                                    fh = (struct ip6_frag *)((char *)pkt_eh);

                                    if (fh->ip6f_offlg & IP6F_OFF_MASK) {
                                        droppacket_f = TRUE;
                                        break;
                                    }

                                    ulhtype = fh->ip6f_nxt;
                                    pkt_eh = (struct ip6_eh *)((char *)fh + sizeof(struct ip6_frag));
                                }
                                else {
                                    if (((unsigned char *)pkt_eh + sizeof(struct ip6_eh)) > pkt_end) {
                                        droppacket_f = TRUE;
                                        break;
                                    }

                                    ulhtype = pkt_eh->eh_nxt;
                                    pkt_eh = (struct ip6_eh *)((char *)pkt_eh + (pkt_eh->eh_len + 1) * 8);
                                }

                                if ((unsigned char *)pkt_eh >= pkt_end) {
                                    droppacket_f = TRUE;
                                    break;
                                }
                            }

                            if (droppacket_f) {
                                continue;
                            }

                            pkt_icmp6 = (struct icmp6_hdr *)((char *)pkt_eh);
                            pkt_tcp = (struct tcp_hdr *)((char *)pkt_eh);
                            pkt_udp = (struct udp_hdr *)((char *)pkt_eh);
                            pkt_ns = (struct nd_neighbor_solicit *)((char *)pkt_eh);

                            if (ulhtype == IPPROTO_ICMPV6) {
                                if (idata.type == DLT_EN10MB && !(idata.flags & IFACE_LOOPBACK) &&
                                    pkt_icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT) {
                                    if ((pkt_end - (unsigned char *)pkt_ns) < sizeof(struct nd_neighbor_solicit))
                                        continue;

                                    /*
                                            If the addresses that we're using are not actually configured on the local
                                       system (i.e., they are "spoofed", we must check whether it is a Neighbor
                                       Solicitation for one of our addresses, and respond with a Neighbor Advertisement.
                                       Otherwise, the kernel will take care of that.
                                     */
                                    if (is_ip6_in_address_list(&(idata.ip6_global), &(pkt_ns->nd_ns_target)) ||
                                        is_eq_in6_addr(&(pkt_ns->nd_ns_target), &(idata.ip6_local))) {
                                        if (send_neighbor_advert(&idata, idata.pfd, pktdata) == -1) {
                                            if (idata.verbose_f)
                                                puts("Error sending Neighbor Advertisement message");

                                            exit(EXIT_FAILURE);
                                        }
                                    }
                                }
                                else if (pscantype == IPPROTO_UDP && pkt_icmp6->icmp6_type == ICMP6_DST_UNREACH &&
                                         pkt_icmp6->icmp6_code == ICMP6_DST_UNREACH_NOPORT) {

                                    /* We are interested in the embedded payload */
                                    pkt_ipv6 = (struct ip6_hdr *)((char *)pkt_icmp6 + sizeof(struct icmp6_hdr));

                                    if (((unsigned char *)pkt_ipv6 + sizeof(struct ip6_hdr)) > pkt_end) {
                                        continue;
                                    }

                                    if (!is_eq_in6_addr(&(pkt_ipv6->ip6_dst), &(idata.dstaddr))) {
                                        continue;
                                    }

                                    ulhtype = pkt_ipv6->ip6_nxt;
                                    pkt_eh = (struct ip6_eh *)((char *)pkt_ipv6 + sizeof(struct ip6_hdr));

                                    droppacket_f = FALSE;

                                    while (ulhtype != IPPROTO_ICMPV6 && ulhtype != IPPROTO_TCP &&
                                           ulhtype != IPPROTO_UDP && !droppacket_f) {
                                        if (ulhtype == IPPROTO_FRAGMENT) {
                                            if (((unsigned char *)pkt_eh + sizeof(struct ip6_frag)) > pkt_end) {
                                                droppacket_f = TRUE;
                                                break;
                                            }

                                            fh = (struct ip6_frag *)((char *)pkt_eh);

                                            if (fh->ip6f_offlg & IP6F_OFF_MASK) {
                                                droppacket_f = TRUE;
                                                break;
                                            }

                                            ulhtype = fh->ip6f_nxt;
                                            pkt_eh = (struct ip6_eh *)((char *)fh + sizeof(struct ip6_frag));
                                        }
                                        else {
                                            /* If the EH is smaller than the minimum EH, we drop the packet */
                                            if (((unsigned char *)pkt_eh + sizeof(struct ip6_eh)) > pkt_end) {
                                                droppacket_f = TRUE;
                                                break;
                                            }

                                            ulhtype = pkt_eh->eh_nxt;
                                            pkt_eh = (struct ip6_eh *)((char *)pkt_eh + (pkt_eh->eh_len + 1) * 8);
                                        }

                                        if ((unsigned char *)pkt_eh >= pkt_end) {
                                            droppacket_f = TRUE;
                                            break;
                                        }
                                    }

                                    if (droppacket_f || ulhtype != IPPROTO_UDP) {
                                        continue;
                                    }

                                    pkt_udp = (struct udp_hdr *)((char *)pkt_eh);
                                    port_results[ntohs(pkt_udp->uh_dport)] = PORT_CLOSED;
                                }
                            }
                            /* We only bother to process TCP segments if we are currently sending TCP segments */
                            else if (pscantype == IPPROTO_TCP && ulhtype == IPPROTO_TCP) {
                                if (!is_eq_in6_addr(&(idata.dstaddr), &(pkt_ipv6->ip6_src)))
                                    continue;

                                if (srcport_f) {
                                    if (pkt_tcp->th_dport != htons(srcport))
                                        continue;
                                }

                                if (in_chksum(pkt_ipv6, pkt_tcp, pkt_end - ((unsigned char *)pkt_tcp), IPPROTO_TCP) !=
                                    0)
                                    continue;

                                /* Record the port number -- XXX might use the port-setting techniques from path6 */
                                if (pkt_tcp->th_flags & TH_RST) {
                                    port_results[ntohs(pkt_tcp->th_sport)] = PORT_CLOSED;
                                }
                                else if (pkt_tcp->th_flags & TH_SYN) {
                                    port_results[ntohs(pkt_tcp->th_sport)] = PORT_OPEN;
                                }
                            }
                        }
                    }

                    if (!donesending_f && !idata.pending_write_f &&
                        is_time_elapsed(&curtime, &lastprobe, pktinterval)) {
                        idata.pending_write_f = TRUE;
                        continue;
                    }

#if defined(sun) || defined(__sun) || defined(__linux__)
                    if (!donesending_f && idata.pending_write_f) {
#else
                    if (!donesending_f && idata.pending_write_f && FD_ISSET(idata.fd, &wset)) {
#endif
                        idata.pending_write_f = FALSE;

                        /* Check whether the current scan_entry is within range. Otherwise, get the next target */
                        if (!is_port_in_range(port_list)) {
                            if (!get_next_port(port_list)) {
                                if (gettimeofday(&lastprobe, NULL) == -1) {
                                    if (idata.verbose_f)
                                        perror("scan6");

                                    exit(EXIT_FAILURE);
                                }

                                donesending_f = TRUE;
                                continue;
                            }
                        }

                        if (!send_pscan_probe(&idata, &scan_list, port_list, &(idata.srcaddr), pscantype)) {
                            exit(EXIT_FAILURE);
                        }

                        if (gettimeofday(&lastprobe, NULL) == -1) {
                            if (idata.verbose_f)
                                perror("scan6");

                            exit(EXIT_FAILURE);
                        }

                        if (!get_next_port(port_list)) {
                            donesending_f = TRUE;
                            continue;
                        }
                    }

                    if (FD_ISSET(idata.fd, &eset)) {
                        if (idata.verbose_f)
                            puts("scan6: Found exception on libpcap descriptor");

                        exit(EXIT_FAILURE);
                    }
                }

                if (pscantype == IPPROTO_TCP) {
                    /* Result types can be PORT_OPEN, PORT_CLOSED, and PORT_FILTERED */
                    print_port_scan(port_list, port_results, PORT_OPEN);
                }
                else {
                    print_port_scan(port_list, port_results, PORT_OPEN);
                }

                /* We always start with TCP scans (if there are any target ports) */
                if (pscantype == IPPROTO_TCP) {
                    if (udp_port_list.nport) {
                        pscantype = IPPROTO_UDP;
                        port_list = &udp_port_list;
                        port_results = udp_results;
                    }
                    else {
                        endpscan_f = TRUE;
                    }
                }
                else {
                    endpscan_f = TRUE;
                }
            }

            if (!get_next_target(&scan_list)) {
                nomoreaddr_f = TRUE;
                continue;
            }

            puts("");
        }

        exit(EXIT_SUCCESS);
    }
    /* Remote scan */
    else {
        /* Smart entries are the first ones to be included */
        if (smart_list.ntarget) {
            if (!load_smart_entries(&scan_list, &smart_list)) {
                puts("Couldn't load smart entries");
                exit(EXIT_FAILURE);
            }
        }

        if (tgt_knowniids_f) {
            if (!load_knowniid_entries(&scan_list, &prefix_list, &iid_list)) {
                puts("Couldn't load known IID IPv6 addresses");
                exit(EXIT_FAILURE);
            }
        }

        if (tgt_knowniidsfile_f) {
            if (!load_knowniidfile_entries(&scan_list, &prefix_list, knowniids_fp)) {
                puts("Couldn't load known IID IPv6 addresses");
                exit(EXIT_FAILURE);
            }

            fclose(knowniids_fp);
        }

        if (tgt_portembedded_f) {
            for (i = 0; i < prefix_list.ntarget; i++) {
                if (!load_embeddedport_entries(&scan_list, prefix_list.target[i])) {
                    puts("Couldn't load embedded-port IPv6 addresses");
                    exit(EXIT_FAILURE);
                }
            }
        }

        if (tgt_lowbyte_f) {
            for (i = 0; i < prefix_list.ntarget; i++) {
                if (!load_lowbyte_entries(&scan_list, prefix_list.target[i])) {
                    puts("Couldn't load prefixes for low-byte IPv6 addresses");
                    exit(EXIT_FAILURE);
                }
            }
        }

        if (tgt_ipv4mapped32_f) {
            for (i = 0; i < prefix_list.ntarget; i++) {
                if (!load_ipv4mapped32_entries(&scan_list, prefix_list.target[i], &v4host)) {
                    puts("Couldn't load prefixes for IPv4-embeded (32-bit) IPv6 addresses");
                    exit(EXIT_FAILURE);
                }
            }
        }

        if (tgt_ipv4mapped64_f) {
            for (i = 0; i < prefix_list.ntarget; i++) {
                if (!load_ipv4mapped64_entries(&scan_list, prefix_list.target[i], &v4host)) {
                    puts("Couldn't load prefixes for IPv4-embeded (64-bit) IPv6 addresses");
                    exit(EXIT_FAILURE);
                }
            }
        }

        if (tgt_vm_f) {
            for (i = 0; i < prefix_list.ntarget; i++) {
                if (!load_vm_entries(&scan_list, prefix_list.target[i], &v4host)) {
                    puts("Couldn't load prefix for IEEE OUI");
                    exit(EXIT_FAILURE);
                }
            }
        }

        if (tgt_oui_f) {
            for (i = 0; i < prefix_list.ntarget; i++) {
                if (!load_oui_entries(&scan_list, prefix_list.target[i], &oui)) {
                    puts("Couldn't load prefix for IEEE OUI");
                    exit(EXIT_FAILURE);
                }
            }
        }

        if (tgt_vendor_f) {
            for (i = 0; i < prefix_list.ntarget; i++) {
                if (!load_vendor_entries(&scan_list, prefix_list.target[i], vendor)) {
                    puts("Couldn't load prefixes for the specified vendor");
                    exit(EXIT_FAILURE);
                }
            }
        }

        if (tgt_bruteforce_f) {
            for (i = 0; i < prefix_list.ntarget; i++) {
                if (!load_bruteforce_entries(&scan_list, prefix_list.target[i])) {
                    puts("Couldn't load prefixes for the specified destination prefix");
                    exit(EXIT_FAILURE);
                }
            }
        }

        /* scan_list.ctarget= scan_list.first; */

        if (idata.verbose_f && !bps_f && !pps_f) {
            puts("Rate-limiting probe packets to 1000 pps (override with the '-r' option if necessary)");
        }

        if (idata.verbose_f) {
            printf("Target address ranges (%d)\n", scan_list.ntarget);

            if (!print_scan_entries(&scan_list)) {
                puts("Error while printing target address ranges");
                exit(EXIT_FAILURE);
            }
        }

        if (!scan_local_f && !idata.ip6_global_flag) {
            if (idata.verbose_f) {
                puts("Cannot obtain a global address to scan remote network");
            }

            exit(EXIT_FAILURE);
        }

        switch (probetype) {
        case PROBE_ICMP6_ECHO:
            if (pcap_compile(idata.pfd, &pcap_filter, PCAP_ICMPV6_ERQNSNA_FILTER, 0, PCAP_NETMASK_UNKNOWN) == -1) {
                if (idata.verbose_f > 1)
                    printf("pcap_compile(): %s\n", pcap_geterr(idata.pfd));

                exit(EXIT_FAILURE);
            }
            break;

        case PROBE_UNREC_OPT:
            if (pcap_compile(idata.pfd, &pcap_filter, PCAP_ICMPV6_ERRORNSNA_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) ==
                -1) {
                if (idata.verbose_f > 1)
                    printf("pcap_compile(): %s\n", pcap_geterr(idata.pfd));

                exit(EXIT_FAILURE);
            }
            break;

        case PROBE_TCP:
            if (pcap_compile(idata.pfd, &pcap_filter, PCAP_TCP_NSNA_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1) {
                if (idata.verbose_f > 1)
                    printf("pcap_compile(): %s\n", pcap_geterr(idata.pfd));

                exit(EXIT_FAILURE);
            }
            break;
        }

        if (pcap_setfilter(idata.pfd, &pcap_filter) == -1) {
            if (idata.verbose_f > 1)
                printf("pcap_setfilter(): %s\n", pcap_geterr(idata.pfd));

            exit(EXIT_FAILURE);
        }

        pcap_freecode(&pcap_filter);

        if (idata.verbose_f)
            puts("\nAlive nodes:");

        FD_ZERO(&sset);
        FD_SET(idata.fd, &sset);

        lastprobe.tv_sec = 0;
        lastprobe.tv_usec = 0;
        idata.pending_write_f = TRUE;

        while (!end_f) {
            rset = sset;
            wset = sset;
            eset = sset;

            if (!donesending_f) {
                timeout.tv_sec = pktinterval / 1000000;
                timeout.tv_usec = pktinterval % 1000000;
            }
            else {
#if defined(sun) || defined(__sun) || defined(__linux__)
                timeout.tv_sec = pktinterval / 1000000;
                timeout.tv_usec = pktinterval % 1000000;
#else
                timeout.tv_usec = 0;
                timeout.tv_sec = SELECT_TIMEOUT;
#endif
            }

#ifdef DEBUG
            puts("Prior to select()");
#endif
            /*
                    Check for readability and exceptions. We only check for writeability if there is pending data
                    to send (the pcap descriptor will usually be writeable!).
             */
#if defined(sun) || defined(__sun) || defined(__linux__)
            if ((sel = select(0, NULL, NULL, NULL, &timeout)) == -1) {
#else
            if ((sel = select(idata.fd + 1, &rset, (idata.pending_write_f ? &wset : NULL), &eset, &timeout)) == -1) {
#endif
                if (errno == EINTR) {
                    continue;
                }
                else {
                    perror("scan6:");
                    exit(EXIT_FAILURE);
                }
            }
#ifdef DEBUG
            puts("After select()");
#endif
            if (gettimeofday(&curtime, NULL) == -1) {
                if (idata.verbose_f)
                    perror("scan6");

                exit(EXIT_FAILURE);
            }

            /* Check whether we have finished probing all targets */
            if (donesending_f) {
                /*
                   If we're not looping, just wait for SELECT_TIMEOUT seconds for any incoming responses.
                   If we are looping (most likely because we're doing host-tracking, wait for nsleep seconds, and
                   reset the targets.
                */
                if (!loop_f) {
                    if (is_time_elapsed(&curtime, &lastprobe, SELECT_TIMEOUT * 1000000)) {
                        end_f = TRUE;
                    }
                }
                else {
                    if (is_time_elapsed(&curtime, &lastprobe, nsleep * 1000000)) {
                        reset_scan_list(&scan_list);
                        donesending_f = FALSE;
                        continue;
                    }
                }
            }

            /*
               If we didn't check for writeability in the previous call to select(), we must do it now. Otherwise, we
               might block when trying to send a packet.
             */
#if !(defined(sun) || defined(__sun) || defined(__linux__))
#ifdef DEBUG
            puts("Prior secondary select()");
#endif
            if (!donesending_f && !idata.pending_write_f) {
                wset = sset;

                timeout.tv_usec = 0;
                timeout.tv_sec = 0;

                if ((sel = select(idata.fd + 1, NULL, &wset, NULL, &timeout)) == -1) {
                    if (errno == EINTR) {
                        continue;
                    }
                    else {
                        perror("scan6:");
                        exit(EXIT_FAILURE);
                    }
                }

                idata.pending_write_f = TRUE;
                continue;
            }
#ifdef DEBUG
            puts("After secondary select()");
#endif
#endif

#if defined(sun) || defined(__sun) || defined(__linux__)
            if (TRUE) {
#else
            if (sel && FD_ISSET(idata.fd, &rset)) {
#endif
                error_f = FALSE;

#ifdef DEBUG
                puts("Prior to pcap_next_ex()");
#endif

                if ((result = pcap_next_ex(idata.pfd, &pkthdr, &pktdata)) == -1) {
                    if (idata.verbose_f)
                        printf("Error while reading packet in main loop: pcap_next_ex(): %s", pcap_geterr(idata.pfd));

                    exit(EXIT_FAILURE);
                }
#ifdef DEBUG
                puts("After to pcap_next_ex()");
#endif
                if (result == 1 && pktdata != NULL) {
                    pkt_ether = (struct ether_header *)pktdata;
                    pkt_ipv6 = (struct ip6_hdr *)((char *)pkt_ether + idata.linkhsize);
                    pkt_icmp6 = (struct icmp6_hdr *)((char *)pkt_ipv6 + sizeof(struct ip6_hdr));
                    pkt_tcp = (struct tcp_hdr *)((char *)pkt_ipv6 + sizeof(struct ip6_hdr));
                    pkt_ns = (struct nd_neighbor_solicit *)pkt_icmp6;
                    pkt_end = (unsigned char *)pktdata + pkthdr->caplen;

                    if ((pkt_end - pktdata) < (idata.linkhsize + MIN_IPV6_HLEN))
                        continue;

                    if (pkt_ipv6->ip6_nxt == IPPROTO_ICMPV6) {
                        if (idata.type == DLT_EN10MB && !(idata.flags & IFACE_LOOPBACK) &&
                            pkt_icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT) {
                            if ((pkt_end - (unsigned char *)pkt_ns) < sizeof(struct nd_neighbor_solicit))
                                continue;

                            /*
                                    If the addresses that we're using are not actually configured on the local system
                                    (i.e., they are "spoofed", we must check whether it is a Neighbor Solicitation for
                                    one of our addresses, and respond with a Neighbor Advertisement. Otherwise, the
                               kernel will take care of that.
                             */
                            if (is_ip6_in_address_list(&(idata.ip6_global), &(pkt_ns->nd_ns_target)) ||
                                is_eq_in6_addr(&(pkt_ns->nd_ns_target), &(idata.ip6_local))) {
#ifdef DEBUG
                                puts("Prior to send_neighbor_advert()");
#endif
                                if (send_neighbor_advert(&idata, idata.pfd, pktdata) == -1) {
                                    if (idata.verbose_f)
                                        puts("Error sending Neighbor Advertisement message");

                                    exit(EXIT_FAILURE);
                                }
#ifdef DEBUG
                                puts("After to send_neighbor_advert()");
#endif
                            }
                        }
                        else if ((probetype == PROBE_ICMP6_ECHO && pkt_icmp6->icmp6_type == ICMP6_ECHO_REPLY) ||
                                 (probetype == PROBE_UNREC_OPT && pkt_icmp6->icmp6_type == ICMP6_PARAM_PROB)) {
                            if (!is_ip6_in_scan_list(&scan_list, &(pkt_ipv6->ip6_src)))
                                continue;

                            if ((pkt_end - (unsigned char *)pkt_icmp6) < sizeof(struct icmp6_hdr))
                                continue;

                            if (valid_icmp6_response_remote(&idata, &scan_list, probetype, pkthdr, pktdata, buffer)) {
                                /* Print the Source Address of the incoming packet */
                                if (inet_ntop(AF_INET6, &(pkt_ipv6->ip6_src), pv6addr, sizeof(pv6addr)) == NULL) {
                                    if (idata.verbose_f > 1)
                                        puts("inet_ntop(): Error converting IPv6 address to presentation format");

                                    exit(EXIT_FAILURE);
                                }

                                if (timestamps_f) {
                                    if (gettimeofday(&pcurtime, NULL) == -1) {
                                        if (idata.verbose_f)
                                            perror("scan6");

                                        exit(EXIT_FAILURE);
                                    }

                                    if (localtime_r((time_t *)&(pcurtime.tv_sec), &pcurtimetm) == NULL) {
                                        if (idata.verbose_f > 1)
                                            puts("localtime_r(): Error obtaining local time.");

                                        exit(EXIT_FAILURE);
                                    }

                                    if (strftime(date, DATE_STR_LEN, "%a %b %d %T %Y", &pcurtimetm) == 0) {
                                        if (idata.verbose_f > 1)
                                            puts("strftime(): Error converting current time to text");

                                        exit(EXIT_FAILURE);
                                    }

                                    printf("%s (%s)\n", pv6addr, date);
                                }
                                else {
                                    printf("%s\n", pv6addr);
                                }
                            }
                        }
                    }
                    else if (probetype == PROBE_TCP && pkt_ipv6->ip6_nxt == IPPROTO_TCP) {
                        if (!is_ip6_in_scan_list(&scan_list, &(pkt_ipv6->ip6_src)))
                            continue;

                        if (srcport_f)
                            if (pkt_tcp->th_dport != htons(srcport))
                                continue;

                        if (dstport_f)
                            if (pkt_tcp->th_sport != htons(dstport))
                                continue;

                        if (in_chksum(pkt_ipv6, pkt_tcp, pkt_end - ((unsigned char *)pkt_tcp), IPPROTO_TCP) != 0)
                            continue;

                        if (inet_ntop(AF_INET6, &(pkt_ipv6->ip6_src), pv6addr, sizeof(pv6addr)) == NULL) {
                            if (idata.verbose_f > 1)
                                puts("inet_ntop(): Error converting IPv6 address to presentation format");

                            exit(EXIT_FAILURE);
                        }

                        if (timestamps_f) {
                            if (gettimeofday(&pcurtime, NULL) == -1) {
                                if (idata.verbose_f)
                                    perror("scan6");

                                exit(EXIT_FAILURE);
                            }

                            if (localtime_r((time_t *)&(pcurtime.tv_sec), &pcurtimetm) == NULL) {
                                if (idata.verbose_f > 1)
                                    puts("localtime_r(): Error obtaining local time.");

                                exit(EXIT_FAILURE);
                            }

                            if (strftime(date, DATE_STR_LEN, "%a %b %d %T %Y", &pcurtimetm) == 0) {
                                if (idata.verbose_f > 1)
                                    puts("strftime(): Error converting current time to text");

                                exit(EXIT_FAILURE);
                            }

                            printf("%s (%s)\n", pv6addr, date);
                        }
                        else {
                            printf("%s\n", pv6addr);
                        }
                    }
                }
            }

            if (!donesending_f && !idata.pending_write_f && is_time_elapsed(&curtime, &lastprobe, pktinterval)) {
                idata.pending_write_f = TRUE;
                continue;
            }

#if defined(sun) || defined(__sun) || defined(__linux__)
            if (!donesending_f && idata.pending_write_f) {
#else
            if (!donesending_f && idata.pending_write_f && FD_ISSET(idata.fd, &wset)) {
#endif

                idata.pending_write_f = FALSE;

                /* Check whether the current scan_entry is within range. Otherwise, get the next target */
                if (!is_target_in_range(&scan_list)) {
                    if (!get_next_target(&scan_list)) {
                        if (gettimeofday(&lastprobe, NULL) == -1) {
                            if (idata.verbose_f)
                                perror("scan6");

                            exit(EXIT_FAILURE);
                        }

                        donesending_f = TRUE;
                        continue;
                    }
                }

                if (!send_probe_remote(&idata, &scan_list, &(idata.srcaddr), probetype)) {
                    puts("Error while sending probe packet");
                    exit(EXIT_FAILURE);
                }

                if (gettimeofday(&lastprobe, NULL) == -1) {
                    if (idata.verbose_f)
                        perror("scan6");

                    exit(EXIT_FAILURE);
                }

                if (!get_next_target(&scan_list)) {
                    donesending_f = TRUE;
                    continue;
                }
            }

#ifdef DEBUG
            puts("Prior to checking eset");
#endif
#if !(defined(sun) || defined(__sun) || defined(__linux__))
            if (FD_ISSET(idata.fd, &eset)) {
                if (idata.verbose_f)
                    puts("scan6: Found exception on libpcap descriptor");

                exit(EXIT_FAILURE);
            }
#endif
#ifdef DEBUG
            puts("After checking eset");
#endif
        }
    }

    exit(EXIT_SUCCESS);
}

/*
 * Function: reset_scan_list()
 *
 * Resets each scan_list.target[]->cur to scan_list.target[]->start.
 */

void reset_scan_list(struct scan_list *scan) {
    unsigned int i;

    for (i = 0; i < scan->ntarget; i++)
        (scan->target[i])->cur = (scan->target[i])->start;

    scan->ctarget = 0;

    return;
}

/*
 * Function: reset_port_list()
 *
 * Resets each port_list.port[]->cur to port_list.port[]->start.
 */

void reset_port_list(struct port_list *port) {
    unsigned int i;

    for (i = 0; i < port->nport; i++)
        (port->port[i])->cur = (port->port[i])->start;

    port->cport = 0;

    return;
}

/*
 * Function: is_port_in_range()
 *
 * Checks whether a port_entry->cur is >= scan_entry->start && <= scan_entry->end
 */

int is_port_in_range(struct port_list *port_list) {
    struct port_entry *port_entry;

    if (port_list->cport >= port_list->nport || port_list->cport >= port_list->maxport) {
        return (0);
    }

    port_entry = port_list->port[port_list->cport];

    if (port_entry->cur < port_entry->start || port_entry->cur > port_entry->end) {
        return (0);
    }

    return (1);
}

/*
 * Function: get_next_port()
 *
 * "Increments" a scan_entry structure to obtain the next target to scan.
 */

int get_next_port(struct port_list *port_list) {
    if ((port_list->port[port_list->cport])->cur >= (port_list->port[port_list->cport])->end) {
        port_list->cport++;

        if (port_list->cport < port_list->nport && port_list->cport < port_list->maxport) {
            return (1);
        }
        else {
            return (0);
        }
    }
    else {
        (port_list->port[port_list->cport])->cur++;
    }

    return (1);
}

/*
 * Function: print_port_scan()
 *
 * Prints the result of a port scan
 */

void print_port_scan(struct port_list *port_list, unsigned int *res, int types) {
    int i, j;
    char portstring[10];

    for (i = 0; i < port_list->nport; i++) {
        for (j = (port_list->port[i])->start; j <= (port_list->port[i])->end; j++) {
            snprintf(portstring, sizeof(portstring), "%u/%s", j, (port_list->proto == IPPROTO_TCP) ? "tcp" : "udp");
            portstring[sizeof(portstring) - 1] = 0;

            switch (res[j]) {
            case PORT_FILTERED:
                if (types & PORT_FILTERED)
                    printf("%-9s filtered  %s\n", portstring, port_list->port_table[j].name);
                break;

            case PORT_OPEN:
                if (types & PORT_OPEN)
                    printf("%-9s open      %s\n", portstring, port_list->port_table[j].name);
                break;

            case PORT_CLOSED:
                if (types & PORT_CLOSED)
                    printf("%-9s closed    %s\n", portstring, port_list->port_table[j].name);
                break;
            }
        }
    }
}

/*
 * Function: is_target_in_range()
 *
 * Checks whether a scan_entry->cur is >= scan_entry->start && <= scan_entry->end
 */

int is_target_in_range(struct scan_list *scan_list) {
    unsigned int i;
    struct scan_entry *scan_entry;

    if (scan_list->ctarget >= scan_list->ntarget || scan_list->ctarget >= scan_list->maxtarget) {
        return (FALSE);
    }

    scan_entry = scan_list->target[scan_list->ctarget];

    for (i = 0; i <= 7; i++) {
        if (ntohs((scan_entry->cur).s6addr16[i]) < ntohs((scan_entry->start).s6addr16[i]) ||
            (ntohs((scan_entry->cur).s6addr16[i]) > ntohs((scan_entry->end).s6addr16[i]))) {
            return (FALSE);
        }
    }

    return (TRUE);
}

/*
 * Function: get_next_target()
 *
 * "Increments" a scan_entry structure to obtain the next target to scan.
 */

int get_next_target(struct scan_list *scan_list) {
    int i;
    unsigned int cind;

    for (i = 7; i >= 0; i--) {
        /*
                Increment scan_entry according to scan_entry->start and scan_entry->end, starting with the low-order
           word
         */

        if (ntohs((scan_list->target[scan_list->ctarget])->cur.s6addr16[i]) >=
            ntohs((scan_list->target[scan_list->ctarget])->end.s6addr16[i])) {
            if (i == 0) {
                scan_list->ctarget++;

                if (scan_list->ctarget < scan_list->ntarget && scan_list->ctarget < scan_list->maxtarget) {
                    return (TRUE);
                }
                else {
                    return (FALSE);
                }
            }

            (scan_list->target[scan_list->ctarget])->cur.s6addr16[i] =
                (scan_list->target[scan_list->ctarget])->start.s6addr16[i];
        }
        else {
            /* We must increment the current word */

            cind = scan_list->ctarget;

            /*
                    If we're incrementing the lowest-order word, and the scan range is larger than MIN_INC_RANGE, we
               increment the word by scan_list->inc. Otherwise, we increment the word by 1.
             */
            if (i == 7 && (ntohs((scan_list->target[cind])->end.s6addr16[7]) -
                           ntohs((scan_list->target[cind])->start.s6addr16[7])) >= MIN_INC_RANGE) {

                /* If the increment would exceed scan_entry->end, we make it "wrap around" */
                if (((unsigned int)ntohs((scan_list->target[cind])->cur.s6addr16[7]) + scan_list->inc) >
                    ntohs((scan_list->target[scan_list->ctarget])->end.s6addr16[7])) {

                    (scan_list->target[cind])->cur.s6addr16[i] =
                        htons((uint16_t)((unsigned int)ntohs((scan_list->target[cind])->start.s6addr16[i]) +
                                         ((unsigned int)ntohs((scan_list->target[cind])->cur.s6addr16[i]) +
                                          scan_list->inc - ntohs((scan_list->target[cind])->start.s6addr16[i])) %
                                             (ntohs((scan_list->target[cind])->end.s6addr16[i]) -
                                              ntohs((scan_list->target[cind])->start.s6addr16[i]))));
                }
                else {
                    /* Otherwise we simply increment the word with scan_list->inc */
                    scan_list->target[cind]->cur.s6addr16[i] =
                        htons(ntohs(scan_list->target[cind]->cur.s6addr16[i]) + scan_list->inc);
                    return (TRUE);
                }
            }
            else {
                /*
                   If the scan range is smaller than MIN_IN_RANGE, or we are incrementing a word other than the
                   lowest-order one, we try to increment in by 1. If this would exceed scan_entry->end, we set it to
                   scan_entry->start and cause the next word to be incremented
                 */
                if (((unsigned int)ntohs((scan_list->target[cind])->cur.s6addr16[i]) + 1) >
                    ntohs(scan_list->target[cind]->end.s6addr16[i])) {
                    (scan_list->target[cind])->cur.s6addr16[i] = (scan_list->target[cind])->start.s6addr16[i];
                }
                else {
                    scan_list->target[cind]->cur.s6addr16[i] =
                        htons(ntohs(scan_list->target[cind]->cur.s6addr16[i]) + 1);
                    return (TRUE);
                }
            }
        }
    }

    return (TRUE);
}

/*
 * Function: print_scan_entries()
 *
 * Print address ranges to scan
 */

int print_scan_entries(struct scan_list *scan) {
    unsigned int i, j;

    for (i = 0; i < scan->ntarget; i++) {
        for (j = 0; j < 8; j++) {
            if ((scan->target[i])->start.s6addr16[j] == (scan->target[i])->end.s6addr16[j])
                printf("%x", ntohs((scan->target[i])->start.s6addr16[j]));
            else
                printf("%x-%x", ntohs((scan->target[i])->start.s6addr16[j]), ntohs((scan->target[i])->end.s6addr16[j]));

            if (j < 7)
                printf(":");
            else
                puts("");
        }
    }

    return (1);
}

/*
 * Function: load_ipv4mapped32_prefixes()
 *
 * Generate scan_entry's for IPv4-mapped (32-bits) addresses
 */

int load_ipv4mapped32_entries(struct scan_list *scan, struct scan_entry *dst, struct prefix4_entry *v4host) {
    unsigned int i;
    uint32_t mask32;
    struct scan_entry dummy;

    dummy.start = dst->start;

    for (i = 4; i <= 5; i++)
        dummy.start.s6addr16[i] = htons(0);

    dummy.start.s6addr16[6] = htons((uint16_t)(ntohl(v4host->ip.s_addr) >> 16));
    dummy.start.s6addr16[7] = htons((uint16_t)(ntohl(v4host->ip.s_addr) & 0x0000ffff));
    dummy.cur = dummy.start;

    dummy.end = dst->end;

    for (i = 4; i <= 7; i++)
        dummy.end.s6addr16[i] = dummy.start.s6addr16[i];

    mask32 = 0xffffffff;

    for (i = 0; i < v4host->len; i++)
        mask32 = mask32 << 1;

    for (i = 0; i < v4host->len; i++)
        mask32 = mask32 >> 1;

    dummy.end.s6addr16[6] = dummy.end.s6addr16[6] | htons((uint16_t)(mask32 >> 16));
    dummy.end.s6addr16[7] = dummy.end.s6addr16[7] | htons((uint16_t)(mask32 & 0x0000ffff));

    return (add_to_scan_list(scan, &dummy));
}

/*
 * Function: load_ipv4mapped64_prefixes()
 *
 * Generate scan_entry's for IPv4-mapped (64-bits) addresses
 */

int load_ipv4mapped64_entries(struct scan_list *scan, struct scan_entry *dst, struct prefix4_entry *v4host) {
    unsigned int i;
    uint32_t mask32;
    struct scan_entry dummy;

    dummy.start = dst->start;

    dummy.start.s6addr16[4] = htons((uint16_t)(ntohl(v4host->ip.s_addr) >> 24));
    dummy.start.s6addr16[5] = htons(((uint16_t)(ntohl(v4host->ip.s_addr) >> 16)) & 0x00ff);
    dummy.start.s6addr16[6] = htons((uint16_t)((ntohl(v4host->ip.s_addr) >> 8) & 0x000000ff));
    dummy.start.s6addr16[7] = htons((uint16_t)(ntohl(v4host->ip.s_addr) & 0x000000ff));
    dummy.cur = dummy.start;

    dummy.end = dst->end;

    for (i = 4; i <= 7; i++)
        dummy.end.s6addr16[i] = dummy.start.s6addr16[i];

    mask32 = 0xffffffff;

    for (i = 0; i < v4host->len; i++)
        mask32 = mask32 << 1;

    for (i = 0; i < v4host->len; i++)
        mask32 = mask32 >> 1;

    dummy.end.s6addr16[4] = dummy.end.s6addr16[4] | htons((uint16_t)(mask32 >> 24));
    dummy.end.s6addr16[5] = dummy.end.s6addr16[5] | htons((uint16_t)(mask32 >> 16 & 0x000000ff));
    dummy.end.s6addr16[6] = dummy.end.s6addr16[6] | htons((uint16_t)(mask32 >> 8 & 0x000000ff));
    dummy.end.s6addr16[7] = dummy.end.s6addr16[7] | htons((uint16_t)(mask32 & 0x000000ff));

    for (i = 4; i <= 7; i++) {
        dummy.start.s6addr16[i] = htons(dec_to_hex(ntohs(dummy.start.s6addr16[i])));
        dummy.end.s6addr16[i] = htons(dec_to_hex(ntohs(dummy.end.s6addr16[i])));
    }

    return (add_to_scan_list(scan, &dummy));
}

/*
 * Function: load_knownprefix_entries()
 *
 * Generate prefix_entry's for known prefixes (populate the prefix_list)
 */

int load_knownprefix_entries(struct scan_list *scan_list, struct scan_list *prefix_list, FILE *fp) {
    unsigned int i;
    int r;
    char line[MAX_LINE_SIZE], *ptr, *charptr, *charstart, *charend, *lastcolon;
    char rangestart[MAX_RANGE_STR_LEN + 1], rangeend[MAX_RANGE_STR_LEN + 1];
    struct prefix_entry prefix;
    struct scan_entry dummy;

    while (fgets(line, sizeof(line), fp) != NULL) {
        r = read_prefix(line, Strnlen(line, MAX_LINE_SIZE), &ptr);

        if (r == 1) {
            if ((ranges = address_contains_ranges(ptr)) == 1) {
                charptr = ptr;
                charstart = rangestart;
                charend = rangeend;
                lastcolon = charend;

                while (*charptr && (ptr - charptr) <= MAX_RANGE_STR_LEN) {
                    if (*charptr != '-') {
                        *charstart = *charptr;
                        *charend = *charptr;
                        charstart++;
                        charend++;

                        if (*charptr == ':')
                            lastcolon = charend;

                        charptr++;
                    }
                    else {
                        charend = lastcolon;
                        charptr++;

                        while (*charptr && (ptr - charptr) <= MAX_RANGE_STR_LEN && *charptr != ':' && *charptr != '-') {
                            *charend = *charptr;
                            charend++;
                            charptr++;
                        }
                    }
                }

                *charstart = 0;
                *charend = 0;
                tgt_range_f = TRUE;

                if (scan_list->ntarget <= scan_list->maxtarget) {

                    if (inet_pton(AF_INET6, rangestart, &(dummy.start)) <= 0) {
                        if (verbose_f > 1)
                            puts("inet_pton(): Error converting IPv6 address from presentation to network format");

                        return (0);
                    }

                    if (inet_pton(AF_INET6, rangeend, &(dummy.end)) <= 0) {
                        if (verbose_f > 1)
                            puts("inet_pton(): Error converting IPv6 address from presentation to network format");

                        return (0);
                    }

                    dummy.cur = dummy.start;

                    /* Check whether the start address is smaller than the end address */
                    for (i = 0; i < 7; i++)
                        if (ntohs(dummy.start.s6addr16[i]) > ntohs(dummy.end.s6addr16[i])) {
                            if (verbose_f > 1)
                                puts("Error in Destination Address range: Start address larger than end address!");

                            return (0);
                        }

                    if (IN6_IS_ADDR_MULTICAST(&(dummy.start.in6_addr))) {
                        if (verbose_f > 1)
                            puts("scan6: Remote scan cannot target a multicast address");

                        return (0);
                    }

                    if (IN6_IS_ADDR_MULTICAST(&(dummy.end.in6_addr))) {
                        if (verbose_f > 1)
                            puts("scan6: Remote scan cannot target a multicast address");

                        return (0);
                    }

                    if (add_to_scan_list(scan_list, &dummy) == FALSE)
                        return (FALSE);
                }
                else {
                    /*
                       If the number of "targets" has already been exceeded, it doesn't make sense to continue further,
                       since there wouldn't be space for any specific target types
                     */
                    if (verbose_f > 1)
                        puts("Too many targets!");

                    return (0);
                }

                if (prefix_list->ntarget <= prefix_list->maxtarget) {
                    if ((prefix_list->target[prefix_list->ntarget] = malloc(sizeof(struct scan_entry))) == NULL) {
                        if (verbose_f > 1)
                            puts("scan6: Not enough memory");

                        return (0);
                    }

                    /* Copy the recently added target to our prefix list */
                    *(prefix_list->target[prefix_list->ntarget]) = dummy;
                    prefix_list->ntarget++;
                }
                else {
                    /*
                       If the number of "targets" has already been exceeded, it doesn't make sense to continue further,
                       since there wouldn't be space for any specific target types
                     */
                    if (verbose_f > 1)
                        puts("Too many targets!");

                    return (0);
                }
            }
            else if (ranges == 0) {
                if ((charptr = strtok_r(ptr, "/", &lasts)) == NULL) {
                    if (verbose_f > 1)
                        puts("Error in Destination Address");

                    return (0);
                }

                if (inet_pton(AF_INET6, charptr, &(prefix.ip6)) <= 0) {
                    if (verbose_f > 1)
                        puts("inet_pton(): Destination Address not valid");

                    return (0);
                }

                if ((charptr = strtok_r(NULL, " ", &lasts)) != NULL) {
                    prefix.len = atoi(charptr);

                    if (prefix.len > 128) {
                        if (verbose_f > 1)
                            puts("Prefix length error in IPv6 Destination Address");

                        return (0);
                    }

                    sanitize_ipv6_prefix(&(prefix.ip6), prefix.len);
                }
                else {
                    prefix.len = 128;
                }

                if (prefix_list->ntarget <= prefix_list->maxtarget) {
                    if ((prefix_list->target[prefix_list->ntarget] = malloc(sizeof(struct scan_entry))) == NULL) {
                        if (verbose_f)
                            puts("scan6: Not enough memory");

                        return (0);
                    }

                    prefix_to_scan(&prefix, prefix_list->target[prefix_list->ntarget]);

                    if (IN6_IS_ADDR_MULTICAST(&((prefix_list->target[prefix_list->ntarget])->start.in6_addr))) {
                        if (verbose_f > 1)
                            puts("scan6: Remote scan cannot target a multicast address");

                        return (0);
                    }

                    if (IN6_IS_ADDR_MULTICAST(&((prefix_list->target[prefix_list->ntarget])->end.in6_addr))) {
                        if (verbose_f > 1)
                            puts("scan6: Remote scan cannot target a multicast address");

                        return (0);
                    }

                    prefix_list->ntarget++;
                }
                else {
                    /*
                       If the number of "targets" has already been exceeded, it doesn't make sense to continue further,
                       since there wouldn't be space for any specific target types
                     */
                    if (verbose_f > 1)
                        puts("Too many targets!");

                    return (0);
                }
            }

            dst_f = TRUE;
        }
        else if (r == -1) {
            if (verbose_f) {
                printf("Error in 'known prefixes' file %s\n", knownprefixesfile);
            }

            fclose(fp);
            return (0);
        }
    }

    return (1);
}

/*
 * Function: load_knowniid_entries()
 *
 * Generate scan_entry's for known Interface IDs
 */

int load_knowniid_entries(struct scan_list *scan, struct scan_list *prefix, struct prefix_list *iid) {
    unsigned int i, j, k;
    struct scan_entry dummy;

    for (i = 0; i < iid->nprefix; i++) {
        for (j = 0; j < prefix->ntarget; j++) {
            dummy.start = (prefix->target[j])->start;

            for (k = 2; k <= 3; k++)
                dummy.start.in6_addr.s6_addr32[k] = (iid->prefix[i])->ip6.s6_addr32[k];

            dummy.cur = dummy.start;

            dummy.end = (prefix->target[j])->end;

            for (k = 2; k <= 3; k++)
                dummy.end.in6_addr.s6_addr32[k] = (iid->prefix[i])->ip6.s6_addr32[k];

            if (add_to_scan_list(scan, &dummy) == FALSE)
                return (FALSE);
        }
    }

    return (TRUE);
}

/*
 * Function: load_knowniidfile_entries()
 *
 * Generate scan_entry's for known Interface IDs
 */

int load_knowniidfile_entries(struct scan_list *scan, struct scan_list *prefix, FILE *fp) {
    unsigned int i;
    int r;
    char line[MAX_LINE_SIZE];
    struct in6_addr iid;
    struct scan_entry dummy;

    while (fgets(line, sizeof(line), fp) != NULL) {
        r = read_ipv6_address(line, Strnlen(line, MAX_LINE_SIZE), &iid);

        if (r == 1) {
            for (i = 0; i < prefix->ntarget; i++) {
                dummy.start = (prefix->target[i])->start;

                for (j = 2; j <= 3; j++)
                    dummy.start.in6_addr.s6_addr32[j] = iid.s6_addr32[j];

                dummy.cur = dummy.start;

                dummy.end = (prefix->target[i])->end;

                for (j = 2; j <= 3; j++)
                    dummy.end.in6_addr.s6_addr32[j] = iid.s6_addr32[j];

                if (add_to_scan_list(scan, &dummy) == FALSE)
                    return (FALSE);
            }
        }
        else if (r == -1) {
            if (verbose_f) {
                printf("Error in 'known IIDs' file %s\n", knowniidsfile);
            }

            fclose(fp);
            return (0);
        }
    }

    return (1);
}

/*
 * Function: load_embeddedport_entries()
 *
 * Generate scan_entry's for IPv6 addresses with embedded service ports
 */

int load_embeddedport_entries(struct scan_list *scan, struct scan_entry *dst) {
    unsigned int i;
    struct scan_entry dummy;

    for (i = 0; i < (sizeof(service_ports_hex) / sizeof(uint16_t)); i++) {
        dummy.start = dst->start;
        dummy.start.s6addr16[4] = htons(0);
        dummy.start.s6addr16[5] = htons(0);
        dummy.start.s6addr16[6] = htons(0);
        dummy.start.s6addr16[7] = htons(service_ports_hex[i]);
        dummy.cur = dummy.start;

        dummy.end = dst->end;
        dummy.end.s6addr16[4] = htons(0);
        dummy.end.s6addr16[5] = htons(0);
        dummy.end.s6addr16[6] = htons(EMBEDDED_PORT_2ND_WORD);
        dummy.end.s6addr16[7] = htons(service_ports_hex[i]);

        if (add_to_scan_list(scan, &dummy) == FALSE)
            return (FALSE);

        dummy.start = dst->start;
        dummy.start.s6addr16[4] = htons(0);
        dummy.start.s6addr16[5] = htons(0);
        dummy.start.s6addr16[6] = htons(service_ports_hex[i]);
        dummy.start.s6addr16[7] = htons(0);
        dummy.cur = dummy.start;

        dummy.end = dst->end;
        dummy.end.s6addr16[4] = htons(0);
        dummy.end.s6addr16[5] = htons(0);
        dummy.end.s6addr16[6] = htons(service_ports_hex[i]);
        dummy.end.s6addr16[7] = htons(EMBEDDED_PORT_2ND_WORD);

        if (add_to_scan_list(scan, &dummy) == FALSE)
            return (FALSE);
    }

    for (i = 0; i < (sizeof(service_ports_dec) / sizeof(uint16_t)); i++) {
        dummy.start = dst->start;
        dummy.start.s6addr16[4] = htons(0);
        dummy.start.s6addr16[5] = htons(0);
        dummy.start.s6addr16[6] = htons(0);
        dummy.start.s6addr16[7] = htons(service_ports_dec[i]);
        dummy.cur = dummy.start;

        dummy.end = dst->end;
        dummy.end.s6addr16[4] = htons(0);
        dummy.end.s6addr16[5] = htons(0);
        dummy.end.s6addr16[6] = htons(EMBEDDED_PORT_2ND_WORD);
        dummy.end.s6addr16[7] = htons(service_ports_dec[i]);

        if (add_to_scan_list(scan, &dummy) == FALSE)
            return (FALSE);

        dummy.start = dst->start;
        dummy.start.s6addr16[4] = htons(0);
        dummy.start.s6addr16[5] = htons(0);
        dummy.start.s6addr16[6] = htons(service_ports_dec[i]);
        dummy.start.s6addr16[7] = htons(0);
        dummy.cur = dummy.start;

        dummy.end = dst->end;
        dummy.end.s6addr16[4] = htons(0);
        dummy.end.s6addr16[5] = htons(0);
        dummy.end.s6addr16[6] = htons(service_ports_dec[i]);
        dummy.end.s6addr16[7] = htons(EMBEDDED_PORT_2ND_WORD);

        if (add_to_scan_list(scan, &dummy) == FALSE)
            return (FALSE);
    }

    return (TRUE);
}

/*
 * Function: load_lowbyte_entries()
 *
 * Generate scan_entry's for low-byte addresses
 */

int load_lowbyte_entries(struct scan_list *scan, struct scan_entry *dst) {
    unsigned int i;
    struct scan_entry dummy;

    dummy.start = dst->start;

    for (i = 4; i <= 7; i++)
        dummy.start.s6addr16[i] = htons(0);

    dummy.cur = dummy.start;
    dummy.end = dst->end;

    for (i = 4; i <= 5; i++)
        dummy.end.s6addr16[i] = htons(0);

    dummy.end.s6addr16[6] = htons(LOW_BYTE_2ND_WORD_UPPER);
    dummy.end.s6addr16[7] = htons(LOW_BYTE_1ST_WORD_UPPER);

    if (add_to_scan_list(scan, &dummy) == FALSE)
        return (FALSE);

    return (TRUE);
}

/*
 * Function: load_oui_entries()
 *
 * Generate scan_entry's based on a specific IEEE OUI
 */

int load_oui_entries(struct scan_list *scan, struct scan_entry *dst, struct ether_addr *oui) {
    unsigned int i;
    struct scan_entry dummy;

    generate_slaac_address(&(dst->start.in6_addr), oui, &(dummy.start.in6_addr));
    dummy.cur = dummy.start;

    for (i = 0; i < 4; i++)
        dummy.end.s6addr16[i] = dst->end.s6addr16[i];

    for (i = 4; i <= 7; i++)
        dummy.end.s6addr16[i] = dummy.start.s6addr16[i];

    /*
       The three low-order bytes must vary from 0x000000 to 0xffffff
     */
    dummy.end.s6addr16[6] = dummy.end.s6addr16[6] | htons(0x00ff);
    dummy.end.s6addr16[7] = dummy.end.s6addr16[7] | htons(0xffff);

    if (add_to_scan_list(scan, &dummy) == FALSE)
        return (FALSE);

    return (TRUE);
}

/*
 * Function: load_vm_entries()
 *
 * Generate scan_entry's based on virtualization prefixes, and scan modes
 */

int load_vm_entries(struct scan_list *scan, struct scan_entry *dst, struct prefix4_entry *v4host) {
    unsigned int i;
    uint32_t mask32;
    struct ether_addr ether;
    struct scan_entry dummy;

    /* VirtualBOX */
    if (vm_vbox_f) {
        if (ether_pton("08:00:27:00:00:00", &ether, sizeof(ether)) == FALSE) {
            if (verbose_f)
                puts("scan6: ether_pton(): Error converting Ethernet Address to presentation format");

            return (0);
        }

        generate_slaac_address(&(dst->start.in6_addr), &ether, &(dummy.start.in6_addr));
        dummy.cur = dummy.start;
        dummy.end = dst->end;

        for (i = 4; i <= 7; i++)
            dummy.end.s6addr16[i] = dummy.start.s6addr16[i];

        /*
           The three low-order bytes must vary from 0x000000 to 0xffffff
         */
        dummy.end.s6addr16[6] = dummy.end.s6addr16[6] | htons(0x00ff);
        dummy.end.s6addr16[7] = dummy.end.s6addr16[7] | htons(0xffff);

        if (add_to_scan_list(scan, &dummy) == FALSE)
            return (FALSE);
    }

    if (vm_vmware_vsphere_f) {
        /*
           Add scan entry for VMWare vSphere. First, include addresses assigned vy vCenter Server.
           Then include addresses assigned by the ESXi host.
 */

        /*
       By default, MAC addresses assigned by the vCenter server use the OUI
       00:50:56, and have the format 00:50:56:XX:YY:ZZ, where XX is
       calculated as (0x80 + vCenter Server ID (in the range 0x00-0x3F)),
       and XX and YY are random two-digit hexadecimal numbers.  Thus, the
       possible IID range is 00:50:56:80:00:00-00:50:56:BF:FF:FF, and
       therefore the search space for the resulting SLAAC addresses will be
       24 bits.
         */

        if (ether_pton("00:50:56:80:00:00", &ether, sizeof(ether)) == FALSE) {
            if (verbose_f)
                puts("scan6: ether_pton(): Error converting Ethernet Address to presentation format");

            return (0);
        }

        generate_slaac_address(&(dst->start.in6_addr), &ether, &(dummy.start.in6_addr));
        dummy.cur = dummy.start;

        if (ether_pton("00:50:56:BF:FF:FF", &ether, sizeof(ether)) == FALSE) {
            if (verbose_f)
                puts("scan6: ether_pton(): Error converting Ethernet Address to presentation format");

            return (0);
        }

        generate_slaac_address(&(dst->end.in6_addr), &ether, &(dummy.end.in6_addr));

        if (add_to_scan_list(scan, &dummy) == FALSE)
            return (FALSE);

        if (ether_pton("00:0C:29:00:00:00", &ether, sizeof(ether)) == FALSE) {
            if (verbose_f)
                puts("scan6: ether_pton(): Error converting Ethernet Address to presentation format");

            return (0);
        }

        generate_slaac_address(&(dst->start.in6_addr), &ether, &(dummy.start.in6_addr));
        dummy.cur = dummy.start;
        dummy.end = dst->end;

        for (i = 4; i <= 7; i++)
            dummy.end.s6addr16[i] = dummy.start.s6addr16[i];

        /*
           The three low-order bytes must vary from 0x000000 to 0xffffff
         */
        dummy.end.s6addr16[6] = dummy.end.s6addr16[6] | htons(0x00ff);
        dummy.end.s6addr16[7] = dummy.end.s6addr16[7] | htons(0xffff);

        if (add_to_scan_list(scan, &dummy) == FALSE)
            return (FALSE);
    }

    if (vm_vmware_esx_f) {
        /* Add scan entry for VMWare ESX Server */

        if (ether_pton("00:05:69:00:00:00", &ether, sizeof(ether)) == FALSE) {
            if (verbose_f)
                puts("scan6: ether_pton(): Error converting Ethernet Address to presentation format");

            return (0);
        }

        generate_slaac_address(&(dst->start.in6_addr), &ether, &(dummy.start.in6_addr));
        dummy.cur = dummy.start;
        dummy.end = dst->end;

        for (i = 4; i <= 7; i++)
            dummy.end.s6addr16[i] = dummy.start.s6addr16[i];

        /*
           If we know the host system IPv4 address, we can narrow down the search space. Otherwise
           the three low-order bytes must vary in the range 0x000000 to 0xffffff
         */
        if (v4hostaddr_f) {
            if (v4hostprefix_f) {
                mask32 = 0xffffffff;

                for (i = 0; i < v4host->len; i++)
                    mask32 = mask32 >> 1;
            }
            else {
                mask32 = 0;
            }

            dummy.start.s6addr16[6] = dummy.start.s6addr16[6] | htons((ntohl(v4host->ip.s_addr) & 0x0000ff00) >> 8);
            dummy.start.s6addr16[7] = dummy.start.s6addr16[7] | htons((ntohl(v4host->ip.s_addr) & 0x000000ff) << 8);

            dummy.end.s6addr16[6] = dummy.end.s6addr16[6] | htons((ntohl(v4host->ip.s_addr) & 0x0000ff00) >> 8) |
                                    htonl((mask32 & 0x0000ff00) >> 8);
            dummy.end.s6addr16[7] = dummy.end.s6addr16[7] | htons((ntohl(v4host->ip.s_addr) & 0x000000ff) << 8) |
                                    htonl((mask32 & 0x000000ff) << 8) | htons(0x00ff);
        }
        else {
            dummy.end.s6addr16[6] = dummy.end.s6addr16[6] | htons(0x00ff);
            dummy.end.s6addr16[7] = dummy.end.s6addr16[7] | htons(0xffff);
        }

        if (add_to_scan_list(scan, &dummy) == FALSE)
            return (FALSE);
    }

    if (vm_vmwarem_f) {
        if (ether_pton("00:50:56:00:00:00", &ether, sizeof(ether)) == FALSE) {
            if (verbose_f)
                puts("scan6: ether_pton(): Error converting Ethernet Address to presentation format");

            return (0);
        }

        generate_slaac_address(&(dst->start.in6_addr), &ether, &(dummy.start.in6_addr));
        dummy.cur = dummy.start;
        dummy.end = dst->end;

        for (i = 4; i <= 7; i++)
            dummy.end.s6addr16[i] = dummy.start.s6addr16[i];

        /*
           The three low-order bytes must vary from 0x000000 to 0x3fffff
         */
        dummy.end.s6addr16[6] = dummy.end.s6addr16[6] | htons(0x003f);
        dummy.end.s6addr16[7] = dummy.end.s6addr16[7] | htons(0xffff);

        if (add_to_scan_list(scan, &dummy) == FALSE)
            return (FALSE);
    }

    return (TRUE);
}

/*
 * Function: load_vendor_entries()
 *
 * Lookup vendor's IEEE OUIs
 */

int load_vendor_entries(struct scan_list *scan, struct scan_entry *dst, char *vendor) {
    FILE *fp;
    struct ether_addr aux_oui, oui_list[MAX_IEEE_OUIS];
    char oui_ascii[ETHER_ADDR_PLEN];
    char *oui_end = ":00:00:00";
    char *oui_hex_string = "(hex)";
    char line[MAX_IEEE_OUIS_LINE_SIZE];
    char *charptr;
    unsigned int lines = 0, ouis;
    int i;
    struct scan_entry dummy;

    ouis = 0;

    if ((fp = fopen(fname, "r")) == NULL) {
        perror("scan6:");
        return (0);
    }

    while (ouis <= MAX_IEEE_OUIS && fgets(line, MAX_IEEE_OUIS_LINE_SIZE, fp) != NULL) {
        /*
           We ship a minimalistic IEEE OUI "database" containing only the first "line" for each IEEE OUI.
           However, in order to handle the case of users employing the OUI database directly downloaded
           from the IEEE site, we perform a simple check to skip those lines that do not start with
           the pattern XX-XX-XX
         */

        if ((lines = Strnlen(line, MAX_IEEE_OUIS_LINE_SIZE)) <= 9)
            continue;

        if (line[2] != '-' || line[5] != '-' || line[8] != ' ')
            continue;

        charptr = (char *)line + 9;

        /* Skip any whitespaces */
        while (charptr < ((char *)line + lines) && *charptr == ' ')
            charptr++;

        /*
           The database we ship contains the complete first line for each OUI, which includes the string "(hex)".
           If we find that string, we should skip it.
         */

        if ((((char *)line + lines) - charptr) >= OUI_HEX_STRING_SIZE) {

            /* If we find the "(hex)" string, we must skip it */
            if (memcmp(oui_hex_string, charptr, OUI_HEX_STRING_SIZE) == 0)
                charptr += OUI_HEX_STRING_SIZE;

            /* Now we mst skip any whitespaces between the "(hex)" string and the vendor name */
            while (charptr < ((char *)line + lines) && *charptr == ' ')
                charptr++;

            if (charptr >= ((char *)line + lines))
                continue;
        }

        if (match_strings(vendor, charptr)) {
            /* Copy the actual OUI to our array */
            memcpy(oui_ascii, line, 8);

            /* Patch the dashes with colons (i.e., s/-/:/ */
            oui_ascii[2] = ':';
            oui_ascii[5] = ':';

            /* zero-terminate the string */
            oui_ascii[8] = 0;

            strncat(oui_ascii, oui_end, ETHER_ADDR_PLEN - Strnlen(oui_ascii, sizeof(oui_ascii)) - 1);

            if (ether_pton(oui_ascii, &oui_list[ouis], sizeof(oui_list[ouis])) == FALSE) {
                if (verbose_f)
                    puts("scan6: ether_pton(): Error converting Ethernet Address to presentation format");

                return (0);
            }

            ouis++;
        }
    }

    if (ferror(fp)) {
        if (verbose_f)
            perror("scan6:");

        return (0);
    }

    fclose(fp);

    /*
     * If the target is a list of IEEE OUIs, we want to start trying from the newest OUIs,
     * to the older OUIs. The older OUIs are left for the end, since they have probably been
     * used for NICs used by legacy systems that are no longer online. Similarly, the very
     * newest OUI is left for the end, since it has probably not been used (yet) for any
     * commercialized Network Interface cards.
     */

    if (sort_ouis_f && ouis >= 4) {
        aux_oui = oui_list[ouis - 1];

        for (i = ouis - 2; i >= 1; i--) {
            oui_list[i + 1] = oui_list[i];
        }

        oui_list[1] = aux_oui;
    }

    if (ouis == 0) {
        if (verbose_f)
            puts("scan6: Couldn't find any IEEE OUI for the target vendor");

        return (0);
    }

    /* We walk the IEEE OUI list backwards: from newer to older OUIs */
    for (i = ouis - 1; i >= 0; i--) {
        if (scan->ntarget >= scan->maxtarget)
            return (0);

        generate_slaac_address(&(dst->start.in6_addr), &oui_list[i], &(dummy.start.in6_addr));
        dummy.cur = dummy.start;
        generate_slaac_address(&(dst->end.in6_addr), &oui_list[i], &(dummy.end.in6_addr));

        /*
           The three low-order bytes must vary from 0x000000 to 0xffffff
         */
        dummy.end.s6addr16[6] = dummy.end.s6addr16[6] | htons(0x00ff);
        dummy.end.s6addr16[7] = dummy.end.s6addr16[6] | htons(0xffff);

        if (add_to_scan_list(scan, &dummy) == FALSE)
            return (FALSE);
    }

    return (1);
}

/*
 * Function: match_strings()
 *
 * Checks whether one string "matches" within another string
 */

int match_strings(char *buscar, char *buffer) {
    unsigned int buscars, buffers;
    unsigned int i = 0, j = 0;

    buscars = Strnlen(buscar, MAX_IEEE_OUIS_LINE_SIZE);
    buffers = Strnlen(buffer, MAX_IEEE_OUIS_LINE_SIZE);

    if (buscars > buffers)
        return (0);

    while (i <= (buffers - buscars)) {
        j = 0;

        while (j < buscars) {
            if (toupper((int)((unsigned char)buscar[j])) != toupper((int)((unsigned char)buffer[i + j])))
                break;

            j++;
        }

        if (j >= buscars)
            return (1);

        i++;
    }

    return (0);
}

/*
 * Function: load_bruteforce_entries()
 *
 * Converts a target prefix to scan_entry format
 */

int load_bruteforce_entries(struct scan_list *scan, struct scan_entry *dst) {
    if (scan->ntarget >= scan->maxtarget)
        return (0);

    return (add_to_scan_list(scan, dst));
}

/*
 * Function: load_smart_entries()
 *
 * Loads targets based on IID type
 */

int load_smart_entries(struct scan_list *scan, struct scan_list *smart) {
    struct decode6 decode;
    unsigned int i, j;
    struct scan_entry dummy;

    for (i = 0; i < smart->ntarget; i++) {
        decode.ip6 = (smart->target[i])->start.in6_addr;
        decode_ipv6_address(&decode);

        dummy = *(smart->target[i]);

        switch (decode.iidtype) {
        case IID_MACDERIVED:
            dummy.start.s6addr32[3] = dummy.start.s6addr32[3] & htonl(0xff000000);
            dummy.end = dummy.start;
            dummy.end.s6addr32[3] = dummy.end.s6addr32[3] | htonl(0x00ffffff);
            dummy.cur = dummy.start;

            if (add_to_scan_list(scan, &dummy) == FALSE)
                return (FALSE);
            break;

        case IID_ISATAP:
            dummy.start.s6addr32[3] = dummy.start.s6addr32[3] & htonl(0xffff0000);
            dummy.end = dummy.start;
            dummy.end.s6addr32[3] = dummy.end.s6addr32[3] | htonl(0x0000ffff);
            dummy.cur = dummy.start;

            if (add_to_scan_list(scan, &dummy) == FALSE)
                return (FALSE);
            break;

        case IID_LOWBYTE:
        case IID_EMBEDDEDPORT:
        case IID_EMBEDDEDPORTREV:
        case IID_UNSPECIFIED:
        case IID_RANDOM:
            /*
               Embedded-port addresses are rather unlikely, and usully a false-positive resulting from low-byte
               addresses. Hence we scan for low-byte addresses when "embedded port" addresses are detected.
             */

            for (j = 4; j <= 7; j++)
                dummy.start.s6addr16[j] = 0;

            dummy.end = dummy.start;
            dummy.end.s6addr16[6] = htons(LOW_BYTE_2ND_WORD_UPPER);
            dummy.end.s6addr16[7] = htons(LOW_BYTE_1ST_WORD_UPPER);
            dummy.cur = dummy.start;

            if (add_to_scan_list(scan, &dummy) == FALSE)
                return (FALSE);
            break;

        case IID_EMBEDDEDIPV4:
            switch (decode.iidsubtype) {
            case IID_EMBEDDEDIPV4_32:
                dummy.start.s6addr32[2] = htonl(0x00000000);
                dummy.start.s6addr32[3] = dummy.start.s6addr32[3] & htonl(0xffff0000);
                dummy.end = dummy.start;
                dummy.end.s6addr32[3] = dummy.end.s6addr32[3] | htonl(0x0000ffff);
                dummy.cur = dummy.start;

                if (add_to_scan_list(scan, &dummy) == FALSE)
                    return (FALSE);
                break;

            case IID_EMBEDDEDIPV4_64:
                dummy.start.s6addr32[2] = dummy.start.s6addr32[2] & htonl(0x00ff00ff);
                dummy.start.s6addr32[3] = htonl(0x00000000);
                dummy.end = dummy.start;
                dummy.end.s6addr32[3] = dummy.end.s6addr32[3] | htonl(0x00ff00ff);
                dummy.cur = dummy.start;

                if (add_to_scan_list(scan, &dummy) == FALSE)
                    return (FALSE);
                break;
            }

            break;

        case IID_PATTERN_BYTES:
            dummy.end = dummy.start;

            for (j = 8; j < 16; j++)
                dummy.end.s6addr[j] = (dummy.start.s6addr[j]) ? 0xff : 0x00;

            for (j = 8; j < 16; j++)
                dummy.start.s6addr[j] = 0x00;

            dummy.cur = dummy.start;

            if (add_to_scan_list(scan, &dummy) == FALSE)
                return (FALSE);
            break;

        case IID_TEREDO_RFC5991:
        case IID_TEREDO_RFC4380:
        case IID_TEREDO_UNKNOWN:
            for (j = 8; j <= 11; j++)
                dummy.start.s6addr[j] = 0x00;

            dummy.end = dummy.start;

            dummy.start.s6addr[8] = 0xbc;

            for (j = 9; j <= 11; j++)
                dummy.start.s6addr[8] = 0xff;

            dummy.cur = dummy.start;

            if (add_to_scan_list(scan, &dummy) == FALSE)
                return (FALSE);
            break;

        default:
            /* By default we scan for low-byte-addresses (same code as above) */
            for (j = 8; j < 16; j++)
                dummy.start.s6addr[j] = 0x00;

            for (j = 8; j < 16; j++)
                dummy.end.s6addr[j] = 0xff;

            dummy.cur = dummy.start;

            if (add_to_scan_list(scan, &dummy) == FALSE)
                return (FALSE);
            break;
        }
    }

    return (TRUE);
}

/*
 * Function: prefix_to_scan()
 *
 * Converts a target prefix to scan_entry format
 */

void prefix_to_scan(struct prefix_entry *pref, struct scan_entry *scan) {
    uint32_t mask;
    uint8_t words;
    unsigned int i;

    scan->start.in6_addr = pref->ip6;
    scan->cur.in6_addr = pref->ip6;
    words = pref->len / 32;

    for (i = 0; i < words; i++)
        (scan->end).in6_addr.s6_addr32[i] = (pref->ip6).s6_addr32[i];

    for (i = (words + 1); i < 4; i++) {
        (scan->end).in6_addr.s6_addr32[i] = htonl(0xffffffff);
    }

    mask = 0xffffffff;

    for (i = 0; i < (pref->len % 32); i++)
        mask = mask >> 1;

    if (pref->len % 32)
        (scan->end).in6_addr.s6_addr32[words] = (scan->start).in6_addr.s6_addr32[words] | htonl(mask);
}

/*
 * Function: usage()
 *
 * Prints the syntax of the scan6 tool
 */

void usage(void) {
    puts("usage: scan6 (-L | -d) [-i INTERFACE] [-s SRC_ADDR[/LEN] | -f] \n"
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

void print_help(void) {
    puts(SI6_TOOLKIT);
    puts("scan6: An advanced IPv6 scanning tool\n");
    usage();

    puts("\nOPTIONS:\n"
         "  --interface, -i             Network interface\n"
         "  --src-addr, -s              IPv6 Source Address\n"
         "  --dst-addr, -d              IPv6 Destination Range or Prefix\n"
         "  --prefixes-file, -m         Prefixes file\n"
         "  --link-src-addr, -S         Link-layer Destination Address\n"
         "  --probe-type, -p            Probe type for host scanning {echo, unrec, all}\n"
         "  --port-scan, -j             Port scan type and range {tcp,udp}:port_low[-port_hi]\n"
         "  --tcp-scan-type, -G         TCP port-scanning type {syn,fin,null,xmas,ack}\n"
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
         " Programmed by Fernando Gont for SI6 Networks <https://www.si6networks.com>\n"
         " Please send any bug reports to <fgont@si6networks.com>\n");
}

/*
 * Function: send_probe_remote()
 *
 * Sends a probe packet to a remote target
 */

int send_probe_remote(struct iface_data *idata, struct scan_list *scan, struct in6_addr *srcaddr, unsigned char type) {
    unsigned char *ptr;
    unsigned int i;
    struct ether_header *ether;
    struct dlt_null *dlt_null;
#if defined(__linux__)
    struct sll_linux *sll_linux;
#endif
    unsigned char *v6buffer;
    struct ip6_hdr *ipv6;
    struct tcp_hdr *tcp;
    struct ip6_dest *destopth;
    struct ip6_option *opt;
    uint32_t *uint32;

    ether = (struct ether_header *)buffer;
    dlt_null = (struct dlt_null *)buffer;
#if defined(__linux__)
    sll_linux = (struct sll_linux *)buffer;
#endif
    v6buffer = buffer + idata->linkhsize;
    ipv6 = (struct ip6_hdr *)v6buffer;

    if (idata->type == DLT_EN10MB) {
        ether->ether_type = htons(ETHERTYPE_IPV6);

        if (!(idata->flags & IFACE_LOOPBACK)) {
            ether->src = idata->ether;

            if (!onlink_f) {
                ether->dst = idata->nhhaddr;
            }
            else {
                if (ipv6_to_ether(idata->pfd, idata, &(scan->target[scan->ctarget])->cur.in6_addr,
                                  &(idata->hdstaddr)) != 1) {
                    return (1);
                }
            }
        }
    }
    else if (idata->type == DLT_NULL) {
        dlt_null->family = PF_INET6;
    }
#if defined(__OpenBSD__)
    else if (idata->type == DLT_LOOP) {
        dlt_null->family = htonl(PF_INET6);
    }
#elif defined(__linux__)
    else if (idata->type == DLT_LINUX_SLL) {
        sll_linux->sll_pkttype = htons(0x0004);
        sll_linux->sll_hatype = htons(0xffff);
        sll_linux->sll_halen = htons(0x0000);
        sll_linux->sll_protocol = htons(ETHERTYPE_IPV6);
    }
#endif

    ipv6->ip6_flow = 0;
    ipv6->ip6_vfc = 0x60;
    ipv6->ip6_hlim = 255;

    /* XXX Double-check this one */
    ipv6->ip6_src =
        idata->srcaddr_f ? (*srcaddr) : *sel_src_addr_ra(idata, &((scan->target[scan->ctarget])->cur.in6_addr));
    ipv6->ip6_dst = (scan->target[scan->ctarget])->cur.in6_addr;

#ifdef DEBUG
    print_ipv6_address("Direccion actual:", &((scan->target[scan->ctarget])->cur.in6_addr));
#endif
    prev_nh = (unsigned char *)&(ipv6->ip6_nxt);

    ptr = (unsigned char *)v6buffer + MIN_IPV6_HLEN;

    switch (type) {
    case PROBE_ICMP6_ECHO:
        *prev_nh = IPPROTO_ICMPV6;

        if ((ptr + sizeof(struct icmp6_hdr) + ICMPV6_ECHO_PAYLOAD_SIZE) > (v6buffer + idata->mtu)) {
            if (idata->verbose_f > 1)
                puts("Packet too large while creating ICMPv6 Echo Request Probe packet");

            return (-1);
        }

        icmp6 = (struct icmp6_hdr *)ptr;
        icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6->icmp6_code = 0;
        icmp6->icmp6_data16[0] = htons(getpid()); /* Identifier */
        icmp6->icmp6_data16[1] = htons(0);        /* Sequence Number */

        ptr = ptr + sizeof(struct icmp6_hdr);

        for (i = 0; i < (ICMPV6_ECHO_PAYLOAD_SIZE >> 2); i++) {
            *(uint32_t *)ptr = random();
            ptr += sizeof(uint32_t);
        }

        ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);
        icmp6->icmp6_cksum = 0;
        icmp6->icmp6_cksum = in_chksum(v6buffer, icmp6, ptr - ((unsigned char *)icmp6), IPPROTO_ICMPV6);
        break;

    case PROBE_UNREC_OPT:
        *prev_nh = IPPROTO_DSTOPTS;

        if ((ptr + sizeof(struct icmp6_hdr) + 8 + ICMPV6_ECHO_PAYLOAD_SIZE) > (v6buffer + idata->mtu)) {
            if (idata->verbose_f > 1)
                puts("Packet too large while creating Unrec. Opt. Probe Packet");

            return (-1);
        }

        destopth = (struct ip6_dest *)ptr;
        destopth->ip6d_len = 0;
        destopth->ip6d_nxt = IPPROTO_ICMPV6;

        ptr = ptr + 2;
        opt = (struct ip6_option *)ptr;
        opt->ip6o_type = 0x80;
        opt->ip6o_len = 4;

        ptr = ptr + 2;
        uint32 = (uint32_t *)ptr;
        *uint32 = random();

        ptr = ptr + 4;
        icmp6 = (struct icmp6_hdr *)ptr;
        icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6->icmp6_code = 0;
        icmp6->icmp6_data16[0] = htons(getpid()); /* Identifier */
        icmp6->icmp6_data16[1] = htons(0);        /* Sequence Number */

        ptr = ptr + sizeof(struct icmp6_hdr);

        for (i = 0; i < (ICMPV6_ECHO_PAYLOAD_SIZE >> 2); i++) {
            *(uint32_t *)ptr = random();
            ptr += sizeof(uint32_t);
        }

        ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);
        icmp6->icmp6_cksum = 0;
        icmp6->icmp6_cksum = in_chksum(v6buffer, icmp6, ptr - ((unsigned char *)icmp6), IPPROTO_ICMPV6);
        break;

    case PROBE_TCP:
        *prev_nh = IPPROTO_TCP;

        if ((ptr + sizeof(struct tcp_hdr)) > (v6buffer + idata->max_packet_size)) {
            if (idata->verbose_f)
                puts("Packet Too Large while inserting TCP header");

            return (0);
        }

        tcp = (struct tcp_hdr *)ptr;
        memset(tcp, 0, sizeof(struct tcp_hdr));

        if (srcport_f)
            tcp->th_sport = htons(srcport);
        else
            tcp->th_sport = htons(1024 + random() % 64512);

        if (dstport_f)
            tcp->th_dport = htons(dstport);
        else
            tcp->th_dport = htons(1 + random() % 1024);

        if (tcpflags_f)
            tcp->th_flags = tcpflags;
        else
            tcp->th_flags = TH_ACK;

        if (tcpflags & TH_ACK)
            tcp->th_ack = htonl(random());
        else
            tcp->th_ack = htonl(0);

        tcp->th_win = htons(4096 * (random() % 9 + 1));

        /* Current version of tcp6 does not support sending TCP options */
        tcp->th_off = sizeof(struct tcp_hdr) >> 2;
        ptr += tcp->th_off << 2;

        if ((ptr + rhbytes) > v6buffer + idata->max_packet_size) {
            puts("Packet Too Large while inserting TCP segment");
            exit(EXIT_FAILURE);
        }

        while (rhbytes >= 4) {
            *(uint32_t *)ptr = random();
            ptr += sizeof(uint32_t);
            rhbytes -= sizeof(uint32_t);
        }

        while (rhbytes > 0) {
            *(uint8_t *)ptr = (uint8_t)random();
            ptr++;
            rhbytes--;
        }

        ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);
        tcp->th_sum = 0;
        tcp->th_sum = in_chksum(v6buffer, tcp, ptr - ((unsigned char *)tcp), IPPROTO_TCP);
        break;
    }

#ifdef DEBUG
    puts("In send_probe_remote(), prior to send");
#endif
    if ((nw = pcap_inject(idata->pfd, buffer, ptr - buffer)) == -1) {
        if (idata->verbose_f)
            printf("pcap_inject(): %s\n", pcap_geterr(idata->pfd));

        return (0);
    }
#ifdef DEBUG
    puts("In send_probe_remote(), after to send");
#endif

    if (nw != (ptr - buffer)) {
        if (idata->verbose_f)
            printf("pcap_inject(): only wrote %d bytes (rather than %lu bytes)\n", nw, (LUI)(ptr - buffer));
        return (0);
    }

    return (1);
}

/*
 * Function: send_pscan_probe()
 *
 * Sends a probe packet to a target port
 */

int send_pscan_probe(struct iface_data *idata, struct scan_list *scan, struct port_list *port_list,
                     struct in6_addr *srcaddr, unsigned char type) {
    unsigned char *ptr;
    struct ether_header *ether;
    struct dlt_null *dlt_null;
#if defined(__linux__)
    struct sll_linux *sll_linux;
#endif
    unsigned char *v6buffer;
    struct ip6_hdr *ipv6;
    struct tcp_hdr *tcp;
    struct udp_hdr *udp;
    unsigned int rhleft;

    ether = (struct ether_header *)buffer;
    dlt_null = (struct dlt_null *)buffer;
#if defined(__linux__)
    sll_linux = (struct sll_linux *)buffer;
#endif
    v6buffer = buffer + idata->linkhsize;
    ipv6 = (struct ip6_hdr *)v6buffer;

    if (idata->type == DLT_EN10MB) {
        ether->ether_type = htons(ETHERTYPE_IPV6);

        if (!(idata->flags & IFACE_LOOPBACK)) {
            ether->src = idata->ether;

            if (!onlink_f) {
                ether->dst = idata->nhhaddr;
            }
            else {
                if (ipv6_to_ether(idata->pfd, idata, &((scan->target[scan->ctarget])->cur.in6_addr),
                                  &(idata->hdstaddr)) != 1) {
                    return (1);
                }
            }
        }
    }
    else if (idata->type == DLT_NULL) {
        dlt_null->family = PF_INET6;
    }
#if defined(__OpenBSD__)
    else if (idata->type == DLT_LOOP) {
        dlt_null->family = htonl(PF_INET6);
    }
#elif defined(__linux__)
    else if (idata->type == DLT_LINUX_SLL) {
        sll_linux->sll_pkttype = htons(0x0004);
        sll_linux->sll_hatype = htons(0xffff);
        sll_linux->sll_halen = htons(0x0000);
        sll_linux->sll_protocol = htons(ETHERTYPE_IPV6);
    }
#endif

    ipv6->ip6_flow = 0;
    ipv6->ip6_vfc = 0x60;
    ipv6->ip6_hlim = 255;

    ipv6->ip6_src = idata->srcaddr;
    /* XXX Double-check this one */
    /* ipv6->ip6_src= idata->srcaddr_f?(*srcaddr):*sel_src_addr_ra(idata,
     * &((scan->target[scan->ctarget])->cur.in6_addr)); */

    ipv6->ip6_dst = (scan->target[scan->ctarget])->cur.in6_addr;
    prev_nh = (unsigned char *)&(ipv6->ip6_nxt);

    ptr = (unsigned char *)v6buffer + MIN_IPV6_HLEN;

    switch (type) {
    case IPPROTO_TCP:
        *prev_nh = IPPROTO_TCP;

        if ((ptr + sizeof(struct tcp_hdr)) > (v6buffer + idata->max_packet_size)) {
            if (idata->verbose_f)
                puts("Packet Too Large while inserting TCP header");

            return (0);
        }

        tcp = (struct tcp_hdr *)ptr;
        memset(tcp, 0, sizeof(struct tcp_hdr));

        if (srcport_f)
            tcp->th_sport = htons(srcport);
        else
            tcp->th_sport = htons(1024 + random() % 64512);

        tcp->th_dport = htons((port_list->port[port_list->cport])->cur);

        if (tcpflags_f)
            tcp->th_flags = tcpflags;
        else
            tcp->th_flags = TH_ACK;

        if (tcpflags & TH_ACK)
            tcp->th_ack = htonl(random());
        else
            tcp->th_ack = htonl(0);

        tcp->th_win = htons(4096 * (random() % 9 + 1));

        /* Current version of tcp6 does not support sending TCP options */
        tcp->th_off = sizeof(struct tcp_hdr) >> 2;
        ptr += tcp->th_off << 2;

        if ((ptr + rhbytes) > v6buffer + idata->max_packet_size) {
            puts("Packet Too Large while inserting TCP segment");
            exit(EXIT_FAILURE);
        }

        while (rhbytes >= 4) {
            *(uint32_t *)ptr = random();
            ptr += sizeof(uint32_t);
            rhbytes -= sizeof(uint32_t);
        }

        while (rhbytes > 0) {
            *(uint8_t *)ptr = (uint8_t)random();
            ptr++;
            rhbytes--;
        }

        ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);
        tcp->th_sum = 0;
        tcp->th_sum = in_chksum(v6buffer, tcp, ptr - ((unsigned char *)tcp), IPPROTO_TCP);
        break;

    case IPPROTO_UDP:
        *prev_nh = IPPROTO_UDP;

        if ((ptr + sizeof(struct udp_hdr)) > (v6buffer + idata->max_packet_size)) {
            puts("Packet too large while inserting ICMPv6 header (should be using Frag. option?)");
            exit(EXIT_FAILURE);
        }

        udp = (struct udp_hdr *)ptr;
        memset(udp, 0, sizeof(struct udp_hdr));
        ptr += sizeof(struct udp_hdr);

        /*
           For UDP, we encode the current probe number and the current Hop Limit as fr TCP.
           Namely, we encode the probe number and the current Hop Limit in the TCP Source Port.
           The probe number is encoded in the upper eight bits, while the current Hop Limit is
           encoded in the lower eight bits. A constant "offset" is employed for encoding the probe
           number, such that the resulting Source Port falls into what is typically known as the
           dynamic ports range (say, ports larger than 50000).
         */

        if (srcport_f)
            udp->uh_sport = htons(srcport);
        else
            udp->uh_sport = htons(1024 + random() % 64512);

        udp->uh_dport = htons((port_list->port[port_list->cport])->cur);

        /* XXX Send some minimum packet size -- should be changed */
        rhbytes = 40;

        if (rhbytes) {
            rhleft = rhbytes;

            if ((ptr + rhleft) > (v6buffer + idata->max_packet_size)) {
                puts("Packet Too Large while inserting TCP segment");
                exit(EXIT_FAILURE);
            }

            while (rhleft >= 4) {
                *(uint32_t *)ptr = random();
                ptr += sizeof(uint32_t);
                rhleft -= sizeof(uint32_t);
            }

            while (rhleft > 0) {
                *(uint8_t *)ptr = (uint8_t)random();
                ptr++;
                rhleft--;
            }
        }

        ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);
        udp->uh_ulen = htons(ptr - (unsigned char *)udp);
        udp->uh_sum = 0;
        udp->uh_sum = in_chksum(v6buffer, udp, ptr - ((unsigned char *)udp), IPPROTO_UDP);
        break;
    }

    if ((nw = pcap_inject(idata->pfd, buffer, ptr - buffer)) == -1) {
        if (idata->verbose_f)
            printf("pcap_inject(): %s\n", pcap_geterr(idata->pfd));

        return (0);
    }

    if (nw != (ptr - buffer)) {
        if (idata->verbose_f)
            printf("pcap_inject(): only wrote %d bytes (rather than %lu bytes)\n", nw, (LUI)(ptr - buffer));
        return (0);
    }

    return (1);
}

/*
 * Function: multi_scan_local()
 *
 * Performs an IPv6 address scan on a local link
 */

int multi_scan_local(pcap_t *pfd, struct iface_data *idata, struct in6_addr *srcaddr, unsigned char type,
                     const char *ptargetaddr, struct host_list *hlist) {

    struct bpf_program pcap_filter;
    struct pcap_pkthdr *pkthdr;
    const u_char *pktdata;
    struct ip6_hdr *pkt_ipv6;
    struct icmp6_hdr *pkt_icmp6;
    struct nd_neighbor_solicit *pkt_ns;
    unsigned char *pkt_end;
    unsigned char *ptr;

    unsigned char buffer[PACKET_BUFFER_SIZE];
    unsigned int icmp6_max_packet_size;
    struct ether_header *ether;
    unsigned char *v6buffer;
    struct ip6_hdr *ipv6;
    volatile unsigned int tries = 0;
    struct in6_addr targetaddr;
    struct sigaction new_sig, old_sig;
    struct ip6_dest *destopth;
    struct ip6_option *opt;
    uint32_t *uint32;
    unsigned char error_f = FALSE, llocalsrc_f = FALSE;
    int result;

    icmp6_max_packet_size = idata->mtu;
    ether = (struct ether_header *)buffer;
    v6buffer = buffer + sizeof(struct ether_header);
    ipv6 = (struct ip6_hdr *)v6buffer;

    if (inet_pton(AF_INET6, ptargetaddr, &targetaddr) <= 0) {
        if (idata->verbose_f > 1)
            puts("inet_pton(): Source Address not valid");

        return (-1);
    }

    if (IN6_IS_ADDR_LINKLOCAL(srcaddr))
        llocalsrc_f = TRUE;

    if (pfd == NULL)
        return (-1);

    switch (type) {
    case PROBE_ICMP6_ECHO:
        if (pcap_compile(pfd, &pcap_filter, PCAP_ICMPV6_ERNS_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1) {
            if (idata->verbose_f)
                printf("pcap_compile(): %s", pcap_geterr(pfd));

            return (-1);
        }
        break;

    case PROBE_UNREC_OPT:
        if (pcap_compile(pfd, &pcap_filter, PCAP_ICMPV6_ERRORNS_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1) {
            if (idata->verbose_f)
                printf("pcap_compile(): %s", pcap_geterr(pfd));

            return (-1);
        }
        break;

    default:
        return (-1);
        break;
    }

    if (pcap_setfilter(pfd, &pcap_filter) == -1) {
        if (idata->verbose_f)
            printf("pcap_setfilter(): %s", pcap_geterr(pfd));

        return (-1);
    }

    pcap_freecode(&pcap_filter);

    ipv6->ip6_flow = 0;
    ipv6->ip6_vfc = 0x60;
    ipv6->ip6_hlim = 255;

    ipv6->ip6_src = *srcaddr;
    ipv6->ip6_dst = targetaddr;

    ether->src = idata->ether;
    ether->dst = ether_multicast(&(ipv6->ip6_dst));
    ether->ether_type = htons(ETHERTYPE_IPV6);

    prev_nh = (unsigned char *)&(ipv6->ip6_nxt);

    ptr = (unsigned char *)v6buffer + MIN_IPV6_HLEN;

    switch (type) {
    case PROBE_ICMP6_ECHO:
        *prev_nh = IPPROTO_ICMPV6;

        if ((ptr + sizeof(struct icmp6_hdr) + ICMPV6_ECHO_PAYLOAD_SIZE) > (v6buffer + icmp6_max_packet_size)) {
            if (idata->verbose_f > 1)
                puts("Packet too large while creating ICMPv6 Echo Request Probe packet");

            return (-1);
        }

        icmp6 = (struct icmp6_hdr *)ptr;
        icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6->icmp6_code = 0;
        icmp6->icmp6_cksum = random();
        icmp6->icmp6_data16[0] = htons(getpid()); /* Identifier */
        icmp6->icmp6_data16[1] = htons(random()); /* Sequence Number */

        ptr = ptr + sizeof(struct icmp6_hdr);

        for (i = 0; i < (ICMPV6_ECHO_PAYLOAD_SIZE >> 2); i++) {
            *(uint32_t *)ptr = random();
            ptr += sizeof(uint32_t);
        }
        break;

    case PROBE_UNREC_OPT:
        *prev_nh = IPPROTO_DSTOPTS;

        if ((ptr + sizeof(struct icmp6_hdr) + 8 + ICMPV6_ECHO_PAYLOAD_SIZE) > (v6buffer + icmp6_max_packet_size)) {
            if (idata->verbose_f > 1)
                puts("Packet too large while creating Unrec. Opt. Probe Packet");

            return (-1);
        }

        destopth = (struct ip6_dest *)ptr;
        destopth->ip6d_len = 0;
        destopth->ip6d_nxt = IPPROTO_ICMPV6;

        ptr = ptr + 2;
        opt = (struct ip6_option *)ptr;
        opt->ip6o_type = 0x80;
        opt->ip6o_len = 4;

        ptr = ptr + 2;
        uint32 = (uint32_t *)ptr;
        *uint32 = random();

        ptr = ptr + 4;
        icmp6 = (struct icmp6_hdr *)ptr;
        icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6->icmp6_code = 0;
        icmp6->icmp6_cksum = random();
        icmp6->icmp6_data16[0] = htons(getpid()); /* Identifier */
        icmp6->icmp6_data16[1] = htons(random()); /* Sequence Number */

        ptr = ptr + sizeof(struct icmp6_hdr);

        for (i = 0; i < (ICMPV6_ECHO_PAYLOAD_SIZE >> 2); i++) {
            *(uint32_t *)ptr = random();
            ptr += sizeof(uint32_t);
        }
        break;
    }

    ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);
    icmp6->icmp6_cksum = 0;
    icmp6->icmp6_cksum = in_chksum(v6buffer, icmp6, ptr - ((unsigned char *)icmp6), IPPROTO_ICMPV6);

    /* We set the signal handler, and the anchor for siglongjump() */
    canjump = 0;
    memset(&new_sig, 0, sizeof(struct sigaction));
    sigemptyset(&new_sig.sa_mask);
    new_sig.sa_handler = &local_sig_alarm;

    if (sigaction(SIGALRM, &new_sig, &old_sig) == -1) {
        if (idata->verbose_f > 1)
            puts("Error setting up 'Alarm' signal");

        return (-1);
    }

    if (sigsetjmp(env, 1) != 0)
        tries++;

    canjump = 1;

    while (tries <= idata->local_retrans && !error_f) {
        if ((nw = pcap_inject(pfd, buffer, ptr - buffer)) == -1) {
            if (idata->verbose_f > 1)
                printf("pcap_inject(): %s\n", pcap_geterr(pfd));

            error_f = TRUE;
            break;
        }

        if (nw != (ptr - buffer)) {
            if (idata->verbose_f > 1)
                printf("pcap_inject(): only wrote %d bytes (rather than %lu bytes)\n", nw, (LUI)(ptr - buffer));

            error_f = TRUE;
            break;
        }

        alarm(idata->local_timeout);

        while ((hlist->nhosts < hlist->maxhosts) && !error_f) {

            do {
                if ((result = pcap_next_ex(pfd, &pkthdr, &pktdata)) == -1) {
                    if (idata->verbose_f > 1)
                        printf("pcap_next_ex(): %s", pcap_geterr(pfd));

                    error_f = TRUE;
                    break;
                }
            } while (result == 0 || pktdata == NULL);

            if (error_f)
                break;

            pkt_ether = (struct ether_header *)pktdata;
            pkt_ipv6 = (struct ip6_hdr *)((char *)pkt_ether + ETHER_HDR_LEN);
            pkt_icmp6 = (struct icmp6_hdr *)((char *)pkt_ipv6 + sizeof(struct ip6_hdr));
            pkt_ns = (struct nd_neighbor_solicit *)pkt_icmp6;
            pkt_end = (unsigned char *)pktdata + pkthdr->caplen;

            if ((pkt_end - pktdata) < (ETHER_HDR_LEN + MIN_IPV6_HLEN))
                continue;

            if (pkt_ipv6->ip6_nxt == IPPROTO_ICMPV6) {
                if (pkt_icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT) {
                    if ((pkt_end - (unsigned char *)pkt_ns) < sizeof(struct nd_neighbor_solicit))
                        continue;

                    if (is_eq_in6_addr(&(pkt_ns->nd_ns_target), srcaddr) ||
                        is_eq_in6_addr(&(pkt_ns->nd_ns_target), &(idata->ip6_local))) {
                        if (send_neighbor_advert(idata, pfd, pktdata) == -1) {
                            error_f = TRUE;
                            break;
                        }
                    }
                }
                else if ((pkt_icmp6->icmp6_type == ICMP6_ECHO_REPLY) || (pkt_icmp6->icmp6_type == ICMP6_PARAM_PROB)) {
                    if ((pkt_end - (unsigned char *)pkt_icmp6) < sizeof(struct icmp6_hdr))
                        continue;

                    /*
                       If the Source Address was a link-local address, we only want link-local addresses.
                       OTOH, if the Source Address was a global address, we only want global addresses.
                     */
                    if (llocalsrc_f) {
                        if (!IN6_IS_ADDR_LINKLOCAL(&(pkt_ipv6->ip6_src)))
                            continue;
                    }
                    else {
                        if (IN6_IS_ADDR_LINKLOCAL(&(pkt_ipv6->ip6_src)))
                            continue;
                    }

                    if (valid_icmp6_response(idata, type, pkthdr, pktdata, buffer)) {
                        if (is_ip6_in_list(&(pkt_ipv6->ip6_src), hlist))
                            continue;

                        if ((hlist->host[hlist->nhosts] = malloc(sizeof(struct host_entry))) == NULL) {
                            if (idata->verbose_f > 1)
                                puts("Error when allocating memory for host data");

                            error_f = TRUE;
                            break;
                        }

                        memset(hlist->host[hlist->nhosts], 0, sizeof(struct host_entry));

                        (hlist->host[hlist->nhosts])->ip6 = pkt_ipv6->ip6_src;
                        (hlist->host[hlist->nhosts])->ether = pkt_ether->src;
                        (hlist->host[hlist->nhosts])->flag = VALID_MAPPING;
                        (hlist->nhosts)++;
                    }
                }
            }

        } /* Processing packets */

    } /* Resending Neighbor Solicitations */

    if (sigaction(SIGALRM, &old_sig, NULL) == -1) {
        if (idata->verbose_f > 1)
            puts("Error setting up 'Alarm' signal");

        error_f = TRUE;
    }

    if (error_f)
        return (-1);
    else
        return 0;
}

/*
 * Function: find_local_globals()
 *
 * Finds Global Unicast Addresses present on the local link
 */

int find_local_globals(pcap_t *pfd, struct iface_data *idata, unsigned char type, const char *ptargetaddr,
                       struct host_list *hlist) {
    unsigned int i;
    for (i = 0; i < idata->ip6_global.nprefix; i++) {
        if (multi_scan_local(pfd, idata, &((idata->ip6_global.prefix[i])->ip6), type, ALL_NODES_MULTICAST_ADDR,
                             hlist) == -1) {
            return (-1);
        }
    }

    return 0;
}

/*
 * Function: host_scan_local()
 *
 * Scans a single IPv6 address
 */

int host_scan_local(pcap_t *pfd, struct iface_data *idata, struct in6_addr *srcaddr, unsigned char type,
                    struct host_entry *host) {
    struct bpf_program pcap_filter;
    struct pcap_pkthdr *pkthdr;
    const u_char *pktdata;
    struct ip6_hdr *pkt_ipv6;
    struct icmp6_hdr *pkt_icmp6;
    struct nd_neighbor_solicit *pkt_ns;
    unsigned char *pkt_end;
    volatile unsigned char *ptr;

    unsigned char buffer[PACKET_BUFFER_SIZE];
    unsigned int icmp6_max_packet_size;
    struct ether_header *ether;
    unsigned char *v6buffer;
    struct ip6_hdr *ipv6;
    volatile unsigned int tries = 0;
    struct in6_addr targetaddr;
    struct sigaction new_sig, old_sig;
    struct ip6_dest *destopth;
    struct ip6_option *opt;
    uint32_t *uint32;
    unsigned char foundaddr_f = FALSE, error_f = FALSE;
    int result;

    icmp6_max_packet_size = idata->mtu;
    ether = (struct ether_header *)buffer;
    v6buffer = buffer + sizeof(struct ether_header);
    ipv6 = (struct ip6_hdr *)v6buffer;

    targetaddr = host->ip6;

    if (pcap_datalink(pfd) != DLT_EN10MB) {
        if (idata->verbose_f > 1)
            printf("Error: Interface %s is not an Ethernet interface", idata->iface);

        return (-1);
    }

    switch (type) {
    case PROBE_ICMP6_ECHO:
        if (pcap_compile(pfd, &pcap_filter, PCAP_ICMPV6_ERNS_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1) {
            if (idata->verbose_f > 1)
                printf("pcap_compile(): %s", pcap_geterr(pfd));

            return (-1);
        }

        break;

    case PROBE_UNREC_OPT:
        if (pcap_compile(pfd, &pcap_filter, PCAP_ICMPV6_ERRORNS_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1) {
            if (idata->verbose_f > 1)
                printf("pcap_compile(): %s", pcap_geterr(pfd));

            return (-1);
        }

        break;

    default:
        return (-1);
        break;
    }

    if (pcap_setfilter(pfd, &pcap_filter) == -1) {
        if (idata->verbose_f > 1)
            printf("pcap_setfilter(): %s", pcap_geterr(pfd));

        return (-1);
    }

    pcap_freecode(&pcap_filter);

    ipv6->ip6_flow = 0;
    ipv6->ip6_vfc = 0x60;
    ipv6->ip6_hlim = 255;
    ipv6->ip6_dst = targetaddr;
    ipv6->ip6_src = *srcaddr;

    ether->src = idata->ether;
    ether->dst = host->ether;
    ether->ether_type = htons(ETHERTYPE_IPV6);

    prev_nh = (unsigned char *)&(ipv6->ip6_nxt);

    ptr = (unsigned char *)v6buffer + MIN_IPV6_HLEN;

    switch (type) {
    case PROBE_ICMP6_ECHO:
        *prev_nh = IPPROTO_ICMPV6;

        if ((ptr + sizeof(struct icmp6_hdr) + ICMPV6_ECHO_PAYLOAD_SIZE) > (v6buffer + icmp6_max_packet_size)) {
            if (idata->verbose_f > 1)
                puts("Packet too large while creating ICMPv6 Echo Request Probe packet");

            return (-1);
        }

        icmp6 = (struct icmp6_hdr *)ptr;
        icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6->icmp6_code = 0;
        icmp6->icmp6_cksum = random();
        icmp6->icmp6_data16[0] = htons(getpid()); /* Identifier */
        icmp6->icmp6_data16[1] = htons(random()); /* Sequence Number */

        ptr = ptr + sizeof(struct icmp6_hdr);

        for (i = 0; i < (ICMPV6_ECHO_PAYLOAD_SIZE >> 2); i++) {
            *(uint32_t *)ptr = random();
            ptr += sizeof(uint32_t);
        }
        break;

    case PROBE_UNREC_OPT:
        *prev_nh = IPPROTO_DSTOPTS;

        if ((ptr + sizeof(struct icmp6_hdr) + 8 + ICMPV6_ECHO_PAYLOAD_SIZE) > (v6buffer + icmp6_max_packet_size)) {
            if (idata->verbose_f > 1)
                puts("Packet too large while creating Unrec. Opt. Probe Packet");

            return (-1);
        }

        destopth = (struct ip6_dest *)ptr;
        destopth->ip6d_len = 0;
        destopth->ip6d_nxt = IPPROTO_ICMPV6;

        ptr = ptr + 2;
        opt = (struct ip6_option *)ptr;
        opt->ip6o_type = 0x80;
        opt->ip6o_len = 4;

        ptr = ptr + 2;
        uint32 = (uint32_t *)ptr;
        *uint32 = random();

        ptr = ptr + 4;
        icmp6 = (struct icmp6_hdr *)ptr;
        icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6->icmp6_code = 0;
        icmp6->icmp6_cksum = random();
        icmp6->icmp6_data16[0] = htons(getpid()); /* Identifier */
        icmp6->icmp6_data16[1] = htons(random()); /* Sequence Number */

        ptr = ptr + sizeof(struct icmp6_hdr);

        for (i = 0; i < (ICMPV6_ECHO_PAYLOAD_SIZE >> 2); i++) {
            *(uint32_t *)ptr = random();
            ptr += sizeof(uint32_t);
        }
        break;
    }

    ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);
    icmp6->icmp6_cksum = 0;
    icmp6->icmp6_cksum = in_chksum(v6buffer, icmp6, ptr - ((unsigned char *)icmp6), IPPROTO_ICMPV6);

    /* We set the signal handler, and the anchor for siglongjump() */
    canjump = 0;
    memset(&new_sig, 0, sizeof(struct sigaction));
    sigemptyset(&new_sig.sa_mask);
    new_sig.sa_handler = &local_sig_alarm;

    if (sigaction(SIGALRM, &new_sig, &old_sig) == -1) {
        if (idata->verbose_f > 1)
            puts("Error setting up 'Alarm' signal");

        return (-1);
    }

    if (sigsetjmp(env, 1) != 0)
        tries++;

    canjump = 1;

    while (tries <= idata->local_retrans && !foundaddr_f && !error_f) {
        if ((nw = pcap_inject(pfd, buffer, ptr - buffer)) == -1) {
            if (idata->verbose_f > 1)
                printf("pcap_inject(): %s\n", pcap_geterr(pfd));

            error_f = TRUE;
            break;
        }

        if (nw != (ptr - buffer)) {
            if (idata->verbose_f > 1)
                printf("pcap_inject(): only wrote %d bytes (rather than %lu bytes)\n", nw, (LUI)(ptr - buffer));

            error_f = TRUE;
            break;
        }

        alarm(idata->local_timeout);

        foundaddr_f = FALSE;

        while (!foundaddr_f && !error_f) {

            do {
                if ((result = pcap_next_ex(pfd, &pkthdr, &pktdata)) == -1) {
                    if (idata->verbose_f > 1)
                        printf("pcap_next_ex(): %s", pcap_geterr(pfd));

                    error_f = TRUE;
                    break;
                }
            } while (result == 0 || pktdata == NULL);

            if (error_f)
                break;

            pkt_ether = (struct ether_header *)pktdata;
            pkt_ipv6 = (struct ip6_hdr *)((char *)pkt_ether + ETHER_HDR_LEN);
            pkt_end = (unsigned char *)pktdata + pkthdr->caplen;

            if ((pkt_end - pktdata) < (ETHER_HDR_LEN + MIN_IPV6_HLEN))
                continue;

            if (pkt_ipv6->ip6_nxt == IPPROTO_ICMPV6) {
                pkt_icmp6 = (struct icmp6_hdr *)((char *)pkt_ipv6 + sizeof(struct ip6_hdr));

                if (pkt_icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT) {
                    pkt_ns = (struct nd_neighbor_solicit *)pkt_icmp6;

                    if ((pkt_end - (unsigned char *)pkt_ns) < sizeof(struct nd_neighbor_solicit))
                        continue;

                    if (is_eq_in6_addr(&(pkt_ns->nd_ns_target), &(idata->ip6_local)) ||
                        is_eq_in6_addr(&(pkt_ns->nd_ns_target), srcaddr)) {
                        if (send_neighbor_advert(idata, pfd, pktdata) == -1) {
                            error_f = TRUE;
                            break;
                        }
                    }
                }
                else if ((pkt_icmp6->icmp6_type == ICMP6_ECHO_REPLY) || (pkt_icmp6->icmp6_type == ICMP6_PARAM_PROB)) {

                    if ((pkt_end - (unsigned char *)pkt_icmp6) < sizeof(struct icmp6_hdr))
                        continue;

                    if (valid_icmp6_response(idata, type, pkthdr, pktdata, buffer)) {
                        host->ether = pkt_ether->src;
                        host->flag = VALID_MAPPING;
                        foundaddr_f = TRUE;
                        break;
                    }
                }
            }

        } /* Processing packets */

    } /* Resending Probe packet */

    if (sigaction(SIGALRM, &old_sig, NULL) == -1) {
        if (idata->verbose_f > 1)
            puts("Error setting up 'Alarm' signal");

        error_f = TRUE;
    }

    if (error_f)
        return (-1);
    else
        return 0;
}

/*
 * Function: print_host_entries()
 *
 * Prints the IPv6 addresses (and optionally the Ethernet addresses) in a list
 */

int print_host_entries(struct host_list *hlist, unsigned char flag) {
    unsigned int i;

    for (i = 0; i < (hlist->nhosts); i++) {
        if (inet_ntop(AF_INET6, &((hlist->host[i])->ip6), pv6addr, sizeof(pv6addr)) == NULL) {
            if (verbose_f > 1)
                puts("inet_ntop(): Error converting IPv6 address to presentation format");

            return (-1);
        }

        if (flag == PRINT_ETHER_ADDR) {
            if (ether_ntop(&((hlist->host[i])->ether), plinkaddr, sizeof(plinkaddr)) == FALSE) {
                if (verbose_f > 1)
                    puts("ether_ntop(): Error converting address");

                return (-1);
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

int print_unique_host_entries(struct host_list *hlist, unsigned char flag) {
    unsigned int i, j, k;

    for (i = 0; i < (hlist->nhosts); i++) {

        if (i) {
            for (j = 0; j < i; j++) {
                for (k = 0; k < ETH_ALEN; k++) {
                    if ((hlist->host[i])->ether.a[k] != (hlist->host[j])->ether.a[k])
                        break;
                }

                if (k == ETH_ALEN)
                    break;
            }

            if (j < i)
                continue;
        }

        if (inet_ntop(AF_INET6, &((hlist->host[i])->ip6), pv6addr, sizeof(pv6addr)) == NULL) {
            if (verbose_f > 1)
                puts("inet_ntop(): Error converting IPv6 address to presentation format");

            return (-1);
        }

        if (flag == PRINT_ETHER_ADDR) {
            if (ether_ntop(&((hlist->host[i])->ether), plinkaddr, sizeof(plinkaddr)) == FALSE) {
                if (verbose_f > 1)
                    puts("ether_ntop(): Error converting address");

                return (-1);
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

void free_host_entries(struct host_list *hlist) {
    unsigned int i;

    for (i = 0; i < hlist->nhosts; i++)
        free(hlist->host[i]);

    hlist->nhosts = 0; /* Set the number of entries to 0, to reflect the released memory */
    return;
}

/*
 * Function: create_candidate_globals()
 *
 * Generates list of cadidate global addresses based on the local Global prefixes and Interface IDs
 */

int create_candidate_globals(struct iface_data *idata, struct host_list *local, struct host_list *global,
                             struct host_list *candidate) {
    unsigned int i, j, k;
    struct in6_addr caddr;

    for (i = 0; (i < local->nhosts) && (candidate->nhosts < candidate->maxhosts); i++) {

        /* Avoid global Address present in "local" list -- shouldn't happen, though */
        if (IN6_IS_ADDR_LINKLOCAL(&((local->host[i])->ip6))) {
            /* We create one candidate address with the Interface-ID of the link-local address,
               for each of the autoconf prefixes
             */
            for (j = 0; (j < idata->prefix_ac.nprefix) && (candidate->nhosts < candidate->maxhosts); j++) {
                for (k = 0; k < 2; k++)
                    caddr.s6_addr32[k] = (idata->prefix_ac.prefix[j])->ip6.s6_addr32[k];

                for (k = 2; k < 4; k++)
                    caddr.s6_addr32[k] = local->host[i]->ip6.s6_addr32[k];

                /* We discard the candidate address if it is already present in the "global" list */
                if (is_ip6_in_list(&caddr, global))
                    continue;

                if ((candidate->host[candidate->nhosts] = malloc(sizeof(struct host_entry))) == NULL) {
                    if (verbose_f > 1)
                        puts("Error allocating memory while creating local -> global list");

                    return (-1);
                }

                memset(candidate->host[candidate->nhosts], 0, sizeof(struct host_entry));

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

int validate_host_entries(pcap_t *pfd, struct iface_data *idata, struct host_list *candidate,
                          struct host_list *global) {
    unsigned int i;
    struct in6_addr *srcaddrptr;

    for (i = 0; i < candidate->nhosts; i++) {
        if ((candidate->host[i])->flag == INVALID_MAPPING) {
            srcaddrptr = sel_src_addr_ra(idata, &((candidate->host[i])->ip6));

            if (probe_unrec_f) {
                if (host_scan_local(pfd, idata, srcaddrptr, PROBE_UNREC_OPT, candidate->host[i]) == -1)
                    return (-1);
            }

            if (((candidate->host[i])->flag == INVALID_MAPPING) && probe_echo_f) {
                if (host_scan_local(pfd, idata, srcaddrptr, PROBE_ICMP6_ECHO, candidate->host[i]) == -1)
                    return (-1);
            }
        }

        if ((candidate->host[i])->flag == VALID_MAPPING) {
            global->host[global->nhosts] = candidate->host[i];
            (global->nhosts)++;
        }
        else {
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

int valid_icmp6_response(struct iface_data *idata, unsigned char type, struct pcap_pkthdr *pkthdr,
                         const u_char *pktdata, unsigned char *pktsent) {

    struct ether_header *pkt_ether;
    struct ip6_hdr *pkt_ipv6, *ipv6;
    struct icmp6_hdr *pkt_icmp6, *pkt_icmp6_icmp6, *icmp6;
    unsigned char *pkt_end;

    ipv6 = (struct ip6_hdr *)(pktsent + sizeof(struct ether_header));

    if (type == PROBE_UNREC_OPT)
        icmp6 = (struct icmp6_hdr *)((char *)ipv6 + sizeof(struct ip6_hdr) + MIN_DST_OPT_HDR_SIZE);
    else
        icmp6 = (struct icmp6_hdr *)((char *)ipv6 + sizeof(struct ip6_hdr));

    pkt_ether = (struct ether_header *)pktdata;
    pkt_ipv6 = (struct ip6_hdr *)((char *)pkt_ether + ETHER_HDR_LEN);
    pkt_icmp6 = (struct icmp6_hdr *)((char *)pkt_ipv6 + MIN_IPV6_HLEN);
    pkt_end = (unsigned char *)pktdata + pkthdr->caplen;

    switch (type) {
    case PROBE_ICMP6_ECHO:
        pkt_icmp6 = (struct icmp6_hdr *)((char *)pkt_ipv6 + MIN_IPV6_HLEN);

        /* The packet length is the minimum of what we capured, and what is specified in the
           IPv6 Total Lenght field
         */
        if (pkt_end > ((unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen))
            pkt_end = (unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen;

        /*
           Discard the packet if it is not of the minimum size to contain an ICMPv6
           header and the payload we included in the ICMPv6 Echo Request
         */
        if ((pkt_end - (unsigned char *)pkt_icmp6) < (sizeof(struct icmp6_hdr) + ICMPV6_ECHO_PAYLOAD_SIZE))
            return 0;

        break;

    case PROBE_UNREC_OPT:
        pkt_icmp6 = (struct icmp6_hdr *)((char *)pkt_ipv6 + MIN_IPV6_HLEN);

        /* The packet length is the minimum of what we capured, and what is specified in the
           IPv6 Total Lenght field
         */
        if (pkt_end > ((unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen))
            pkt_end = (unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen;

        /*
           Discard the packet if it is not of the minimum size to contain an ICMPv6
           header and the embedded payload
         */
        if ((pkt_end - (unsigned char *)pkt_icmp6) <
            (sizeof(struct icmp6_hdr) + +sizeof(struct ip6_hdr) + MIN_DST_OPT_HDR_SIZE + sizeof(struct icmp6_hdr) +
             ICMPV6_ECHO_PAYLOAD_SIZE))
            return 0;

        break;
    }

    /*
       Check that that the Destination Address of the incoming packet is the same as the one
       we used for the Source Address of the Probe packet.
     */
    if (!is_eq_in6_addr(&(pkt_ipv6->ip6_dst), &(ipv6->ip6_src)))
        return 0;

    /* Check that the ICMPv6 checksum is correct */
    if (in_chksum(pkt_ipv6, pkt_icmp6, pkt_end - ((unsigned char *)pkt_icmp6), IPPROTO_ICMPV6) != 0)
        return 0;

    switch (type) {
    case PROBE_ICMP6_ECHO:
        if (pkt_icmp6->icmp6_data16[0] != icmp6->icmp6_data16[0]) {
            return 0;
        }
        else if (pkt_icmp6->icmp6_data16[1] != icmp6->icmp6_data16[1]) {
            return 0;
        }

        break;

    case PROBE_UNREC_OPT:
        pkt_icmp6_icmp6 = (struct icmp6_hdr *)((unsigned char *)pkt_icmp6 + sizeof(struct icmp6_hdr) +
                                               sizeof(struct ip6_hdr) + MIN_DST_OPT_HDR_SIZE);

        if (pkt_icmp6_icmp6->icmp6_data16[0] != icmp6->icmp6_data16[0]) {
            return 0;
        }
        else if (pkt_icmp6_icmp6->icmp6_data16[1] != icmp6->icmp6_data16[1]) {
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

int valid_icmp6_response_remote(struct iface_data *idata, struct scan_list *scan, unsigned char type,
                                struct pcap_pkthdr *pkthdr, const u_char *pktdata, unsigned char *pktsent) {

    struct ether_header *pkt_ether;
    struct ip6_hdr *pkt_ipv6, *ipv6;
    struct icmp6_hdr *pkt_icmp6, *pkt_icmp6_icmp6, *icmp6;
    unsigned char *pkt_end;

    ipv6 = (struct ip6_hdr *)(pktsent + idata->linkhsize);

    if (type == PROBE_UNREC_OPT)
        icmp6 = (struct icmp6_hdr *)((char *)ipv6 + sizeof(struct ip6_hdr) + MIN_DST_OPT_HDR_SIZE);
    else
        icmp6 = (struct icmp6_hdr *)((char *)ipv6 + sizeof(struct ip6_hdr));

    pkt_ether = (struct ether_header *)pktdata;
    pkt_ipv6 = (struct ip6_hdr *)((char *)pkt_ether + idata->linkhsize);
    pkt_icmp6 = (struct icmp6_hdr *)((char *)pkt_ipv6 + sizeof(struct ip6_hdr));
    pkt_end = (unsigned char *)pktdata + pkthdr->caplen;

    switch (type) {
    case PROBE_ICMP6_ECHO:
        /* The packet length is the minimum of what we capured, and what is specified in the
           IPv6 Total Lenght field
         */
        if (pkt_end > ((unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen))
            pkt_end = (unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen;

        /*
           Discard the packet if it is not of the minimum size to contain an ICMPv6
           header and the payload we included in the ICMPv6 Echo Request
         */
        if ((pkt_end - (unsigned char *)pkt_icmp6) < (sizeof(struct icmp6_hdr) + ICMPV6_ECHO_PAYLOAD_SIZE))
            return 0;

        break;

    case PROBE_UNREC_OPT:
        /* The packet length is the minimum of what we capured, and what is specified in the
           IPv6 Total Lenght field
         */
        if (pkt_end > ((unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen))
            pkt_end = (unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen;

        /*
           Discard the packet if it is not of the minimum size to contain an ICMPv6
           header and the empedded payload
         */
        if ((pkt_end - (unsigned char *)pkt_icmp6) <
            (sizeof(struct icmp6_hdr) + +sizeof(struct ip6_hdr) + MIN_DST_OPT_HDR_SIZE + sizeof(struct icmp6_hdr) +
             ICMPV6_ECHO_PAYLOAD_SIZE))
            return 0;

        break;
    }

    /*
       Check that that the Destination Address of the incoming packet is the same as the one
       we used for the Source Address of the Probe packet.
     */
    if (!is_eq_in6_addr(&(pkt_ipv6->ip6_dst), &(ipv6->ip6_src)))
        return 0;

    /* Check that the ICMPv6 checksum is correct */
    if (in_chksum(pkt_ipv6, pkt_icmp6, pkt_end - ((unsigned char *)pkt_icmp6), IPPROTO_ICMPV6) != 0)
        return 0;

    switch (type) {
    case PROBE_ICMP6_ECHO:
        if (pkt_icmp6->icmp6_data16[0] != icmp6->icmp6_data16[0]) {
            return 0;
        }
        else if (pkt_icmp6->icmp6_data16[1] != icmp6->icmp6_data16[1]) {
            return 0;
        }

        break;

    case PROBE_UNREC_OPT:
        pkt_icmp6_icmp6 = (struct icmp6_hdr *)((unsigned char *)pkt_icmp6 + sizeof(struct icmp6_hdr) +
                                               sizeof(struct ip6_hdr) + MIN_DST_OPT_HDR_SIZE);

        if (pkt_icmp6_icmp6->icmp6_data16[0] != icmp6->icmp6_data16[0]) {
            return 0;
        }

        else if (pkt_icmp6_icmp6->icmp6_data16[1] != icmp6->icmp6_data16[1]) {
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

int process_config_file(const char *path) {
    FILE *fp;
    char *key, *value;
    char line[MAX_LINE_SIZE];
    int r;
    unsigned int ln = 1;

    if ((fp = fopen(path, "r")) == NULL) {
        return (0);
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        r = keyval(line, Strnlen(line, MAX_LINE_SIZE), &key, &value);

        if (r == 1) {
            if (strncmp(key, "OUI-Database", MAX_VAR_NAME_LEN) == 0) {
                strncpy(fname, value, MAX_FILENAME_SIZE - 1);
                fname[MAX_FILENAME_SIZE - 1] = 0;
                fname_f = TRUE;
            }
            else if (strncmp(key, "Ports-Database", MAX_VAR_NAME_LEN) == 0) {
                strncpy(portsfname, value, MAX_FILENAME_SIZE - 1);
                portsfname[MAX_FILENAME_SIZE - 1] = 0;
                portsfname_f = TRUE;
            }
            else if (strncmp(key, "Top-Ports-Database", MAX_VAR_NAME_LEN) == 0) {
                strncpy(topportsfname, value, MAX_FILENAME_SIZE - 1);
                topportsfname[MAX_FILENAME_SIZE - 1] = 0;
                topportsfname_f = TRUE;
            }
        }
        else if (r == -1) {
            if (verbose_f) {
                printf("Error in configuration file %s", configfile);
            }

            fclose(fp);
            return (0);
        }

        ln++;
    }

    fclose(fp);

    if (!fname_f)
        strncpy(fname, "/usr/local/share/ipv6toolkit/oui.txt", MAX_FILENAME_SIZE - 1);

    if (!portsfname_f)
        strncpy(portsfname, "/usr/local/share/ipv6toolkit/service-names-port-numbers.csv", MAX_FILENAME_SIZE - 1);

    if (!topportsfname_f)
        strncpy(topportsfname, "/usr/local/share/ipv6toolkit/top-port-numbers.csv", MAX_FILENAME_SIZE - 1);

    return (1);
}

/*
 * Function: is_ip6_in_scan_list()
 *
 * Check whether an IPv6 address belongs to one of our scan ranges
 */
int is_ip6_in_scan_list(struct scan_list *scan, struct in6_addr *ip6) {
    unsigned int i, j;
    union my6_addr myip6;

    myip6.in6_addr = *ip6;

    for (i = 0; i < scan->ntarget; i++) {
        for (j = 0; j < 8; j++) {
            if ((ntohs(myip6.s6addr16[j]) < ntohs((scan->target[i])->start.s6addr16[j])) ||
                (ntohs(myip6.s6addr16[j]) > ntohs((scan->target[i])->end.s6addr16[j]))) {
                break;
            }
        }

        if (j == 8)
            return (TRUE);
    }

    return (FALSE);
}

/*
 * Handler for the ALARM signal.
 *
 * Used for setting a timeout on libpcap reads
 */

void local_sig_alarm(int num) {
    if (canjump == 0)
        return;

    siglongjmp(env, 1);
}

/*
 * Function: load_port_table()
 *
 * Create table with mappings of port number -> service name
 */

int load_port_table(struct port_table_entry *pentry, char *prot, unsigned int maxport) {
    FILE *fp;
    char line[MAX_PORTS_LINE_SIZE], proto[MAX_PORTS_LINE_SIZE], name[MAX_PORTS_LINE_SIZE];
    char *charptr, *lasts;
    unsigned int lines = 0, ports = 0;
    unsigned int port;
    char unassigned[] = "Unassigned";

    /* We initialize all entries to "Unassigned" */
    for (i = 0; i < maxport; i++) {
        strncpy(pentry[i].name, unassigned, sizeof(pentry[i].name));
        pentry[i].name[sizeof(pentry[i].name) - 1] = 0;
    }

    if ((fp = fopen(portsfname, "r")) == NULL) {
        perror("scan6:");
        return (FALSE);
    }

    while (ports < maxport && fgets(line, MAX_PORTS_LINE_SIZE, fp) != NULL) {
        lines = Strnlen(line, MAX_PORTS_LINE_SIZE);
        charptr = (char *)line;

        /* Skip any whitespaces */
        while (charptr < ((char *)line + lines) && *charptr == ' ')
            charptr++;

        if ((charptr = strtok_r(charptr, ",", &lasts)) == NULL) {
            continue;
        }

        strncpy(name, charptr, sizeof(name));
        name[sizeof(name) - 1] = 0;

        if ((charptr = strtok_r(NULL, ",", &lasts)) == NULL) {
            continue;
        }

        port = atoi(charptr);

        if (port >= maxport)
            continue;

        if ((charptr = strtok_r(NULL, ",", &lasts)) == NULL) {
            continue;
        }

        strncpy(proto, charptr, sizeof(proto));
        proto[sizeof(proto) - 1] = 0;

        if (strncmp(prot, proto, sizeof(proto)) == 0) {
            strncpy(pentry[port].name, name, sizeof(pentry[port].name));
            pentry[port].name[sizeof(pentry[port].name) - 1] = 0;
        }
    }

    if (ferror(fp)) {
        perror("scan6:");

        return (FALSE);
    }

    fclose(fp);
    return (TRUE);
}

/*
 * Function: load_top_ports_entries()
 *
 * Load target ports from top ports file
 */

int load_top_ports_entries(struct port_list *tcp_port_list, struct port_list *udp_port_list, uint8_t protocol,
                           unsigned int maxport) {
    FILE *fp;
    char line[MAX_PORTS_LINE_SIZE];
    char *charptr, *lasts;
    unsigned int lines = 0, ports = 0;
    uint16_t port;
    uint8_t cprotocol;
    struct port_list *port_list;

    if ((fp = fopen(topportsfname, "r")) == NULL) {
        perror("scan6:");
        return (0);
    }

    while (ports < maxport && fgets(line, MAX_PORTS_LINE_SIZE, fp) != NULL) {
        lines = Strnlen(line, MAX_PORTS_LINE_SIZE);
        charptr = (char *)line;

        /* Skip any whitespaces */
        while (charptr < ((char *)line + lines) && *charptr == ' ')
            charptr++;

        if ((charptr = strtok_r(charptr, ",", &lasts)) == NULL) {
            continue;
        }

        port = atoi(charptr);

        if ((charptr = strtok_r(NULL, ",", &lasts)) == NULL) {
            continue;
        }

        if (strncmp(charptr, "tcp", 3) == 0 || strncmp(charptr, "TCP", 3) == 0) {
            cprotocol = IPPROTO_TCP;
            port_list = tcp_port_list;
        }
        else if (strncmp(charptr, "udp", 3) == 0 || strncmp(charptr, "UDP", 3) == 0) {
            cprotocol = IPPROTO_UDP;
            port_list = udp_port_list;
        }
        else
            continue;

        /* If this entry corresponds to the protocol we have selected, incorporate the entry */
        if (protocol == cprotocol || protocol == IPPROTO_ALL) {
            if (port_list->nport < port_list->maxport) {
                if ((port_list->port[port_list->nport] = malloc(sizeof(struct port_entry))) == NULL) {
                    if (idata.verbose_f)
                        puts("scan6: Not enough memory");

                    exit(EXIT_FAILURE);
                }

                port_list->port[port_list->nport]->start = port;
                port_list->port[port_list->nport]->end = port;
                (port_list->port[port_list->nport])->cur = (port_list->port[port_list->nport])->start;
                port_list->nport++;
                ports++;
            }
            else {
                /*
                   If the number of "prots" has already been exceeded, it doesn't make sense to continue further,
                   since there wouldn't be space for any specific target types
                                                 */
                if (idata.verbose_f)
                    puts("Too many port ranges!");

                exit(EXIT_FAILURE);
            }
        }
    }

    if (ferror(fp)) {
        perror("scan6:");

        return (0);
    }

    fclose(fp);
    return (TRUE);
}

/*
 * Function: print_port_table()
 *
 * Print the port table (for debugging puroses)
 */

void print_port_table(struct port_table_entry *pentry, unsigned int maxport) {
    unsigned int i;

    for (i = 0; i < maxport; i++) {
        printf("%5d (%s)\n", i, pentry[i].name);
    }
}

/*
 * Function: init_packet_data()
 *
 * Initialize the contents of the attack packet (Ethernet header, IPv6 Header, and ICMPv6 header)
 * that are expected to remain constant for the specified attack.
 */
void init_packet_data(struct iface_data *idata) {
    struct dlt_null *dlt_null;
    ethernet = (struct ether_header *)buffer;
    dlt_null = (struct dlt_null *)buffer;
    v6buffer = buffer + idata->linkhsize;
    ipv6 = (struct ip6_hdr *)v6buffer;

    if (idata->type == DLT_EN10MB) {
        ethernet->ether_type = htons(ETHERTYPE_IPV6);

        if (!(idata->flags & IFACE_LOOPBACK)) {
            ethernet->src = idata->hsrcaddr;
            ethernet->dst = idata->hdstaddr;
        }
    }
    else if (idata->type == DLT_NULL) {
        dlt_null->family = PF_INET6;
    }
#if defined(__OpenBSD__)
    else if (idata->type == DLT_LOOP) {
        dlt_null->family = htonl(PF_INET6);
    }
#endif

    ipv6->ip6_flow = 0;
    ipv6->ip6_vfc = 0x60;
    ipv6->ip6_hlim = hoplimit;
    ipv6->ip6_src = idata->srcaddr;
    ipv6->ip6_dst = idata->dstaddr;

    prev_nh = (unsigned char *)&(ipv6->ip6_nxt);

    ptr = (unsigned char *)v6buffer + MIN_IPV6_HLEN;

    if (hbhopthdr_f) {
        hbhopthdrs = 0;

        while (hbhopthdrs < nhbhopthdr) {
            if ((ptr + hbhopthdrlen[hbhopthdrs]) > (v6buffer + idata->mtu)) {
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

    if (dstoptuhdr_f) {
        dstoptuhdrs = 0;

        while (dstoptuhdrs < ndstoptuhdr) {
            if ((ptr + dstoptuhdrlen[dstoptuhdrs]) > (v6buffer + idata->mtu)) {
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

    if (idata->fragh_f) {
        /* Check that we are able to send the Unfragmentable Part, together with a
           Fragment Header and a chunk data over our link layer
         */
        if ((fragpart + sizeof(fraghdr) + nfrags) > (v6buffer + idata->mtu)) {
            puts("Unfragmentable part too large for current MTU");
            exit(EXIT_FAILURE);
        }

        /* We prepare a separete Fragment Header, but we do not include it in the packet to be sent.
           This Fragment Header will be used (an assembled with the rest of the packet by the
           send_packet() function.
        */
        memset(&fraghdr, 0, FRAG_HDR_SIZE);
        *prev_nh = IPPROTO_FRAGMENT;
        prev_nh = (unsigned char *)&fraghdr;
    }

    if (dstopthdr_f) {
        dstopthdrs = 0;

        while (dstopthdrs < ndstopthdr) {
            if ((ptr + dstopthdrlen[dstopthdrs]) > (v6buffer + idata->max_packet_size)) {
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

    *prev_nh = IPPROTO_TCP;

    startofprefixes = ptr;
}

/*
 * Function: print_port_entries()
 *
 * Print port entries
 */

void print_port_entries(struct port_list *port_list) {
    int i;

    for (i = 0; i < port_list->nport; i++) {
        if ((port_list->port[i])->start == (port_list->port[i])->end) {
            printf("%u;", (port_list->port[i])->start);
        }
        else {
            printf("%u-%u;", (port_list->port[i])->start, (port_list->port[i])->end);
        }
    }
}

/*
 * Function: add_to_scan_list()
 *
 * Check whether an IPv6 address belongs to one of our scan ranges
 */
int add_to_scan_list(struct scan_list *scan_list, struct scan_entry *new_entry) {

    if (scan_list->ntarget >= scan_list->maxtarget) {
        return (FALSE);
    }

    /* Do not add this entry if it is a duplicate */
    if (is_scan_entry_duplicate(scan_list, new_entry)) {
        return (TRUE);
    }

    if ((scan_list->target[scan_list->ntarget] = malloc(sizeof(struct scan_entry))) == NULL) {
        if (verbose_f > 1)
            puts("scan6: Not enough memory");

        return (FALSE);
    }

    *(scan_list->target[scan_list->ntarget]) = *new_entry;
    (scan_list->ntarget)++;
    return (TRUE);
}

/*
 * Function: is_scan_entry_duplicate()
 *
 * Compares two IPv6 addresses
 */

int is_scan_entry_duplicate(struct scan_list *scan_list, struct scan_entry *scan_entry) {
    unsigned int i, j;

    for (i = 0; i < scan_list->ntarget; i++) {
        for (j = 0; j < 8; j++) {
            if (ntohs(scan_entry->start.in6_addr.s6_addr16[j]) <
                    ntohs((scan_list->target[i])->start.in6_addr.s6_addr16[j]) ||
                ntohs(scan_entry->end.in6_addr.s6_addr16[j]) >
                    ntohs((scan_list->target[i])->end.in6_addr.s6_addr16[j])) {
                break;
            }
        }

        if (j >= 8)
            return (TRUE);
    }

    return (FALSE);
}
