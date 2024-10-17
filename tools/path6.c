/*
 * path6: A versatile IPv6 traceroute
 *
 * Copyright (C) 2011-2024 Fernando Gont <fgont@si6networks.com>
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
 *
 * Build with: make path6
 *
 * It requires that the libpcap library be installed on your system.
 *
 * Please send any bug reports to Fernando Gont <fgont@si6networks.com>
 */

#include <sys/param.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include <errno.h>
#include <getopt.h>
#include <math.h>
#include <pcap.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ipv6toolkit.h"
#include "libipv6.h"
#include "path6.h"

/* Function prototypes */
void init_packet_data(struct iface_data *);
int send_probe(struct iface_data *, unsigned int, unsigned char, unsigned char, uint32_t);
void print_attack_info(struct iface_data *);
void print_help(void);
void usage(void);

/* Used for router discovery */
struct iface_data idata;

struct in6_addr randprefix;
unsigned char randpreflen;

/* Data structures for packets read from the wire */
struct pcap_pkthdr *pkthdr;
const u_char *pktdata;
unsigned char *pkt_end, *pkt_ptr;
struct ether_header *pkt_ether;
struct ip6_hdr *pkt_ipv6;
struct ip6_frag *pkt_fh;
struct icmp6_hdr *pkt_icmp6;
struct tcp_hdr *pkt_tcp;
struct udp_hdr *pkt_udp;
struct ah_hdr *pkt_ah;
struct esp_hdr *pkt_esp;
struct ip6_eh *pkt_eh;

struct nd_neighbor_solicit *pkt_ns;
struct in6_addr *pkt_ipv6addr;
unsigned int pktbytes;
unsigned int rhbytes, rhleft;

bpf_u_int32 my_netmask;
bpf_u_int32 my_ip;
struct bpf_program pcap_filter;
char dev[64], errbuf[PCAP_ERRBUF_SIZE];
unsigned char buffer[PACKET_BUFFER_SIZE], buffrh[MIN_IPV6_HLEN + MIN_TCP_HLEN];
unsigned char *v6buffer, *ptr, *startofprefixes;
char *pref;

struct ip6_hdr *ipv6;
struct icmp6_hdr *icmp6;

struct ether_header *ethernet;
struct dlt_null *dlt_null;
#if defined(__linux__)
struct sll_linux *sll_linux;
#endif
struct nd_opt_tlla *tllaopt;

char *lasts, *rpref;
char *charptr;

int nw;
unsigned long ul_res, ul_val;
unsigned int i, j, startrand;
unsigned int skip;
unsigned int frags, nfrags;
uint16_t mask, ip6length;
uint8_t hoplimit;

char plinkaddr[ETHER_ADDR_PLEN];
char psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN], pv6addr[INET6_ADDRSTRLEN];
unsigned char verbose_f = FALSE, numeric_f = TRUE;
unsigned char loop_f = FALSE, localaddr_f = 0, probe_f = 0, flowlabel_f = FALSE, flowlabelr_f = FALSE;
unsigned char srcprefix_f = FALSE, hoplimit_f = FALSE, ip6length_f = FALSE, icmp6psize_f = FALSE, send_f = FALSE,
              end_f = FALSE, delayp_f = FALSE;

/* Support for Extension Headers */
unsigned int dstopthdrs, dstoptuhdrs, hbhopthdrs;
char hbhopthdr_f = 0, dstoptuhdr_f = 0, dstopthdr_f = 0;
unsigned char *dstopthdr[MAX_DST_OPT_HDR], *dstoptuhdr[MAX_DST_OPT_U_HDR];
unsigned char *hbhopthdr[MAX_HBH_OPT_HDR];
unsigned int dstopthdrlen[MAX_DST_OPT_HDR], dstoptuhdrlen[MAX_DST_OPT_U_HDR];
unsigned int hbhopthdrlen[MAX_HBH_OPT_HDR], m, pad;

struct ip6_frag *fh, fraghdr;
struct ip6_hdr *fipv6;
unsigned char fragbuffer[FRAG_BUFFER_SIZE];

unsigned char *fragpart, *fptr, *fptrend, *ptrend, *ptrhdr, *ptrhdrend;
unsigned int hdrlen, ndstopthdr = 0, nhbhopthdr = 0, ndstoptuhdr = 0;
unsigned int nfrags, fragsize;
unsigned char *prev_nh, *startoffragment;

/* Parameters for the probe packets */
unsigned char probetype = PROBE_ICMP6_ECHO;
unsigned char dstport_f = FALSE, tcpflags_f = FALSE, pps_f = FALSE, bps_f = FALSE, endhost_f = FALSE, rhbytes_f = FALSE,
              droppacket_f = FALSE;
unsigned char scriptmode_f = FALSE;
uint16_t dstport, pid;
uint8_t tcpflags = 0, cprobe, pprobe, nprobe, maxprobes, chop, phop, nhop, maxhops;

struct in6_addr nsrc;
uint32_t tcpseq, spi, nflow = 0, flowlabel = 0;

#define MAXHOPS 30
#define MAXPROBES 3
struct probe test[MAXHOPS][MAXPROBES];
unsigned long pktinterval, rate;
unsigned int packetsize;

char line[LINE_BUFFER_SIZE];

int main(int argc, char **argv) {
    extern char *optarg;
    fd_set sset, rset;

    int r, sel;
    struct timeval curtime, start, lastprobe, sched, timeout;
    uint8_t ulhtype;
    struct target_ipv6 targetipv6;
    unsigned long fl;

    static struct option longopts[] = {{"interface", required_argument, 0, 'i'},
                                       {"link-src-addr", required_argument, 0, 'S'},
                                       {"link-dst-addr", required_argument, 0, 'D'},
                                       {"src-addr", required_argument, 0, 's'},
                                       {"dst-addr", required_argument, 0, 'd'},
                                       {"dst-opt-hdr", required_argument, 0, 'u'},
                                       {"dst-opt-u-hdr", required_argument, 0, 'U'},
                                       {"hbh-opt-hdr", required_argument, 0, 'H'},
                                       {"frag-hdr", required_argument, 0, 'y'},
                                       {"numeric", no_argument, 0, 'n'},
                                       {"flow-label", required_argument, 0, 'f'},
                                       {"probe-type", required_argument, 0, 'p'},
                                       {"payload-size", required_argument, 0, 'P'},
                                       {"dst-port", required_argument, 0, 'a'},
                                       {"tcp-flags", required_argument, 0, 'X'},
                                       {"rate-limit", required_argument, 0, 'r'},
                                       {"mode", required_argument, 0, 'm'},
                                       {"verbose", no_argument, 0, 'v'},
                                       {"help", no_argument, 0, 'h'},
                                       {0, 0, 0, 0}};

    const char shortopts[] = "i:S:D:s:d:u:U:H:y:nf:p:P:a:X:r:m:vh";

    char option;

    if (argc <= 1) {
        usage();
        exit(EXIT_FAILURE);
    }

    srandom(time(NULL));
    hoplimit = 64 + random() % 180;
    init_iface_data(&idata);

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

            if (inet_pton(AF_INET6, charptr, &(idata.srcaddr)) <= 0) {
                puts("inet_pton(): Source Address not valid");
                exit(EXIT_FAILURE);
            }

            idata.srcaddr_f = 1;

            if ((charptr = strtok_r(NULL, " ", &lasts)) != NULL) {
                idata.srcpreflen = atoi(charptr);

                if (idata.srcpreflen > 128) {
                    puts("Prefix length error in IPv6 Source Address");
                    exit(EXIT_FAILURE);
                }

                sanitize_ipv6_prefix(&(idata.srcaddr), idata.srcpreflen);
                idata.srcprefix_f = 1;
            }

            break;

        case 'd': /* IPv6 Destination Address */
            strncpy(targetipv6.name, optarg, NI_MAXHOST);
            targetipv6.name[NI_MAXHOST - 1] = 0;
            targetipv6.flags = AI_CANONNAME;

            if ((r = get_ipv6_target(&targetipv6)) != 0) {

                if (r < 0) {
                    printf("Unknown Destination: %s\n", gai_strerror(targetipv6.res));
                }
                else {
                    puts("Unknown Destination: No IPv6 address found for specified destination");
                }

                exit(EXIT_FAILURE);
            }

            idata.dstaddr = targetipv6.ip6;
            idata.dstaddr_f = 1;
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
            dstopthdr_f = 1;
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
            dstoptuhdr_f = 1;
            break;

        case 'H': /* Hop-by-Hop Options Header */
            if (nhbhopthdr >= MAX_HBH_OPT_HDR) {
                puts("Too many Hop-by-Hop Options Headers");
                exit(EXIT_FAILURE);
            }

            hdrlen = atoi(optarg);

            if (hdrlen < 8) {
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
            hbhopthdr_f = 1;
            break;

        case 'y': /* Fragment header */
            nfrags = atoi(optarg);
            if (nfrags < 8) {
                puts("Error in Fragmentation option: Fragment Size must be at least 8 bytes");
                exit(EXIT_FAILURE);
            }

            idata.fragh_f = TRUE;
            break;

        case 'n': /* Print IPv6 addresses ratther than hostnames */
            numeric_f = TRUE;
            break;

        case 'S': /* Source Ethernet address */
            if (ether_pton(optarg, &(idata.hsrcaddr), sizeof(idata.hsrcaddr)) == FALSE) {
                puts("Error in Source link-layer address.");
                exit(EXIT_FAILURE);
            }

            idata.hsrcaddr_f = 1;
            break;

        case 'D': /* Destination Ethernet Address */
            if (ether_pton(optarg, &(idata.hdstaddr), sizeof(idata.hdstaddr)) == FALSE) {
                puts("Error in Source link-layer address.");
                exit(EXIT_FAILURE);
            }

            idata.hdstaddr_f = 1;
            break;

        case 'f': /* Flow Label */
            if (strncmp(optarg, "rand", sizeof(rand)) == 0) {
                flowlabelr_f = TRUE;
            }
            else {
                if ((fl = strtoul(optarg, NULL, 0)) == ULONG_MAX) {
                    puts("Flow Label value is too large");
                    exit(EXIT_FAILURE);
                }

                flowlabel = fl & 0x000fffff;
                /*					flowlabel= atoi(optarg) & 0x000fffff; */
                flowlabel_f = TRUE;
            }

            break;

        case 'p': /* Probe type */
            if (strncmp(optarg, "echo", strlen("echo")) == 0 || strncmp(optarg, "icmp", strlen("icmp")) == 0) {
                probetype = PROBE_ICMP6_ECHO;
                probe_f = TRUE;
            }
            else if (strncmp(optarg, "udp", strlen("udp")) == 0) {
                probetype = PROBE_UDP;
                probe_f = TRUE;
            }
            else if (strncmp(optarg, "tcp", strlen("tcp")) == 0) {
                probetype = PROBE_TCP;
                probe_f = TRUE;
            }
            else if (strncmp(optarg, "esp", strlen("ESP")) == 0) {
                probetype = PROBE_ESP;
                probe_f = TRUE;
            }
            else if (strncmp(optarg, "ah", strlen("AH")) == 0) {
                probetype = PROBE_AH;
                probe_f = TRUE;
            }
            else {
                puts("Error in '-p' option: Unknown probe type");
                exit(EXIT_FAILURE);
            }

            break;

        case 'P': /* Payload Size*/
            rhbytes = atoi(optarg);
            rhbytes_f = 1;
            break;

        case 'a': /* TCP/UDP Destination Port */
            dstport = atoi(optarg);
            dstport_f = TRUE;
            break;

        case 'X':
            if (strncmp(optarg, "no", 2) == 0 || strncmp(optarg, "noflags", strlen("noflags")) == 0) {
                tcpflags_f = 1;
                break;
            }

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
                    printf("Error: Unknown TCP flag '%c'\n", *charptr);
                    exit(EXIT_FAILURE);
                    break;
                }

                if (*charptr == 'X')
                    break;

                charptr++;
            }

            tcpflags_f = TRUE;
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

        case 'm':
            if (strncmp(optarg, "num", sizeof("num")) == 0) {
                numeric_f = TRUE;
            }
            else if (strncmp(optarg, "script", sizeof("script")) == 0) {
                scriptmode_f = TRUE;
            }

            break;

        case 'v': /* Be verbose */
            idata.verbose_f++;
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

    verbose_f = idata.verbose_f;

    if (geteuid()) {
        puts("path6 needs root privileges to run.");
        exit(EXIT_FAILURE);
    }

    if (!idata.dstaddr_f) {
        puts("Error: Must specify Destination System");
        exit(EXIT_FAILURE);
    }

    if (!idata.iface_f) {
        if (idata.dstaddr_f && IN6_IS_ADDR_LINKLOCAL(&(idata.dstaddr))) {
            puts("Must specify a network interface for link-local destinations");
            exit(EXIT_FAILURE);
        }
    }

    if (load_dst_and_pcap(&idata, LOAD_SRC_NXT_HOP) == FAILURE) {
        puts("Error while learning Source Address and Next Hop");
        exit(EXIT_FAILURE);
    }

    release_privileges();

    if ((idata.ip6_local_flag && idata.ip6_global_flag) && !idata.srcaddr_f)
        localaddr_f = 1;

    if (!probe_f)
        probetype = PROBE_ICMP6_ECHO;

    if (probetype == PROBE_TCP) {
        if (!dstport_f)
            dstport = 80;

        if (!tcpflags_f)
            tcpflags = TH_SYN;

        tcpseq = random() & 0x7fffffff;
    }
    else if (probetype == PROBE_UDP) {
        if (!dstport_f)
            dstport = 60000 + random() % 5000;
    }
    else if (probetype == PROBE_ESP || probetype == PROBE_AH) {
        spi = random();
    }

    if (pps_f) {
        if (rate < 1)
            rate = 1;

        pktinterval = 1000000 / rate;
    }

    if (bps_f) {
        switch (probetype) {
        case PROBE_ICMP6_ECHO:
            packetsize = MIN_IPV6_HLEN + MIN_DST_OPT_HDR_SIZE + sizeof(struct icmp6_hdr);
            break;

        case PROBE_TCP:
            packetsize = MIN_IPV6_HLEN + sizeof(struct tcp_hdr);
            break;

        case PROBE_ESP:
            packetsize = MIN_IPV6_HLEN + sizeof(struct esp_hdr);
            break;

        case PROBE_AH:
            packetsize = MIN_IPV6_HLEN + sizeof(struct ah_hdr);
            break;
        }

        if (rate == 0 || ((packetsize * 8) / rate) <= 0)
            pktinterval = 1000000;
        else
            pktinterval = ((packetsize * 8) / rate) * 1000000;
    }

    /* We Default to 10 pps */
    if (!pps_f && !bps_f)
        pktinterval = 100000;

    if (inet_ntop(AF_INET6, &(idata.dstaddr), pv6addr, sizeof(pv6addr)) == NULL) {
        puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
        exit(EXIT_FAILURE);
    }

    if (idata.verbose_f) {
        print_attack_info(&idata);
    }

    if (!scriptmode_f)
        printf("Tracing path to %s (%s)...\n\n", targetipv6.name, pv6addr);

    /* Set initial contents of the attack packet */
    init_packet_data(&idata);

    /*
       Set filter for receiving IPv6 packets
       XXX: This filter should probably be refined
     */
    if (pcap_compile(idata.pfd, &pcap_filter, PCAP_IPV6_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("pcap_compile(): %s\n", pcap_geterr(idata.pfd));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(idata.pfd, &pcap_filter) == -1) {
        printf("pcap_setfilter(): %s\n", pcap_geterr(idata.pfd));
        exit(EXIT_FAILURE);
    }

    pid = getpid();

    pcap_freecode(&pcap_filter);

    maxhops = MAXHOPS;
    maxprobes = MAXPROBES;

    /* Initialize the table of results for the different tests */
    memset(test, 0, sizeof(test));

    FD_ZERO(&sset);
    FD_SET(idata.fd, &sset);

    /* Next probe to be printed out */
    phop = 0;
    pprobe = 0;

    /* Next probe to be sent */
    chop = 0;
    cprobe = 0;

    if (gettimeofday(&start, NULL) == -1) {
        if (idata.verbose_f)
            perror("path6");

        exit(EXIT_FAILURE);
    }

    /* PROBE_TIMEOUT is in seconds */
    sched.tv_sec = PROBE_TIMEOUT;
    sched.tv_usec = 0;

    lastprobe = timeval_sub(&start, &sched);

    end_f = 0;

    while (!end_f) {
        if (gettimeofday(&curtime, NULL) == -1) {
            if (idata.verbose_f)
                perror("path6");

            exit(EXIT_FAILURE);
        }

        if (scriptmode_f && phop < maxhops && pprobe < maxprobes && test[phop][pprobe].sent) {
            if (test[phop][pprobe].received) {
                /* If a response was received, print the RTT. */
                if (inet_ntop(AF_INET6, &(test[phop][pprobe].srcaddr), psrcaddr, sizeof(psrcaddr)) == NULL) {
                    puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
                    exit(EXIT_FAILURE);
                }

                printf("#%02d#%s#%08x#%08x#%.3f\n", phop + 1, psrcaddr, test[phop][pprobe].sflow,
                       test[phop][pprobe].rflow,
                       time_diff_ms(&(test[phop][pprobe].rtstamp), &(test[phop][pprobe].ststamp)));

                pprobe++;

                if (pprobe >= maxprobes) {
                    pprobe = 0;
                    phop++;

                    if (phop >= maxhops)
                        end_f = 1;
                }

                /*					puts(""); */
            }
            else if (is_time_elapsed(&curtime, &(test[phop][pprobe].ststamp), PROBE_TIMEOUT * 1000000)) {
                /* If there was a probe timeout, we allow to send another probe */
                send_f = 1;
                printf("#%02d####\n", phop + 1);

                pprobe++;

                if (pprobe >= maxprobes) {
                    pprobe = 0;
                    phop++;

                    if (phop >= maxhops)
                        end_f = 1;
                }
            }
        }
        else if (phop < maxhops && pprobe < maxprobes && test[phop][pprobe].sent) {
            /*
               If the next probe to be printed out has been sent, evaluate whether it is time to print out
               the result.

               phop: Holds hop to be printed
               probe: Holds probe number to be printed
             */
            if (test[phop][pprobe].received) {
                /* If a response was received, print the RTT. */
                if (inet_ntop(AF_INET6, &(test[phop][pprobe].srcaddr), psrcaddr, sizeof(psrcaddr)) == NULL) {
                    puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
                    exit(EXIT_FAILURE);
                }

                /*
                   delayp_f is set when no response has been received for this specific hop. So we wait until we receive
                   a response, such that we can print the IPv6 address followed by asterisks (for each missing response)
                 */
                if (delayp_f) {
                    if (numeric_f) {
                        printf(" %2d (%s)", phop + 1, psrcaddr);
                    }
                    else {
                    }

                    for (i = 0; i < pprobe; i++)
                        printf("  *");

                    printf("  %.3f ms", time_diff_ms(&(test[phop][pprobe].rtstamp), &(test[phop][pprobe].ststamp)));

                    delayp_f = 0;
                }
                else {
                    /* If this is the first "response" for this probe, print the IPv6 address
                       and the reverse domain name.
                     */
                    if (pprobe == 0) {
                        if (numeric_f) {
                            printf("%2d (%s)", phop + 1, psrcaddr);
                        }
                        else {
                        }
                    }

                    printf("  %.3f ms", time_diff_ms(&(test[phop][pprobe].rtstamp), &(test[phop][pprobe].ststamp)));
                }

                pprobe++;

                if (pprobe >= maxprobes) {
                    puts("");

                    pprobe = 0;
                    phop++;

                    if (phop >= maxhops)
                        end_f = 1;
                }

                fflush(stdout);
            }
            else if (is_time_elapsed(&curtime, &(test[phop][pprobe].ststamp), PROBE_TIMEOUT * 1000000)) {
                /* If there was a probe timeout, we allow to send another probe */
                send_f = 1;

                /*
                   If more than probe_timeout seconds have elapsed, consider the probe lost.
                   Print an asterisk, and wait for the next probe.
                 */

                if (pprobe == 0 || delayp_f) {
                    pprobe++;

                    if (pprobe >= maxprobes) {
                        printf("%2d ()   *  *  *\n", phop + 1);
                        fflush(stdout);
                        pprobe = 0;
                        phop++;

                        if (phop >= maxhops)
                            end_f = 1;

                        delayp_f = 0;
                    }
                    else {
                        delayp_f = 1;
                    }
                }
                else {
                    printf(" *");
                    pprobe++;

                    if (pprobe >= maxprobes) {
                        puts("");
                        pprobe = 0;

                        phop++;

                        if (phop >= maxhops)
                            end_f = 1;
                    }

                    fflush(stdout);
                }
            }
        }

        /* If there is a probe to be sent, and rate-limiting allows, send the probe send_f || */
        while ((is_time_elapsed(&curtime, &lastprobe, pktinterval)) && chop < maxhops && cprobe < maxprobes) {
            if (gettimeofday(&curtime, NULL) == -1) {
                if (idata.verbose_f)
                    perror("path6");

                exit(EXIT_FAILURE);
            }

            if (flowlabelr_f)
                flowlabel = random() & 0x00fffff;

            test[chop][cprobe].sent = TRUE;
            test[chop][cprobe].ststamp = curtime;
            test[chop][cprobe].sflow = flowlabel;
            lastprobe = curtime;

            if (send_probe(&idata, probetype, chop, cprobe, flowlabel) == -1) {
                puts("path6: Error while sending probe packet");
                exit(EXIT_FAILURE);
            }

            send_f = 0;

            cprobe++;

            if (cprobe >= maxprobes) {
                cprobe = 0;
                chop++;
            }
        }

        /*
           XXX: This should be improved. Essentially, select() might sleep for at most one second (if no
           packets are received). Then a bunch of probe packets might be sent out all at once.
          */
        rset = sset;
        timeout.tv_sec = pktinterval / 1000000;
        timeout.tv_usec = pktinterval % 1000000;

        /*
           Since we cannot count on the pcap_socket being readable, we should wait the smaller of 10ms or
   the packet rate "timeout"
         */

#if defined(sun) || defined(__sun) || defined(__linux__)
        if (timeout.tv_sec || timeout.tv_usec > 10000) {
            timeout.tv_sec = 0;
            timeout.tv_usec = 10000;
        }
#endif

        if ((sel = select(idata.fd + 1, &rset, NULL, NULL, &timeout)) == -1) {
            if (errno == EINTR) {
                continue;
            }
            else {
                if (idata.verbose_f)
                    puts("Error in select()");

                exit(EXIT_FAILURE);
            }
        }

#if defined(sun) || defined(__sun) || defined(__linux__)
        if (TRUE) {
#else
        if (FD_ISSET(idata.fd, &rset)) {
#endif
            /* Read a packet (Echo Reply, ICMPv6 Error, or Neighbor Solicitation) */
            if ((r = pcap_next_ex(idata.pfd, &pkthdr, &pktdata)) == -1) {
                if (idata.verbose_f)
                    printf("pcap_next_ex(): %s", pcap_geterr(idata.pfd));

                exit(EXIT_FAILURE);
            }
            else if (r == 1 && pktdata != NULL) {
#ifdef DEBUG
                puts("Got packet");
#endif
                nflow = 0xffffffff;
                pkt_ether = (struct ether_header *)pktdata;
                pkt_ipv6 = (struct ip6_hdr *)((char *)pkt_ether + idata.linkhsize);
                pkt_end = (unsigned char *)pktdata + pkthdr->caplen;

                if ((pkt_end - pktdata) < (idata.linkhsize + MIN_IPV6_HLEN))
                    continue;

                /*
                   We currently handle two cases: In the first case, there are extension headers, and hence we need to
                   walk through the extension header chain. In the other, the upper layer protocol is right after the
                   fixed IPv6 header
                 */
                if (pkt_ipv6->ip6_nxt != IPPROTO_ICMPV6 && pkt_ipv6->ip6_nxt != IPPROTO_TCP &&
                    pkt_ipv6->ip6_nxt != IPPROTO_UDP && pkt_ipv6->ip6_nxt != IPPROTO_ESP &&
                    pkt_ipv6->ip6_nxt != IPPROTO_AH) {
                    pkt_eh = (struct ip6_eh *)((char *)pkt_ipv6 + sizeof(struct ip6_hdr));

                    while (((unsigned char *)pkt_eh + MIN_EXT_HLEN) <= pkt_end &&
                           (pkt_eh->eh_nxt != IPPROTO_ICMPV6 && pkt_eh->eh_nxt != IPPROTO_TCP &&
                            pkt_eh->eh_nxt != IPPROTO_UDP && pkt_ipv6->ip6_nxt != IPPROTO_ESP &&
                            pkt_ipv6->ip6_nxt != IPPROTO_AH)) {
                        pkt_eh = (struct ip6_eh *)((char *)pkt_eh + (pkt_eh->eh_len + 1) * 8);
                    }

                    if ((unsigned char *)pkt_eh >= pkt_end) {
                        continue;
                    }
                    else {
                        ulhtype = pkt_eh->eh_nxt;
                        pkt_icmp6 = (struct icmp6_hdr *)((char *)pkt_eh + (pkt_eh->eh_len + 1) * 8);
                        pkt_udp = (struct udp_hdr *)pkt_icmp6;
                        pkt_icmp6 = (struct icmp6_hdr *)pkt_icmp6;
                        pkt_tcp = (struct tcp_hdr *)pkt_icmp6;
                        pkt_ah = (struct ah_hdr *)pkt_icmp6;
                        pkt_esp = (struct esp_hdr *)pkt_icmp6;
                        pkt_ns = (struct nd_neighbor_solicit *)pkt_icmp6;
                    }
                }
                else {
                    ulhtype = pkt_ipv6->ip6_nxt;
                    pkt_icmp6 = (struct icmp6_hdr *)((char *)pkt_ipv6 + sizeof(struct ip6_hdr));
                    pkt_ns = (struct nd_neighbor_solicit *)pkt_icmp6;
                    pkt_tcp = (struct tcp_hdr *)pkt_icmp6;
                    pkt_ah = (struct ah_hdr *)pkt_icmp6;
                    pkt_esp = (struct esp_hdr *)pkt_icmp6;
                    pkt_udp = (struct udp_hdr *)pkt_icmp6;
                }

                /*
                   At this point, we have skipped IPv6 EHs if there were any, and pkt_* pointers are set
                   accordingly.
                 */
                if (ulhtype == IPPROTO_ICMPV6) {
                    if (idata.type == DLT_EN10MB && !(idata.flags & IFACE_LOOPBACK) &&
                        pkt_icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT) {
                        if ((pkt_end - (unsigned char *)pkt_ns) < sizeof(struct nd_neighbor_solicit))
                            continue;
                        /*
                                If the addresses that we're using are not actually configured on the local system
                                (i.e., they are "spoofed", we must check whether it is a Neighbor Solicitation for
                                one of our addresses, and respond with a Neighbor Advertisement. Otherwise, the kernel
                                will take care of that.
                         */
                        if (!localaddr_f && is_eq_in6_addr(&(pkt_ns->nd_ns_target), &idata.srcaddr)) {
                            if (send_neighbor_advert(&idata, idata.pfd, pktdata) == -1) {
                                puts("Error sending Neighbor Advertisement");
                                exit(EXIT_FAILURE);
                            }
                        }

                        continue;
                    }
                    else if (probetype == PROBE_ICMP6_ECHO && (pkt_icmp6->icmp6_type == ICMP6_ECHO_REPLY)) {
#ifdef DEBUG
                        puts("Got Echo Reply");
#endif
                        /* Process the ICMPv6 Echo Reply */
                        if ((pkt_end - (unsigned char *)pkt_icmp6) < sizeof(struct icmp6_hdr))
                            continue;

                        if (ntohs(pkt_icmp6->icmp6_data16[0]) != pid)
                            continue;

                        nhop = ntohs(pkt_icmp6->icmp6_data16[1]) >> 8;
                        nprobe = ntohs(pkt_icmp6->icmp6_data16[1]) & 0x00ff;

                        if (nhop >= maxhops)
                            continue;

                        if (!is_eq_in6_addr(&(pkt_ipv6->ip6_src), &(idata.dstaddr)))
                            continue;

                        nsrc = pkt_ipv6->ip6_src;
                        endhost_f = 1;
                    }
                    else if ((pkt_icmp6->icmp6_type == ICMP6_TIME_EXCEEDED &&
                              pkt_icmp6->icmp6_code == ICMP6_TIME_EXCEED_TRANSIT) ||
                             pkt_icmp6->icmp6_type == ICMP6_DST_UNREACH || pkt_icmp6->icmp6_type == ICMP6_PARAM_PROB) {
#ifdef DEBUG
                        puts("Got ICMPv6 error");
#endif
                        /* XXX: TODO: THe code currently does not differentiate between different ICMPv6 error types.
                           This should be properly signaled to the user */
                        /* Process the ICMPv6 Error message */
                        /* Record the source address of the error message */
                        nsrc = pkt_ipv6->ip6_src;

                        if (is_eq_in6_addr(&nsrc, &(idata.dstaddr)))
                            endhost_f = 1;

                        if (inet_ntop(AF_INET6, &(nsrc), psrcaddr, sizeof(psrcaddr)) == NULL) {
                            puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
                            exit(EXIT_FAILURE);
                        }

                        /* IPv6 header of embedded payload */
                        pkt_ipv6 = (struct ip6_hdr *)((char *)pkt_icmp6 + sizeof(struct icmp6_hdr));

                        /*
                            Discard the packet if the ICMPv6 error does not contain a full IPv6 header
                            embedded in the ICMPv6 payload
                         */
                        if (((unsigned char *)pkt_ipv6 + sizeof(struct ip6_hdr)) > pkt_end)
                            continue;

                        /*
                            Discard the packet if the embeded IPv6 packet was not directed to our
                            current destination.
                         */
                        if (!is_eq_in6_addr(&(pkt_ipv6->ip6_dst), &(idata.dstaddr)))
                            continue;

                        /*
                            Discard the packet if the embeded IPv6 packet did not use our current
                            Source Address.
                         */
                        if (!is_eq_in6_addr(&(pkt_ipv6->ip6_src), &(idata.srcaddr)))
                            continue;

                        nflow = ntohl(pkt_ipv6->ip6_flow) & 0x000fffff;

                        ulhtype = pkt_ipv6->ip6_nxt;
                        pkt_eh = (struct ip6_eh *)((char *)pkt_ipv6 + sizeof(struct ip6_hdr));

                        droppacket_f = FALSE;

#ifdef DEBUG
                        puts("Passed all basic checks");
#endif

                        /* If the embedded packet contains EHs, we need to skip the EHs to get to the upper layer
                         * protocol */
                        /* XXX
                           The current code assumes that anything that's not a possible probe packet or an ICMPv6 error
                           is an EH. Other ULPs will be processed as malformed EHs, and thus be dealt with gracefully.
                           However, the code should only process currently-specified EHs, or drop the packet when any
                           other header type (whether EH or ULP) is found.
                         */
                        while (ulhtype != IPPROTO_ICMPV6 && ulhtype != IPPROTO_TCP && ulhtype != IPPROTO_UDP &&
                               ulhtype != IPPROTO_ESP && ulhtype != IPPROTO_AH && !droppacket_f) {
                            if ((unsigned char *)pkt_eh >= pkt_end) {
                                droppacket_f = TRUE;
                                break;
                            }

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

                                /* XXX */
                                pkt_eh = (struct ip6_eh *)((char *)fh + sizeof(struct ip6_frag));
                                break;
                            }
                            else {
                                if (((unsigned char *)pkt_eh + sizeof(struct ip6_eh)) > pkt_end) {
                                    droppacket_f = TRUE;
                                    break;
                                }

                                ulhtype = pkt_eh->eh_nxt;
                                pkt_eh = (struct ip6_eh *)((char *)pkt_eh + (pkt_eh->eh_len + 1) * 8);
                            }
                        }

                        if (droppacket_f) {
                            continue;
                        }

                        pkt_icmp6 = (struct icmp6_hdr *)((char *)pkt_eh);
                        pkt_tcp = (struct tcp_hdr *)((char *)pkt_eh);
                        pkt_udp = (struct udp_hdr *)((char *)pkt_eh);
                        pkt_esp = (struct esp_hdr *)((char *)pkt_eh);
                        pkt_ah = (struct ah_hdr *)((char *)pkt_eh);

#ifdef DEBUG
                        puts("Passed even more checks");
#endif
                        /* Packet was an ICMPv6 error, and we're now processing the embedded payload */

                        if (probetype == PROBE_ICMP6_ECHO && ulhtype == IPPROTO_ICMPV6 &&
                            pkt_icmp6->icmp6_type == ICMP6_ECHO_REQUEST) {

                            if ((pkt_end - (unsigned char *)pkt_icmp6) < sizeof(struct icmp6_hdr))
                                continue;

                            if (ntohs(pkt_icmp6->icmp6_data16[0]) != pid)
                                continue;

                            nhop = ntohs(pkt_icmp6->icmp6_data16[1]) >> 8;
                            nprobe = ntohs(pkt_icmp6->icmp6_data16[1]) & 0x00ff;
#ifdef DEBUG
                            printf("hop %d, probe: %d\n", nhop, nprobe);
#endif
                        }
                        else if (probetype == PROBE_TCP && ulhtype == IPPROTO_TCP) {
                            /* Must still verify the TCP checksum */

                            if ((pkt_end - (unsigned char *)pkt_tcp) < sizeof(struct tcp_hdr))
                                continue;

                            if (ntohl(pkt_tcp->th_seq) != tcpseq)
                                continue;

                            nhop = (ntohs(pkt_tcp->th_sport) >> 8) - PROBE_PORT_OFFSET;
                            nprobe = ntohs(pkt_tcp->th_sport) & 0xff;
#ifdef DEBUG
                            puts("Got Time Exceeded for TCP probe");
#endif
                        }
                        else if (probetype == PROBE_UDP && ulhtype == IPPROTO_UDP) {
                            /* Must still verify the UDP checksum */
                            if ((pkt_end - (unsigned char *)pkt_udp) < sizeof(struct udp_hdr))
                                continue;

                            if (ntohs(pkt_udp->uh_ulen) < sizeof(struct udp_hdr))
                                continue;

                            nhop = (ntohs(pkt_udp->uh_sport) >> 8) - PROBE_PORT_OFFSET;
                            nprobe = ntohs(pkt_udp->uh_sport) & 0xff;
#ifdef DEBUG
                            puts("Got Time Exceeded for UDP probe");
#endif
                        }

                        else if (probetype == PROBE_ESP && ulhtype == IPPROTO_ESP) {
                            if ((pkt_end - (unsigned char *)pkt_esp) < sizeof(struct esp_hdr))
                                continue;

                            if (pkt_esp->esp_spi != spi)
                                continue;

                            nhop = ntohl(pkt_esp->esp_seq) >> 16;
                            nprobe = ntohl(pkt_esp->esp_seq) & 0x000000ff;
                        }
                        else if (probetype == PROBE_AH && ulhtype == IPPROTO_AH) {
                            if ((pkt_end - (unsigned char *)pkt_ah) < sizeof(struct ah_hdr))
                                continue;

                            if (pkt_ah->ah_spi != spi)
                                continue;

                            nhop = ntohl(pkt_ah->ah_seq) >> 16;
                            nprobe = ntohl(pkt_ah->ah_seq) & 0x000000ff;
#ifdef DEBUG
                            puts("Got time exceeeded for AH");
#endif
                        }
                    }
                    else {
                        continue;
                    }
                }
                else if (ulhtype == IPPROTO_TCP && probetype == PROBE_TCP) {
                    /* Must still verify the TCP checksum -- We do not do it yet */

                    if ((pkt_end - (unsigned char *)pkt_tcp) < sizeof(struct tcp_hdr))
                        continue;

                    if (!is_eq_in6_addr(&(pkt_ipv6->ip6_src), &(idata.dstaddr))) {
                        continue;
                    }

                    /* XXX: This check should really take into account the payload size */
                    if (ntohl(pkt_tcp->th_ack) < tcpseq || ntohl(pkt_tcp->th_ack) > (tcpseq + 100000)) {
                        continue;
                    }

                    if (ntohs(pkt_tcp->th_sport) != dstport) {
                        continue;
                    }

                    nhop = (ntohs(pkt_tcp->th_dport) >> 8) - PROBE_PORT_OFFSET;
                    nprobe = ntohs(pkt_tcp->th_dport) & 0x00ff;

                    nsrc = pkt_ipv6->ip6_src;
                    endhost_f = 1;
                }
                else if (probetype == PROBE_UDP && ulhtype == IPPROTO_UDP) {
                    /* Must still verify the UDP checksum */
                    if ((pkt_end - (unsigned char *)pkt_udp) < sizeof(struct udp_hdr))
                        continue;

                    if (ntohs(pkt_udp->uh_sport) != dstport) {
                        continue;
                    }

                    nprobe = (ntohs(pkt_udp->uh_sport) >> 8) - PROBE_PORT_OFFSET;
                    nhop = ntohs(pkt_udp->uh_sport) & 0x00ff;

                    nsrc = pkt_ipv6->ip6_src;
                    endhost_f = 1;
                }
                else {
                    continue;
                }

                if (nprobe >= maxprobes) {
#ifdef DEBUG
                    printf("Descarte por nprobe mayor o igual que maxprobe (%u >= %u)\n", nprobe, maxprobes);
#endif
                    continue;
                }

                if (nhop >= maxhops) {
#ifdef DEBUG
                    printf("Descarte por nhop mayor o igual que maxhops (%u >= %u)\n", nhop, maxhops);
#endif
                    continue;
                }

                if (test[nhop][nprobe].received) {
#ifdef DEBUG
                    printf("Descarte por (nhop, nprobe) ya habia sido recibido (%u, %u)\n", nhop, nprobe);
#endif
                    continue;
                }

                if (test[nhop][nprobe].sent == FALSE) {
#ifdef DEBUG
                    printf("Descarte por (nhop, nprobe) no habia sido enviado (%u, %u)\n", nhop, nprobe);
#endif
                    continue;
                }

                test[nhop][nprobe].received = TRUE;

                /* Record the receive time from the pkthdr timestamp
                   XXX: We employ the ts member (struct timeval) in struct pcap_pkthdr. That way we do not need to
                   hurry up to process the received packets, and can e.g. do DNS resolutions without screwing up the
                   measured RTTs.
                 */
                test[nhop][nprobe].rtstamp.tv_sec = (pkthdr->ts).tv_sec;
                test[nhop][nprobe].rtstamp.tv_usec = (pkthdr->ts).tv_usec;
                test[nhop][nprobe].srcaddr = nsrc;
                test[nhop][nprobe].rflow = nflow;

                /* If we got a response to a probe packet, allow for an additional probe to be sent */
                send_f = TRUE;

                /*
                   If we received a response from the end host, we artificially change maxhops such that we do not
                   send probes for larger Hop Limits
                 */

                if (endhost_f && nhop < maxhops && phop <= nhop)
                    maxhops = nhop + 1;

                endhost_f = 0;
            }
        }
    }

    exit(EXIT_SUCCESS);
}

/*
 * Function: usage()
 *
 * Prints the syntax of the frag6 tool
 */
void usage(void) {
    puts("usage: path6 -d DST_ADDR [-i INTERFACE] [-S LINK_SRC_ADDR] [-D LINK-DST-ADDR]\n"
         "       [-s SRC_ADDR[/LEN]] [-u DST_OPT_HDR_SIZE] [-U DST_OPT_U_HDR_SIZE]\n"
         "       [-H HBH_OPT_HDR_SIZE] [-y FRAG:SIZE] [-f FLOW_LABEL]\n"
         "       [-m MODE] [-p PROBE_TYPE] [-P PAYLOAD_SIZE] [-a DST_PORT] \n"
         "       [-X TCP_FLAGS] [-r RATE_LIMIT] [-v] [-h]");
}

/*
 * Function: print_help()
 *
 * Prints help information for the path6 tool
 */
void print_help(void) {
    puts(SI6_TOOLKIT);
    puts("path6: A versatile IPv6 traceroute\n");
    usage();

    puts("\nOPTIONS:\n"
         "  --interface, -i           Network interface\n"
         "  --link-src-addr, -S       Link-layer Destination Address\n"
         "  --link-dst-addr, -D       Link-layer Source Address\n"
         "  --src-addr, -s            IPv6 Source Address\n"
         "  --dst-addr, -d            IPv6 Destination Address\n"
         "  --frag-hdr. -y            Fragment Header\n"
         "  --dst-opt-hdr, -u         Destination Options Header (Fragmentable Part)\n"
         "  --dst-opt-u-hdr, -U       Destination Options Header (Unfragmentable Part)\n"
         "  --hbh-opt-hdr, -H         Hop by Hop Options Header\n"
         "  --flow-label, -f          Specifies the Flow Label Value (or 'random')\n"
         "  --output-mode, -m         Specifies output mode (e.g. 'script')\n"
         "  --probe-type, -p          Probe type {icmp, tcp, udp, ah, esp}\n"
         "  --payload-size, -P        Payload Size\n"
         "  --dst-port, -a            Transport-layer Destination Port\n"
         "  --tcp-flags, -X           TCP Flags\n"
         "  --rate-limit, -r          Rate limit the probe packets\n"
         "  --verbose, -v             Be verbose\n"
         "  --help, -h                Print help for the path6 tool\n"
         "\n"
         "Programmed by Fernando Gont for SI6 Networks <https://www.si6networks.com>\n"
         "Please send any bug reports to <fgont@si6networks.com>\n");
}

/*
 * Function: print_attack_info()
 *
 * Prints attack details (when the verbose ("-v") option is specified).
 */

void print_attack_info(struct iface_data *idata) {
    if (idata->type == DLT_EN10MB && !(idata->flags & IFACE_LOOPBACK)) {
        if (ether_ntop(&(idata->hsrcaddr), plinkaddr, sizeof(plinkaddr)) == FALSE) {
            puts("ether_ntop(): Error converting address");
            exit(EXIT_FAILURE);
        }

        printf("Ethernet Source Address: %s%s\n", plinkaddr, (!idata->hsrcaddr_f) ? " (automatically selected)" : "");

        /*
           Ethernet Destination Address only used if a IPv6 Destination Address or an
           Ethernet Destination Address were specified.
         */
        if (ether_ntop(&(idata->hdstaddr), plinkaddr, sizeof(plinkaddr)) == FALSE) {
            puts("ether_ntop(): Error converting address");
            exit(EXIT_FAILURE);
        }

        printf("Ethernet Destination Address: %s%s\n", plinkaddr,
               (!idata->hdstaddr_f) ? " (automatically selected)" : "");
    }

    if (inet_ntop(AF_INET6, &(idata->srcaddr), psrcaddr, sizeof(psrcaddr)) == NULL) {
        puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
        exit(EXIT_FAILURE);
    }

    if (idata->dstaddr_f) {
        printf("IPv6 Source Address: %s%s\n", psrcaddr, ((!idata->srcaddr_f) ? " (automatically selected)" : ""));
    }

    if (inet_ntop(AF_INET6, &(idata->dstaddr), pdstaddr, sizeof(pdstaddr)) == NULL) {
        puts("inet_ntop(): Error converting IPv6 Destination Address to presentation format");
        exit(EXIT_FAILURE);
    }

    printf("IPv6 Destination Address: %s\n", pdstaddr);

    for (i = 0; i < ndstoptuhdr; i++)
        printf("Destination Options Header (Unfragmentable part): %u bytes\n", dstoptuhdrlen[i]);

    for (i = 0; i < nhbhopthdr; i++)
        printf("Hop by Hop Options Header: %u bytes\n", hbhopthdrlen[i]);

    for (i = 0; i < ndstopthdr; i++)
        printf("Destination Options Header: %u bytes\n", dstopthdrlen[i]);

    switch (probetype) {
    case PROBE_ICMP6_ECHO:
        puts("Probe type: ICMPv6 Echo Request");

        break;

    case PROBE_UDP:
        puts("Probe type: UDP");
        printf("Destination Port: %u%s\n", dstport, (dstport_f ? "" : " (default)"));
        break;

    case PROBE_TCP:
        puts("Probe type: TCP");
        printf("TCP Flags: %s%s%s%s%s%s%s%s\t", ((tcpflags & TH_FIN) ? "F" : ""), ((tcpflags & TH_SYN) ? "S" : ""),
               ((tcpflags & TH_RST) ? "R" : ""), ((tcpflags & TH_PUSH) ? "P" : ""), ((tcpflags & TH_ACK) ? "A" : ""),
               ((tcpflags & TH_URG) ? "U" : ""), ((!tcpflags) ? "none" : ""), ((!tcpflags_f) ? " (default)" : ""));

        printf("Destination Port: %u%s\n", dstport, (dstport_f ? "" : " (default)"));
        break;

    case PROBE_ESP:
        puts("Probe type: ESP");
        break;

    case PROBE_AH:
        puts("Probe type: AH");
        break;

    default:
        puts("Probe type: Unknown"); /* Should never get here */
        break;
    }

    if (rhbytes_f) {
        printf("Payload size: %u byte%s\n", rhbytes, (rhbytes > 1) ? "s" : "");
    }
}

/*
 * Function: init_packet_data()
 *
 * Initialize the contents of the attack packet (Ethernet header, IPv6 Header, and ICMPv6 header)
 * that are expected to remain constant for the specified attack.
 */
void init_packet_data(struct iface_data *idata) {
    ethernet = (struct ether_header *)buffer;
    dlt_null = (struct dlt_null *)buffer;
    v6buffer = buffer + idata->linkhsize;
    ipv6 = (struct ip6_hdr *)v6buffer;
#if defined(__linux__)
    sll_linux = (struct sll_linux *)buffer;
#endif

    if (idata->type == DLT_EN10MB) {
        ethernet->ether_type = htons(ETHERTYPE_IPV6);

        if (idata->flags != IFACE_LOOPBACK) {
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
#elif defined(__linux__)
    else if (idata->type == DLT_LINUX_SLL) {
        sll_linux->sll_pkttype = htons(0x0004);
        sll_linux->sll_hatype = htons(0xffff);
        sll_linux->sll_halen = htons(0x0000);
        sll_linux->sll_protocol = htons(ETHERTYPE_IPV6);
    }
#endif

    ipv6->ip6_flow = htonl(flowlabel);
    ipv6->ip6_vfc = 0x60;
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
            printf("Unfragmentable part too large for current MTU (%u bytes)\n", idata->mtu);
            exit(EXIT_FAILURE);
        }

        /* We prepare a separate Fragment Header, but we do not include it in the packet to be sent.
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

    startofprefixes = ptr;
}

/*
 * Function: send_probe()
 *
 * Send a probe packet
 */
int send_probe(struct iface_data *idata, unsigned int probetype, unsigned char chop, unsigned char cprobe,
               uint32_t flowlabel) {
    struct tcp_hdr *tcp;
    struct udp_hdr *udp;
    struct ah_hdr *ah;
    struct esp_hdr *esp;
    struct icmp6_hdr *icmp6;

    ptr = startofprefixes;
    ipv6->ip6_hlim = chop + 1;

    if (flowlabelr_f)
        ipv6->ip6_flow = (ipv6->ip6_flow & htonl(0xfff00000)) | htonl(flowlabel);

    if (probetype == PROBE_ICMP6_ECHO) {
        *prev_nh = IPPROTO_ICMPV6;

        if ((ptr + sizeof(struct icmp6_hdr)) > (v6buffer + idata->max_packet_size)) {
            puts("Packet too large while inserting ICMPv6 header (should be using Frag. option?)");
            exit(EXIT_FAILURE);
        }

        icmp6 = (struct icmp6_hdr *)ptr;

        icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6->icmp6_code = 0;
        /*
           The Identifier field (icmp6_data16[0]) contains the PID of this process (as usual
           for the ping(8) tool. The "Sequence Number" field (icmp6_data16[1]) encodes the original
           Hop Limit and the probe number. The probe number is encoded in the upper 8 bits, while the
           hop limit is encoded in the lower 8 bits.
         */
        icmp6->icmp6_data16[0] = htons(pid);
        icmp6->icmp6_data16[1] = htons(((uint16_t)chop << 8) + (cprobe & 0xff));
        ptr += sizeof(struct icmp6_hdr);

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

        icmp6->icmp6_cksum = 0;
        icmp6->icmp6_cksum = in_chksum(v6buffer, icmp6, ptr - ((unsigned char *)icmp6), IPPROTO_ICMPV6);
    }
    else if (probetype == PROBE_TCP) {
        *prev_nh = IPPROTO_TCP;

        if ((ptr + sizeof(struct tcp_hdr)) > (v6buffer + idata->max_packet_size)) {
            puts("Packet too large while inserting ICMPv6 header (should be using Frag. option?)");
            exit(EXIT_FAILURE);
        }

        tcp = (struct tcp_hdr *)ptr;
        ptr += sizeof(struct tcp_hdr);
        memset(tcp, 0, sizeof(struct tcp_hdr));

        /*
           For TCP, we encode the probe number and the current Hop Limit in the TCP Source Port.
           The probe number is encoded in the upper eight bits, while the current Hop Limit is
           encoded in the lower eight bits. A constant "offset" is employed for encoding the probe
           number, such that the resulting Source Port falls into what is typically known as the
           dynamic ports range (say, ports larger than 50000).
         */
        tcp->th_sport = htons((((uint16_t)chop + PROBE_PORT_OFFSET) << 8) + cprobe);
        tcp->th_dport = htons(dstport);
        tcp->th_seq = htonl(tcpseq);

        /*
           If no flags were specified, we set the ACK bit, since all TCP segments other than SYNs
           are required to have the ACK bit set.
         */
        tcp->th_ack = htonl((tcpflags & TH_ACK) ? random() : 0);
        tcp->th_flags = tcpflags;
        tcp->th_urp = htons(0);
        tcp->th_win = htons((random() + 1024) & 0x7f00);
        tcp->th_off = MIN_TCP_HLEN >> 2;

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
        tcp->th_sum = 0;
        tcp->th_sum = in_chksum(v6buffer, tcp, ptr - ((unsigned char *)tcp), IPPROTO_TCP);
    }
    else if (probetype == PROBE_UDP) {
        *prev_nh = IPPROTO_UDP;

        if ((ptr + sizeof(struct udp_hdr)) > (v6buffer + idata->max_packet_size)) {
            puts("Packet too large while inserting ICMPv6 header (should be using Frag. option?)");
            exit(EXIT_FAILURE);
        }

        udp = (struct udp_hdr *)ptr;
        ptr += sizeof(struct udp_hdr);
        memset(udp, 0, sizeof(struct udp_hdr));

        /*
           For UDP, we encode the current probe number and the current Hop Limit as fr TCP.
           Namely, we encode the probe number and the current Hop Limit in the TCP Source Port.
           The probe number is encoded in the upper eight bits, while the current Hop Limit is
           encoded in the lower eight bits. A constant "offset" is employed for encoding the probe
           number, such that the resulting Source Port falls into what is typically known as the
           dynamic ports range (say, ports larger than 50000).
         */

        udp->uh_sport = htons((((uint16_t)chop + PROBE_PORT_OFFSET) << 8) + cprobe);

        udp->uh_dport = htons(dstport + (chop * 3) + cprobe);

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
    }

    else if (probetype == PROBE_AH) {
        *prev_nh = IPPROTO_AH;

        if ((ptr + sizeof(struct ah_hdr)) > (v6buffer + idata->max_packet_size)) {
            puts("Packet too large while inserting AH header (should be using Frag. option?)");
            exit(EXIT_FAILURE);
        }

        ah = (struct ah_hdr *)ptr;
        ptr += sizeof(struct ah_hdr);
        memset(ah, 0, sizeof(struct ah_hdr));

        /*
           For AH, we set the SPI to a random value, and encode the probe numbers in the SEQ
         */

        ah->ah_spi = spi;
        ah->ah_seq = htonl((((uint32_t)chop) << 16) + cprobe);

        ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);
        ah->ah_nxt = IPPROTO_TCP;               /* XXX: This should be changed */
        ah->ah_len = sizeof(struct ah_hdr) / 4; /* XXX: Should be modified if we relax the AH format */
    }

    else if (probetype == PROBE_ESP) {
        *prev_nh = IPPROTO_ESP;

        if ((ptr + sizeof(struct esp_hdr)) > (v6buffer + idata->max_packet_size)) {
            puts("Packet too large while inserting ESP header (should be using Frag. option?)");
            exit(EXIT_FAILURE);
        }

        esp = (struct esp_hdr *)ptr;
        ptr += sizeof(struct esp_hdr);
        memset(esp, 0, sizeof(struct esp_hdr));

        /*
           For ESP, we set the SPI to a random value, and encode the probe numbers in the SEQ
         */

        esp->esp_spi = spi;
        esp->esp_seq = htonl((((uint32_t)chop) << 16) + cprobe);

        ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);
    }

    if (!idata->fragh_f) {
        ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);

        if ((nw = pcap_inject(idata->pfd, buffer, ptr - buffer)) == -1) {
            printf("pcap_inject(): %s\n", pcap_geterr(idata->pfd));
            return (-1);
        }

        if (nw != (ptr - buffer)) {
            printf("pcap_inject(): only wrote %d bytes (rather than %lu bytes)\n", nw, (LUI)(ptr - buffer));
            return (-1);
        }

        return (0);
    }
    else {
        ptrend = ptr;
        ptr = fragpart;
        fptr = fragbuffer;
        fipv6 = (struct ip6_hdr *)(fragbuffer + idata->linkhsize);
        fptrend = fptr + FRAG_BUFFER_SIZE;
        memcpy(fptr, buffer, fragpart - buffer);
        fptr = fptr + (fragpart - buffer);

        if ((fptr + FRAG_HDR_SIZE) > fptrend) {
            puts("Unfragmentable Part is Too Large");
            exit(EXIT_FAILURE);
        }

        memcpy(fptr, (char *)&fraghdr, FRAG_HDR_SIZE);
        fh = (struct ip6_frag *)fptr;
        fh->ip6f_ident = random();
        startoffragment = fptr + FRAG_HDR_SIZE;

        /*
         * Check that the selected fragment size is not larger than the largest
         * fragment size that can be sent
         */

        if (nfrags > (fptrend - fptr))
            nfrags = (fptrend - fptr);

        m = IP6F_MORE_FRAG;

        while ((ptr < ptrend) && m == IP6F_MORE_FRAG) {
            fptr = startoffragment;

            if ((ptrend - ptr) <= nfrags) {
                fragsize = ptrend - ptr;
                m = 0;
            }
            else {
                fragsize = (nfrags + 7) & ntohs(IP6F_OFF_MASK);
            }

            memcpy(fptr, ptr, fragsize);
            fh->ip6f_offlg = (htons(ptr - fragpart) & IP6F_OFF_MASK) | m;
            ptr += fragsize;
            fptr += fragsize;

            fipv6->ip6_plen = htons((fptr - fragbuffer) - MIN_IPV6_HLEN - idata->linkhsize);

            if ((nw = pcap_inject(idata->pfd, fragbuffer, fptr - fragbuffer)) == -1) {
                printf("pcap_inject(): %s\n", pcap_geterr(idata->pfd));
                exit(EXIT_FAILURE);
            }

            if (nw != (fptr - fragbuffer)) {
                printf("pcap_inject(): only wrote %d bytes (rather than %lu bytes)\n", nw, (LUI)(ptr - buffer));
                exit(EXIT_FAILURE);
            }
        } /* Sending fragments */

        return (0);
    } /* Sending fragmented datagram */
}
