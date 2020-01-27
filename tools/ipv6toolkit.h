#define SI6_TOOLKIT "SI6 Networks' IPv6 Toolkit v2.1 (Jan)"
#define	MAX_CMDLINE_OPT_LEN	40
#define DATE_STR_LEN		40

#include <pcap.h>
#include <setjmp.h>

extern char errbuf[PCAP_ERRBUF_SIZE];
extern struct bpf_program pcap_filter;
extern sigjmp_buf env;
extern unsigned int canjump;
