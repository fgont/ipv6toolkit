#ifndef IN6_ADDR_HELPERS__H
#define IN6_ADDR_HELPERS__H

#include <netinet/in.h>

#include "ether_addr.h"

void in6_addr_cpy64(struct in6_addr *, struct in6_addr *, unsigned int);

void in6_addr_clear64(struct in6_addr *, unsigned int);

void in6_addr_paste_ether(struct in6_addr *, struct ether_addr *);

void in6_addr_set_linklocal_prefix(struct in6_addr *);

void in6_addr_clear_set_linklocal_prefix(struct in6_addr *);

void in6_addr_set_random_linklocal(struct in6_addr *);

int in6_addr_cmp64(struct in6_addr *, struct in6_addr *, unsigned int);

int in6_addr_cmp(struct in6_addr *, struct in6_addr *);

uint32_t in6_addr_get_macvendor_bytes(struct in6_addr *);

uint32_t in6_addr_get32(struct in6_addr *, int);

uint16_t in6_addr_get16(struct in6_addr *, int);

void in6_addr_set32(struct in6_addr *addr, int i, uint32_t);

void in6_addr_set16(struct in6_addr *addr, int i, uint16_t);

void in6_addr_set_sig_and_key(struct in6_addr *, uint16_t, uint16_t);

int in6_addr_check_sig_and_key(struct in6_addr *, uint16_t, uint16_t);

int in6_addr_check_double_key(struct in6_addr *, uint16_t);

void in6_addr_clear(struct in6_addr *);

#endif
