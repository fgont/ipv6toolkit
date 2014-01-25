#include <assert.h>
#include <stdlib.h>

#include <netinet/in.h>

#include "in6_addr_helpers.h"

/* i == which 64-bit part to copy; i==0: left part, i==1 right part */
void in6_addr_cpy64(struct in6_addr * d, struct in6_addr * s, unsigned int i) {

	assert (i <= 1);

	((uint32_t *) d)[2*i] = ((uint32_t *) s)[2*i];
	((uint32_t *) d)[2*i+1] = ((uint32_t *) s)[2*i+1];

}

void in6_addr_clear64(struct in6_addr * d, unsigned int i) {

	assert (i <= 1);

	((uint32_t *) d)[2*i] = 0;
	((uint32_t *) d)[2*i+1] = 0;

}

void in6_addr_clear(struct in6_addr * d) {

	((uint32_t *) d)[0] = 0;
	((uint32_t *) d)[1] = 0;
	((uint32_t *) d)[2] = 0;
	((uint32_t *) d)[3] = 0;

}

void in6_addr_paste_ether(struct in6_addr * d, struct ether_addr * s) {

	((uint16_t *) d)[4] = ((uint16_t *) s)[0];
	d->s6_addr[10] = s->a[2];
	d->s6_addr[11] = 0xff;
	d->s6_addr[12] = 0xfe;
	d->s6_addr[13] = s->a[3];
	((uint16_t *) d)[7] = ((uint16_t *) s)[2];
}

void in6_addr_set_linklocal_prefix(struct in6_addr * d) {
	((uint16_t *) d)[0] = htons(0xfe80);
}

void in6_addr_clear_set_linklocal_prefix(struct in6_addr * d) {
	((uint32_t *) d)[0] = htonl(0xfe800000);
	((uint32_t *) d)[1] = htonl(0x00000000);
}

void in6_addr_set_random_linklocal(struct in6_addr * d) {
	((uint32_t *) d)[0] = htonl(0xfe800000);
	((uint32_t *) d)[1] = htonl(0x00000000);
	((uint32_t *) d)[2] = random() << 16 | random();
	((uint32_t *) d)[3] = random() << 16 | random();
}

/* i == which 64-bit part to compare; i==0: left part, i==1 right part */
int in6_addr_cmp64(struct in6_addr * a, struct in6_addr * b, unsigned int i) {

	assert (i <= 1);

	if (ntohl(((uint32_t *) b)[2*i]) > ntohl(((uint32_t *) a)[2*i]))
		return 1;

	if (ntohl(((uint32_t *) b)[2*i]) < ntohl(((uint32_t *) a)[2*i]))
		return -1;

	if (ntohl(((uint32_t *) b)[2*i+1]) > ntohl(((uint32_t *) a)[2*i+1]))
		return 1;

	if (ntohl(((uint32_t *) b)[2*i+1]) < ntohl(((uint32_t *) a)[2*i+1]))
		return -1;

	return 0;

}

int in6_addr_cmp(struct in6_addr * a, struct in6_addr * b) {

	int i;

	for (i = 0; i < 4; i++) {
		if (ntohl(((uint32_t *) b)[i]) > ntohl(((uint32_t *) a)[i]))
			return 1;

		if (ntohl(((uint32_t *) b)[i]) < ntohl(((uint32_t *) a)[i]))
			return -1;
	}

	return 0;

}

uint32_t in6_addr_get_macvendor_bytes(struct in6_addr *addr) {

	return ntohl(((uint32_t *) addr)[2]) >> 8;

	//return (addr->s6_addr[8] << 16) + (addr->s6_addr[9] << 8) + addr->s6_addr[10];

	//return (addr->s6_addr32[2]) >> 8);
}

uint32_t in6_addr_get32(struct in6_addr *addr, int i) {
	assert(i < 4);

	return ntohl(((uint32_t *) addr)[i]);
}

uint16_t in6_addr_get16(struct in6_addr *addr, int i) {
	assert(i < 8);

	return ntohs(((uint16_t *) addr)[i]);
}

void in6_addr_set32(struct in6_addr *addr, int i, uint32_t value) {
	assert(i < 4);

	((uint32_t *) addr)[i] = htonl(value);
}

void in6_addr_set16(struct in6_addr *addr, int i, uint16_t value) {
	assert(i < 8);

	((uint16_t *) addr)[i] = htons(value);
}

void in6_addr_set_sig_and_key(struct in6_addr *addr, uint16_t sig, uint16_t key) {
	((uint16_t *) addr)[5] = sig;
	((uint16_t *) addr)[7] = ((uint16_t *) addr)[6] ^ key;
}

int in6_addr_check_sig_and_key(struct in6_addr *addr, uint16_t sig, uint16_t key) {
	return (((uint16_t *) addr)[5] == sig) && \
	  (((uint16_t *) addr)[7] == (((uint16_t *) addr)[6] ^ key));
}

int in6_addr_check_double_key(struct in6_addr *addr, uint16_t key) {
	return (((uint16_t *) addr)[5] == (((uint16_t *) addr)[4] ^ key)) && \
	  (((uint16_t *) addr)[7] == (((uint16_t *) addr)[6] ^ key));
}

