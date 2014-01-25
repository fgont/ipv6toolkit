#include <assert.h>
#include <stdlib.h>

#include <netinet/in.h>

#include "libipv6.h"

#include "gnu-fixer.h"

int main(void) {

	int i;

	struct in6_addr i61 = {
		.s6_addr = { 0 }
	};

	struct in6_addr expected6 = {
		.s6_addr = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 2, 3, 4, 0xff, 0xfe, 5, 6, 7 }
	};

	struct ether_addr e1 = {
		.a = { 0 }
	};

	for (i = 0; i < 6; i++) {
		e1.a[i] = i+2;
	}

	ether_to_ipv6_linklocal(&e1, &i61);

	assert(IN6_ARE_ADDR_EQUAL(&i61, &expected6));

	return EXIT_SUCCESS;
}
