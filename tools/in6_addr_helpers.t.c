#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "in6_addr_helpers.h"

int main(void) {

	/* First test (validate each step along the test):
	 * Init d and s to 0.
	 * Copying the first half of an IPv6 address from s to d.
	 * Paste an ethernet address on the second half.
	 * Set link local prefix.
	 * Compare d and s using in6_addr_cmp64();
	 */
	struct in6_addr d = {
		.s6_addr = {0}
	};
	struct in6_addr s = {
		.s6_addr = {0}
	};
	struct ether_addr ether = {
		.a = {0}
	};

	int i;
	for (i = 0; i < 15; i++) {
		s.s6_addr[i] = i;
	}

	for (i = 0; i < 6; i++) {
		ether.a[i] = i+3;
	}

	in6_addr_cpy64(&d, &s, 0);

	for (i = 0; i < 8; i++) {
		assert(d.s6_addr[i] == i);
	}

	for (i = 8; i < 16; i++) {
		assert(d.s6_addr[i] == 0);
	}

	in6_addr_paste_ether(&d, &ether);

	for (i = 0; i < 8; i++) {
		assert(d.s6_addr[i] == i);
	}

	for (i = 8; i < 11; i++) {
		assert(d.s6_addr[i] == ether.a[i-8]);
	}

	assert(d.s6_addr[11] == 0xff);
	assert(d.s6_addr[12] == 0xfe);

	for (i = 13; i < 16; i++) {
		assert(d.s6_addr[i] == ether.a[i-10]);
	}

	in6_addr_set_linklocal_prefix(&d);

	assert(d.s6_addr[0] == 0xfe);
	assert(d.s6_addr[1] == 0x80);

	for (i = 3; i < 8; i++) {
		assert(d.s6_addr[i] == i);
	}

	for (i = 8; i < 11; i++) {
		assert(d.s6_addr[i] == ether.a[i-8]);
	}

	assert(d.s6_addr[11] == 0xff);
	assert(d.s6_addr[12] == 0xfe);

	for (i = 13; i < 16; i++) {
		assert(d.s6_addr[i] == ether.a[i-10]);
	}

	/* At this point, d is fe80:0203:0405:0607:0304:05ff:fe06:0708 */
	/* At this point, s is 0001:0203:0405:0607:0809:0a0b:0c0d:0e0f */
	assert(in6_addr_cmp64(&d, &s, 0) < 0);
	assert(in6_addr_cmp64(&s, &d, 0) > 0);
	assert(in6_addr_cmp64(&d, &d, 0) == 0);
	assert(in6_addr_cmp64(&d, &s, 1) > 0);
	assert(in6_addr_cmp64(&s, &d, 1) < 0);
	assert(in6_addr_cmp64(&d, &d, 1) == 0);

	assert(in6_addr_cmp(&d, &s) < 0);
	assert(in6_addr_cmp(&s, &d) > 0);
	assert(in6_addr_cmp(&d, &d) == 0);

	assert(in6_addr_get_macvendor_bytes(&d) == 0x030405); 

	assert(in6_addr_get32(&d, 0) == 0xfe800203);
	assert(in6_addr_get32(&d, 1) == 0x04050607);
	assert(in6_addr_get32(&d, 2) == 0x030405ff);
	assert(in6_addr_get32(&d, 3) == 0xfe060708);

	assert(in6_addr_get16(&d, 0) == 0xfe80);
	assert(in6_addr_get16(&d, 1) == 0x0203);
	assert(in6_addr_get16(&d, 2) == 0x0405);
	assert(in6_addr_get16(&d, 3) == 0x0607);
	assert(in6_addr_get16(&d, 4) == 0x0304);
	assert(in6_addr_get16(&d, 5) == 0x05ff);
	assert(in6_addr_get16(&d, 6) == 0xfe06);
	assert(in6_addr_get16(&d, 7) == 0x0708);

	/* Test in6_addr_set16 and 32() */
	in6_addr_set32(&d, 0, 0x76543210);
	in6_addr_set32(&d, 1, 0x89abcdef);
	in6_addr_set32(&d, 2, 0x4567890a);
	in6_addr_set16(&d, 6, 0x0246);
	in6_addr_set16(&d, 7, 0x8ace);
	assert(in6_addr_get32(&d, 0) == 0x76543210);
	assert(in6_addr_get32(&d, 1) == 0x89abcdef);
	assert(in6_addr_get32(&d, 2) == 0x4567890a);
	assert(in6_addr_get32(&d, 3) == 0x02468ace);

	/* FIXME: in6_addr_get|check_sig_and_key() are not tested */

	/* Test in6_addr_clear_set_linklocal_prefix() */
	in6_addr_clear_set_linklocal_prefix(&d);
	assert(in6_addr_get32(&d, 0) == 0xfe800000);
	assert(in6_addr_get32(&d, 1) == 0x00000000);
	assert(in6_addr_get32(&d, 2) == 0x4567890a);
	assert(in6_addr_get32(&d, 3) == 0x02468ace);

	/* Test in6_addr_clear64 */
	in6_addr_clear64(&d, 1);
	assert(in6_addr_get32(&d, 0) == 0xfe800000);
	assert(in6_addr_get32(&d, 1) == 0x00000000);
	assert(in6_addr_get32(&d, 2) == 0x00000000);
	assert(in6_addr_get32(&d, 3) == 0x00000000);

	in6_addr_clear64(&d, 0);
	assert(in6_addr_get32(&d, 0) == 0x00000000);
	assert(in6_addr_get32(&d, 1) == 0x00000000);
	assert(in6_addr_get32(&d, 2) == 0x00000000);
	assert(in6_addr_get32(&d, 3) == 0x00000000);

	in6_addr_clear(&s);
	assert(in6_addr_get32(&s, 0) == 0x00000000);
	assert(in6_addr_get32(&s, 1) == 0x00000000);
	assert(in6_addr_get32(&s, 2) == 0x00000000);
	assert(in6_addr_get32(&s, 3) == 0x00000000);

	return EXIT_SUCCESS;
}
