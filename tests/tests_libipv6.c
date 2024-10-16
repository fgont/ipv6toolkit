#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "../tools/libipv6.h"

void test_ether_ntop(void);
void test_ether_pton(void);
void test_is_service_port(void);

int main(void){
    test_ether_ntop();
    test_ether_pton();
    test_is_service_port();
    exit(EXIT_SUCCESS);
}

void test_ether_ntop(void){
    struct ether_addr ether;
    unsigned int i;
    char plinkaddr[ETHER_ADDR_PLEN];

    for (i=0; i < 6; i++) {
        ether.a[i]= i+1;
    }

    assert(ether_ntop(&ether, plinkaddr, 5) != TRUE);
    assert(ether_ntop(&ether, plinkaddr, sizeof(plinkaddr)) == TRUE);
    assert(Strnlen(plinkaddr, 18) == 17);
    assert(strncmp(plinkaddr, "01:02:03:04:05:06", 18) == 0);
    return;
}

void test_ether_pton(void){
    struct ether_addr ether;
    char *linkaddr= "01:02:03:04:05:06";
    unsigned int i;

    assert(ether_pton(linkaddr, &ether, 5) != TRUE);
    assert(ether_pton(linkaddr, &ether, sizeof(ether)));

    for (i=0; i < 6; i++) {
        assert(ether.a[i] == (i+1));
    }

    return;
}

void test_is_service_port(void){
    assert(is_service_port(443));
    assert(is_service_port(1000) == FALSE);
    return;
}
