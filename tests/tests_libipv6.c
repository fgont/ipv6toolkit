#include <assert.h>
#include <stdlib.h>
#include "../tools/libipv6.h"

void test_is_service_port(void);

int main(void){
    test_is_service_port();
    exit(EXIT_SUCCESS);
}

void test_is_service_port(void){
    assert(is_service_port(443));
    assert(is_service_port(1000) == FALSE);
    return;
}
