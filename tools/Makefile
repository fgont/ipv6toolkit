CC?=		gcc
CFLAGS?=	-O2 -Wall
LDFLAGS?=	-lpcap -lm
PROGS?=		flow6 frag6 icmp6 jumbo6 na6 ni6 ns6 ra6 rd6 rs6 scan6 tcp6
PREFIX?=	/usr
INSTALL_BIN?=	${PREFIX}/bin
INSTALL?=	cp -p

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

all: ${PROGS}

clean:
	rm -f ${PROGS}

install: all
	mkdir -p $(INSTALL_BIN)
	${INSTALL} ${PROGS} ${INSTALL_BIN}

.PHONY: clean install
