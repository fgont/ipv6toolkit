#
# SI6 Networks' IPv6 toolkit Makefile
#
CC= gcc
CFLAGS= -Wall
LDFLAGS+= -lpcap -lm
MANPATH= /usr/share/man
DATAPATH= /usr/share
BINPATH= /usr/bin
SRCPATH= tools
TOOLS= flow6 frag6 icmp6 jumbo6 na6 ni6 ns6 ra6 rd6 rs6 scan6 tcp6

all: $(TOOLS)

%:	${SRCPATH}/%.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) 

clean: 
	-rm -f $(TOOLS)

install: all
	# Install the binaries
	install -m0755 -d ${BINPATH}
	install -m0755 $(TOOLS) ${BINPATH}

	# Install the configuration file
	install -m0644 data/ipv6toolkit.conf /etc	

	# Install the IEEE OUI database
	install -m0755 -d ${DATAPATH}/ipv6toolkit
	install -m0644 data/oui.txt ${DATAPATH}/ipv6toolkit

	# Install the manual pages
	install -m0755 -d ${MANPATH}/man1
	install -m0644 manuals/*.1 ${MANPATH}/man1
	install -m0755 -d ${MANPATH}/man5
	install -m0644 manuals/*.5 ${MANPATH}/man1

