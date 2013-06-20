#
# SI6 Networks' IPv6 toolkit Makefile
#
CC= gcc
CFLAGS+= -Wall
LDFLAGS+= -lpcap -lm
DESTDIR= /
PREFIX= ${DESTDIR}/usr
MANPATH= ${PREFIX}/share/man
DATAPATH= ${PREFIX}/share
BINPATH= ${PREFIX}/bin
SRCPATH= tools
TOOLS= address6 flow6 frag6 icmp6 jumbo6 na6 ni6 ns6 ra6 rd6 rs6 scan6 tcp6

all: $(TOOLS)

address6: $(SRCPATH)/address6.c
	$(CC) $(CFLAGS) -o address6 $(SRCPATH)/address6.c $(LDFLAGS) 

flow6: $(SRCPATH)/flow6.c
	$(CC) $(CFLAGS) -o flow6 $(SRCPATH)/flow6.c $(LDFLAGS) 

frag6: $(SRCPATH)/frag6.c
	$(CC) $(CFLAGS) -o frag6 $(SRCPATH)/frag6.c $(LDFLAGS) 

icmp6: $(SRCPATH)/icmp6.c
	$(CC) $(CFLAGS) -o icmp6 $(SRCPATH)/icmp6.c $(LDFLAGS)

jumbo6: $(SRCPATH)/jumbo6.c
	$(CC) $(CFLAGS) -o jumbo6 $(SRCPATH)/jumbo6.c $(LDFLAGS)

na6: $(SRCPATH)/na6.c
	$(CC) $(CFLAGS) -o na6 $(SRCPATH)/na6.c $(LDFLAGS)

ni6: $(SRCPATH)/ni6.c
	$(CC) $(CFLAGS) -o ni6 $(SRCPATH)/ni6.c $(LDFLAGS)

ns6: $(SRCPATH)/ns6.c
	$(CC) $(CFLAGS) -o ns6 $(SRCPATH)/ns6.c $(LDFLAGS)

ra6: $(SRCPATH)/ra6.c
	$(CC) $(CFLAGS) -o ra6 $(SRCPATH)/ra6.c $(LDFLAGS)

rd6: $(SRCPATH)/rd6.c
	$(CC) $(CFLAGS) -o rd6 $(SRCPATH)/rd6.c $(LDFLAGS)

rs6: $(SRCPATH)/rs6.c
	$(CC) $(CFLAGS) -o rs6 $(SRCPATH)/rs6.c $(LDFLAGS)

scan6: $(SRCPATH)/scan6.c
	$(CC) $(CFLAGS) -o scan6 $(SRCPATH)/scan6.c $(LDFLAGS)

tcp6: $(SRCPATH)/tcp6.c
	$(CC) $(CFLAGS) -o tcp6 $(SRCPATH)/tcp6.c $(LDFLAGS)

clean: 
	rm -f $(TOOLS)

install: all
	# Install the binaries
	install -m0755 -d $(BINPATH)
	install -m0755 $(TOOLS) $(BINPATH)

	# Install the configuration file
	install -m0644 data/ipv6toolkit.conf ${PREFIX}/etc	

	# Install the IEEE OUI database
	install -m0755 -d $(DATAPATH)/ipv6toolkit
	install -m0644 data/oui.txt $(DATAPATH)/ipv6toolkit

	# Install the manual pages
	install -m0755 -d $(MANPATH)/man1
	install -m0644 manuals/*.1 $(MANPATH)/man1
	install -m0755 -d $(MANPATH)/man5
	install -m0644 manuals/*.5 $(MANPATH)/man5

uninstall:
	# Remove the binaries
	rm -f $(BINPATH)/address6
	rm -f $(BINPATH)/flow6
	rm -f $(BINPATH)/frag6
	rm -f $(BINPATH)/icmp6
	rm -f $(BINPATH)/jumbo6
	rm -f $(BINPATH)/na6
	rm -f $(BINPATH)/ni6
	rm -f $(BINPATH)/ns6
	rm -f $(BINPATH)/ra6
	rm -f $(BINPATH)/rd6
	rm -f $(BINPATH)/rs6
	rm -f $(BINPATH)/scan6
	rm -f $(BINPATH)/tcp6

	# Remove the configuration file
	rm -f ${PREFIX}/etc/ipv6toolkit.conf

	# Remove the IEEE OUI database
	rm -rf $(DATAPATH)/ipv6toolkit

	# Remove the manual pages
	rm -f $(MANPATH)/man1/address6.1
	rm -f $(MANPATH)/man1/flow6.1
	rm -f $(MANPATH)/man1/frag6.1
	rm -f $(MANPATH)/man1/icmp6.1
	rm -f $(MANPATH)/man1/jumbo6.1
	rm -f $(MANPATH)/man1/na6.1
	rm -f $(MANPATH)/man1/ni6.1
	rm -f $(MANPATH)/man1/ns6.1
	rm -f $(MANPATH)/man1/ra6.1
	rm -f $(MANPATH)/man1/rd6.1
	rm -f $(MANPATH)/man1/rs6.1
	rm -f $(MANPATH)/man1/scan6.1
	rm -f $(MANPATH)/man1/tcp6.1
	rm -f $(MANPATH)/man5/ipv6toolkit.conf.5

