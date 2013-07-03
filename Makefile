#
# SI6 Networks' IPv6 toolkit Makefile
#
CC= gcc
CFLAGS+= -Wall
LDFLAGS+= -lpcap -lm
MANPATH= /usr/share/man
DATAPATH= /usr/share
BINPATH= /usr/bin
SRCPATH= tools
TOOLS= addr6 flow6 frag6 icmp6 jumbo6 na6 ni6 ns6 ra6 rd6 rs6 scan6 tcp6

all: $(TOOLS)

addr6: $(SRCPATH)/addr6.c $(SRCPATH)/addr6.h $(SRCPATH)/ipv6toolkit.h
	$(CC) $(CFLAGS) -o addr6 $(SRCPATH)/addr6.c $(LDFLAGS) 

flow6: $(SRCPATH)/flow6.c $(SRCPATH)/flow6.h $(SRCPATH)/ipv6toolkit.h
	$(CC) $(CFLAGS) -o flow6 $(SRCPATH)/flow6.c $(LDFLAGS) 

frag6: $(SRCPATH)/frag6.c $(SRCPATH)/frag6.h $(SRCPATH)/ipv6toolkit.h
	$(CC) $(CFLAGS) -o frag6 $(SRCPATH)/frag6.c $(LDFLAGS) 

icmp6: $(SRCPATH)/icmp6.c $(SRCPATH)/icmp6.h $(SRCPATH)/ipv6toolkit.h
	$(CC) $(CFLAGS) -o icmp6 $(SRCPATH)/icmp6.c $(LDFLAGS)

jumbo6: $(SRCPATH)/jumbo6.c $(SRCPATH)/jumbo6.h $(SRCPATH)/ipv6toolkit.h
	$(CC) $(CFLAGS) -o jumbo6 $(SRCPATH)/jumbo6.c $(LDFLAGS)

na6: $(SRCPATH)/na6.c $(SRCPATH)/na6.h $(SRCPATH)/ipv6toolkit.h
	$(CC) $(CFLAGS) -o na6 $(SRCPATH)/na6.c $(LDFLAGS)

ni6: $(SRCPATH)/ni6.c $(SRCPATH)/ni6.h $(SRCPATH)/ipv6toolkit.h
	$(CC) $(CFLAGS) -o ni6 $(SRCPATH)/ni6.c $(LDFLAGS)

ns6: $(SRCPATH)/ns6.c $(SRCPATH)/ns6.h $(SRCPATH)/ipv6toolkit.h
	$(CC) $(CFLAGS) -o ns6 $(SRCPATH)/ns6.c $(LDFLAGS)

ra6: $(SRCPATH)/ra6.c $(SRCPATH)/ra6.h $(SRCPATH)/ipv6toolkit.h
	$(CC) $(CFLAGS) -o ra6 $(SRCPATH)/ra6.c $(LDFLAGS)

rd6: $(SRCPATH)/rd6.c $(SRCPATH)/rd6.h $(SRCPATH)/ipv6toolkit.h
	$(CC) $(CFLAGS) -o rd6 $(SRCPATH)/rd6.c $(LDFLAGS)

rs6: $(SRCPATH)/rs6.c $(SRCPATH)/rs6.h $(SRCPATH)/ipv6toolkit.h
	$(CC) $(CFLAGS) -o rs6 $(SRCPATH)/rs6.c $(LDFLAGS)

scan6: $(SRCPATH)/scan6.c $(SRCPATH)/scan6.h $(SRCPATH)/ipv6toolkit.h
	$(CC) $(CFLAGS) -o scan6 $(SRCPATH)/scan6.c $(LDFLAGS)

tcp6: $(SRCPATH)/tcp6.c $(SRCPATH)/tcp6.h $(SRCPATH)/ipv6toolkit.h
	$(CC) $(CFLAGS) -o tcp6 $(SRCPATH)/tcp6.c $(LDFLAGS)

clean: 
	rm -f $(TOOLS)

install: all
	# Install the binaries
	install -m0755 -d $(BINPATH)
	install -m0755 $(TOOLS) $(BINPATH)

	# Install the configuration file
	install -m0644 data/ipv6toolkit.conf /etc	

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
	rm -f $(BINPATH)/addr6
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
	rm -f /etc/ipv6toolkit.conf

	# Remove the IEEE OUI database
	rm -rf $(DATAPATH)/ipv6toolkit

	# Remove the manual pages
	rm -f $(MANPATH)/man1/addr6.1
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

