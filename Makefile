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
	-rm -f $(TOOLS)

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

