#
# SI6 Networks' IPv6 toolkit Makefile
#
# Notes to package developers:
#
# By default, binaries will be installed in /usr/local/bin, manual pages in
# /usr/local/man, data files in /usr/local/share/ipv6toolkit, and configuration
# files in /etc
#
# The path of the binaries and data files can be overriden by setting "PREFIX"
# variable accordingly. The path of the manual pages can be overriden by setting
# the MANPREFIX variable. Typically, packages will set these variables as follows:
#
# PREFIX=/usr
# MANPREFIX=/usr/share
#
# Finally, please note that this makefile supports the DESTDIR variable, as 
# typically employed by package developers.


CC= gcc
CFLAGS+= -Wall
LDFLAGS+= -lpcap -lm

.ifndef(PREFIX)
PREFIX=/usr/local
.ifndef(MANPREFIX)
MANPREFIX=/usr/local
.endif
.else
.ifndef(MANPREFIX)
MANPREFIX=/usr/share
.endif
.endif 

ETCPATH= $(DESTDIR)/etc
MANPATH= $(DESTDIR)$(MANPREFIX)/man
DATAPATH= $(DESTDIR)$(PREFIX)/share/ipv6toolkit
BINPATH= $(DESTDIR)$(PREFIX)/bin
SBINPATH= $(DESTDIR)$(PREFIX)/sbin
SRCPATH= tools


SBINTOOLS= flow6 frag6 icmp6 jumbo6 na6 ni6 ns6 ra6 rd6 rs6 scan6 tcp6
BINTOOLS= addr6
TOOLS= $(BINTOOLS) $(SBINTOOLS)
LIBS= libipv6.o

all: $(TOOLS) ipv6toolkit.conf

addr6: $(SRCPATH)/addr6.c $(SRCPATH)/addr6.h $(SRCPATH)/ipv6toolkit.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o addr6 $(SRCPATH)/addr6.c $(LDFLAGS) 

flow6: $(SRCPATH)/flow6.c $(SRCPATH)/flow6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o flow6 $(SRCPATH)/flow6.c $(LIBS) $(LDFLAGS) 

frag6: $(SRCPATH)/frag6.c $(SRCPATH)/frag6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o frag6 $(SRCPATH)/frag6.c $(LIBS) $(LDFLAGS)  

icmp6: $(SRCPATH)/icmp6.c $(SRCPATH)/icmp6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o icmp6 $(SRCPATH)/icmp6.c $(LIBS) $(LDFLAGS)

jumbo6: $(SRCPATH)/jumbo6.c $(SRCPATH)/jumbo6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o jumbo6 $(SRCPATH)/jumbo6.c $(LIBS) $(LDFLAGS)

na6: $(SRCPATH)/na6.c $(SRCPATH)/na6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o na6 $(SRCPATH)/na6.c $(LIBS) $(LDFLAGS)

ni6: $(SRCPATH)/ni6.c $(SRCPATH)/ni6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o ni6 $(SRCPATH)/ni6.c $(LIBS) $(LDFLAGS)

ns6: $(SRCPATH)/ns6.c $(SRCPATH)/ns6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o ns6 $(SRCPATH)/ns6.c $(LIBS) $(LDFLAGS)

ra6: $(SRCPATH)/ra6.c $(SRCPATH)/ra6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o ra6 $(SRCPATH)/ra6.c $(LIBS) $(LDFLAGS)

rd6: $(SRCPATH)/rd6.c $(SRCPATH)/rd6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o rd6 $(SRCPATH)/rd6.c $(LIBS) $(LDFLAGS)

rs6: $(SRCPATH)/rs6.c $(SRCPATH)/rs6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o rs6 $(SRCPATH)/rs6.c $(LIBS) $(LDFLAGS)

scan6: $(SRCPATH)/scan6.c $(SRCPATH)/scan6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o scan6 $(SRCPATH)/scan6.c $(LIBS) $(LDFLAGS)

tcp6: $(SRCPATH)/tcp6.c $(SRCPATH)/tcp6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o tcp6 $(SRCPATH)/tcp6.c $(LIBS) $(LDFLAGS)

libipv6.o: $(SRCPATH)/libipv6.c $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o libipv6.o $(SRCPATH)/libipv6.c

ipv6toolkit.conf:
	echo "# SI6 Networks' IPv6 Toolkit Configuration File" > \
           data/ipv6toolkit.conf
	echo OUI-Database=$(PREFIX)/share/ipv6toolkit/oui.txt >> \
           data/ipv6toolkit.conf 

clean: 
	rm -f $(TOOLS) $(LIBS)
	rm -f data/ipv6toolkit.conf

install: all
	# Install the binaries
	install -m0755 -d $(BINPATH)
	install -m0755 -d $(SBINPATH)
	install -m0755 $(BINTOOLS) $(BINPATH)
	install -m0755 $(SBINTOOLS) $(SBINPATH)

	# Install the configuration file
	install -m0644 data/ipv6toolkit.conf $(ETCPATH)

	# Install the IEEE OUI database
	install -m0755 -d $(DATAPATH)
	install -m0644 data/oui.txt $(DATAPATH)

	# Install the manual pages
	install -m0755 -d $(MANPATH)/man1
	install -m0644 manuals/*.1 $(MANPATH)/man1
	install -m0755 -d $(MANPATH)/man5
	install -m0644 manuals/*.5 $(MANPATH)/man5
	install -m0755 -d $(MANPATH)/man7
	install -m0644 manuals/*.7 $(MANPATH)/man7

uninstall:
	# Remove the binaries
	rm -f $(BINPATH)/addr6
	rm -f $(SBINPATH)/flow6
	rm -f $(SBINPATH)/frag6
	rm -f $(SBINPATH)/icmp6
	rm -f $(SBINPATH)/jumbo6
	rm -f $(SBINPATH)/na6
	rm -f $(SBINPATH)/ni6
	rm -f $(SBINPATH)/ns6
	rm -f $(SBINPATH)/ra6
	rm -f $(SBINPATH)/rd6
	rm -f $(SBINPATH)/rs6
	rm -f $(SBINPATH)/scan6
	rm -f $(SBINPATH)/tcp6

	# Remove the configuration file
	rm -f $(ETCPATH)/ipv6toolkit.conf

	# Remove the IEEE OUI database
	rm -rf $(DATAPATH)

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
	rm -f $(MANPATH)/man7/ipv6toolkit.7

