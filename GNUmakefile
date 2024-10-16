#
# SI6 Networks' IPv6 toolkit Makefile (for GNU make)
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
# PREFIX=/usr/
# MANPREFIX=/usr/share
#
# Finally, please note that this makefile supports the DESTDIR variable, as 
# typically employed by package developers.


CC= gcc
CFLAGS+= -Wall -Wno-address-of-packed-member -Wno-missing-braces
LDFLAGS+= -lpcap -lm

ifeq ($(shell uname),SunOS)
  LDFLAGS+=-lsocket -lnsl
  OS=SunOS
endif


ifndef PREFIX
	PREFIX=/usr/local
	ifndef MANPREFIX
		MANPREFIX=/usr/local
	endif
else
	ifndef MANPREFIX
		MANPREFIX=/usr/share
	endif
endif


ETCPATH= $(DESTDIR)/etc
MANPATH= $(DESTDIR)$(MANPREFIX)/man
DATAPATH= $(DESTDIR)$(PREFIX)/share/ipv6toolkit
BINPATH= $(DESTDIR)$(PREFIX)/bin
SBINPATH= $(DESTDIR)$(PREFIX)/sbin
SRCPATH= tools
TESTSPATH= tests


SBINTOOLS= blackhole6 flow6 frag6 icmp6 jumbo6 messi mldq6 na6 ni6 ns6 path6 ra6 rd6 rs6 scan6 script6 tcp6 udp6
BINTOOLS= addr6
TOOLS= $(BINTOOLS) $(SBINTOOLS)
TESTS= tests_libipv6
LIBS= libipv6.o

all: $(TOOLS) data/ipv6toolkit.conf

addr6: $(SRCPATH)/addr6.c $(SRCPATH)/addr6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o addr6 $(SRCPATH)/addr6.c $(LIBS) $(LDFLAGS) 

blackhole6: $(SRCPATH)/blackhole6
	cp $(SRCPATH)/blackhole6 ./

flow6: $(SRCPATH)/flow6.c $(SRCPATH)/flow6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o flow6 $(SRCPATH)/flow6.c $(LIBS) $(LDFLAGS)

frag6: $(SRCPATH)/frag6.c $(SRCPATH)/frag6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o frag6 $(SRCPATH)/frag6.c $(LIBS) $(LDFLAGS) 

icmp6: $(SRCPATH)/icmp6.c $(SRCPATH)/icmp6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o icmp6 $(SRCPATH)/icmp6.c $(LIBS) $(LDFLAGS)

jumbo6: $(SRCPATH)/jumbo6.c $(SRCPATH)/jumbo6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o jumbo6 $(SRCPATH)/jumbo6.c $(LIBS) $(LDFLAGS)

messi: $(SRCPATH)/messi
	cp $(SRCPATH)/messi ./
	
mldq6: $(SRCPATH)/mldq6.c $(SRCPATH)/mldq6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o mldq6 $(SRCPATH)/mldq6.c $(LIBS) $(LDFLAGS)

na6: $(SRCPATH)/na6.c $(SRCPATH)/na6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o na6 $(SRCPATH)/na6.c $(LIBS) $(LDFLAGS)

ni6: $(SRCPATH)/ni6.c $(SRCPATH)/ni6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o ni6 $(SRCPATH)/ni6.c $(LIBS) $(LDFLAGS)

ns6: $(SRCPATH)/ns6.c $(SRCPATH)/ns6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o ns6 $(SRCPATH)/ns6.c $(LIBS) $(LDFLAGS)

path6: $(SRCPATH)/path6.c $(SRCPATH)/path6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o path6 $(SRCPATH)/path6.c $(LIBS) $(LDFLAGS)

ra6: $(SRCPATH)/ra6.c $(SRCPATH)/ra6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o ra6 $(SRCPATH)/ra6.c $(LIBS) $(LDFLAGS)

rd6: $(SRCPATH)/rd6.c $(SRCPATH)/rd6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o rd6 $(SRCPATH)/rd6.c $(LIBS) $(LDFLAGS)

rs6: $(SRCPATH)/rs6.c $(SRCPATH)/rs6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o rs6 $(SRCPATH)/rs6.c $(LIBS) $(LDFLAGS)

scan6: $(SRCPATH)/scan6.c $(SRCPATH)/scan6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o scan6 $(SRCPATH)/scan6.c $(LIBS) $(LDFLAGS)

script6: $(SRCPATH)/script6
	cp $(SRCPATH)/script6 ./

tests: $(TESTS)

tests_libipv6: $(TESTSPATH)/tests_libipv6.c libipv6.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -o tests_libipv6 $(TESTSPATH)/tests_libipv6.c $(LIBS) $(LDFLAGS)

tcp6: $(SRCPATH)/tcp6.c $(SRCPATH)/tcp6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o tcp6 $(SRCPATH)/tcp6.c $(LIBS) $(LDFLAGS)

udp6: $(SRCPATH)/udp6.c $(SRCPATH)/udp6.h $(SRCPATH)/ipv6toolkit.h $(LIBS) $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o udp6 $(SRCPATH)/udp6.c $(LIBS) $(LDFLAGS)

libipv6.o: $(SRCPATH)/libipv6.c $(SRCPATH)/libipv6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o libipv6.o $(SRCPATH)/libipv6.c

data/ipv6toolkit.conf:
	echo "# SI6 Networks' IPv6 Toolkit Configuration File" > \
           data/ipv6toolkit.conf
	echo WWW-client=curl >> \
           data/ipv6toolkit.conf 
	echo OUI-Database=$(PREFIX)/share/ipv6toolkit/oui.txt >> \
           data/ipv6toolkit.conf 
	echo Ports-Database=$(PREFIX)/share/ipv6toolkit/service-names-port-numbers.csv >> \
           data/ipv6toolkit.conf 
	echo Top-Ports-Database=$(PREFIX)/share/ipv6toolkit/top-port-numbers.csv >> \
           data/ipv6toolkit.conf 
	echo Country-Database=$(PREFIX)/share/ipv6toolkit/country-data.csv >> \
           data/ipv6toolkit.conf 
	echo DNS-TLD-Database=$(PREFIX)/share/ipv6toolkit/dns-tld-database.csv >> \
           data/ipv6toolkit.conf
	echo DNS-Suffix-Database=$(PREFIX)/share/ipv6toolkit/public_suffix_list.dat >> \
           data/ipv6toolkit.conf
	echo RIR-Database=$(PREFIX)/share/ipv6toolkit/rir-database.csv >> \
           data/ipv6toolkit.conf 
	echo DNS-UKGOV-Database=$(PREFIX)/share/ipv6toolkit/dns-gov-uk-domains.csv >> \
           data/ipv6toolkit.conf 
	echo DNS-Dictionary=$(PREFIX)/share/ipv6toolkit/dns-dictionary.txt >> \
           data/ipv6toolkit.conf 

clean: 
	rm -f $(TOOLS) $(LIBS) $(TESTS)
	rm -f data/ipv6toolkit.conf

install: all
ifneq ($(OS),SunOS)
	# Install the binaries
	install -m0755 -d $(BINPATH)
	install -m0755 -d $(SBINPATH)
	install -m0755 $(BINTOOLS) $(BINPATH)
	install -m0755 $(SBINTOOLS) $(SBINPATH)

	# Install the configuration file
	install -m0755 -d $(ETCPATH)
	install -m0644 data/ipv6toolkit.conf $(ETCPATH)

	# Install the IEEE OUI database
	install -m0755 -d $(DATAPATH)
	install -m0644 data/oui.txt $(DATAPATH)

	# Install the port numbers database
	install -m0644 data/service-names-port-numbers.csv $(DATAPATH)

	# Install the top port numbers database
	install -m0644 data/top-port-numbers.csv $(DATAPATH)

	# Install the country information database
	install -m0644 data/country-data.csv $(DATAPATH)

	# Install the DNS TLD database
	install -m0644 data/dns-tld-database.csv $(DATAPATH)

	# Install the DNS Suffixes database
	install -m0644 data/public_suffix_list.dat $(DATAPATH)

	# Install the RIR database
	install -m0644 data/rir-database.csv $(DATAPATH)

	# Install the UK Gov Database
	install -m0644 data/dns-gov-uk-domains.csv $(DATAPATH)

	# Install the DNS Dictionary
	install -m0644 data/dns-dictionary.txt $(DATAPATH)

	# Install the manual pages
	install -m0755 -d $(MANPATH)/man1
	install -m0644 manuals/*.1 $(MANPATH)/man1
	install -m0755 -d $(MANPATH)/man5
	install -m0644 manuals/*.5 $(MANPATH)/man5
	install -m0755 -d $(MANPATH)/man7
	install -m0644 manuals/*.7 $(MANPATH)/man7
else
	# Install the binaries
	install -m 0755 -d $(BINPATH)
	install -m 0755 -d $(SBINPATH)

	install -m 0755 -f $(BINPATH) addr6 
	install -m 0755 -f $(SBINPATH) blackhole6
	install -m 0755 -f $(SBINPATH) flow6
	install -m 0755 -f $(SBINPATH) frag6
	install -m 0755 -f $(SBINPATH) icmp6
	install -m 0755 -f $(SBINPATH) jumbo6
	install -m 0755 -f $(SBINPATH) script6
	install -m 0755 -f $(SBINPATH) messi
	install -m 0755 -f $(SBINPATH) mldq6
	install -m 0755 -f $(SBINPATH) na6
	install -m 0755 -f $(SBINPATH) ni6
	install -m 0755 -f $(SBINPATH) ns6
	install -m 0755 -f $(SBINPATH) path6
	install -m 0755 -f $(SBINPATH) ra6
	install -m 0755 -f $(SBINPATH) rd6
	install -m 0755 -f $(SBINPATH) rs6
	install -m 0755 -f $(SBINPATH) scan6
	install -m 0755 -f $(SBINPATH) tcp6
	install -m 0755 -f $(SBINPATH) udp6

	# Install the configuration file
	install -m 0755 -d $(ETCPATH)
	install -m 0644 -f $(ETCPATH) data/ipv6toolkit.conf

	# Install the IEEE OUI database
	install -m 0755 -d $(DATAPATH)
	install -m 0644 -f $(DATAPATH) data/oui.txt

	# Install the port numbers database
	install -m 0644 -f $(DATAPATH) data/service-names-port-numbers.csv

	# Install the top port numbers database
	install -m 0644 -f $(DATAPATH) data/top-port-numbers.csv

	# Install the top port numbers database
	install -m 0644 -f $(DATAPATH) data/country-data.csv

	# Install the DNS TLD database
	install -m 0644 -f $(DATAPATH) data/dns-tld-database.csv

	# Install the DNS Suffixes database
	install -m 0644 -f $(DATAPATH) data/public_suffix_list.dat

	# Install the RIR Database
	install -m 0644 -f $(DATAPATH) data/rir-database.csv

	# Install the UK Gov Database
	install -m 0644 -f $(DATAPATH) data/dns-gov-uk-domains.csv 

	# Install the DNS Dictionary
	install -m 0644 -f $(DATAPATH) data/dns-dictionary.txt


	# Install the manual pages
	install -m 0755 -d $(MANPATH)/man1
	install -m 0644 -f $(MANPATH)/man1 manuals/addr6.1
	install -m 0644 -f $(MANPATH)/man1 manuals/blackhole6.1
	install -m 0644 -f $(MANPATH)/man1 manuals/flow6.1
	install -m 0644 -f $(MANPATH)/man1 manuals/frag6.1
	install -m 0644 -f $(MANPATH)/man1 manuals/icmp6.1
	install -m 0644 -f $(MANPATH)/man1 manuals/jumbo6.1
	install -m 0644 -f $(MANPATH)/man1 manuals/mldq6.1
	install -m 0644 -f $(MANPATH)/man1 manuals/na6.1
	install -m 0644 -f $(MANPATH)/man1 manuals/ni6.1
	install -m 0644 -f $(MANPATH)/man1 manuals/ns6.1
	install -m 0644 -f $(MANPATH)/man1 manuals/path6.1
	install -m 0644 -f $(MANPATH)/man1 manuals/ra6.1
	install -m 0644 -f $(MANPATH)/man1 manuals/rd6.1
	install -m 0644 -f $(MANPATH)/man1 manuals/rs6.1
	install -m 0644 -f $(MANPATH)/man1 manuals/scan6.1
	install -m 0644 -f $(MANPATH)/man1 manuals/script6.1
	install -m 0644 -f $(MANPATH)/man1 manuals/tcp6.1
	install -m 0644 -f $(MANPATH)/man1 manuals/udp6.1
	install -m 0755 -d $(MANPATH)/man5
	install -m 0644 -f $(MANPATH)/man5 manuals/ipv6toolkit.conf.5
	install -m 0755 -d $(MANPATH)/man7
	install -m 0644 -f $(MANPATH)/man7 manuals/ipv6toolkit.7
endif


uninstall:
	# Remove the binaries
	rm -f $(BINPATH)/addr6
	rm -f $(SBINPATH)/blackhole6
	rm -f $(SBINPATH)/flow6
	rm -f $(SBINPATH)/frag6
	rm -f $(SBINPATH)/icmp6
	rm -f $(SBINPATH)/jumbo6
	rm -f $(SBINPATH)/script6
	rm -f $(SBINPATH)/messi
	rm -f $(SBINPATH)/mldq6
	rm -f $(SBINPATH)/na6
	rm -f $(SBINPATH)/ni6
	rm -f $(SBINPATH)/ns6
	rm -f $(SBINPATH)/path6
	rm -f $(SBINPATH)/ra6
	rm -f $(SBINPATH)/rd6
	rm -f $(SBINPATH)/rs6
	rm -f $(SBINPATH)/scan6
	rm -f $(SBINPATH)/tcp6
	rm -f $(SBINPATH)/udp6

	# Remove the configuration file
	rm -f $(ETCPATH)/ipv6toolkit.conf

	# Remove the IEEE OUI database, port number database and other databases
	rm -rf $(DATAPATH)

	# Remove the manual pages
	rm -f $(MANPATH)/man1/addr6.1
	rm -f $(MANPATH)/man1/blackhole6.1
	rm -f $(MANPATH)/man1/flow6.1
	rm -f $(MANPATH)/man1/frag6.1
	rm -f $(MANPATH)/man1/icmp6.1
	rm -f $(MANPATH)/man1/jumbo6.1
	rm -f $(MANPATH)/man1/messi	
	rm -f $(MANPATH)/man1/mldq6.1
	rm -f $(MANPATH)/man1/na6.1
	rm -f $(MANPATH)/man1/ni6.1
	rm -f $(MANPATH)/man1/ns6.1
	rm -f $(MANPATH)/man1/path6.1
	rm -f $(MANPATH)/man1/ra6.1
	rm -f $(MANPATH)/man1/rd6.1
	rm -f $(MANPATH)/man1/rs6.1
	rm -f $(MANPATH)/man1/scan6.1
	rm -f $(MANPATH)/man1/script6.1
	rm -f $(MANPATH)/man1/tcp6.1
	rm -f $(MANPATH)/man1/udp6.1
	rm -f $(MANPATH)/man5/ipv6toolkit.conf.5
	rm -f $(MANPATH)/man7/ipv6toolkit.7

unit_tests: tests
	./tests_libipv6
