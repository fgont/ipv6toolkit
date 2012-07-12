********************************************************************************
*                           UK CPNI IPv6 Toolkit v1.1                          *
********************************************************************************

Description of each of the directories:
---------------------------------------

manuals: Contains the manual pages for the security assessment tools.
tools:   Contains the source code for the security assessment tools.


Building the tools
------------------

All tools should be built with: gcc name.c -Wall -lpcap -o name

(where 'name' should be replaced with the tool name)

Note: The libpcap library must be previously installed on the system.

All the tools have been tested to compile and run on Debian GNU/Linux 6.0,
FreeBSD 8.2, NetBSD 5.1, OpenBSD 5.0, and Ubuntu 11.10.


Bug reports
-----------

Please send any bug reports to Fernando Gont <fgont@si6networks.com>

