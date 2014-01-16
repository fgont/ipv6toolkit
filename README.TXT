*******************************************************************************
*                      SI6 Networks IPv6 Toolkit v1.5.2                       *
*******************************************************************************

Description of each of the files and directories:
-------------------------------------------------

 manuals:     Contains the manual pages for the security assessment tools.
 tools:       Contains the source code for the security assessment tools.
 CHANGES.TXT: Contains the changelog of the toolkit
 CONTRIB.TXT: Contains the list of people that have contributed to this 
              project.
 LICENSE.TXT: Contains the license for this software (GPLv3)
 README.TXT:  This file.


Building the tools
------------------

You can build the tools by running the following command:
 
   make all

You can install the tools, configuration file, database, and existing manual
pages by running the following command:

   make install

Note: The libpcap library must be previously installed on the system.

All the tools have been tested to build (both with gcc and clang) and run on 
Debian GNU/Linux 7.0, Debian GNU/kfreebsd 7.0, FreeBSD 9.0, NetBSD 6.1.1, 
OpenBSD 5.3, Ubuntu 11.10, and Mac 0S 10.8.0.


Bug reports
-----------

Please send any bug reports to Fernando Gont <fgont@si6networks.com>

