# tools

[packet_capture]
This is sniffer of network packets, implemented using libpap.
It supports load packets from a capture file spedified by argument, with tcpdump format.
It's a pity that you can not specify the interface which you listen on, but you can change it from the source code.


[TestDlopen]
This is a example of dynamic loading of some dynamic library when a program running.
The libcalc.so realizes an exchange of two numbers.
You can exec make to create the libcacl.so, and make TestDlopen to create the TestDlopen, which loads the libcalc.so by dlopen when running.


[TestLibcurlFTP]
This is a example of downloading files from a FTP Server, using ftp protocol, implemented by libcurl.
