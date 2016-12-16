bin_PROGRAMS = http_parser_plus
http_parser_plus_SOURCES = http_parser_plus.cpp pkt_processor.cpp \
			beap_hash.cpp  TCPServer.cpp UDPServer.cpp

# set the include path found by configure
INCLUDES= $(all_includes)

# the library search path.
http_parser_plus_LDFLAGS = $(all_libraries) 
http_parser_plus_LDADD = -lz -lpthread -lpcap
noinst_HEADERS = linux_list.h common_include.h data_def.h \
				pkt_processor.h beap_hash.h  TCPServer.h UDPServer.h main_process.h 
