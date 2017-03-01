bin_PROGRAMS = http_parser_plus
http_parser_plus_SOURCES = http_parser_plus.cpp pkt_processor.cpp \
			tcp_reassemble.cpp beap_hash.cpp http_url_cache.cpp conn_hash_cache.cpp \
			http_reassemble.cpp mwm.cpp BitMap.cpp db_operate.cpp TCPServer.cpp UDPServer.cpp

# set the include path found by configure
INCLUDES= $(all_includes)

# the library search path.
http_parser_plus_LDFLAGS = $(all_libraries) 
http_parser_plus_LDADD = -lmysqlclient -lz -lpthread -lpcap
noinst_HEADERS = linux_list.h common_include.h data_def.h tcp_reassemble.h \
				pkt_processor.h tcp_reassemble.h beap_hash.h http_url_cache.h conn_hash_cache.h \
				http_reassemble.h mwm.h BitMap.h db_operate.h TCPServer.h UDPServer.h main_process.h \
	main_process.h
