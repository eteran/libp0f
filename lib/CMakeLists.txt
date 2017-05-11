cmake_minimum_required (VERSION 3.0)

set(p0f-api_SOURCES
	api.c
	fp_http.c
	fp_mtu.c
	fp_tcp.c
	process.c
	readfp.c
	p0f.c
)

add_library(p0f-api ${p0f-api_SOURCES})

set_property(TARGET p0f-api PROPERTY C_STANDARD 99)
set_property(TARGET p0f-api PROPERTY C_EXTENSIONS Off)

target_link_libraries(p0f-api pcap)

# TODO(eteran): add libs needed for various supported platforms
#if [ "$OSTYPE" = "cygwin" ]; then
#  USE_LIBS="-lwpcap $LIBS"
#elif [ "$OSTYPE" = "solaris" ]; then
#  USE_LIBS="-lsocket -lnsl $LIBS"
#else
#  USE_LIBS="-lpcap $LIBS"
#fi

set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR})
