cmake_minimum_required (VERSION 3.0)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

find_package(PCAP REQUIRED)

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

target_include_directories(p0f-api SYSTEM 
	PUBLIC ${PCAP_INCLUDE_DIR}
)

target_link_libraries(p0f-api
	${PCAP_LIBRARIES}
)

# TODO(eteran): add libs needed for various supported platforms
#if [ "$OSTYPE" = "cygwin" ]; then
#  USE_LIBS="-lwpcap $LIBS"
#elif [ "$OSTYPE" = "solaris" ]; then
#  USE_LIBS="-lsocket -lnsl $LIBS"
#fi

set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR})
