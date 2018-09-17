cmake_minimum_required (VERSION 3.0)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

find_package(PCAP REQUIRED)

if(CMAKE_BUILD_TYPE EQUAL "Debug")
	add_definitions(-DDEBUG_BUILD)
endif()


set(FP_FILE         p0f.fp CACHE STRING "Default location of p0f.fp" FORCE)
set(LOG_MODE        0600   CACHE STRING "Initial permissions on log files" FORCE)
set(API_MODE        0666   CACHE STRING "Initial permissions on API sockets" FORCE)
set(MAX_CONN        1000   CACHE STRING "Default connection cache sizes" FORCE)
set(MAX_HOSTS       10000  CACHE STRING "Default host cache sizes" FORCE)
set(CONN_MAX_AGE    30     CACHE STRING "Default connectiontime limits" FORCE)
set(HOST_IDLE_LIMIT 120    CACHE STRING "Default host time limits" FORCE)
set(API_MAX_CONN    20     CACHE STRING "Default number of API connections permitted" FORCE)
set(MAX_DIST        35     CACHE STRING "Maximum TTL distance for non-fuzzy signature matching" FORCE)

option(CHECK_UAF "Detect use-after-free, at the expense of some performance cost" ON)

# Obscure Options
set(MAX_ALLOC			0x40000000  			)
set(KILL_PERCENT		10  					)
set(SNAPLEN 			65535					)
set(MAX_FLOW_DATA		8192					)
set(MAX_TCP_OPT 		24  					)
set(MIN_TSCALE  		0.7 					)
set(MAX_TSCALE  		1500					)
set(MIN_TWAIT			25  					)
set(MAX_TWAIT			"(1000 * 60 * 10)"  	)
set(TSTAMP_GRACE		100 					)
set(MAX_NAT_TS  		"(1000 * 60 * 60 * 24)" )
set(MIN_PORT_DROP		64  					)
set(SMALL_TTL_CHG		2						)
set(LOCAL_TTL_LIMIT 	5						)
set(NEAR_TTL_LIMIT  	9						)
set(NAT_SCORES  		32  					)
set(SIG_BUCKETS 		64  					)
set(FLOW_BUCKETS		256 					)
set(HOST_BUCKETS		1024					)
set(EXPIRE_INTERVAL 	50  					)
set(NAME_CHARS  		" ./-_!?()" 			)
set(SPECIAL_MSS 		1331					)
set(SPECIAL_WIN 		1337					)
set(HTTP_MAX_URL		1024					)
set(HTTP_MAX_HDRS		32  					)
set(HTTP_MAX_HDR_NAME	32  					)
set(HTTP_MAX_HDR_VAL	1024					)
set(HTTP_MAX_SHOW		200 					)
set(HTTP_MAX_DATE_DIFF  10  					)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${PROJECT_BINARY_DIR}/config.h)

set(p0f-api_SOURCES
	alloc-inl.h
	api.c
	api.h
	debug.h
	fp_http.c
	fp_http.h
	fp_mtu.c
	fp_mtu.h
	fp_tcp.c
	fp_tcp.h
	hash.h
	languages.h
	p0f.c
	p0f.h
	process.c
	process.h
	readfp.c
	readfp.h
	tcp.h
	types.h
)

add_library(p0f-api ${p0f-api_SOURCES})

set_property(TARGET p0f-api PROPERTY C_STANDARD 99)
set_property(TARGET p0f-api PROPERTY C_EXTENSIONS Off)


target_include_directories(p0f-api
	PUBLIC ${PCAP_INCLUDE_DIR}
	PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
	PUBLIC ${PROJECT_BINARY_DIR}
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
