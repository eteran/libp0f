cmake_minimum_required (VERSION 3.0)

project(p0f)

if(CMAKE_BUILD_TYPE EQUAL "Debug")
	add_definitions(-DDEBUG_BUILD)
endif()

set(P0F_MAJOR_VERSION "3")
set(P0F_MINOR_VERSION "09")
set(P0F_PATCH_VERSION "b")
set(P0F_VERSION \"${P0F_MAJOR_VERSION}.${P0F_MINOR_VERSION}${P0F_PATCH_VERSION}\")

set(FP_FILE         \"p0f.fp\")
set(LOG_MODE        0600)
set(API_MODE        0666)
set(MAX_CONN        1000)
set(MAX_HOSTS       10000)
set(CONN_MAX_AGE    30)
set(HOST_IDLE_LIMIT 120)
set(API_MAX_CONN    20)
set(MAX_DIST        35)
set(CHECK_UAF       1)

# Obscure Options

set(MAX_ALLOC           0x40000000)
set(KILL_PERCENT        10)
set(SNAPLEN             65535)
set(MAX_FLOW_DATA       8192)
set(MAX_TCP_OPT         24)
set(MIN_TSCALE          0.7)
set(MAX_TSCALE          1500)
set(MIN_TWAIT           25)
set(MAX_TWAIT           "(1000 * 60 * 10)")
set(TSTAMP_GRACE        100)
set(MAX_NAT_TS          "(1000 * 60 * 60 * 24)")
set(MIN_PORT_DROP       64)
set(SMALL_TTL_CHG       2)
set(LOCAL_TTL_LIMIT     5)
set(NEAR_TTL_LIMIT      9)
set(NAT_SCORES          32)
set(SIG_BUCKETS         64)
set(FLOW_BUCKETS        256)
set(HOST_BUCKETS        1024)
set(EXPIRE_INTERVAL     50)
set(NAME_CHARS          "\" ./-_!?()\"")
set(SPECIAL_MSS         1331)
set(SPECIAL_WIN         1337)
set(HTTP_MAX_URL        1024)
set(HTTP_MAX_HDRS       32)
set(HTTP_MAX_HDR_NAME   32)
set(HTTP_MAX_HDR_VAL    1024)
set(HTTP_MAX_SHOW       200)
set(HTTP_MAX_DATE_DIFF  10)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

set(p0f_SOURCES
	alloc-inl.h
	api.c
	api.h
	config.h
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

add_executable(p0f ${p0f_SOURCES})

set_property(TARGET p0f PROPERTY C_STANDARD 99)
set_property(TARGET p0f PROPERTY C_EXTENSIONS Off)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

add_definitions(-DVERSION=${P0F_VERSION} -DDEBUG_BUILD -D_DEFAULT_SOURCE)

target_link_libraries(p0f pcap)
