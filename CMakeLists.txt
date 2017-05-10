cmake_minimum_required (VERSION 3.0)

project(p0f)


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

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

add_definitions(-DVERSION="3.09b" -DDEBUG_BUILD)

target_link_libraries(p0f pcap)
