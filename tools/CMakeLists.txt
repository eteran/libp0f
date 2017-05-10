cmake_minimum_required (VERSION 3.0)

set(p0f-client_SOURCES p0f-client.c)
set(p0f-sendsyn_SOURCES p0f-sendsyn.c)
set(p0f-sendsyn6_SOURCES p0f-sendsyn6.c)

add_executable(p0f-client ${p0f-client_SOURCES})
add_executable(p0f-sendsyn ${p0f-sendsyn_SOURCES})
add_executable(p0f-syndsyn6 ${p0f-sendsyn6_SOURCES})

