cmake_minimum_required (VERSION 3.0)

set(p0f-client_SOURCES p0f-client.c)
set(p0f-sendsyn_SOURCES p0f-sendsyn.c)
set(p0f-sendsyn6_SOURCES p0f-sendsyn6.c)

add_executable(p0f-client ${p0f-client_SOURCES})
add_executable(p0f-sendsyn ${p0f-sendsyn_SOURCES})
add_executable(p0f-syndsyn6 ${p0f-sendsyn6_SOURCES})

set_target_properties(p0f-client
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

set_target_properties(p0f-sendsyn
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

set_target_properties(p0f-syndsyn6
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

set_property(TARGET p0f-client PROPERTY C_STANDARD 99)
set_property(TARGET p0f-client PROPERTY C_EXTENSIONS Off)
set_property(TARGET p0f-sendsyn PROPERTY C_STANDARD 99)
set_property(TARGET p0f-sendsyn PROPERTY C_EXTENSIONS Off)
set_property(TARGET p0f-syndsyn6 PROPERTY C_STANDARD 99)
set_property(TARGET p0f-syndsyn6 PROPERTY C_EXTENSIONS Off)
