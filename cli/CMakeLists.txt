cmake_minimum_required (VERSION 3.0)

set(p0f-cli-SOURCES
	main.c
)

add_executable(p0f ${p0f-cli-SOURCES})

set_property(TARGET p0f PROPERTY C_STANDARD 99)
set_property(TARGET p0f PROPERTY C_EXTENSIONS Off)

target_link_libraries(p0f p0f-api)

set_target_properties(p0f
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)
