cmake_minimum_required (VERSION 3.0)

project(p0f C)

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic -Wunused -W -Wall -Wno-format-zero-length -Wno-sign-compare")

set(P0F_MAJOR_VERSION "3")
set(P0F_MINOR_VERSION "09")
set(P0F_PATCH_VERSION "b")
set(P0F_VERSION \"${P0F_MAJOR_VERSION}.${P0F_MINOR_VERSION}${P0F_PATCH_VERSION}\")
add_definitions(-DVERSION=${P0F_VERSION} -D_DEFAULT_SOURCE)

add_subdirectory (lib)
add_subdirectory (cli)

if(BUILD_TOOLS)
	add_subdirectory (tools)
endif()
