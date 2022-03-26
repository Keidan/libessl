cmake_minimum_required(VERSION 3.1 FATAL_ERROR)

project(libessl)


message("Supported distrib.: cmake -DDISTRIBUTION=[debug|release]")

set(DISTRIBUTION "release" CACHE STRING "Distribution type (release or debug)")

# Information
message("-- Distrib.: ${DISTRIBUTION}")
  
# update directories
set(outputDir ${CMAKE_SOURCE_DIR}/deploy/${CMAKE_HOST_SYSTEM_PROCESSOR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${outputDir})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${outputDir})

set(C_OPTIONS "")
if("${DISTRIBUTION}" MATCHES "release")
  set(C_OPTIONS "-o3 -Wl,-z,relro,-z,now -fstack-protector-all -D_FORTIFY_SOURCE=2 -ffunction-sections -Wall -W -pedantic -fPIC")
  add_definitions(-DNDEBUG)
else()
  set(DISTRIBUTION "debug")
  set(C_OPTIONS "-Og -g -ffunction-sections -Wall -W -pedantic -fPIC")
  add_definitions(-DDEBUG)
  add_definitions(-D_DEBUG)
endif()
set(CMAKE_C_FLAGS "${C_OPTIONS}")

include_directories(${CMAKE_SOURCE_DIR}/api)

file(GLOB_RECURSE files ${CMAKE_SOURCE_DIR}/lib/*.cmake ${CMAKE_SOURCE_DIR}/demo/*.cmake)
foreach(file ${files})
  include(${file})
endforeach()
