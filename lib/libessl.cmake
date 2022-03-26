

set(module essl)
add_library(${module} SHARED
  ${CMAKE_SOURCE_DIR}/lib/${module}.c
)
target_link_libraries(${module} ssl crypto m)
