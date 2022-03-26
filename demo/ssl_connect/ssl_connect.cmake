
set(module ssl_connect)
add_executable(${module}.elf
  ${CMAKE_SOURCE_DIR}/demo/${module}/${module}.c
)
target_link_libraries(${module}.elf essl)
