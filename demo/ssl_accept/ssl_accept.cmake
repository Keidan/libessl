
set(module ssl_accept)
add_executable(${module}.elf
  ${CMAKE_SOURCE_DIR}/demo/${module}/${module}.c
)
target_link_libraries(${module}.elf essl)

set(cert_sh generate_cert.sh)
add_custom_command(
  TARGET ${module}.elf POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
    ${CMAKE_SOURCE_DIR}/demo/${module}/${cert_sh}
    ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${cert_sh}
)
