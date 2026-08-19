set(SOURCE_FILES
  Mumble.pb-c.c
  ban.c
  channel.c
  client.c
  conf.c
  crypt.c
  log.c
  main.c
  memory.c
  messagehandler.c
  messages.c
  pds.c
  server.c
  timer.c
  util.c
  voicetarget.c
)

if(SSL MATCHES "mbedtls")
  list(APPEND SOURCE_FILES ssli_mbedtls.c)
elseif(SSL MATCHES "gnutls")
  list(APPEND SOURCE_FILES ssli_gnutls.c)
else()
  list(APPEND SOURCE_FILES ssli_openssl.c)
endif()

if(USE_SHAREDMEMORY_API)
  list(APPEND SOURCE_FILES sharedmemory.c)
endif(USE_SHAREDMEMORY_API)

configure_file(config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

add_executable(${PROJECT_NAME} ${SOURCE_FILES})

set_target_properties(${PROJECT_NAME} PROPERTIES
  C_STANDARD 99
  C_STANDARD_REQUIRED YES
  C_EXTENSIONS YES
)

target_compile_definitions(${PROJECT_NAME} PRIVATE
  _GNU_SOURCE
  _XOPEN_SOURCE=700
)
# _XOPEN_SOURCE hides BSD APIs on Darwin (initgroups).
if(APPLE)
  target_compile_definitions(${PROJECT_NAME} PRIVATE _DARWIN_C_SOURCE)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall
    -Wextra
    -Wformat=2
    -Wpointer-arith
    -Wundef
  )
endif()

target_include_directories(${PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}
  ${LIBCONFIG_INCLUDE_DIR}
  ${PROTOBUFC_INCLUDE_DIR}
  ${SSLIMP_INCLUDE_DIR}
)

target_link_libraries(${PROJECT_NAME} PRIVATE
  ${LIBCONFIG_LIBRARIES}
  ${PROTOBUFC_LIBRARIES}
  ${SSLIMP_LIBRARIES}
  ${LIBRT}
  ${CRYPTO_LIBRARIES}
)

install(TARGETS ${PROJECT_NAME}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
