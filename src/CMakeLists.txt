set(SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/Mumble.pb-c.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ban.c
  ${CMAKE_CURRENT_SOURCE_DIR}/channel.c
  ${CMAKE_CURRENT_SOURCE_DIR}/client.c
  ${CMAKE_CURRENT_SOURCE_DIR}/conf.c
  ${CMAKE_CURRENT_SOURCE_DIR}/crypt.c
  ${CMAKE_CURRENT_SOURCE_DIR}/log.c
  ${CMAKE_CURRENT_SOURCE_DIR}/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/memory.c
  ${CMAKE_CURRENT_SOURCE_DIR}/messagehandler.c
  ${CMAKE_CURRENT_SOURCE_DIR}/messages.c
  ${CMAKE_CURRENT_SOURCE_DIR}/pds.c
  ${CMAKE_CURRENT_SOURCE_DIR}/server.c
  ${CMAKE_CURRENT_SOURCE_DIR}/timer.c
  ${CMAKE_CURRENT_SOURCE_DIR}/util.c
  ${CMAKE_CURRENT_SOURCE_DIR}/voicetarget.c
  )

if(SSL MATCHES "mbedtls")
  list(APPEND SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/ssli_mbedtls.c)
elseif(SSL MATCHES "gnutls")
  list(APPEND SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/ssli_gnutls.c)
else()
  list(APPEND SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/ssli_openssl.c)
endif(SSL MATCHES "mbedtls")

if(USE_SHAREDMEMORY_API)
  list(APPEND SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/sharedmemory.c)
endif(USE_SHAREDMEMORY_API)

configure_file(config.h.in ${CMAKE_SOURCE_DIR}/src/config.h)

include_directories(${LIBCONFIG_INCLUDE_DIR}
                    ${PROTOBUFC_INCLUDE_DIR}
                    ${SSLIMP_INCLUDE_DIR})

link_directories(${LIBCONFIG_LIB_DIR}
                 ${PROTOBUFC_LIB_DIR}
                 ${SSLIMP_LIB_DIR})

add_executable(${PROJECT_NAME} ${SOURCE_FILES})

set_target_properties(${PROJECT_NAME} PROPERTIES
  C_STANDARD 99
  C_STANDARD_REQUIRED YES
  C_EXTENSIONS YES
)

target_compile_definitions(${PROJECT_NAME} PRIVATE
  _GNU_SOURCE
  _BSD_SOURCE
  _NETBSD_SOURCE
  _DARWIN_C_SOURCE
  _XOPEN_SOURCE=700
)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall
    -Wextra
    -Wformat=2
    -Wpointer-arith
    -Wundef
  )
endif()

target_link_libraries(${PROJECT_NAME}
                      ${LIBCONFIG_LIBRARIES}
                      ${PROTOBUFC_LIBRARIES}
                      ${SSLIMP_LIBRARIES}
                      ${LIBRT}
                      ${CRYPTO_LIBRARIES})

install(TARGETS ${PROJECT_NAME}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
