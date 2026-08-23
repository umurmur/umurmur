include(GNUInstallDirs)

configure_file(
    umurmurd.8.in
    ${CMAKE_CURRENT_BINARY_DIR}/umurmurd.8
    @ONLY
)

configure_file(
    umurmur.conf.5.in
    ${CMAKE_CURRENT_BINARY_DIR}/umurmur.conf.5
    @ONLY
)

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/umurmurd.8
    DESTINATION "${CMAKE_INSTALL_MANDIR}/man8"
    OPTIONAL
)

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/umurmur.conf.5
    DESTINATION "${CMAKE_INSTALL_MANDIR}/man5"
    OPTIONAL
)
