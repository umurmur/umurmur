cmake_minimum_required(VERSION 2.6)
project(uMurmurd-Websocket)

	macro(create_test_app TEST_NAME MAIN_SRC)
		
		set(TEST_SRCS ${MAIN_SRC})
		set(TEST_HDR)

		source_group("Headers Private"   FILES ${TEST_HDR})
		source_group("Sources"   FILES ${TEST_SRCS})
		add_executable(${TEST_NAME} ${TEST_SRCS} ${TEST_HDR})
		
		if (LWS_LINK_TESTAPPS_DYNAMIC)
			target_link_libraries(${TEST_NAME} websockets_shared)
			add_dependencies(${TEST_NAME} websockets_shared)
		else(LWS_LINK_TESTAPPS_DYNAMIC)
			target_link_libraries(${TEST_NAME} websockets)
			add_dependencies(${TEST_NAME} websockets)
		endif(LWS_LINK_TESTAPPS_DYNAMIC)

		# Set test app specific defines.
		set_property(TARGET ${TEST_NAME}
					PROPERTY COMPILE_DEFINITIONS 
						INSTALL_DATADIR="${CMAKE_INSTALL_PREFIX}/share"
					)

		# Prefix the binary names with libwebsockets.
		#set_target_properties(${TEST_NAME} 
		#	PROPERTIES
			#OUTPUT_NAME libwebsockets-${TEST_NAME})

		# Add to the list of tests.
		list(APPEND TEST_APP_LIST ${TEST_NAME})
	endmacro()



create_test_app(uMurmurd-Websocket "src/uMurmurd_Websocket.c")

FIND_LIBRARY(JANSSON_LIBRARY jansson)
TARGET_LINK_LIBRARIES(uMurmurd-Websocket ${JANSSON_LIBRARY})
