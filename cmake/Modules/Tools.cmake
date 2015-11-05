function(EnableSHMAPI)
  if(NOT USE_SHAREDMEMORY_API)
    message(STATUS "Enabling shared memory API")
    set(USE_SHAREDMEMORY_API ON CACHE BOOL "" FORCE)
  endif()
endfunction()

set(TOOLS_DIR "${PROJECT_SOURCE_DIR}/tools")

if(EXISTS "${TOOLS_DIR}/umurmur-monitor/CMakeLists.txt")
  set(UMURMUR_MONITOR_DIR "${TOOLS_DIR}/umurmur-monitor")
  option(BUILD_UMURMUR_MONITOR "Build the umurmur-monitor utility" OFF)
endif()

if(EXISTS "${TOOLS_DIR}/numurmon/CMakeLists.txt")
  set(NUMURMON_DIR "${TOOLS_DIR}/numurmon")
  option(BUILD_NUMURMON "Build the numurmon utility" OFF)
endif()

if(BUILD_UMURMUR_MONITOR OR BUILD_NUMURMON)
  set(UMURMUR_ROOT_PATH "${PROJECT_SOURCE_DIR}")
  EnableSHMAPI()
endif()

if(BUILD_UMURMUR_MONITOR)
  add_subdirectory(${UMURMUR_MONITOR_DIR})
endif()

if(BUILD_NUMURMON)
  add_subdirectory(${NUMURMON_DIR})
endif()
