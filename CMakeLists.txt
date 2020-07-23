cmake_minimum_required(VERSION 3.0.0)

project(TsAuth)
set(TsAuth_TARGET tsauth)

aux_source_directory(src TsAuth_SOURCES)

set(TsAuth_INCLUDES include)
set(TsAuth_LIBRARIES m)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
find_package(CURL REQUIRED)
if(CURL_FOUND)
  list(APPEND TsAuth_INCLUDES ${CURL_INCLUDE_DIRS})
  list(APPEND TsAuth_LIBRARIES ${CURL_LIBRARIES})
else()
  message(FATAL_ERROR "Dependency libcurl not found!")
endif()

find_package(mbedTLS REQUIRED)
if(MBEDTLS_FOUND)
  list(APPEND TsAuth_INCLUDES ${MBEDTLS_INCLUDE_DIRS})
  list(APPEND TsAuth_LIBRARIES ${MBEDTLS_LIBRARIES})
else()
  message(FATAL_ERROR "Dependency libmbedtls not found!")
endif()

find_package(JSONC REQUIRED)
if(JSONC_FOUND)
  list(APPEND TsAuth_INCLUDES ${JSONC_INCLUDE_DIRS})
  list(APPEND TsAuth_LIBRARIES ${JSONC_LIBRARIES})
else()
  message(FATAL_ERROR "Dependency libjson-c not found!")
endif()

# execute_process(COMMAND git rev-parse --short=8 HEAD
#                 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
#                 OUTPUT_VARIABLE GIT_COMMIT_ID)
# string(STRIP ${GIT_COMMIT_ID} GIT_COMMIT_ID)

add_executable(${TsAuth_TARGET} ${TsAuth_SOURCES})
target_include_directories(${TsAuth_TARGET} PUBLIC ${TsAuth_INCLUDES})
target_compile_definitions(${TsAuth_TARGET} PUBLIC TSAUTH_VERSION="0.4.2")
# target_compile_definitions(${TsAuth_TARGET} PUBLIC TSAUTH_GIT_COMMIT_ID="${GIT_COMMIT_ID}")
target_link_libraries(${TsAuth_TARGET} ${TsAuth_LIBRARIES})
install(TARGETS ${TsAuth_TARGET} RUNTIME DESTINATION bin)
