# - Try to find json-c
# Once done this will define
#
# Read-Only variables
#  JSONC_FOUND - system has json-c
#  JSONC_INCLUDE_DIRS - the json-c include directory
#  JSONC_LIBRARIES - link these to use json-c
#  JSONC_LIBRARY - path to mbedTLS library

find_path(JSONC_INCLUDE_DIR NAMES json-c/json.h)
mark_as_advanced(JSONC_INCLUDE_DIR)

set(JSONC_NAMES ${JSONC_NAMES} json-c libjson-c)
find_library(JSONC_LIBRARY NAMES ${JSONC_NAMES})
mark_as_advanced(JSONC_LIBRARY)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(JSONC DEFAULT_MSG JSONC_LIBRARY JSONC_INCLUDE_DIR)

if(JSONC_FOUND)
  set(JSONC_LIBRARIES ${JSONC_LIBRARY})
  set(JSONC_INCLUDE_DIRS ${JSONC_INCLUDE_DIR})
endif()
