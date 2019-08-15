# - Try to find mbedTLS
# Once done this will define
#
# Read-Only variables
#  MBEDTLS_FOUND - system has mbedTLS
#  MBEDTLS_INCLUDE_DIRS - the mbedTLS include directory
#  MBEDTLS_LIBRARIES - Link these to use mbedTLS
#  MBEDTLS_LIBRARY - path to mbedTLS library
#  MBEDX509_LIBRARY - path to mbedTLS X.509 library
#  MBEDCRYPTO_LIBRARY - path to mbedTLS Crypto library

find_path(MBEDTLS_INCLUDE_DIR NAMES mbedtls/ssl.h)
mark_as_advanced(MBEDTLS_INCLUDE_DIR)

set(MBEDCRYPTO_NAMES ${MBEDCRYPTO_NAMES} mbedcrypto libmbedcrypto)
set(MBEDTLS_NAMES ${MBEDTLS_NAMES} mbedtls libmbedtls)
set(MBEDX509_NAMES ${MBEDX509_NAMES} mbedx509 libmbedx509)

find_library(MBEDCRYPTO_LIBRARY NAMES ${MBEDCRYPTO_NAMES})
find_library(MBEDTLS_LIBRARY NAMES ${MBEDTLS_NAMES})
find_library(MBEDX509_LIBRARY NAMES ${MBEDX509_NAMES})
mark_as_advanced(MBEDCRYPTO_LIBRARY MBEDTLS_LIBRARY MBEDX509_LIBRARY)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(MBEDTLS DEFAULT_MSG MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY MBEDTLS_INCLUDE_DIR)

if(MBEDTLS_FOUND)
  set(MBEDTLS_LIBRARIES ${MBEDCRYPTO_LIBRARY} ${MBEDTLS_LIBRARY} ${MBEDX509_LIBRARY})
  set(MBEDTLS_INCLUDE_DIRS ${MBEDTLS_INCLUDE_DIR})
endif()
