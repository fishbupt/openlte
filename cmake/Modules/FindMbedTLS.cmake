# - Try to find mbedtls libraray
#
# Once done this will define
#  MBEDTLS_FOUND        - System has mbedtls
#  MBEDTLS_INCLUDE_DIR - The mbedtls include directories
#  MBEDTLS_LIBRARIES    - The mbedtls library
find_path(MBEDTLS_INCLUDE_DIR
        NAMES mbedtls/ssl.h
        PATH_SUFFIXES include
        HINTS ${MBEDTLS_ROOT})

find_library(MBEDTLS_LIBRARY
        NAMES mbedtls
        PATH_SUFFIXES lib
        HINTS ${MBEDTLS_ROOT})

find_library(MBEDCRYPTO_LIBRARY
        NAMES mbedcrypto
        PATH_SUFFIXES lib
        HINTS ${MBEDTLS_ROOT})

find_library(MBEDX509_LIBRARY
        NAMES mbedx509
        PATH_SUFFIXES lib
        HINTS ${MBEDTLS_ROOT})

if(MBEDTLS_INCLUDE_DIR AND MBEDTLS_LIBRARY)
    set(MBEDTLS_FOUND TRUE)
    set(MBEDTLS_LIBRARIES ${MBEDTLS_LIBRARY} ${MBEDCRYPTO_LIBRARY} ${MBEDX509_LIBRARY})
endif()

if(MBEDTLS_FOUND)
    if(NOT MBEDTLS_FIND_QUIETLY)
        message(STATUS "Found mbed TLS: ${MBEDTLS_LIBRARIES}")
    endif()
else()
    if(MBEDTLS_FIND_REQUIRED)
        message(FATAL_ERROR "mbed TLS was not found")
    endif()
endif()

mark_as_advanced(MBEDTLS_INCLUDE_DIR MBEDTLS_LIBRARY)