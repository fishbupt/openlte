cmake_minimum_required(VERSION 2.6)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/../../cmake/Modules)

find_package(MbedTLS REQUIRED)

if(NOT MBEDTLS_FOUND)
    message(FATAL_ERROR "mbedtls required to compile openLTE lib")
endif()
include_directories(${MBEDTLS_INCLUDE_DIR})
link_directories(${MBEDTLS_LIBRARIES})

include_directories(../hdr ${CMAKE_SOURCE_DIR}/../../cmn_hdr)
add_library(lte
  ../src/liblte_common.cc
  ../src/liblte_interface.cc
  ../src/liblte_phy.cc
  ../src/liblte_mac.cc
  ../src/liblte_rlc.cc
  ../src/liblte_pdcp.cc
  ../src/liblte_rrc.cc
  ../src/liblte_mme.cc
  ../src/liblte_security.cc
)

# install
file(GLOB HEADER_FILES "../hdr/*.h" "${CMAKE_SOURCE_DIR}/../../cmn_hdr/*.h")
install(TARGETS lte DESTINATION lib)
install(FILES ${HEADER_FILES} DESTINATION include/lte)
