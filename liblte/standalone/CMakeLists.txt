cmake_minimum_required(VERSION 2.6)
project(openLTE CXX C)
set(openLTE_version 0.20.3)
enable_testing()

#select the release build type by default to get optimization flags
if(NOT CMAKE_BUILD_TYPE)
   set(CMAKE_BUILD_TYPE "Release")
   message(STATUS "Build type not specified: defaulting to release.")
endif(NOT CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE} CACHE STRING "")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

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
