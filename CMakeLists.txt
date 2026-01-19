# Copyright (C) 2017-2021 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

cmake_minimum_required(VERSION 3.10)

message("-- Configuring gsad")

project(gsad VERSION 24.13.0 LANGUAGES C)

if(NOT DEFINED PROJECT_VERSION_STRING)
  set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
  include(ProjectVersion)
endif()

set(GSAD_VERSION "${PROJECT_VERSION_STRING}")

message(STATUS "Building gsad version ${GSAD_VERSION}")

## Code coverage

option(ENABLE_COVERAGE "Enable support for coverage analysis" OFF)
if(ENABLE_COVERAGE)
  set(COVERAGE_FLAGS "--coverage -ftest-coverage -fprofile-arcs")
  set(COVERAGE_DIR "${CMAKE_BINARY_DIR}/coverage")
  file(MAKE_DIRECTORY ${COVERAGE_DIR})
  message("-- Code Coverage enabled")
endif(ENABLE_COVERAGE)

## Files generated on installation

# generate compile_commands.json file
# see https://clang.llvm.org/docs/JSONCompilationDatabase.html
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

enable_testing()

## make format
message(STATUS "Looking for clang-format...")
find_program(CLANG_FORMAT clang-format)

if(CLANG_FORMAT)
  message(STATUS "Looking for clang-format... ${CLANG_FORMAT}")
  add_custom_target(
    format
    COMMAND ${CLANG_FORMAT} "-i" "./src/*.c" "./src/*.h"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  )
else(CLANG_FORMAT)
  message(STATUS "clang-format not found.")
endif(CLANG_FORMAT)

if(NOT SYSCONFDIR)
  set(SYSCONFDIR "/etc")
endif(NOT SYSCONFDIR)

if(NOT EXEC_PREFIX)
  set(EXEC_PREFIX "${CMAKE_INSTALL_PREFIX}")
endif(NOT EXEC_PREFIX)

if(NOT BINDIR)
  set(BINDIR "${EXEC_PREFIX}/bin")
endif(NOT BINDIR)

if(NOT SBINDIR)
  set(SBINDIR "${EXEC_PREFIX}/sbin")
endif(NOT SBINDIR)

if(NOT LIBDIR)
  set(LIBDIR "${EXEC_PREFIX}/lib")
endif(NOT LIBDIR)

if(NOT LOCALSTATEDIR)
  set(LOCALSTATEDIR "/var")
endif(NOT LOCALSTATEDIR)

if(NOT INCLUDEDIR)
  set(INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/include")
endif(NOT INCLUDEDIR)

if(NOT DATADIR)
  set(DATADIR "${CMAKE_INSTALL_PREFIX}/share")
endif(NOT DATADIR)

set(GSAD_DATA_DIR "${DATADIR}/gvm/gsad")
set(GSAD_CONFIG_DIR "${SYSCONFDIR}/gvm/")

if(NOT GSAD_RUN_DIR)
  set(GSAD_RUN_DIR "/run/gsad")
endif(NOT GSAD_RUN_DIR)

if(NOT GSAD_PID_PATH)
  set(GSAD_PID_PATH "${GSAD_RUN_DIR}/gsad.pid")
endif(NOT GSAD_PID_PATH)

if(NOT GVMD_RUN_DIR)
  set(GVMD_RUN_DIR "/run/gvmd")
endif(NOT GVMD_RUN_DIR)

if(NOT GVM_STATE_DIR)
  set(GVM_STATE_DIR "${LOCALSTATEDIR}/lib/gvm")
else(NOT GVM_STATE_DIR)
  set(GVM_STATE_DIR "${GVM_STATE_DIR}")
endif(NOT GVM_STATE_DIR)

if(NOT GSAD_LOG_FILE)
  if(GVM_LOG_DIR)
    set(GSAD_LOG_FILE "${GVM_LOG_DIR}/gsad.log")
  else(GVM_LOG_DIR)
    set(GSAD_LOG_FILE "-")
  endif(GVM_LOG_DIR)
endif(NOT GSAD_LOG_FILE)

if(NOT GVM_SERVER_CERTIFICATE)
  set(GVM_SERVER_CERTIFICATE "${GVM_STATE_DIR}/CA/servercert.pem")
else(NOT GVM_SERVER_CERTIFICATE)
  set(GVM_SERVER_CERTIFICATE "${GVM_SERVER_CERTIFICATE}")
endif(NOT GVM_SERVER_CERTIFICATE)

if(NOT GVM_SERVER_KEY)
  set(GVM_SERVER_KEY "${GVM_STATE_DIR}/private/CA/serverkey.pem")
else(NOT GVM_SERVER_KEY)
  set(GVM_SERVER_KEY "${GVM_SERVER_KEY}")
endif(NOT GVM_SERVER_KEY)

if(NOT GVM_CA_CERTIFICATE)
  set(GVM_CA_CERTIFICATE "${GVM_STATE_DIR}/CA/cacert.pem")
else(NOT GVM_CA_CERTIFICATE)
  set(GVM_CA_CERTIFICATE "${GVM_CA_CERTIFICATE}")
endif(NOT GVM_CA_CERTIFICATE)

configure_file(src/gsad_log_conf.cmake_in src/gsad_log.conf)

## Install

install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/src/gsad_log.conf
  DESTINATION ${GSAD_CONFIG_DIR}
)

add_subdirectory(src)
add_subdirectory(config)

add_subdirectory(doc)

# vim: set ts=2 sw=2 tw=80:
