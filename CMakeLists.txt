# Copyright (C) 2017-2021 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

cmake_minimum_required(VERSION 3.5)

message("-- Configuring gsad")

project(gsad VERSION 24.5.2 LANGUAGES C)

if(NOT DEFINED PROJECT_VERSION_STRING)
  set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
  include(ProjectVersion)
endif()

set(GSAD_VERSION "${PROJECT_VERSION_STRING}")

message(STATUS "Building gsad version ${GSAD_VERSION}")

# Feature toggles

if(NOT ENABLE_AGENTS)
  set(ENABLE_AGENTS 0)
endif(NOT ENABLE_AGENTS)
add_definitions(-DENABLE_AGENTS=${ENABLE_AGENTS})

if(NOT ENABLE_CONTAINER_SCANNING)
  set(ENABLE_CONTAINER_SCANNING 0)
endif(NOT ENABLE_CONTAINER_SCANNING)
add_definitions(-DENABLE_CONTAINER_SCANNING=${ENABLE_CONTAINER_SCANNING})

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
