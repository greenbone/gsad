# Copyright (C) 2026 Greenbone AG
#
# SPDX-License-Identifier: AGPL-2.0-or-later

macro(add_unit_test _baseName ${ARGN})
  string(REPLACE "-" "_" _testSource "${_baseName}")
  # utils.c
  set(_source "${_testSource}.c")
  # utils_tests.c
  set(_testSource "${_testSource}_tests.c")
  # utils-test
  set(_testName "${_baseName}-test")

  list(APPEND TEST_DEPENDENCIES ${_testName})

  add_executable(
    ${_testName}
    EXCLUDE_FROM_ALL
    ${_source}
    ${_testSource}
    ${ARGN}
  )
  target_compile_options(${_testName} PRIVATE "-fsanitize=address")
  target_link_options(${_testName} PRIVATE "-fsanitize=address")
  add_test(${_testName} ${_testName})
  target_link_libraries(
    ${_testName}
    ${CGREEN_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
    ${LINKER_HARDENING_FLAGS}
    ${LINKER_DEBUG_FLAGS}
    ${GLIB_LDFLAGS}
    ${LIBGVM_UTIL_LDFLAGS}
  )
  set_target_properties(${_testName} PROPERTIES LINKER_LANGUAGE C)
  if(NOT CMAKE_BUILD_TYPE MATCHES "Release")
    target_compile_options(${_testName} PUBLIC ${C_FLAGS_DEBUG_GVMD})
  endif(NOT CMAKE_BUILD_TYPE MATCHES "Release")
endmacro()
