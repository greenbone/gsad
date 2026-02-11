# Copyright (C) 2009-2021 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Needed for 'pkg_check_modules' function
include(FindPkgConfig)

if(NOT PKG_CONFIG_FOUND)
  message(FATAL_ERROR "pkg-config executable not found. Aborting.")
endif(NOT PKG_CONFIG_FOUND)

## Check for existence of required libraries
pkg_check_modules(LIBMICROHTTPD REQUIRED libmicrohttpd>=0.9.0)
pkg_check_modules(LIBXML REQUIRED libxml-2.0)
pkg_check_modules(GLIB REQUIRED glib-2.0>=2.42)
pkg_check_modules(LIBGVM_BASE REQUIRED libgvm_base>=22.8)
pkg_check_modules(LIBGVM_UTIL REQUIRED libgvm_util>=22.8)
pkg_check_modules(LIBGVM_GMP REQUIRED libgvm_gmp>=22.8)
pkg_check_modules(GNUTLS REQUIRED gnutls>=3.2.15)
pkg_check_modules(ZLIB REQUIRED zlib>=1.2)
pkg_check_modules(BROTLI libbrotlienc)

message(STATUS "Looking for libgcrypt...")
pkg_check_modules(GCRYPT REQUIRED libgcrypt)

if(
  NOT LIBMICROHTTPD_FOUND
  OR NOT LIBXML_FOUND
  OR NOT GLIB_FOUND
  OR (GTHREAD_REQUIRED AND NOT GTHREAD_FOUND)
  OR NOT LIBGVM_GMP_FOUND
  OR NOT GNUTLS_FOUND
  OR NOT ZLIB_FOUND
)
  message(
    FATAL_ERROR
    "One or more required libraries was not found "
    "(see message above), please install the missing "
    "libraries and run cmake again."
  )
endif(
  NOT LIBMICROHTTPD_FOUND
  OR NOT LIBXML_FOUND
  OR NOT GLIB_FOUND
  OR (GTHREAD_REQUIRED AND NOT GTHREAD_FOUND)
  OR NOT LIBGVM_GMP_FOUND
  OR NOT GNUTLS_FOUND
  OR NOT ZLIB_FOUND
)

## Program

set(HARDENING_FLAGS "-D_FORTIFY_SOURCE=2 -fstack-protector")
set(LINKER_HARDENING_FLAGS "-Wl,-z,relro -Wl,-z,now")

set(UNUSED_FUNCTIONS_FLAGS "")
# Enable this to find unused functions, and search for "removing" in output.
#set(UNUSED_FUNCTIONS_FLAGS "-flto -fwhole-program -ffunction-sections -Wl,--gc-sections -Wl,--print-gc-sections")
set(
  CMAKE_C_FLAGS
  "${CMAKE_C_FLAGS} ${UNUSED_FUNCTIONS_FLAGS} -Wall -Wformat -Wformat-security ${COVERAGE_FLAGS}"
)
if(BROTLI_FOUND)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_BROTLI=1")
endif(BROTLI_FOUND)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Werror")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${HARDENING_FLAGS}")

include_directories(
  ${LIBMICROHTTPD_INCLUDE_DIRS}
  ${LIBXML_INCLUDE_DIRS}
  ${GLIB_INCLUDE_DIRS}
  ${LIBGVM_BASE_INCLUDE_DIRS}
  ${LIBGVM_UTIL_INCLUDE_DIRS}
  ${LIBGVM_GMP_INCLUDE_DIRS}
  ${GNUTLS_INCLUDE_DIRS}
  ${ZLIB_INCLUDE_DIRS}
  ${BROTLI_INCLUDE_DIRS}
)

find_package(Threads)

## Program

add_executable(
  gsad
  gsad.c
  gsad_args.c
  gsad_base.c
  gsad_cmd.c
  gsad_connection_info.c
  gsad_credentials.c
  gsad_gmp.c
  gsad_gmp_arguments.c
  gsad_gmp_request.c
  gsad_http.c
  gsad_http_handler.c
  gsad_i18n.c
  gsad_session.c
  gsad_settings.c
  gsad_user.c
  gsad_validator.c
  utils.c
  validator.c
)

target_link_libraries(
  gsad
  ${LIBMICROHTTPD_LDFLAGS}
  ${GTHREAD_LDFLAGS}
  ${GLIB_LDFLAGS}
  ${LIBXML_LDFLAGS}
  ${GCRYPT_LDFLAGS}
  ${GNUTLS_LDFLAGS}
  ${ZLIB_LDFLAGS}
  ${BROTLI_LDFLAGS}
  ${LIBGVM_BASE_LDFLAGS}
  ${LIBGVM_UTIL_LDFLAGS}
  ${LIBGVM_GMP_LDFLAGS}
  ${LIBGVM_GMP_LDFLAGS}
  ${CMAKE_THREAD_LIBS_INIT}
  ${LINKER_HARDENING_FLAGS}
)
set_target_properties(gsad PROPERTIES LINKER_LANGUAGE C)

if(GSAD_VERSION)
  add_definitions(-DGSAD_VERSION="${GSAD_VERSION}")
endif(GSAD_VERSION)

if(GVM_SERVER_CERTIFICATE)
  add_definitions(-DGVM_SERVER_CERTIFICATE="${GVM_SERVER_CERTIFICATE}")
endif(GVM_SERVER_CERTIFICATE)

if(GVM_SERVER_KEY)
  add_definitions(-DGVM_SERVER_KEY="${GVM_SERVER_KEY}")
endif(GVM_SERVER_KEY)

if(GVM_CA_CERTIFICATE)
  add_definitions(-DGVM_CA_CERTIFICATE="${GVM_CA_CERTIFICATE}")
endif(GVM_CA_CERTIFICATE)

if(GVMD_RUN_DIR)
  add_definitions(-DGVMD_RUN_DIR="${GVMD_RUN_DIR}")
endif(GVMD_RUN_DIR)

if(GSAD_RUN_DIR)
  add_definitions(-DGSAD_RUN_DIR="${GSAD_RUN_DIR}")
endif(GSAD_RUN_DIR)

if(GSAD_PID_PATH)
  add_definitions(-DGSAD_PID_PATH="${GSAD_PID_PATH}")
endif(GSAD_PID_PATH)

if(GSAD_DATA_DIR)
  add_definitions(-DGSAD_DATA_DIR="${GSAD_DATA_DIR}")
endif(GSAD_DATA_DIR)

if(GSAD_STATIC_CONTENT_DIR)
  add_definitions(-DGSAD_STATIC_CONTENT_DIR="${GSAD_STATIC_CONTENT_DIR}")
endif(GSAD_STATIC_CONTENT_DIR)

if(GSAD_CONFIG_DIR)
  add_definitions(-DGSAD_CONFIG_DIR="${GSAD_CONFIG_DIR}")
endif(GSAD_CONFIG_DIR)

if(GSAD_LOCALE_DIR)
  add_definitions(-DGSAD_LOCALE_DIR="${GSAD_LOCALE_DIR}")
endif(GSAD_LOCALE_DIR)

if(GSAD_CHROOT_LOCALE_DIR)
  add_definitions(-DGSAD_CHROOT_LOCALE_DIR="${GSAD_CHROOT_LOCALE_DIR}")
endif(GSAD_CHROOT_LOCALE_DIR)

add_definitions(-DGVM_OS_NAME="${CMAKE_SYSTEM}")
add_definitions(-DPREFIX="${CMAKE_INSTALL_PREFIX}")

## Install

install(
  TARGETS gsad
  RUNTIME DESTINATION ${SBINDIR}
  LIBRARY DESTINATION ${LIBDIR}
  ARCHIVE DESTINATION ${LIBDIR}/static
)

## Static analysis

add_custom_target(
  cppcheck
  COMMENT "Running cppcheck..."
  COMMAND sh -c \"cppcheck ${CMAKE_CURRENT_SOURCE_DIR}\"
)

add_custom_target(check COMMENT "Checking code...")
add_dependencies(check cppcheck)

## Tag files

set(C_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.c")
add_custom_target(etags COMMENT "Building TAGS..." COMMAND etags ${C_FILES})
add_custom_target(ctags COMMENT "Building tags..." COMMAND ctags ${C_FILES})
add_custom_target(tags COMMENT "Building tags files...")
add_dependencies(tags etags ctags)

## Testing

if(BUILD_TESTING)
  find_package(cgreen REQUIRED)

  include(${CMAKE_SOURCE_DIR}/cmake/add_unit_test.cmake)

  add_unit_test(utils "")
  add_unit_test(gsad-validator validator.c)
  add_unit_test(gsad-args "")
  add_unit_test(gsad-settings "")
  add_custom_target(
    tests
    DEPENDS gsad-validator-test utils-test gsad-args-test gsad-settings-test
  )
endif(BUILD_TESTING)

if(ENABLE_COVERAGE)
  add_custom_target(
    coverage-html
    COMMAND
      gcovr --html-details ${COVERAGE_DIR}/coverage.html -r ${CMAKE_SOURCE_DIR}
      ${CMAKE_BINARY_DIR}
  )
  add_custom_target(
    coverage-xml
    COMMAND
      gcovr --xml ${COVERAGE_DIR}/coverage.xml -r ${CMAKE_SOURCE_DIR}
      ${CMAKE_BINARY_DIR}
  )
  add_custom_target(coverage DEPENDS coverage-xml coverage-html)
endif(ENABLE_COVERAGE)

add_custom_target(
  clean-coverage
  COMMAND find . -name *.gcda -delete -or -name *.gcno -delete
  COMMAND rm -f ${COVERAGE_DIR}/*
)

## End
