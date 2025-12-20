# Copyright (C) 2019-2021 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

if(NOT SYSTEMD_SERVICE_DIR)
  set(SYSTEMD_SERVICE_DIR "${LIBDIR}/systemd/system")
endif(NOT SYSTEMD_SERVICE_DIR)

message(STATUS "Installing systemd service files to ${SYSTEMD_SERVICE_DIR}")

if(NOT LOGROTATE_DIR)
  set(LOGROTATE_DIR "${SYSCONFDIR}/logrotate.d")
endif(NOT LOGROTATE_DIR)

configure_file(gsad.service.in gsad.service)
configure_file(gsad.logrotate.in gsad.logrotate)

install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/gsad.service
  DESTINATION ${SYSTEMD_SERVICE_DIR}/
)

install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/gsad.logrotate
  DESTINATION ${LOGROTATE_DIR}/
  RENAME gsad
)
