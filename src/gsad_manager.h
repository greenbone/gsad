/* Copyright (C) 2016-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_MANAGER_H
#define _GSAD_MANAGER_H

/**
 * @file gsad_manager.h
 * @brief Manager Connection handling for gsad
 */

#include "gsad_credentials.h" /* for gsad_credentials_t */

#include <gvm/gmp/gmp.h>          /* for gmp_authenticate_info_opts_t */
#include <gvm/util/serverutils.h> /* for gvm_connection_t */

int
gsad_manager_connect_with_credentials (gvm_connection_t *connection,
                                       gsad_credentials_t *credentials);

int
gsad_manager_connect_with_username_password (gvm_connection_t *connection,
                                             const gchar *username,
                                             const gchar *password);

int
gsad_manager_connect (gvm_connection_t *connection,
                      gmp_authenticate_info_opts_t auth_opts);

#endif /* _GSAD_MANAGER_H */
