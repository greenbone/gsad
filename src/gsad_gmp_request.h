/* Copyright (C) 2019-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_GMP_REQUEST_H
#define _GSAD_GMP_REQUEST_H

#include "gsad_gmp_arguments.h" /* for gmp_arguments_t */

#include <glib.h>
#include <gvm/util/serverutils.h> /* for gvm_connection_t */

int
gmp_request (gvm_connection_t *connection, const gchar *cmd,
             gmp_arguments_t *arguments);

#endif
