/* Copyright (C) 2019-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "gsad_gmp_request.h"

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "gsad gmp request"

int
gmp_request (gvm_connection_t *connection, const char *cmd,
             gmp_arguments_t *arguments)
{
  int retval;
  gchar *args;

  args = gmp_arguments_string (arguments);

  retval = gvm_connection_sendf (connection, "<%s %s/>", cmd, args);

  g_free (args);

  return retval;
}
