/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_logging.h"

#include <gnutls/gnutls.h> /* for gnutls_global_set_log_function and gnutls_global_set_log_level */
#include <gvm/base/logging.h> /* for load_log_configuration, setup_log_handlers, free_log_configuration, log_func_for_gnutls */
#include <gvm/util/fileutils.h> /* for gvm_file_is_readable */

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "gsad logging"

/**
 * Initialize the logging handlers
 */
gsad_log_config_t *
gsad_logging_init (gsad_settings_t *gsad_settings)
{
  /* Setup logging. */
  gsad_log_config_t *log_config = NULL;
  const gchar *rc_name = gsad_settings_get_log_config_filename (gsad_settings);
  if (gvm_file_is_readable (rc_name))
    log_config = load_log_configuration ((gchar *) rc_name);
  else
    g_debug (
      "Log configuration file %s not found or not readable, using defaults.",
      rc_name);

  setup_log_handlers (log_config);
  /* Set to ensure that recursion is left out, in case two threads log
   * concurrently. */
  g_log_set_always_fatal (G_LOG_FATAL_MASK);
  /* Enable GNUTLS debugging if requested via env variable.  */
  {
    const gchar *s;
    if ((s = getenv ("GVM_GNUTLS_DEBUG")))
      {
        gnutls_global_set_log_function (log_func_for_gnutls);
        gnutls_global_set_log_level (atoi (s));
      }
  }
  return log_config;
}

/**
 * Cleanup the logging handlers
 *
 * @param[in] log_config The log configuration to clean up, as returned by
 * gsad_logging_init.
 */
void
gsad_logging_cleanup (gsad_log_config_t *log_config)
{
  if (log_config)
    {
      g_debug ("Cleaning up log configuration...");
      free_log_configuration (log_config);
    }
}
