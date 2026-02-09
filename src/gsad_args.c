/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_args.h"

#include "gsad_settings.h" // for defaults

#include <gvm/util/fileutils.h>

#define COPYRIGHT                                                        \
  "Copyright (C) 2010 - 2026 Greenbone AG\n"                             \
  "License: AGPL-3.0-or-later\n"                                         \
  "This is free software: you are free to change and redistribute it.\n" \
  "There is NO WARRANTY, to the extent permitted by law.\n\n"

int
gsad_args_parse (int argc, char **argv, gsad_args_t *args)
{
  GError *error = NULL;
  GOptionContext *option_context;
  GOptionEntry option_entries[] = {
    {"drop-privileges", '\0', 0, G_OPTION_ARG_STRING, &args->drop,
     "Drop privileges to <user>.", "<user>"},
    {"foreground", 'f', 0, G_OPTION_ARG_NONE, &args->foreground,
     "Run in foreground.", NULL},
    {"http-only", '\0', 0, G_OPTION_ARG_NONE, &args->http_only,
     "Serve HTTP only, without SSL. Implies --no-redirect.", NULL},
    {"listen", '\0', 0, G_OPTION_ARG_STRING_ARRAY, &args->gsad_address_string,
     "Listen on <address>.", "<address>"},
    {"mlisten", '\0', 0, G_OPTION_ARG_STRING,
     &args->gsad_manager_address_string, "Manager address.", "<address>"},
    {"port", 'p', 0, G_OPTION_ARG_INT, &args->gsad_port,
     "Use port number <number>.", "<number>"},
    {"mport", 'm', 0, G_OPTION_ARG_INT, &args->gsad_manager_port,
     "Use manager port number <number>.", "<number>"},
    {"rport", 'r', 0, G_OPTION_ARG_INT, &args->gsad_redirect_port,
     "Redirect HTTP from this port number <number>.", "<number>"},
    {"no-redirect", '\0', 0, G_OPTION_ARG_NONE, &args->no_redirect,
     "Don't redirect HTTP to HTTPS (implied when using --http-only).", NULL},
    {"verbose", 'v', 0, G_OPTION_ARG_NONE, &args->verbose,
     "Has no effect.  See INSTALL for logging config.", NULL},
    {"version", 'V', 0, G_OPTION_ARG_NONE, &args->print_version,
     "Print version and exit.", NULL},
    {"vendor-version", '\0', 0, G_OPTION_ARG_STRING,
     &args->gsad_vendor_version_string, "Use <string> as version in interface.",
     "<string>"},
    {"ssl-private-key", 'k', 0, G_OPTION_ARG_FILENAME,
     &args->ssl_private_key_filename,
     "Use <file> as the private key for HTTPS. Defaults "
     "to " DEFAULT_GSAD_TLS_PRIVATE_KEY,
     "<file>"},
    {"ssl-certificate", 'c', 0, G_OPTION_ARG_FILENAME,
     &args->ssl_certificate_filename,
     "Use <file> as the certificate for HTTPS. Defaults "
     "to " DEFAULT_GSAD_TLS_CERTIFICATE,
     "<file>"},
    {"dh-params", '\0', 0, G_OPTION_ARG_FILENAME, &args->dh_params_filename,
     "Diffie-Hellman parameters file", "<file>"},
    {"do-chroot", '\0', 0, G_OPTION_ARG_NONE, &args->do_chroot, "Do chroot.",
     NULL},
    {"secure-cookie", '\0', 0, G_OPTION_ARG_NONE, &args->secure_cookie,
     "Use a secure cookie (implied when using HTTPS).", NULL},
    {"timeout", '\0', 0, G_OPTION_ARG_INT, &args->timeout,
     "Minutes of user idle time before session expires. Defaults "
     "to " G_STRINGIFY (SESSION_TIMEOUT) " minutes",
     "<number>"},
    {"client-watch-interval", '\0', 0, G_OPTION_ARG_INT,
     &args->client_watch_interval,
     "Check if client connection was closed every <number> seconds."
     " 0 to disable. Defaults to " G_STRINGIFY (
       DEFAULT_CLIENT_WATCH_INTERVAL) ".",
     "<number>"},
    {"debug-tls", 0, 0, G_OPTION_ARG_INT, &args->debug_tls,
     "Enable TLS debugging at <level>", "<level>"},
    {"gnutls-priorities", '\0', 0, G_OPTION_ARG_STRING,
     &args->gnutls_priorities, "GnuTLS priorities string.", "<string>"},
    {"http-frame-opts", 0, 0, G_OPTION_ARG_STRING, &args->http_frame_opts,
     "X-Frame-Options HTTP header.  Defaults to "
     "\"" DEFAULT_GSAD_X_FRAME_OPTIONS "\".",
     "<frame-opts>"},
    {"http-csp", 0, 0, G_OPTION_ARG_STRING, &args->http_csp,
     "Content-Security-Policy HTTP header.  Defaults to "
     "\"" DEFAULT_GSAD_CONTENT_SECURITY_POLICY "\".",
     "<csp>"},
    {"http-sts", 0, 0, G_OPTION_ARG_NONE, &args->hsts_enabled,
     "Enable HTTP Strict-Transport-Security header.", NULL},
    {"http-sts-max-age", 0, 0, G_OPTION_ARG_INT, &args->hsts_max_age,
     "max-age in seconds for HTTP Strict-Transport-Security header."
     "  Defaults to \"" G_STRINGIFY (DEFAULT_GSAD_HSTS_MAX_AGE) "\".",
     "<max-age>"},
    {"ignore-x-real-ip", '\0', 0, G_OPTION_ARG_NONE, &args->ignore_x_real_ip,
     "Do not use X-Real-IP to determine the client address.", NULL},
    {"per-ip-connection-limit", '\0', 0, G_OPTION_ARG_INT,
     &args->per_ip_connection_limit,
     "Sets the maximum number of connections per ip. Use 0 for unlimited. "
     "Default is " G_STRINGIFY (DEFAULT_GSAD_PER_IP_CONNECTION_LIMIT) ".",
     "<number>"},
    {"unix-socket", '\0', 0, G_OPTION_ARG_FILENAME, &args->unix_socket_path,
     "Path to unix socket to listen on. Set to listen on a unix socket.",
     "<file>"},
    {"unix-socket-owner", '\0', 0, G_OPTION_ARG_STRING,
     &args->unix_socket_owner, "Owner of the unix socket", "<string>"},
    {"unix-socket-group", '\0', 0, G_OPTION_ARG_STRING,
     &args->unix_socket_group, "Group of the unix socket", "<string>"},
    {"unix-socket-mode", '\0', 0, G_OPTION_ARG_STRING, &args->unix_socket_mode,
     "File mode of the unix socket", "<string>"},
    {"munix-socket", '\0', 0, G_OPTION_ARG_FILENAME,
     &args->gsad_manager_unix_socket_path, "Path to Manager unix socket",
     "<file>"},
    {"http-cors", 0, 0, G_OPTION_ARG_STRING, &args->http_cors,
     "Set Cross-Origin Resource Sharing (CORS) allow origin http header ",
     "<cors>"},
    {"user-session-limit", '\0', 0, G_OPTION_ARG_INT,
     &args->gsad_user_session_limit,
     "Set maximum number of active sessions per user. 0 for unlimited. "
     "Defaults to 0.",
     "<max-sessions>"},
    {"log-config", '\0', 0, G_OPTION_ARG_FILENAME,
     &args->gsad_log_config_filename,
     "Path to logging configuration file. Defaults to " GSAD_CONFIG_DIR
     "gsad_log.conf",
     "<file>"},
    {"pid-file", '\0', 0, G_OPTION_ARG_FILENAME, &args->gsad_pid_filename,
     "Path to PID file. Defaults to " GSAD_CONFIG_DIR "gsad.pid", "<file>"},
    {NULL}};

  option_context =
    g_option_context_new ("- Greenbone Security Assistant Daemon");

  g_option_context_set_summary (option_context, COPYRIGHT);

  g_option_context_add_main_entries (option_context, option_entries, NULL);
  if (!g_option_context_parse (option_context, &argc, &argv, &error))
    {
      g_critical ("%s: %s\n\n", __func__, error->message);
      g_option_context_free (option_context);
      return 1;
    }
  g_option_context_free (option_context);
  return 0;
}

/**
 * @brief Create a new gsad_args_t structure with default values.
 *
 * This function allocates and initializes a new gsad_args_t structure with
 * default values for all fields. The caller is responsible for freeing the
 * allocated memory using gsad_args_free().
 *
 * @return A pointer to the newly created gsad_args_t structure.
 */
gsad_args_t *
gsad_args_new ()
{
  gsad_args_t *args = g_malloc0 (sizeof (gsad_args_t));
  args->client_watch_interval = DEFAULT_CLIENT_WATCH_INTERVAL;
  args->debug_tls = 0;
  args->dh_params_filename = NULL;
  args->do_chroot = FALSE;
  args->drop = NULL;
  args->foreground = FALSE;
  args->gnutls_priorities = NULL;
  args->gsad_address_string = NULL;
  args->gsad_log_config_filename =
    g_build_filename (GSAD_CONFIG_DIR, "gsad_log.conf", NULL);
  args->gsad_manager_address_string = NULL;
  args->gsad_manager_port = PORT_NOT_SET;
  args->gsad_manager_unix_socket_path = NULL;
  args->gsad_pid_filename =
    g_build_filename (GSAD_CONFIG_DIR, "gsad.pid", NULL);
  args->gsad_port = PORT_NOT_SET;
  args->gsad_redirect_port = PORT_NOT_SET;
  args->gsad_user_session_limit = 0;
  args->gsad_vendor_version_string = NULL;
  args->hsts_enabled = FALSE;
  args->hsts_max_age = DEFAULT_GSAD_HSTS_MAX_AGE;
  args->http_cors = NULL;
  args->http_csp = g_strdup (DEFAULT_GSAD_CONTENT_SECURITY_POLICY);
  args->http_frame_opts = g_strdup (DEFAULT_GSAD_X_FRAME_OPTIONS);
  args->http_only = FALSE;
  args->ignore_x_real_ip = FALSE;
  args->no_redirect = FALSE;
  args->per_ip_connection_limit = DEFAULT_PER_IP_CONNECTION_LIMIT;
  args->print_version = FALSE;
  args->secure_cookie = FALSE;
  args->ssl_certificate_filename = g_strdup (DEFAULT_GSAD_TLS_CERTIFICATE);
  args->ssl_private_key_filename = g_strdup (DEFAULT_GSAD_TLS_PRIVATE_KEY);
  args->timeout = DEFAULT_SESSION_TIMEOUT;
  args->unix_socket_group = NULL;
  args->unix_socket_mode = NULL;
  args->unix_socket_owner = NULL;
  args->unix_socket_path = NULL;
  args->verbose = FALSE;
  return args;
}

/**
 * @brief Free a gsad_args_t structure and its associated resources.
 *
 * @param[in] args The gsad_args_t structure to free.
 */
void
gsad_args_free (gsad_args_t *args)
{
  if (args)
    {
      g_free (args->dh_params_filename);
      g_free (args->drop);
      g_free (args->gnutls_priorities);
      if (args->gsad_address_string)
        g_strfreev (args->gsad_address_string);
      g_free (args->gsad_log_config_filename);
      g_free (args->gsad_manager_address_string);
      g_free (args->gsad_manager_unix_socket_path);
      g_free (args->gsad_pid_filename);
      g_free (args->gsad_vendor_version_string);
      g_free (args->http_cors);
      g_free (args->http_csp);
      g_free (args->http_frame_opts);
      g_free (args->ssl_certificate_filename);
      g_free (args->ssl_private_key_filename);
      g_free (args->unix_socket_group);
      g_free (args->unix_socket_mode);
      g_free (args->unix_socket_owner);
      g_free (args->unix_socket_path);

      g_free (args);
    }
}

/**
 * @brief Check if HTTP to HTTPS redirection should be enabled based on the
 * command-line arguments.
 *
 * @param[in] args The parsed command-line arguments.
 *
 * @return TRUE if HTTP to HTTPS redirection should be enabled, FALSE otherwise.
 */
gboolean
gsad_args_enable_redirect (const gsad_args_t *args)
{
  return !args->http_only && !args->no_redirect;
}

/**
 * @brief Check if listening on a unix socket should be enabled based on the
 * command-line arguments.
 *
 * @param[in] args The parsed command-line arguments.
 *
 * @return TRUE if listening on a unix socket should be enabled, FALSE
 * otherwise.
 */
gboolean
gsad_args_enable_unix_socket (const gsad_args_t *args)
{
  return args->unix_socket_path != NULL;
}

/**
 * @brief Check if HTTPS should be enabled based on the command-line arguments.
 *
 * @param[in] args The parsed command-line arguments.
 *
 * @return TRUE if HTTPS should be enabled, FALSE otherwise.
 */
gboolean
gsad_args_enable_https (const gsad_args_t *args)
{
  return !args->http_only;
}

/**
 * @brief Check if HTTP Strict-Transport-Security should be enabled based on the
 * command-line arguments.
 *
 * @param[in] args The parsed command-line arguments.
 *
 * @return TRUE if HTTP Strict-Transport-Security should be enabled, FALSE
 */
gboolean
gsad_args_enable_http_strict_transport_security (const gsad_args_t *args)
{
  return !args->http_only && args->hsts_enabled;
}

/**
 * @brief Check if the server should run in the foreground based on the
 * command-line arguments.
 *
 * @param[in] args The parsed command-line arguments.
 *
 * @return TRUE if the server should run in the foreground, FALSE otherwise.
 */
gboolean
gsad_args_enable_run_in_foreground (const gsad_args_t *args)
{
  return args->foreground;
}

/**
 * @brief Validate the session timeout value.
 *
 * @param[in] args The parsed command-line arguments.
 *
 * @return 0 if the session timeout is valid, non-zero otherwise.
 */
int
gsad_args_validate_session_timeout (const gsad_args_t *args)
{
  if (args->timeout < 0 || args->timeout > GSAD_MAX_SESSION_TIMEOUT)
    {
      g_critical ("%s: timeout needs to be between 0 and %d\n", __func__,
                  GSAD_MAX_SESSION_TIMEOUT);
      return 1;
    }
  return 0;
}

/**
 * @brief Validate a port number.
 *
 * @param[in] port The port number to validate.
 * @param[in] port_name The name of the port (for error messages).
 *
 * @return 0 if the port number is valid, non-zero otherwise.
 */
static int
gsad_validate_port (int port, const char *port_name)
{
  if (port != PORT_NOT_SET && (port < 1 || port > 65535))
    {
      g_critical ("%s: %s port %d needs to be between 1 and 65535\n", __func__,
                  port_name, port);
      return 1;
    }
  return 0;
}

/**
 * @brief Validate the gsad port number.
 *
 * @param[in] args The parsed command-line arguments.
 *
 * @return 0 if the gsad port number is valid, non-zero otherwise.
 */
int
gsad_args_validate_port (const gsad_args_t *args)
{
  return gsad_validate_port (args->gsad_port, "gsad");
}

/**
 * @brief Validate the manager port number.
 *
 * @param[in] args The parsed command-line arguments.
 *
 * @return 0 if the manager port number is valid, non-zero otherwise.
 */
int
gsad_args_validate_manager_port (const gsad_args_t *args)
{
  return gsad_validate_port (args->gsad_manager_port, "gvmd");
}

/**
 * @brief Validate the redirect port number.
 *
 * @param[in] args The parsed command-line arguments.
 *
 * @return 0 if the redirect port number is valid, non-zero otherwise.
 */
int
gsad_args_validate_redirect_port (const gsad_args_t *args)
{
  return gsad_validate_port (args->gsad_redirect_port, "redirect port");
}

/**
 * @brief Get the effective port number for gsad to listen on based on the
 * command-line arguments and defaults.
 *
 * @param[in] args The parsed command-line arguments.
 *
 * @return The effective port number for gsad to listen on.
 */
int
gsad_args_get_port (const gsad_args_t *args)
{
  if (args->gsad_port != PORT_NOT_SET)
    return args->gsad_port;
  else
    return args->http_only ? DEFAULT_GSAD_HTTP_PORT : DEFAULT_GSAD_HTTPS_PORT;
}

/**
 * @brief Get the effective redirect port number for HTTP to HTTPS redirection
 * based on the command-line arguments and defaults.
 *
 * @param[in] args The parsed command-line arguments.
 *
 * @return The effective redirect port number for HTTP to HTTPS redirection, or
 * PORT_NOT_SET if redirection is disabled.
 */
int
gsad_args_get_redirect_port (const gsad_args_t *args)
{
  if (gsad_args_enable_redirect (args) == FALSE)
    return PORT_NOT_SET;

  return args->gsad_redirect_port == PORT_NOT_SET ? DEFAULT_GSAD_HTTP_PORT
                                                  : args->gsad_redirect_port;
}

/**
 * @brief Get the effective max-age for the HTTP Strict-Transport-Security
 * header based on the command-line arguments and defaults.
 *
 * @param[in] args The parsed command-line arguments.
 *
 * @return The effective max-age for the HTTP Strict-Transport-Security header.
 */
int
gsad_args_get_http_strict_transport_security_max_age (const gsad_args_t *args)
{
  return args->hsts_max_age >= 0 ? args->hsts_max_age
                                 : DEFAULT_GSAD_HSTS_MAX_AGE;
}

/**
 * @brief Get the effective maximum number of connections per IP address based
 * on the command-line arguments and defaults.
 *
 * @param[in] args The parsed command-line arguments.
 *
 * @return The effective maximum number of connections per IP address.
 */
int
gsad_args_get_per_ip_connection_limit (const gsad_args_t *args)
{
  return args->per_ip_connection_limit >= 0 ? args->per_ip_connection_limit
                                            : DEFAULT_PER_IP_CONNECTION_LIMIT;
}

/**
 * @brief Get the effective client watch interval based on the command-line
 * arguments and defaults.
 *
 * @param[in] args The parsed command-line arguments.
 *
 * @return The effective client watch interval in seconds.
 */
int
gsad_args_get_client_watch_interval (const gsad_args_t *args)
{
  return args->client_watch_interval < 0 ? 0 : args->client_watch_interval;
}

/**
 * @brief Get the configuration filename from the command-line arguments.
 *
 * @param[in] args The parsed command-line arguments.
 *
 * @return The configuration filename specified in the command-line arguments,
 * or the default configuration filename if not specified. The returned string
 * is owned by the gsad args structure and should not be modified or freed
 * by the caller.
 */
const char *
gsad_args_get_log_config_filename (gsad_args_t *args)
{
  return args->gsad_log_config_filename;
}

/**
 * @brief Get the PID filename from the command-line arguments.
 *
 * @param[in] args The parsed command-line arguments.
 *
 * @return The PID filename specified in the command-line arguments, or the
 * default PID filename if not specified. The returned string is owned by the
 * gsad args structure and should not be modified or freed by the caller.
 */
const char *
gsad_args_get_pid_filename (gsad_args_t *args)
{
  return args->gsad_pid_filename;
}

/**
 * @brief Validate the TLS private key file.
 *
 * @param[in] args The parsed command-line arguments.
 *
 * @return OK if the TLS private key file is readable or not required,
 * ERROR_MISSING_FILENAME if the TLS private key file is not set but required,
 * ERROR_UNREADABLE_FILE if the TLS private key file is required but not
 * readable.
 */
gsad_args_file_validation_result_t
gsad_args_validate_tls_private_key (const gsad_args_t *args)
{
  if (args->http_only)
    {
      return OK;
    }

  if (args->ssl_private_key_filename == NULL
      || g_strcmp0 (args->ssl_private_key_filename, "") == 0)
    {
      g_debug ("%s: TLS private key file is not set\n", __func__);
      return ERROR_MISSING_FILENAME;
    }

  if (!gvm_file_is_readable (args->ssl_private_key_filename))
    {
      g_debug ("%s: Cannot access TLS private key file %s\n", __func__,
               args->ssl_private_key_filename);
      return ERROR_UNREADABLE_FILE;
    }

  return OK;
}

/**
 * @brief Validate the TLS certificate file.
 *
 * @param[in] args The parsed command-line arguments.
 *
 * @return OK if the TLS certificate file is readable or not required,
 * ERROR_MISSING_FILENAME if the TLS certificate file is not set but required,
 * ERROR_UNREADABLE_FILE if the TLS certificate file is required but not
 * readable.
 */
gsad_args_file_validation_result_t
gsad_args_validate_tls_certificate (const gsad_args_t *args)
{
  if (args->http_only)
    {
      return OK;
    }

  if (args->ssl_certificate_filename == NULL
      || g_strcmp0 (args->ssl_certificate_filename, "") == 0)
    {
      g_debug ("%s: TLS certificate file is not set\n", __func__);
      return ERROR_MISSING_FILENAME;
    }

  if (!gvm_file_is_readable (args->ssl_certificate_filename))
    {
      g_debug ("%s: Cannot access TLS certificate file %s\n", __func__,
               args->ssl_certificate_filename);
      return ERROR_UNREADABLE_FILE;
    }

  return OK;
}
