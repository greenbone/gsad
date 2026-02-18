/* Copyright (C) 2016-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_settings.c
 * @brief Global settings for GSA
 */

#include "gsad_settings.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "gsad settings"

static const gchar *
null_or_value (const gchar *value)
{
  return value ? value : "NULL";
}

struct gsad_settings
{
  gboolean ignore_http_x_real_ip;
  gboolean use_secure_cookie;
  gboolean api_only;
  gchar *log_config_filename;
  gchar *http_content_security_policy;
  gchar *http_coep;
  gchar *http_coop;
  gchar *http_corp;
  gchar *http_cors_origin;
  gchar *http_guest_chart_content_security_policy;
  gchar *http_guest_chart_x_frame_options;
  gchar *http_strict_transport_security;
  gchar *http_x_frame_options;
  gchar *pid_filename;
  gchar *vendor_version;
  int client_watch_interval;
  int per_ip_connection_limit;
  int session_timeout;
  int unix_socket;
  int user_session_limit;
};

static gsad_settings_t *settings = NULL;

/**
 * @brief Get the global settings instance.
 *
 * @return A pointer to the global gsad_settings_t instance. The caller should
 * free this instance.
 */
gsad_settings_t *
gsad_settings_get_global_settings ()
{
  if (!settings)
    settings = gsad_settings_new ();
  return settings;
}

/**
 * @brief Create a new gsad_settings_t instance with default values.
 *
 * @return A new gsad_settings_t instance. The caller is responsible for freeing
 * this instance using gsad_settings_free().
 */
gsad_settings_t *
gsad_settings_new ()
{
  gsad_settings_t *settings = g_malloc0 (sizeof (gsad_settings_t));
  settings->api_only = FALSE;
  settings->ignore_http_x_real_ip = FALSE;
  settings->use_secure_cookie = FALSE;
  settings->http_content_security_policy = NULL;
  settings->http_cors_origin = NULL;
  settings->http_guest_chart_content_security_policy = NULL;
  settings->http_guest_chart_x_frame_options = NULL;
  settings->http_strict_transport_security = NULL;
  settings->http_x_frame_options = NULL;
  settings->log_config_filename = NULL;
  settings->pid_filename = NULL;
  settings->vendor_version = NULL;
  settings->client_watch_interval = DEFAULT_CLIENT_WATCH_INTERVAL;
  settings->per_ip_connection_limit = DEFAULT_PER_IP_CONNECTION_LIMIT;
  settings->session_timeout = DEFAULT_SESSION_TIMEOUT;
  settings->unix_socket = 0;
  settings->user_session_limit = DEFAULT_USER_SESSION_LIMIT;
  return settings;
}

/**
 * @brief Free a gsad_settings_t instance and its associated resources.
 *
 * @param[in]  settings  The settings instance to free.
 */
void
gsad_settings_free (gsad_settings_t *settings)
{
  if (settings)
    {
      g_free (settings->log_config_filename);
      g_free (settings->http_content_security_policy);
      g_free (settings->http_cors_origin);
      g_free (settings->http_guest_chart_content_security_policy);
      g_free (settings->http_guest_chart_x_frame_options);
      g_free (settings->http_strict_transport_security);
      g_free (settings->http_x_frame_options);
      g_free (settings->pid_filename);
      g_free (settings->vendor_version);
      g_free (settings);
    }
}

/**
 * @brief Set the vendor version.
 *
 * @param[in]  settings  The settings instance to modify.
 * @param[in]  version   Vendor version.
 */
void
gsad_settings_set_vendor_version (gsad_settings_t *settings,
                                  const gchar *version)
{
  g_debug ("Setting vendor version to: %s", null_or_value (version));

  g_free (settings->vendor_version);

  settings->vendor_version = g_strdup (version);
}

/**
 * @brief Get the vendor version.
 *
 * @param[in]  settings  The settings instance to query.
 *
 * @return Vendor version. The value is owned by the settings and should not be
 * modified or freed by the caller.
 */
const gchar *
gsad_settings_get_vendor_version (const gsad_settings_t *settings)
{
  return settings->vendor_version ? settings->vendor_version : "";
}

/**
 * @brief Set the per-IP connection limit.
 *
 * @param[in]  settings  The settings instance to modify.
 * @param[in]  timeout   Session timeout in minutes.
 */
void
gsad_settings_set_session_timeout (gsad_settings_t *settings, int timeout)
{
  settings->session_timeout = timeout;
}

/**
 * @brief Get the session timeout.
 *
 * @param[in]  settings  The settings instance to query.
 *
 * @return Session timeout in minutes.
 */
int
gsad_settings_get_session_timeout (const gsad_settings_t *settings)
{
  return settings->session_timeout;
}

/**
 * @brief Enable or disable the use of secure cookies.
 *
 * secure cookies MUST only be enabled if gsad is served over HTTPS, otherwise
 * users may not be able to log in.
 *
 * @param[in]  settings  The settings instance to modify.
 * @param[in]  secure    Whether to use secure cookies.
 */
void
gsad_settings_set_use_secure_cookie (gsad_settings_t *settings, gboolean secure)
{
  settings->use_secure_cookie = secure;
}

/**
 * @brief Check if secure cookies are enabled.
 *
 * @param[in]  settings  The settings instance to query.
 *
 * @return TRUE if secure cookies are enabled, FALSE otherwise.
 */
gboolean
gsad_settings_enable_secure_cookie (const gsad_settings_t *settings)
{
  return settings->use_secure_cookie;
}

/**
 * @brief Set whether to ignore the X-Real-IP header.
 *
 * @param[in]  settings  The settings instance to modify.
 * @param[in]  ignore    Whether to ignore the X-Real-IP header.
 */
void
gsad_settings_set_ignore_http_x_real_ip (gsad_settings_t *settings,
                                         gboolean ignore)
{
  settings->ignore_http_x_real_ip = ignore;
}

/**
 * @brief Check if ignoring the X-Real-IP header is enabled.
 *
 * @param[in]  settings  The settings instance to query.
 *
 * @return TRUE if ignoring the X-Real-IP header is enabled, FALSE otherwise.
 */
gboolean
gsad_settings_is_http_x_real_ip_enabled (const gsad_settings_t *settings)
{
  return !settings->ignore_http_x_real_ip;
}

/**
 * @brief Set the Unix socket for using communication of unix domain sockets.
 *
 * @param[in]  settings  The settings instance to modify.
 * @param[in]  socket    Unix socket fd.
 */
void
gsad_settings_set_unix_socket (gsad_settings_t *settings, int socket)
{
  settings->unix_socket = socket;
}

/**
 * @brief Check if using a Unix socket communication is enabled.
 *
 * @param[in]  settings  The settings instance to query.
 *
 * @return TRUE if using a Unix socket communication is enabled, FALSE
 * otherwise.
 */
gboolean
gsad_settings_is_unix_socket_enabled (const gsad_settings_t *settings)
{
  return settings->unix_socket > 0;
}

/**
 * @brief Set the HTTP Content-Security-Policy header value.
 *
 * @param[in]  settings  The settings instance to modify.
 * @param[in]  policy    The value to set for the HTTP Content-Security-Policy
 * header, or NULL to disable the header.
 */
void
gsad_settings_set_http_content_security_policy (gsad_settings_t *settings,
                                                const gchar *policy)
{
  g_debug ("Setting HTTP Content-Security-Policy to: %s",
           null_or_value (policy));

  g_free (settings->http_content_security_policy);

  settings->http_content_security_policy = g_strdup (policy);
}

/**
 * @brief Get the HTTP Content-Security-Policy header value.
 *
 * @param[in]  settings  The settings instance to query.
 *
 * @return The value set for the HTTP Content-Security-Policy header, or NULL
 * if the header is disabled. The value is owned by the settings and should not
 * be modified or freed by the caller.
 */
const gchar *
gsad_settings_get_http_content_security_policy (const gsad_settings_t *settings)
{
  return settings->http_content_security_policy;
}

/**
 * @brief Set the HTTP Cross-Origin-Embedder-Policy header value.
 *
 * @param[in]  settings  The settings instance to modify.
 * @param[in]  policy    The value to set for the HTTP
 * Cross-Origin-Embedder-Policy header, or NULL to disable the header.
 */
void
gsad_settings_set_http_coep (gsad_settings_t *settings, const gchar *policy)
{
  g_debug ("Setting HTTP Cross-Origin-Embedder-Policy to: %s",
           null_or_value (policy));

  g_free (settings->http_coep);

  settings->http_coep = g_strdup (policy);
}

/**
 * @brief Get the HTTP Cross-Origin-Opener-Policy header value.
 *
 * @param[in]  settings  The settings instance to query.
 *
 * @return The value set for the HTTP Cross-Origin-Opener-Policy header,
 * or NULL if the header is disabled. The value is owned by the settings and
 * should not be modified or freed by the caller.
 */
const gchar *
gsad_settings_get_http_coep (const gsad_settings_t *settings)
{
  return settings->http_coep;
}

/**
 * @brief Set the HTTP Cross-Origin-Opener-Policy header value.
 *
 * @param[in]  settings  The settings instance to modify.
 * @param[in]  policy    The value to set for the HTTP
 * Cross-Origin-Opener-Policy header, or NULL to disable the header.
 */
void
gsad_settings_set_http_coop (gsad_settings_t *settings, const gchar *policy)
{
  g_debug ("Setting HTTP Cross-Origin-Opener-Policy to: %s",
           null_or_value (policy));

  g_free (settings->http_coop);

  settings->http_coop = g_strdup (policy);
}

/**
 * @brief Get the HTTP Cross-Origin-Opener-Policy header value.
 *
 * @param[in]  settings  The settings instance to query.
 *
 * @return The value set for the HTTP Cross-Origin-Opener-Policy header,
 * or NULL if the header is disabled. The value is owned by the settings and
 * should not be modified or freed by the caller.
 */
const gchar *
gsad_settings_get_http_coop (const gsad_settings_t *settings)
{
  return settings->http_coop;
}

/**
 * @brief Set the HTTP Cross-Origin-Resource-Policy header value.
 *
 * @param[in]  settings  The settings instance to modify.
 * @param[in]  policy    The value to set for the HTTP
 * Cross-Origin-Resource-Policy header, or NULL to disable the header.
 */
void
gsad_settings_set_http_corp (gsad_settings_t *settings, const gchar *policy)
{
  g_debug ("Setting HTTP Cross-Origin-Resource-Policy to: %s",
           null_or_value (policy));

  g_free (settings->http_corp);

  settings->http_corp = g_strdup (policy);
}

/**
 * @brief Get the HTTP Cross-Origin-Resource-Policy header value.
 *
 * @param[in]  settings  The settings instance to query.
 *
 * @return The value set for the HTTP Cross-Origin-Resource-Policy header,
 * or NULL if the header is disabled. The value is owned by the settings and
 * should not be modified or freed by the caller.
 */
const gchar *
gsad_settings_get_http_corp (const gsad_settings_t *settings)
{
  return settings->http_corp;
}

/**
 * @brief Set the HTTP X-Frame-Options header value.
 *
 * @param[in]  settings  The settings instance to modify.
 * @param[in]  options   The value to set for the HTTP X-Frame-Options header,
 * or NULL to disable the header.
 */
void
gsad_settings_set_http_x_frame_options (gsad_settings_t *settings,
                                        const gchar *options)
{
  g_debug ("Setting HTTP X-Frame-Options to: %s", null_or_value (options));

  g_free (settings->http_x_frame_options);

  settings->http_x_frame_options = g_strdup (options);
}

/**
 * @brief Get the HTTP X-Frame-Options header value.
 *
 * @param[in]  settings  The settings instance to query.
 *
 * @return The value set for the HTTP X-Frame-Options header, or NULL if the
 * header is disabled. The value is owned by the settings and should not be
 * modified or freed by the caller.
 */
const gchar *
gsad_settings_get_http_x_frame_options (const gsad_settings_t *settings)
{
  return settings->http_x_frame_options;
}

/**
 * @brief Set the HTTP CORS Origin header value.
 *
 * @param[in]  settings The settings instance to modify.
 * @param[in]  origin   The value to set for the HTTP CORS Origin header, or
 * NULL to disable the header.
 */
void
gsad_settings_set_http_cors_origin (gsad_settings_t *settings,
                                    const gchar *origin)
{
  g_debug ("Setting HTTP CORS origin to: %s", null_or_value (origin));

  g_free (settings->http_cors_origin);

  settings->http_cors_origin = g_strdup (origin);
}

/**
 * @brief Get the HTTP CORS Origin header value.
 *
 * @param[in]  settings  The settings instance to query.
 *
 * @return The value set for the HTTP CORS Origin header, or NULL if the
 * header is disabled. The value is owned by the settings and should not be
 * modified or freed by the caller.
 */
const gchar *
gsad_settings_get_http_cors_origin (const gsad_settings_t *settings)
{
  return settings->http_cors_origin;
}

/**
 * @brief Set the HTTP X-Frame-Options header value for the guest charts.
 *
 * @param[in]  settings  The settings instance to modify.
 * @param[in]  options   The value to set for the HTTP X-Frame-Options header
 * for the guest charts, or NULL to disable the header.
 */
void
gsad_settings_set_http_guest_chart_x_frame_options (gsad_settings_t *settings,
                                                    const gchar *options)
{
  g_debug ("Setting HTTP Guest Chart X-Frame-Options to: %s",
           null_or_value (options));

  g_free (settings->http_guest_chart_x_frame_options);

  settings->http_guest_chart_x_frame_options = g_strdup (options);
}

/**
 * @brief Get the HTTP X-Frame-Options header value for the guest charts.
 *
 * @param[in]  settings  The settings instance to query.
 *
 * @return The value set for the HTTP X-Frame-Options header for the guest
 * charts, or NULL if the header is disabled. The value is owned by the settings
 * and should not be modified or freed by the caller.
 */
const gchar *
gsad_settings_get_http_guest_chart_x_frame_options (
  const gsad_settings_t *settings)
{
  return settings->http_guest_chart_x_frame_options;
}

/**
 * @brief Set the HTTP Content-Security-Policy header value for the guest
 * charts.
 *
 * @param[in]  settings  The settings instance to modify.
 * @param[in]  policy    The value to set for the HTTP Content-Security-Policy
 * header for the guest charts, or NULL to disable the header.
 */
void
gsad_settings_set_http_guest_chart_content_security_policy (
  gsad_settings_t *settings, const gchar *policy)
{
  g_debug ("Setting HTTP Guest Chart Content-Security-Policy to: %s",
           null_or_value (policy));

  g_free (settings->http_guest_chart_content_security_policy);

  settings->http_guest_chart_content_security_policy = g_strdup (policy);
}

/**
 * @brief Get the HTTP Content-Security-Policy header value for the guest
 * charts.
 *
 * @param[in]  settings  The settings instance to query.
 *
 * @return The value set for the HTTP Content-Security-Policy header for the
 * guest charts, or NULL if the header is disabled. The value is owned by the
 * settings and should not be modified or freed by the caller.
 */
const gchar *
gsad_settings_get_http_guest_chart_content_security_policy (
  const gsad_settings_t *settings)
{
  return settings->http_guest_chart_content_security_policy;
}

/**
 * @brief Set the HTTP Strict-Transport-Security header value.
 *
 * @param[in]  settings  The settings instance to modify.
 * @param[in]  policy    The value to set for the HTTP Strict-Transport-Security
 * header, or NULL to disable the header.
 */
void
gsad_settings_set_http_strict_transport_security (gsad_settings_t *settings,
                                                  const gchar *policy)
{
  g_debug ("Setting HTTP Strict-Transport-Security to: %s",
           null_or_value (policy));

  g_free (settings->http_strict_transport_security);

  settings->http_strict_transport_security = g_strdup (policy);
}

/**
 * @brief Get the HTTP Strict-Transport-Security header value.
 *
 * @param[in]  settings  The settings instance to query.
 *
 * @return The value set for the HTTP Strict-Transport-Security header, or NULL
 * if the header is disabled. The value is owned by the settings and should not
 * be modified or freed by the caller.
 */
const gchar *
gsad_settings_get_http_strict_transport_security (
  const gsad_settings_t *settings)
{
  return settings->http_strict_transport_security;
}

/**
 * @brief Set the connection limit per IP address.
 *
 * @param[in]  settings  The settings instance to modify.
 * @param[in]  limit     The connection limit per IP address. A value of 0 means
 * no limit.
 */
void
gsad_settings_set_per_ip_connection_limit (gsad_settings_t *settings, int limit)
{
  if (limit >= 0)
    {
      g_debug ("Setting per-IP connection limit to: %d", limit);
      settings->per_ip_connection_limit = limit;
    }
  else
    {
      g_debug ("Setting per-IP connection limit to unlimited");
      settings->per_ip_connection_limit = 0;
    }
}

/**
 * @brief Get the connection limit per IP address.
 *
 * @return The connection limit per IP address. A value of 0 means no limit.
 */
int
gsad_settings_get_per_ip_connection_limit (const gsad_settings_t *settings)
{
  return settings->per_ip_connection_limit;
}

/**
 * @brief Set the user session limit.
 *
 * @param[in]  settings  The settings instance to modify.
 * @param[in]  new_limit The user session limit. A value of 0 or less means no
 * limit.
 */
void
gsad_settings_set_user_session_limit (gsad_settings_t *settings, int new_limit)
{
  if (new_limit >= 0)
    {
      g_debug ("Setting user session limit to: %d", new_limit);
      settings->user_session_limit = new_limit;
    }
  else
    {
      g_debug ("Setting user session limit to unlimited");
      settings->user_session_limit = 0;
    }
}

/**
 * @brief Get the user session limit.
 *
 * @return The user session limit. A value of 0 means no limit.
 */
int
gsad_settings_get_user_session_limit (const gsad_settings_t *settings)
{
  return settings->user_session_limit;
}

/**
 * @brief Set the client watch interval.
 *
 * @param[in]  settings  The settings instance to modify.
 * @param[in]  interval  The client watch interval in seconds. A value of 0
 * or less means disabled.
 */
void
gsad_settings_set_client_watch_interval (gsad_settings_t *settings,
                                         int interval)
{
  if (interval > 0)
    {
      g_debug ("Setting client watch interval to: %d", interval);
      settings->client_watch_interval = interval;
    }
  else
    {
      g_debug ("Setting client watch interval to disabled");
      settings->client_watch_interval = 0;
    }
}

/**
 * @brief Get the client watch interval.
 *
 * @return The client watch interval in seconds. A value of 0 means disabled.
 */
int
gsad_settings_get_client_watch_interval (const gsad_settings_t *settings)
{
  return settings->client_watch_interval;
}

/**
 * @brief Set the configuration filename.
 *
 * @param[in]  settings        The settings instance to modify.
 * @param[in]  config_filename The configuration filename to set. The caller is
 * responsible for freeing the passed string if it is dynamically allocated. The
 * settings will copy the string and free it when the settings instance is
 * freed.
 */
void
gsad_settings_set_log_config_filename (gsad_settings_t *settings,
                                       const gchar *log_config_filename)
{
  g_debug ("Setting config filename to: %s",
           null_or_value (log_config_filename));

  g_free (settings->log_config_filename);

  settings->log_config_filename = g_strdup (log_config_filename);
}

/**
 * @brief Get the configuration filename.
 *
 * @param[in]  settings  The settings instance to query.
 *
 * @return The configuration filename. The value is owned by the settings and
 * should not be modified or freed by the caller.
 */
const gchar *
gsad_settings_get_log_config_filename (const gsad_settings_t *settings)
{
  return settings->log_config_filename;
}

/**
 * @brief Set the PID filename.
 *
 * @param[in]  settings      The settings instance to modify.
 * @param[in]  pid_filename  The PID filename to set. The caller is responsible
 * for freeing the passed string if it is dynamically allocated. The settings
 * will copy the string and free it when the settings instance is freed.
 */
void
gsad_settings_set_pid_filename (gsad_settings_t *settings,
                                const gchar *pid_filename)
{
  g_debug ("Setting PID filename to: %s", null_or_value (pid_filename));

  g_free (settings->pid_filename);

  settings->pid_filename = g_strdup (pid_filename);
}

/**
 * @brief Get the PID filename.
 *
 * @param[in]  settings  The settings instance to query.
 *
 * @return The PID filename. The value is owned by the settings and should not
 * be modified or freed by the caller.
 */
const gchar *
gsad_settings_get_pid_filename (const gsad_settings_t *settings)
{
  return settings->pid_filename;
}

/**
 * @brief Set whether to run in API-only mode.
 *
 * @param[in]  settings  The settings instance to modify.
 * @param[in]  api_only  Whether to run in API-only mode, disabling serving of
 * static content.
 */
void
gsad_settings_set_api_only (gsad_settings_t *settings, gboolean api_only)
{
  settings->api_only = api_only;
}

/**
 * @brief Check if API-only mode is enabled.
 *
 * API-only mode is enabled if the --api-only flag is set. It disables
 * serving of static content and only serves the API.
 *
 * @param[in]  settings  The settings instance to query.
 *
 * @return TRUE if API-only mode is enabled, FALSE otherwise.
 */
gboolean
gsad_settings_is_api_only_enabled (const gsad_settings_t *settings)
{
  return settings->api_only;
}
