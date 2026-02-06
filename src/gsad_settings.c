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

struct gsad_settings
{
  gboolean ignore_http_x_real_ip;
  gboolean use_secure_cookie;
  gchar *http_content_security_policy;
  gchar *http_cors_origin;
  gchar *http_guest_chart_content_security_policy;
  gchar *http_guest_chart_x_frame_options;
  gchar *http_strict_transport_security;
  gchar *http_x_frame_options;
  gchar *vendor_version;
  int per_ip_connection_limit;
  int session_timeout;
  int unix_socket;
  int user_session_limit;
};

gsad_settings_t settings = {
  .http_content_security_policy = NULL,
  .http_cors_origin = NULL,
  .http_guest_chart_content_security_policy = NULL,
  .http_guest_chart_x_frame_options = NULL,
  .http_strict_transport_security = NULL,
  .http_x_frame_options = NULL,
  .ignore_http_x_real_ip = FALSE,
  .per_ip_connection_limit = 0,
  .session_timeout = 0,
  .unix_socket = 0,
  .use_secure_cookie = FALSE,
  .user_session_limit = 0,
  .vendor_version = NULL,
};

gsad_settings_t *
gsad_settings_get_global_settings ()
{
  return &settings;
}

/**
 * @brief Set the vendor version.
 *
 * @param[in]  version  Vendor version.
 */
void
gsad_settings_set_vendor_version (gsad_settings_t *settings,
                                  const gchar *version)
{
  g_free (settings->vendor_version);
  settings->vendor_version = g_strdup (version);
}

/**
 * @brief Get the vendor version.
 *
 * @return Vendor version.
 */
const gchar *
gsad_settings_get_vendor_version (const gsad_settings_t *settings)
{
  return settings->vendor_version ? settings->vendor_version : "";
}

void
gsad_settings_set_session_timeout (gsad_settings_t *settings, int timeout)
{
  settings->session_timeout = timeout;
}

int
gsad_settings_get_session_timeout (const gsad_settings_t *settings)
{
  return settings->session_timeout;
}

void
gsad_settings_set_use_secure_cookie (gsad_settings_t *settings, gboolean secure)
{
  settings->use_secure_cookie = secure;
}

gboolean
gsad_settings_enable_secure_cookie (const gsad_settings_t *settings)
{
  return settings->use_secure_cookie;
}

static const gchar *
null_or_value (const gchar *value)
{
  return value ? value : "NULL";
}

void
gsad_settings_set_http_content_security_policy (gsad_settings_t *settings,
                                                const gchar *policy)
{
  g_debug ("Setting HTTP Content-Security-Policy to: %s",
           null_or_value (policy));
  settings->http_content_security_policy = g_strdup (policy);
}

const gchar *
gsad_settings_get_http_content_security_policy (const gsad_settings_t *settings)
{
  return settings->http_content_security_policy;
}

void
gsad_settings_set_http_x_frame_options (gsad_settings_t *settings,
                                        const gchar *options)
{
  g_debug ("Setting HTTP X-Frame-Options to: %s", null_or_value (options));
  settings->http_x_frame_options = g_strdup (options);
}

const gchar *
gsad_settings_get_http_x_frame_options (const gsad_settings_t *settings)
{
  return settings->http_x_frame_options;
}

void
gsad_settings_set_http_cors_origin (gsad_settings_t *settings,
                                    const gchar *origin)
{
  g_debug ("Setting HTTP CORS origin to: %s", null_or_value (origin));
  settings->http_cors_origin = g_strdup (origin);
}

const gchar *
gsad_settings_get_http_cors_origin (const gsad_settings_t *settings)
{
  return settings->http_cors_origin;
}

void
gsad_settings_set_http_guest_chart_x_frame_options (gsad_settings_t *settings,
                                                    const gchar *options)
{
  g_debug ("Setting HTTP Guest Chart X-Frame-Options to: %s",
           null_or_value (options));
  settings->http_guest_chart_x_frame_options = g_strdup (options);
}

const gchar *
gsad_settings_get_http_guest_chart_x_frame_options (
  const gsad_settings_t *settings)
{
  return settings->http_guest_chart_x_frame_options;
}

void
gsad_settings_set_http_guest_chart_content_security_policy (
  gsad_settings_t *settings, const gchar *policy)
{
  g_debug ("Setting HTTP Guest Chart Content-Security-Policy to: %s",
           null_or_value (policy));
  settings->http_guest_chart_content_security_policy = g_strdup (policy);
}

const gchar *
gsad_settings_get_http_guest_chart_content_security_policy (
  const gsad_settings_t *settings)
{
  return settings->http_guest_chart_content_security_policy;
}

void
gsad_settings_set_http_strict_transport_security (gsad_settings_t *settings,
                                                  const gchar *policy)
{
  g_debug ("Setting HTTP Strict-Transport-Security to: %s",
           null_or_value (policy));
  settings->http_strict_transport_security = g_strdup (policy);
}

const gchar *
gsad_settings_get_http_strict_transport_security (
  const gsad_settings_t *settings)
{
  return settings->http_strict_transport_security;
}

void
gsad_settings_set_ignore_http_x_real_ip (gsad_settings_t *settings,
                                         gboolean ignore)
{
  settings->ignore_http_x_real_ip = ignore;
}

gboolean
gsad_settings_enable_ignore_http_x_real_ip (const gsad_settings_t *settings)
{
  return settings->ignore_http_x_real_ip;
}

void
gsad_settings_set_per_ip_connection_limit (gsad_settings_t *settings, int limit)
{
  if (limit >= 0)
    settings->per_ip_connection_limit = limit;
  else
    settings->per_ip_connection_limit = 0;
}

int
gsad_settings_get_per_ip_connection_limit (const gsad_settings_t *settings)
{
  return settings->per_ip_connection_limit;
}

void
gsad_settings_set_unix_socket (gsad_settings_t *settings, int socket)
{
  settings->unix_socket = socket;
}

gboolean
gsad_settings_enable_unix_socket (const gsad_settings_t *settings)
{
  return settings->unix_socket > 0;
}

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

int
gsad_settings_get_user_session_limit (const gsad_settings_t *settings)
{
  return settings->user_session_limit;
}
