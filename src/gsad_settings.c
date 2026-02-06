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
  gchar *guest_password;
  gchar *guest_username;
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
  .guest_password = NULL,
  .guest_username = NULL,
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

/**
 * @brief Set the vendor version.
 *
 * @param[in]  version  Vendor version.
 */
void
vendor_version_set (const gchar *version)
{
  g_free (settings.vendor_version);
  settings.vendor_version = g_strdup (version);
}

/**
 * @brief Get the vendor version.
 *
 * @return Vendor version.
 */
const gchar *
vendor_version_get ()
{
  return settings.vendor_version ? settings.vendor_version : "";
}

void
set_guest_username (const gchar *username)
{
  settings.guest_username = g_strdup (username);
}

const gchar *
get_guest_username ()
{
  return settings.guest_username;
}

void
set_guest_password (const gchar *password)
{
  settings.guest_password = g_strdup (password);
}

const gchar *
get_guest_password ()
{
  return settings.guest_password;
}

void
set_session_timeout (int timeout)
{
  settings.session_timeout = timeout;
}

int
get_session_timeout ()
{
  return settings.session_timeout;
}

void
set_use_secure_cookie (int secure)
{
  settings.use_secure_cookie = secure;
}

gboolean
is_use_secure_cookie ()
{
  return settings.use_secure_cookie;
}

const gchar *
null_or_value (const gchar *value)
{
  return value ? value : "NULL";
}

void
set_http_content_security_policy (const gchar *policy)
{
  g_debug ("Setting HTTP Content-Security-Policy to: %s",
           null_or_value (policy));
  settings.http_content_security_policy = g_strdup (policy);
}

const gchar *
get_http_content_security_policy ()
{
  return settings.http_content_security_policy;
}

void
set_http_x_frame_options (const gchar *options)
{
  g_debug ("Setting HTTP X-Frame-Options to: %s", null_or_value (options));
  settings.http_x_frame_options = g_strdup (options);
}

const gchar *
get_http_x_frame_options ()
{
  return settings.http_x_frame_options;
}

void
set_http_cors_origin (const gchar *origin)
{
  g_debug ("Setting HTTP CORS origin to: %s", null_or_value (origin));
  settings.http_cors_origin = g_strdup (origin);
}

const gchar *
get_http_cors_origin ()
{
  return settings.http_cors_origin;
}

void
set_http_guest_chart_x_frame_options (const gchar *options)
{
  g_debug ("Setting HTTP Guest Chart X-Frame-Options to: %s",
           null_or_value (options));
  settings.http_guest_chart_x_frame_options = g_strdup (options);
}

const gchar *
get_http_guest_chart_x_frame_options ()
{
  return settings.http_guest_chart_x_frame_options;
}

void
set_http_guest_chart_content_security_policy (const gchar *policy)
{
  g_debug ("Setting HTTP Guest Chart Content-Security-Policy to: %s",
           null_or_value (policy));
  settings.http_guest_chart_content_security_policy = g_strdup (policy);
}

const gchar *
get_http_guest_chart_content_security_policy ()
{
  return settings.http_guest_chart_content_security_policy;
}

void
set_http_strict_transport_security (const gchar *policy)
{
  g_debug ("Setting HTTP Strict-Transport-Security to: %s",
           null_or_value (policy));
  settings.http_strict_transport_security = g_strdup (policy);
}

const gchar *
get_http_strict_transport_security ()
{
  return settings.http_strict_transport_security;
}

void
set_ignore_http_x_real_ip (gboolean ignore)
{
  settings.ignore_http_x_real_ip = ignore;
}

gboolean
is_ignore_http_x_real_ip ()
{
  return settings.ignore_http_x_real_ip;
}

void
set_per_ip_connection_limit (int limit)
{
  if (limit >= 0)
    settings.per_ip_connection_limit = limit;
  else
    settings.per_ip_connection_limit = 0;
}

int
get_per_ip_connection_limit ()
{
  return settings.per_ip_connection_limit;
}

void
set_unix_socket (int socket)
{
  settings.unix_socket = socket;
}

gboolean
is_unix_socket ()
{
  return settings.unix_socket > 0;
}

void
set_user_session_limit (int new_limit)
{
  if (new_limit >= 0)
    {
      g_debug ("Setting user session limit to: %d", new_limit);
      settings.user_session_limit = new_limit;
    }
  else
    {
      g_debug ("Setting user session limit to unlimited");
      settings.user_session_limit = 0;
    }
}

int
get_user_session_limit ()
{
  return settings.user_session_limit;
}
