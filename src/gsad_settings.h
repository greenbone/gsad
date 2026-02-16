/* Copyright (C) 2016-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_settings.h
 * @brief Global settings for GSA
 */

#ifndef _GSAD_SETTINGS_H
#define _GSAD_SETTINGS_H

#include <glib.h>

/**
 * @brief Default value for client_watch_interval.  A value of 0 means disabled.
 */
#define DEFAULT_CLIENT_WATCH_INTERVAL 0

/**
 * @brief Default number of minutes between activity in a session. A value of 0
 * means no timeout.
 */
#define DEFAULT_SESSION_TIMEOUT 15

/**
 * @brief Default value for the maximum number of connection per IP address. A
 * value of 0 means no limit.
 */
#define DEFAULT_PER_IP_CONNECTION_LIMIT 30

/**
 * @brief Default limit for number of concurrent user sessions. A value of 0
 * means no limit.
 */
#define DEFAULT_USER_SESSION_LIMIT 0

typedef struct gsad_settings gsad_settings_t;

gsad_settings_t *
gsad_settings_get_global_settings ();

gsad_settings_t *
gsad_settings_new ();

void
gsad_settings_free (gsad_settings_t *settings);

void
gsad_settings_set_vendor_version (gsad_settings_t *, const gchar *);

const gchar *
gsad_settings_get_vendor_version (const gsad_settings_t *);

void
gsad_settings_set_session_timeout (gsad_settings_t *, int);

int
gsad_settings_get_session_timeout (const gsad_settings_t *);

void
gsad_settings_set_use_secure_cookie (gsad_settings_t *, gboolean);

gboolean
gsad_settings_enable_secure_cookie (const gsad_settings_t *);

void
gsad_settings_set_http_content_security_policy (gsad_settings_t *,
                                                const gchar *);

const gchar *
gsad_settings_get_http_content_security_policy (const gsad_settings_t *);

void
gsad_settings_set_http_x_frame_options (gsad_settings_t *, const gchar *);

const gchar *
gsad_settings_get_http_x_frame_options (const gsad_settings_t *);

void
gsad_settings_set_http_cors_origin (gsad_settings_t *, const gchar *);

const gchar *
gsad_settings_get_http_cors_origin (const gsad_settings_t *);

void
gsad_settings_set_http_guest_chart_x_frame_options (gsad_settings_t *,
                                                    const gchar *);

const gchar *
gsad_settings_get_http_guest_chart_x_frame_options (const gsad_settings_t *);

void
gsad_settings_set_http_guest_chart_content_security_policy (gsad_settings_t *,
                                                            const gchar *);

const gchar *
gsad_settings_get_http_guest_chart_content_security_policy (
  const gsad_settings_t *);

void
gsad_settings_set_http_strict_transport_security (gsad_settings_t *,
                                                  const gchar *);

const gchar *
gsad_settings_get_http_strict_transport_security (const gsad_settings_t *);

void
gsad_settings_set_ignore_http_x_real_ip (gsad_settings_t *, gboolean);

gboolean
gsad_settings_get_ignore_http_x_real_ip (const gsad_settings_t *);

void
gsad_settings_set_per_ip_connection_limit (gsad_settings_t *, int);

int
gsad_settings_get_per_ip_connection_limit (const gsad_settings_t *);

void
gsad_settings_set_unix_socket (gsad_settings_t *, int);

void
gsad_settings_set_user_session_limit (gsad_settings_t *, int);

int
gsad_settings_get_user_session_limit (const gsad_settings_t *);

void
gsad_settings_set_client_watch_interval (gsad_settings_t *, int);

int
gsad_settings_get_client_watch_interval (const gsad_settings_t *);

gboolean
gsad_settings_is_unix_socket_enabled (const gsad_settings_t *);

gboolean
gsad_settings_is_http_x_real_ip_enabled (const gsad_settings_t *);

void
gsad_settings_set_log_config_filename (gsad_settings_t *, const gchar *);

const gchar *
gsad_settings_get_log_config_filename (const gsad_settings_t *);

void
gsad_settings_set_pid_filename (gsad_settings_t *, const gchar *);

const gchar *
gsad_settings_get_pid_filename (const gsad_settings_t *);

void
gsad_settings_set_api_only (gsad_settings_t *, gboolean);

gboolean
gsad_settings_is_api_only_enabled (const gsad_settings_t *);

#endif /* _GSAD_SETTINGS_H */
