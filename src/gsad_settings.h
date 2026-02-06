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

gboolean
gsad_settings_enable_unix_socket (const gsad_settings_t *);

gboolean
gsad_settings_enable_ignore_http_x_real_ip (const gsad_settings_t *);

#endif /* _GSAD_SETTINGS_H */
