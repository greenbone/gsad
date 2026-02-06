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

void
gsad_settings_set_vendor_version (const gchar *);

const gchar *
gsad_settings_get_vendor_version ();


void
gsad_settings_set_session_timeout (int timeout);

int
gsad_settings_get_session_timeout ();

void
gsad_settings_set_use_secure_cookie (int use);

gboolean
gsad_settings_enable_secure_cookie ();

void
gsad_settings_set_http_content_security_policy (const gchar *policy);

const gchar *
gsad_settings_get_http_content_security_policy ();

void
gsad_settings_set_http_x_frame_options (const gchar *options);

const gchar *
gsad_settings_get_http_x_frame_options ();

void
gsad_settings_set_http_cors_origin (const gchar *origin);

const gchar *
gsad_settings_get_http_cors_origin ();

void
gsad_settings_set_http_guest_chart_x_frame_options (const gchar *options);

const gchar *
gsad_settings_get_http_guest_chart_x_frame_options ();

void
gsad_settings_set_http_guest_chart_content_security_policy (
  const gchar *policy);

const gchar *
gsad_settings_get_http_guest_chart_content_security_policy ();

void
gsad_settings_set_http_strict_transport_security (const gchar *policy);

const gchar *
gsad_settings_get_http_strict_transport_security ();

void
gsad_settings_set_ignore_http_x_real_ip (gboolean ignore);

gboolean
gsad_settings_get_ignore_http_x_real_ip ();

void
gsad_settings_set_per_ip_connection_limit (int limit);

int
gsad_settings_get_per_ip_connection_limit ();

void
gsad_settings_set_unix_socket (int socket);

gboolean
gsad_setings_enable_unix_socket ();

gboolean
gsad_settings_enable_ignore_http_x_real_ip ();

void
gsad_settings_set_user_session_limit (int);

int
gsad_settings_get_user_session_limit ();

#endif /* _GSAD_SETTINGS_H */
