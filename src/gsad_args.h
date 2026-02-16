/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_ARGS_H
#define _GSAD_ARGS_H

#include <glib.h>

/**
 * @brief Value indicating that no port has been set.
 */
#define PORT_NOT_SET -1

/**
 * @brief Upper limit of minutes for a session timeout. Currently 4 weeks.
 */
#define GSAD_MAX_SESSION_TIMEOUT 40320

/**
 * @brief Default value for HTTP header "X-Frame-Options"
 */
#define DEFAULT_GSAD_X_FRAME_OPTIONS "SAMEORIGIN"

/**
 * @brief Default "max-age" for HTTP header "Strict-Transport-Security"
 */
#define DEFAULT_GSAD_HSTS_MAX_AGE 31536000

/**
 * @brief Default value for HTTP header "Content-Security-Policy"
 */
#define DEFAULT_GSAD_CONTENT_SECURITY_POLICY \
  "default-src 'none'; "                     \
  "object-src 'none'; "                      \
  "base-uri 'none'; "                        \
  "connect-src 'self'; "                     \
  "script-src 'self'; "                      \
  "script-src-elem 'self' 'unsafe-inline';"  \
  "frame-ancestors 'none'; "                 \
  "form-action 'self'; "                     \
  "style-src-elem 'self' 'unsafe-inline'; "  \
  "style-src 'self' 'unsafe-inline'; "       \
  "font-src 'self';"                         \
  "img-src 'self' blob: data:;"

/**
 * @brief Fallback GSAD port for HTTPS.
 */
#define DEFAULT_GSAD_HTTPS_PORT 443

/**
 * @brief Fallback GSAD port for HTTP.
 */
#define DEFAULT_GSAD_HTTP_PORT 9392

/**
 * @brief Defines the default TLS private key used by gsad.
 *
 * Defines the default TLS private key used by gsad.
 * This macro is set to the value of GVM_SERVER_KEY, which specifies
 * the path or identifier for the server's TLS private key.
 */
#define DEFAULT_GSAD_TLS_PRIVATE_KEY GVM_SERVER_KEY

/**
 * @brief Defines the default TLS certificate used by gsad.
 *
 * Defines the default TLS certificate used by gsad.
 * This macro is set to the value of GVM_SERVER_CERTIFICATE, which specifies
 * the path or identifier for the server's TLS certificate.
 */
#define DEFAULT_GSAD_TLS_CERTIFICATE GVM_SERVER_CERTIFICATE

/**
 * @brief Default pid file path for gsad.
 */
#define DEFAULT_GSAD_PID_FILE GSAD_PID_PATH

#define DEFAULT_GSAD_STATIC_CONTENT_DIRECTORY GSAD_STATIC_CONTENT_DIR

/**
 * @brief Structure to hold the parsed command-line arguments for gsad.
 *
 * This structure contains fields corresponding to the various command-line
 * options that can be passed to gsad. It is used to store the parsed values
 * after processing the command-line arguments.
 */
typedef struct gsad_args gsad_args_t;

typedef enum
{
  OK = 0,
  ERROR_MISSING_FILENAME = 1,
  ERROR_UNREADABLE_FILE = 2,
} gsad_args_file_validation_result_t;

gsad_args_t *
gsad_args_new ();

void
gsad_args_free (gsad_args_t *);

int
gsad_args_parse (int, char **, gsad_args_t *);

gboolean
gsad_args_is_redirect_enabled (const gsad_args_t *);

gboolean
gsad_args_is_unix_socket_enabled (const gsad_args_t *);

gboolean
gsad_args_is_https_enabled (const gsad_args_t *);

gboolean
gsad_args_is_http_strict_transport_security_enabled (const gsad_args_t *);

gboolean
gsad_args_is_run_in_foreground_enabled (const gsad_args_t *);

gboolean
gsad_args_is_print_version_enabled (const gsad_args_t *);

gboolean
gsad_args_is_debug_tls_enabled (const gsad_args_t *);

gboolean
gsad_args_is_ignore_x_real_ip_enabled (const gsad_args_t *);

gboolean
gsad_args_is_secure_cookie_enabled (const gsad_args_t *);

gboolean
gsad_args_is_chroot_enabled (const gsad_args_t *);

gboolean
gsad_args_is_api_only_enabled (const gsad_args_t *);

int
gsad_args_validate_session_timeout (const gsad_args_t *);

int
gsad_args_validate_port (const gsad_args_t *);

int
gsad_args_validate_manager_port (const gsad_args_t *);

int
gsad_args_validate_redirect_port (const gsad_args_t *);

gsad_args_file_validation_result_t
gsad_args_validate_tls_private_key (const gsad_args_t *);

gsad_args_file_validation_result_t
gsad_args_validate_tls_certificate (const gsad_args_t *);

int
gsad_args_get_port (const gsad_args_t *);

int
gsad_args_get_redirect_port (const gsad_args_t *);

int
gsad_args_get_http_strict_transport_security_max_age (const gsad_args_t *);

int
gsad_args_get_per_ip_connection_limit (const gsad_args_t *);

int
gsad_args_get_client_watch_interval (const gsad_args_t *);

int
gsad_args_get_session_timeout (const gsad_args_t *);

int
gsad_args_get_manager_port (const gsad_args_t *);

int
gsad_args_get_user_session_limit (const gsad_args_t *);

int
gsad_args_get_tls_debug_level (const gsad_args_t *);

const gchar *
gsad_args_get_log_config_filename (const gsad_args_t *);

const gchar *
gsad_args_get_pid_filename (const gsad_args_t *);

const gchar *
gsad_args_get_static_content_directory (const gsad_args_t *);

const gchar *
gsad_args_get_tls_private_key_filename (const gsad_args_t *);

const gchar *
gsad_args_get_tls_certificate_filename (const gsad_args_t *);

const gchar *
gsad_args_get_http_x_frame_options (const gsad_args_t *);

const gchar *
gsad_args_get_http_content_security_policy (const gsad_args_t *);

const gchar *
gsad_args_get_http_cors_origin (const gsad_args_t *);

const gchar *
gsad_args_get_vendor_version (const gsad_args_t *);

gchar **
gsad_args_get_listen_addresses (const gsad_args_t *);

const gchar *
gsad_args_get_manager_unix_socket_path (const gsad_args_t *);

const gchar *
gsad_args_get_manager_address (const gsad_args_t *);

const gchar *
gsad_args_get_unix_socket_path (const gsad_args_t *);

const gchar *
gsad_args_get_unix_socket_group (const gsad_args_t *);

const gchar *
gsad_args_get_unix_socket_owner (const gsad_args_t *);

const gchar *
gsad_args_get_unix_socket_mode (const gsad_args_t *);

const gchar *
gsad_args_get_dh_params_filename (const gsad_args_t *);

const gchar *
gsad_args_get_gnutls_priorities (const gsad_args_t *);

const gchar *
gsad_args_get_drop_privileges (const gsad_args_t *);

#endif /* _GSAD_ARGS_H */
