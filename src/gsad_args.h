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
#define DEFAULT_GSAD_PID_FILE GSAD_CONFIG_DIR "gsad.pid"

#define DEFAULT_GSAD_STATIC_CONTENT_DIRECTORY GSAD_STATIC_CONTENT_DIR

/**
 * @brief Structure to hold the parsed command-line arguments for gsad.
 *
 * This structure contains fields corresponding to the various command-line
 * options that can be passed to gsad. It is used to store the parsed values
 * after processing the command-line arguments.
 */
typedef struct gsad_args
{
  gboolean do_chroot;
  gboolean foreground;
  gboolean hsts_enabled;
  gboolean http_only;
  gboolean ignore_x_real_ip;
  gboolean no_redirect;
  gboolean print_version;
  gboolean secure_cookie;
  gboolean verbose;
  gchar **gsad_address_string;
  gchar *dh_params_filename;
  gchar *drop;
  gchar *gnutls_priorities;
  gchar *gsad_log_config_filename;
  gchar *gsad_manager_address_string;
  gchar *gsad_manager_unix_socket_path;
  gchar *gsad_static_content_directory;
  gchar *gsad_pid_filename;
  gchar *gsad_vendor_version_string;
  gchar *http_cors;
  gchar *http_csp;
  gchar *http_frame_opts;
  gchar *ssl_certificate_filename;
  gchar *ssl_private_key_filename;
  gchar *unix_socket_group;
  gchar *unix_socket_mode;
  gchar *unix_socket_owner;
  gchar *unix_socket_path;
  int client_watch_interval;
  int debug_tls;
  int gsad_manager_port;
  int gsad_port;
  int gsad_redirect_port;
  int gsad_user_session_limit;
  int hsts_max_age;
  int per_ip_connection_limit;
  int timeout;
} gsad_args_t;

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

const char *
gsad_args_get_log_config_filename (gsad_args_t *);

const char *
gsad_args_get_pid_filename (gsad_args_t *);

const char *
gsad_args_get_static_content_directory (gsad_args_t *);

#endif /* _GSAD_ARGS_H */
