/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_ARGS_INTERNAL_H
#define _GSAD_ARGS_INTERNAL_H

#include <glib.h>

/**
 * @brief Internal structure for command line arguments.
 */
struct gsad_args
{
  gboolean api_only;   ///< Whether to enable API only mode.
  gboolean do_chroot;  ///< Whether chroot should be enabled.
  gboolean foreground; ///< Whether to run in foreground.
  gboolean
    hsts_enabled; ///< Whether HTTP Strict-Transport-Security should be enabled.
  gboolean http_only;        ///< Whether to serve HTTP only, without TLS.
  gboolean ignore_x_real_ip; ///< Whether to ignore the X-Real-IP header.
  gboolean no_redirect;      ///< Whether to disable HTTP to HTTPS redirection.
  gboolean print_version;    ///< Whether to print version and exit.
  gboolean secure_cookie;    ///< Whether to use secure cookies.
  gboolean verbose;          ///< Whether to enable verbose logging.
  gchar **gsad_address_string;     ///< List of addresses to listen on
  gchar *dh_params_filename;       ///< Filename for Diffie-Hellman parameters.
  gchar *drop;                     ///< User to drop privileges to.
  gchar *gnutls_priorities;        ///< GnuTLS priorities string.
  gchar *gsad_log_config_filename; ///< Filename for logging configuration.
  gchar *gsad_manager_address_string;   ///< Address for manager interface.
  gchar *manager_unix_socket_path;      ///< Path for manager Unix socket.
  gchar *gsad_static_content_directory; ///< Directory for static content.
  gchar *gsad_pid_filename;             ///< Filename for PID file.
  gchar *gsad_vendor_version_string;    ///< Vendor version string.
  gchar *http_coep;                     ///< HTTP COEP configuration.
  gchar *http_coop;                     ///< HTTP COOP configuration.
  gchar *http_corp;                     ///< HTTP CORP configuration.
  gchar *http_cors;                     ///< HTTP CORS configuration.
  gchar *http_csp;        ///< HTTP Content Security Policy configuration.
  gchar *http_frame_opts; ///< HTTP frame options configuration.
  gchar *ssl_certificate_filename; ///< Filename for SSL certificate.
  gchar *ssl_private_key_filename; ///< Filename for SSL private key.
  gchar *unix_socket_group;        ///< Group for Unix socket.
  gchar *unix_socket_mode;         ///< Mode for Unix socket.
  gchar *unix_socket_owner;        ///< Owner for Unix socket.
  gchar *unix_socket_path;         ///< Path for Unix socket.
  int client_watch_interval;       ///< Interval in seconds to check if client
                                   ///< connection was closed.
  int debug_tls;                   ///< TLS debug level.
  int gsad_manager_port;           ///< Port for manager interface.
  int gsad_port;                   ///< Port for gsad to listen on.
  int gsad_redirect_port;          ///< Port for HTTP to HTTPS redirection.
  int user_session_limit; ///< Limit for number of concurrent user sessions. A
                          ///< value of 0 means no limit.
  int hsts_max_age; ///< max-age in seconds for HTTP Strict-Transport-Security
                    ///< header.
  int per_ip_connection_limit; ///< Limit for number of connections per IP
                               ///< address. A value of 0 means no limit.
  int session_timeout; ///< Minutes of user idle time before session expires. A
                       ///< value of 0 means no timeout.
};

#endif /* _GSAD_ARGS_INTERNAL_H */
