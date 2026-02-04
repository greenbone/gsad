/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_args.h"

#include <cgreen/cgreen.h>
#include <stdlib.h> // for mkstemp
#include <unistd.h> // for close

char *
create_temp_file ()
{
  char template[] = "/tmp/gsad_args_testXXXXXX";
  int fd = mkstemp (template);
  if (fd == -1)
    {
      return NULL;
    }
  close (fd);
  return g_strdup (template);
}

Describe (gsad_args);

BeforeEach (gsad_args)
{
}
AfterEach (gsad_args)
{
}

Ensure (gsad_args, gsad_args_new)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (args->client_watch_interval,
               is_equal_to (DEFAULT_CLIENT_WATCH_INTERVAL));
  assert_that (args->debug_tls, is_equal_to (0));
  assert_that (args->dh_params_filename, is_null);
  assert_that (args->do_chroot, is_false);
  assert_that (args->drop, is_null);
  assert_that (args->foreground, is_false);
  assert_that (args->gnutls_priorities, is_null);
  assert_that (args->gsad_address_string, is_null);
  assert_that (args->gsad_manager_address_string, is_null);
  assert_that (args->gsad_manager_port, is_equal_to (PORT_NOT_SET));
  assert_that (args->gsad_manager_unix_socket_path, is_null);
  assert_that (args->gsad_port, is_equal_to (PORT_NOT_SET));
  assert_that (args->gsad_redirect_port, is_equal_to (PORT_NOT_SET));
  assert_that (args->gsad_user_session_limit, is_equal_to (0));
  assert_that (args->gsad_vendor_version_string, is_null);
  assert_that (args->hsts_enabled, is_false);
  assert_that (args->hsts_max_age, is_equal_to (DEFAULT_GSAD_HSTS_MAX_AGE));
  assert_that (args->http_cors, is_null);
  assert_that (args->http_csp,
               is_equal_to_string (DEFAULT_GSAD_CONTENT_SECURITY_POLICY));
  assert_that (args->http_frame_opts,
               is_equal_to_string (DEFAULT_GSAD_X_FRAME_OPTIONS));
  assert_that (args->http_only, is_false);
  assert_that (args->ignore_x_real_ip, is_false);
  assert_that (args->no_redirect, is_false);
  assert_that (args->per_ip_connection_limit,
               is_equal_to (DEFAULT_GSAD_PER_IP_CONNECTION_LIMIT));
  assert_that (args->print_version, is_false);
  assert_that (args->secure_cookie, is_false);
  assert_that (args->ssl_certificate_filename,
               is_equal_to_string (DEFAULT_GSAD_TLS_CERTIFICATE));
  assert_that (args->ssl_private_key_filename,
               is_equal_to_string (DEFAULT_GSAD_TLS_PRIVATE_KEY));
  assert_that (args->timeout, is_equal_to (SESSION_TIMEOUT));
  assert_that (args->unix_socket_group, is_null);
  assert_that (args->unix_socket_mode, is_null);
  assert_that (args->unix_socket_owner, is_null);
  assert_that (args->unix_socket_path, is_null);
  assert_that (args->verbose, is_false);

  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_client_watch_interval)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--client-watch-interval", "10"};
  gsad_args_parse (3, argv, args);

  assert_that (args->client_watch_interval, is_equal_to (10));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_client_watch_interval_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->client_watch_interval,
               is_equal_to (DEFAULT_CLIENT_WATCH_INTERVAL));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_debug_tls)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--debug-tls", "3"};
  gsad_args_parse (3, argv, args);

  assert_that (args->debug_tls, is_equal_to (3));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_debug_tls_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->debug_tls, is_equal_to (0));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_dh_params_filename)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--dh-params", "/path/to/dhparams.pem"};
  gsad_args_parse (3, argv, args);

  assert_that (args->dh_params_filename,
               is_equal_to_string ("/path/to/dhparams.pem"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_dh_params_filename_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->dh_params_filename, is_null);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_do_chroot)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--do-chroot"};
  gsad_args_parse (2, argv, args);

  assert_that (args->do_chroot, is_true);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_do_chroot_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->do_chroot, is_false);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_drop)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--drop-privileges", "nobody"};
  gsad_args_parse (3, argv, args);

  assert_that (args->drop, is_equal_to_string ("nobody"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_drop_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->drop, is_null);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_foreground)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--foreground"};
  gsad_args_parse (2, argv, args);

  assert_that (args->foreground, is_true);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_foreground_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->foreground, is_false);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gnu_tls_priorities)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--gnutls-priorities", "NORMAL:-VERS-ALL"};
  gsad_args_parse (3, argv, args);

  assert_that (args->gnutls_priorities,
               is_equal_to_string ("NORMAL:-VERS-ALL"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gnutls_priorities_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->gnutls_priorities, is_null);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_address_string)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--listen", "127.0.0.1"};
  gsad_args_parse (3, argv, args);

  assert_that (args->gsad_address_string[0], is_equal_to_string ("127.0.0.1"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_address_string_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->gsad_address_string, is_null);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_address_string_multiple)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--listen", "127.0.0.1", "--listen", "192.168.1.1"};
  gsad_args_parse (5, argv, args);

  assert_that (args->gsad_address_string[0], is_equal_to_string ("127.0.0.1"));
  assert_that (args->gsad_address_string[1],
               is_equal_to_string ("192.168.1.1"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_manager_address_string)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--mlisten", "127.0.0.1"};
  gsad_args_parse (3, argv, args);

  assert_that (args->gsad_manager_address_string,
               is_equal_to_string ("127.0.0.1"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_manager_address_string_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->gsad_manager_address_string, is_null);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_manager_port)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--mport", "9390"};
  gsad_args_parse (3, argv, args);

  assert_that (args->gsad_manager_port, is_equal_to (9390));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_manager_port_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->gsad_manager_port, is_equal_to (PORT_NOT_SET));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_manager_unix_socket_path)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--munix-socket", "/var/run/gsad.sock"};
  gsad_args_parse (3, argv, args);

  assert_that (args->gsad_manager_unix_socket_path,
               is_equal_to_string ("/var/run/gsad.sock"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_manager_unix_socket_path_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->gsad_manager_unix_socket_path, is_null);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_port)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--port", "8080"};
  gsad_args_parse (3, argv, args);

  assert_that (args->gsad_port, is_equal_to (8080));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_port_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->gsad_port, is_equal_to (PORT_NOT_SET));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_redirect_port)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--rport", "8443"};
  gsad_args_parse (3, argv, args);

  assert_that (args->gsad_redirect_port, is_equal_to (8443));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_redirect_port_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->gsad_redirect_port, is_equal_to (PORT_NOT_SET));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_user_session_limit)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--user-session-limit", "5"};
  gsad_args_parse (3, argv, args);

  assert_that (args->gsad_user_session_limit, is_equal_to (5));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_user_session_limit_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->gsad_user_session_limit, is_equal_to (0));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_vendor_version_string)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--vendor-version", "MyCustomVersion"};
  gsad_args_parse (3, argv, args);

  assert_that (args->gsad_vendor_version_string,
               is_equal_to_string ("MyCustomVersion"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_vendor_version_string_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->gsad_vendor_version_string, is_null);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_hsts_enabled)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--http-sts"};
  gsad_args_parse (2, argv, args);

  assert_that (args->hsts_enabled, is_true);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_hsts_enabled_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->hsts_enabled, is_false);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_hsts_max_age)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--http-sts-max-age", "600"};
  gsad_args_parse (3, argv, args);

  assert_that (args->hsts_max_age, is_equal_to (600));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_hsts_max_age_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->hsts_max_age, is_equal_to (DEFAULT_GSAD_HSTS_MAX_AGE));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_http_cors)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--http-cors", "https://example.com"};
  gsad_args_parse (3, argv, args);

  assert_that (args->http_cors, is_equal_to_string ("https://example.com"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_http_cors_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->http_cors, is_null);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_http_csp)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--http-csp", "default-src 'self'"};
  gsad_args_parse (3, argv, args);

  assert_that (args->http_csp, is_equal_to_string ("default-src 'self'"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_http_csp_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->http_csp,
               is_equal_to_string (DEFAULT_GSAD_CONTENT_SECURITY_POLICY));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_frame_opts)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--http-frame-opts", "DENY"};
  gsad_args_parse (3, argv, args);

  assert_that (args->http_frame_opts, is_equal_to_string ("DENY"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_frame_opts_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->http_frame_opts,
               is_equal_to_string (DEFAULT_GSAD_X_FRAME_OPTIONS));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_http_only)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--http-only"};
  gsad_args_parse (2, argv, args);

  assert_that (args->http_only, is_true);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_http_only_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->http_only, is_false);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_ignore_x_real_ip)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--ignore-x-real-ip"};
  gsad_args_parse (2, argv, args);

  assert_that (args->ignore_x_real_ip, is_true);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_ignore_x_real_ip_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->ignore_x_real_ip, is_false);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_no_redirect)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--no-redirect"};
  gsad_args_parse (2, argv, args);

  assert_that (args->no_redirect, is_true);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_no_redirect_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->no_redirect, is_false);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_per_ip_connection_limit)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--per-ip-connection-limit", "50"};
  gsad_args_parse (3, argv, args);

  assert_that (args->per_ip_connection_limit, is_equal_to (50));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_per_ip_connection_limit_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->per_ip_connection_limit,
               is_equal_to (DEFAULT_GSAD_PER_IP_CONNECTION_LIMIT));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_print_version)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--version"};
  gsad_args_parse (2, argv, args);

  assert_that (args->print_version, is_true);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_print_version_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->print_version, is_false);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_secure_cookie)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--secure-cookie"};
  gsad_args_parse (2, argv, args);

  assert_that (args->secure_cookie, is_true);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_secure_cookie_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->secure_cookie, is_false);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_ssl_certificate_filename)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--ssl-certificate", "/path/to/cert.pem"};
  gsad_args_parse (3, argv, args);

  assert_that (args->ssl_certificate_filename,
               is_equal_to_string ("/path/to/cert.pem"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_ssl_certificate_filename_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->ssl_certificate_filename,
               is_equal_to_string (DEFAULT_GSAD_TLS_CERTIFICATE));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_ssl_private_key_filename)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--ssl-private-key", "/path/to/key.pem"};
  gsad_args_parse (3, argv, args);

  assert_that (args->ssl_private_key_filename,
               is_equal_to_string ("/path/to/key.pem"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_ssl_private_key_filename_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->ssl_private_key_filename,
               is_equal_to_string (DEFAULT_GSAD_TLS_PRIVATE_KEY));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_timeout)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--timeout", "120"};
  gsad_args_parse (3, argv, args);

  assert_that (args->timeout, is_equal_to (120));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_timeout_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->timeout, is_equal_to (SESSION_TIMEOUT));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_unix_socket_group)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--unix-socket-group", "gsadgroup"};
  gsad_args_parse (3, argv, args);

  assert_that (args->unix_socket_group, is_equal_to_string ("gsadgroup"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_unix_socket_group_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->unix_socket_group, is_null);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_unix_socket_mode)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--unix-socket-mode", "0660"};
  gsad_args_parse (3, argv, args);

  assert_that (args->unix_socket_mode, is_equal_to_string ("0660"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_unix_socket_mode_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->unix_socket_mode, is_null);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_unix_socket_owner)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--unix-socket-owner", "gsaduser"};
  gsad_args_parse (3, argv, args);

  assert_that (args->unix_socket_owner, is_equal_to_string ("gsaduser"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_unix_socket_owner_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->unix_socket_owner, is_null);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_unix_socket_path)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--unix-socket", "/var/run/gsad.sock"};
  gsad_args_parse (3, argv, args);

  assert_that (args->unix_socket_path,
               is_equal_to_string ("/var/run/gsad.sock"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_unix_socket_path_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->unix_socket_path, is_null);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_verbose)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--verbose"};
  gsad_args_parse (2, argv, args);

  assert_that (args->verbose, is_true);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_verbose_default)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->verbose, is_false);
  gsad_args_free (args);
}

Ensure (gsad_args, should_enable_redirect)
{
  gsad_args_t *args = gsad_args_new ();

  args->no_redirect = FALSE;
  args->http_only = TRUE;
  assert_that (gsad_args_enable_redirect (args), is_false);

  args->http_only = FALSE;
  args->no_redirect = TRUE;
  assert_that (gsad_args_enable_redirect (args), is_false);

  args->http_only = FALSE;
  args->no_redirect = FALSE;
  assert_that (gsad_args_enable_redirect (args), is_true);
  gsad_args_free (args);
}

Ensure (gsad_args, should_validate_session_timout)
{
  gsad_args_t *args = gsad_args_new ();
  args->timeout = 0;
  assert_that (gsad_args_validate_session_timeout (args), is_equal_to (0));

  args->timeout = -1;
  assert_that (gsad_args_validate_session_timeout (args), is_equal_to (1));

  args->timeout = GSAD_MAX_SESSION_TIMEOUT + 1;
  assert_that (gsad_args_validate_session_timeout (args), is_equal_to (1));
  gsad_args_free (args);
}

Ensure (gsad_args, should_validate_port)
{
  gsad_args_t *args = gsad_args_new ();

  assert_that (args->gsad_port, is_equal_to (PORT_NOT_SET));
  assert_that (gsad_args_validate_port (args), is_equal_to (0));

  args->gsad_port = 0;
  assert_that (gsad_args_validate_port (args), is_equal_to (1));

  args->gsad_port = 65536;
  assert_that (gsad_args_validate_port (args), is_equal_to (1));

  args->gsad_port = 8080;
  assert_that (gsad_args_validate_port (args), is_equal_to (0));

  args->gsad_port = -1234;
  assert_that (gsad_args_validate_port (args), is_equal_to (1));
  gsad_args_free (args);
}

Ensure (gsad_args, should_validate_manager_port)
{
  gsad_args_t *args = gsad_args_new ();

  assert_that (args->gsad_manager_port, is_equal_to (PORT_NOT_SET));
  assert_that (gsad_args_validate_manager_port (args), is_equal_to (0));

  args->gsad_manager_port = 0;
  assert_that (gsad_args_validate_manager_port (args), is_equal_to (1));

  args->gsad_manager_port = 65536;
  assert_that (gsad_args_validate_manager_port (args), is_equal_to (1));

  args->gsad_manager_port = 8080;
  assert_that (gsad_args_validate_manager_port (args), is_equal_to (0));

  args->gsad_manager_port = -1234;
  assert_that (gsad_args_validate_manager_port (args), is_equal_to (1));
  gsad_args_free (args);
}

Ensure (gsad_args, should_validate_redirect_port)
{
  gsad_args_t *args = gsad_args_new ();

  assert_that (args->gsad_redirect_port, is_equal_to (PORT_NOT_SET));
  assert_that (gsad_args_validate_redirect_port (args), is_equal_to (0));

  args->gsad_redirect_port = 0;
  assert_that (gsad_args_validate_redirect_port (args), is_equal_to (1));
  args->gsad_redirect_port = 65536;
  assert_that (gsad_args_validate_redirect_port (args), is_equal_to (1));

  args->gsad_redirect_port = 8080;
  assert_that (gsad_args_validate_redirect_port (args), is_equal_to (0));

  args->gsad_redirect_port = -1234;
  assert_that (gsad_args_validate_redirect_port (args), is_equal_to (1));
  gsad_args_free (args);
}

Ensure (gsad_args, should_get_port)
{
  gsad_args_t *args = gsad_args_new ();

  args->gsad_port = PORT_NOT_SET;
  args->http_only = TRUE;
  assert_that (gsad_args_get_port (args), is_equal_to (DEFAULT_GSAD_HTTP_PORT));

  args->gsad_port = PORT_NOT_SET;
  args->http_only = FALSE;
  assert_that (gsad_args_get_port (args),
               is_equal_to (DEFAULT_GSAD_HTTPS_PORT));

  args->gsad_port = 8080;
  assert_that (gsad_args_get_port (args), is_equal_to (8080));

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_redirect_port)
{
  gsad_args_t *args = gsad_args_new ();

  args->gsad_redirect_port = 1234;
  args->http_only = TRUE;
  args->no_redirect = FALSE;
  assert_that (gsad_args_get_redirect_port (args), is_equal_to (PORT_NOT_SET));

  args->gsad_redirect_port = 1234;
  args->http_only = FALSE;
  args->no_redirect = TRUE;
  assert_that (gsad_args_get_redirect_port (args), is_equal_to (PORT_NOT_SET));

  args->gsad_redirect_port = 8443;
  args->http_only = FALSE;
  args->no_redirect = FALSE;
  assert_that (gsad_args_get_redirect_port (args), is_equal_to (8443));

  args->gsad_redirect_port = PORT_NOT_SET;
  args->http_only = FALSE;
  args->no_redirect = FALSE;
  assert_that (gsad_args_get_redirect_port (args),
               is_equal_to (DEFAULT_GSAD_HTTP_PORT));

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_http_strict_transport_security_max_age)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_http_strict_transport_security_max_age (args),
               is_equal_to (DEFAULT_GSAD_HSTS_MAX_AGE));

  args->hsts_max_age = 600;
  assert_that (gsad_args_get_http_strict_transport_security_max_age (args),
               is_equal_to (600));

  args->hsts_max_age = 0;
  assert_that (gsad_args_get_http_strict_transport_security_max_age (args),
               is_equal_to (0));

  args->hsts_max_age = -1;
  assert_that (gsad_args_get_http_strict_transport_security_max_age (args),
               is_equal_to (DEFAULT_GSAD_HSTS_MAX_AGE));

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_per_ip_connection_limit)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_per_ip_connection_limit (args),
               is_equal_to (DEFAULT_GSAD_PER_IP_CONNECTION_LIMIT));

  args->per_ip_connection_limit = 50;
  assert_that (gsad_args_get_per_ip_connection_limit (args), is_equal_to (50));

  args->per_ip_connection_limit = 0;
  assert_that (gsad_args_get_per_ip_connection_limit (args), is_equal_to (0));

  args->per_ip_connection_limit = -1;
  assert_that (gsad_args_get_per_ip_connection_limit (args),
               is_equal_to (DEFAULT_GSAD_PER_IP_CONNECTION_LIMIT));

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_client_watch_interval)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_client_watch_interval (args),
               is_equal_to (DEFAULT_CLIENT_WATCH_INTERVAL));

  args->client_watch_interval = 30;
  assert_that (gsad_args_get_client_watch_interval (args), is_equal_to (30));

  args->client_watch_interval = 0;
  assert_that (gsad_args_get_client_watch_interval (args), is_equal_to (0));

  args->client_watch_interval = -1;
  assert_that (gsad_args_get_client_watch_interval (args), is_equal_to (0));

  gsad_args_free (args);
}

Ensure (gsad_args, should_enable_unix_socket)
{
  gsad_args_t *args = gsad_args_new ();

  args->unix_socket_path = "/var/run/gsad.sock";
  assert_that (gsad_args_enable_unix_socket (args), is_true);

  args->unix_socket_path = NULL;
  assert_that (gsad_args_enable_unix_socket (args), is_false);

  gsad_args_free (args);
}

Ensure (gsad_args, should_enable_https)
{
  gsad_args_t *args = gsad_args_new ();

  args->http_only = FALSE;
  assert_that (gsad_args_enable_https (args), is_true);

  args->http_only = TRUE;
  assert_that (gsad_args_enable_https (args), is_false);

  gsad_args_free (args);
}

Ensure (gsad_args, should_enable_http_strict_transport_security)
{
  gsad_args_t *args = gsad_args_new ();

  args->http_only = FALSE;
  args->hsts_enabled = TRUE;
  assert_that (gsad_args_enable_http_strict_transport_security (args), is_true);

  args->http_only = FALSE;
  args->hsts_enabled = FALSE;
  assert_that (gsad_args_enable_http_strict_transport_security (args),
               is_false);

  args->http_only = TRUE;
  args->hsts_enabled = TRUE;
  assert_that (gsad_args_enable_http_strict_transport_security (args),
               is_false);

  gsad_args_free (args);
}

Ensure (gsad_args, should_enable_run_in_foreground)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_enable_run_in_foreground (args), is_false);

  args->foreground = TRUE;
  assert_that (gsad_args_enable_run_in_foreground (args), is_true);

  args->foreground = FALSE;
  assert_that (gsad_args_enable_run_in_foreground (args), is_false);

  gsad_args_free (args);
}

Ensure (gsad_args, should_validate_tls_private_key)
{
  gsad_args_t *args = gsad_args_new ();
  args->http_only = TRUE;
  args->ssl_private_key_filename = NULL;
  assert_that (gsad_args_validate_tls_private_key (args), is_equal_to (0));

  args->http_only = FALSE;
  args->ssl_private_key_filename = NULL;
  assert_that (gsad_args_validate_tls_private_key (args), is_equal_to (1));

  args->http_only = FALSE;
  args->ssl_private_key_filename = "/path/to/key.pem";
  assert_that (gsad_args_validate_tls_private_key (args), is_equal_to (2));

  char *tempfile = create_temp_file ();
  args->http_only = FALSE;
  args->ssl_private_key_filename = tempfile;
  assert_that (gsad_args_validate_tls_private_key (args), is_equal_to (0));

  gsad_args_free (args);
}

Ensure (gsad_args, should_validate_tls_certificate)
{
  gsad_args_t *args = gsad_args_new ();
  args->http_only = TRUE;
  args->ssl_certificate_filename = NULL;
  assert_that (gsad_args_validate_tls_certificate (args), is_equal_to (0));

  args->http_only = FALSE;
  args->ssl_certificate_filename = NULL;
  assert_that (gsad_args_validate_tls_certificate (args), is_equal_to (1));

  args->http_only = FALSE;
  args->ssl_certificate_filename = "/path/to/cert.pem";
  assert_that (gsad_args_validate_tls_certificate (args), is_equal_to (2));

  char *tempfile = create_temp_file ();
  args->http_only = FALSE;
  args->ssl_certificate_filename = tempfile;
  assert_that (gsad_args_validate_tls_certificate (args), is_equal_to (0));

  gsad_args_free (args);
}

Ensure (gsad_args, should_free_gsad_args)
{
  gsad_args_t *args = NULL;
  gsad_args_free (args);

  args = gsad_args_new ();
  assert_that (args, is_not_null);
  gsad_args_free (args);
}

int
main (int argc, char **argv)
{
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, gsad_args, gsad_args_new);
  add_test_with_context (suite, gsad_args, should_parse_client_watch_interval);
  add_test_with_context (suite, gsad_args,
                         should_parse_client_watch_interval_default);
  add_test_with_context (suite, gsad_args, should_parse_debug_tls);
  add_test_with_context (suite, gsad_args, should_parse_debug_tls_default);
  add_test_with_context (suite, gsad_args, should_parse_dh_params_filename);
  add_test_with_context (suite, gsad_args,
                         should_parse_dh_params_filename_default);
  add_test_with_context (suite, gsad_args, should_parse_do_chroot);
  add_test_with_context (suite, gsad_args, should_parse_do_chroot_default);
  add_test_with_context (suite, gsad_args, should_parse_drop);
  add_test_with_context (suite, gsad_args, should_parse_drop_default);
  add_test_with_context (suite, gsad_args, should_parse_foreground);
  add_test_with_context (suite, gsad_args, should_parse_foreground_default);
  add_test_with_context (suite, gsad_args, should_parse_gnu_tls_priorities);
  add_test_with_context (suite, gsad_args,
                         should_parse_gnutls_priorities_default);
  add_test_with_context (suite, gsad_args, should_parse_gsad_address_string);
  add_test_with_context (suite, gsad_args,
                         should_parse_gsad_address_string_default);
  add_test_with_context (suite, gsad_args,
                         should_parse_gsad_address_string_multiple);
  add_test_with_context (suite, gsad_args,
                         should_parse_gsad_manager_address_string);
  add_test_with_context (suite, gsad_args,
                         should_parse_gsad_manager_address_string_default);
  add_test_with_context (suite, gsad_args, should_parse_gsad_manager_port);
  add_test_with_context (suite, gsad_args,
                         should_parse_gsad_manager_port_default);
  add_test_with_context (suite, gsad_args,
                         should_parse_gsad_manager_unix_socket_path);
  add_test_with_context (suite, gsad_args,
                         should_parse_gsad_manager_unix_socket_path_default);
  add_test_with_context (suite, gsad_args, should_parse_gsad_port);
  add_test_with_context (suite, gsad_args, should_parse_gsad_port_default);
  add_test_with_context (suite, gsad_args, should_parse_gsad_redirect_port);
  add_test_with_context (suite, gsad_args,
                         should_parse_gsad_redirect_port_default);
  add_test_with_context (suite, gsad_args,
                         should_parse_gsad_user_session_limit);
  add_test_with_context (suite, gsad_args,
                         should_parse_gsad_user_session_limit_default);
  add_test_with_context (suite, gsad_args,
                         should_parse_gsad_vendor_version_string);
  add_test_with_context (suite, gsad_args,
                         should_parse_gsad_vendor_version_string_default);
  add_test_with_context (suite, gsad_args, should_parse_hsts_enabled);
  add_test_with_context (suite, gsad_args, should_parse_hsts_enabled_default);
  add_test_with_context (suite, gsad_args, should_parse_hsts_max_age);
  add_test_with_context (suite, gsad_args, should_parse_hsts_max_age_default);
  add_test_with_context (suite, gsad_args, should_parse_http_cors);
  add_test_with_context (suite, gsad_args, should_parse_http_cors_default);
  add_test_with_context (suite, gsad_args, should_parse_http_csp);
  add_test_with_context (suite, gsad_args, should_parse_http_csp_default);
  add_test_with_context (suite, gsad_args, should_parse_frame_opts);
  add_test_with_context (suite, gsad_args, should_parse_frame_opts_default);
  add_test_with_context (suite, gsad_args, should_parse_http_only);
  add_test_with_context (suite, gsad_args, should_parse_http_only_default);
  add_test_with_context (suite, gsad_args, should_parse_ignore_x_real_ip);
  add_test_with_context (suite, gsad_args,
                         should_parse_ignore_x_real_ip_default);
  add_test_with_context (suite, gsad_args, should_parse_no_redirect);
  add_test_with_context (suite, gsad_args, should_parse_no_redirect_default);
  add_test_with_context (suite, gsad_args,
                         should_parse_per_ip_connection_limit);
  add_test_with_context (suite, gsad_args,
                         should_parse_per_ip_connection_limit_default);
  add_test_with_context (suite, gsad_args, should_parse_print_version);
  add_test_with_context (suite, gsad_args, should_parse_print_version_default);
  add_test_with_context (suite, gsad_args, should_parse_secure_cookie);
  add_test_with_context (suite, gsad_args, should_parse_secure_cookie_default);
  add_test_with_context (suite, gsad_args,
                         should_parse_ssl_certificate_filename);
  add_test_with_context (suite, gsad_args,
                         should_parse_ssl_certificate_filename_default);
  add_test_with_context (suite, gsad_args,
                         should_parse_ssl_private_key_filename);
  add_test_with_context (suite, gsad_args,
                         should_parse_ssl_private_key_filename_default);
  add_test_with_context (suite, gsad_args, should_parse_timeout);
  add_test_with_context (suite, gsad_args, should_parse_timeout_default);
  add_test_with_context (suite, gsad_args, should_parse_unix_socket_group);
  add_test_with_context (suite, gsad_args,
                         should_parse_unix_socket_group_default);
  add_test_with_context (suite, gsad_args, should_parse_unix_socket_mode);
  add_test_with_context (suite, gsad_args,
                         should_parse_unix_socket_mode_default);
  add_test_with_context (suite, gsad_args, should_parse_unix_socket_owner);
  add_test_with_context (suite, gsad_args,
                         should_parse_unix_socket_owner_default);
  add_test_with_context (suite, gsad_args, should_parse_unix_socket_path);
  add_test_with_context (suite, gsad_args,
                         should_parse_unix_socket_path_default);
  add_test_with_context (suite, gsad_args, should_parse_verbose);
  add_test_with_context (suite, gsad_args, should_parse_verbose_default);

  add_test_with_context (suite, gsad_args, should_enable_redirect);
  add_test_with_context (suite, gsad_args, should_enable_unix_socket);
  add_test_with_context (suite, gsad_args, should_enable_https);
  add_test_with_context (suite, gsad_args,
                         should_enable_http_strict_transport_security);
  add_test_with_context (suite, gsad_args, should_enable_run_in_foreground);

  add_test_with_context (suite, gsad_args, should_validate_session_timout);
  add_test_with_context (suite, gsad_args, should_validate_port);
  add_test_with_context (suite, gsad_args, should_validate_manager_port);
  add_test_with_context (suite, gsad_args, should_validate_redirect_port);
  add_test_with_context (suite, gsad_args, should_validate_tls_private_key);
  add_test_with_context (suite, gsad_args, should_validate_tls_certificate);

  add_test_with_context (suite, gsad_args, should_get_port);
  add_test_with_context (suite, gsad_args, should_get_redirect_port);
  add_test_with_context (suite, gsad_args,
                         should_get_http_strict_transport_security_max_age);
  add_test_with_context (suite, gsad_args, should_get_per_ip_connection_limit);
  add_test_with_context (suite, gsad_args, should_get_client_watch_interval);

  add_test_with_context (suite, gsad_args, should_free_gsad_args);

  int ret = run_test_suite (suite, create_text_reporter ());
  destroy_test_suite (suite);
  return ret;
}
