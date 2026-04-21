/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_args.h"
#include "gsad_args_internal.h"
#include "gsad_settings.h"

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
  g_unsetenv ("GSAD_API_ONLY");
  g_unsetenv ("GSAD_CLIENT_WATCH_INTERVAL");
  g_unsetenv ("GSAD_DEBUG_TLS");
  g_unsetenv ("GSAD_DH_PARAMS");
  g_unsetenv ("GSAD_DROP_PRIVILEGES");
  g_unsetenv ("GSAD_DO_CHROOT");
  g_unsetenv ("GSAD_FOREGROUND");
  g_unsetenv ("GSAD_GNUTLS_PRIORITIES");
  g_unsetenv ("GSAD_ADDRESS");
  g_unsetenv ("GSAD_LOG_CONFIG");
  g_unsetenv ("GSAD_MANAGER_UNIX_SOCKET");
  g_unsetenv ("GSAD_PID_FILE");
  g_unsetenv ("GSAD_PORT");
  g_unsetenv ("GSAD_STATIC_CONTENT");
  g_unsetenv ("GSAD_REDIRECT_PORT");
  g_unsetenv ("GSAD_USER_SESSION_LIMIT");
  g_unsetenv ("GSAD_HSTS_ENABLED");
  g_unsetenv ("GSAD_HSTS_MAX_AGE");
  g_unsetenv ("GSAD_HTTP_CORS");
  g_unsetenv ("GSAD_HTTP_COEP");
  g_unsetenv ("GSAD_HTTP_COOP");
  g_unsetenv ("GSAD_HTTP_CORP");
  g_unsetenv ("GSAD_HTTP_CSP");
  g_unsetenv ("GSAD_HTTP_FRAME_OPTS");
  g_unsetenv ("GSAD_HTTP_ONLY");
  g_unsetenv ("GSAD_IGNORE_X_REAL_IP");
  g_unsetenv ("GSAD_NO_REDIRECT");
  g_unsetenv ("GSAD_PER_IP_CONNECTION_LIMIT");
  g_unsetenv ("GSAD_SECURE_COOKIE");
  g_unsetenv ("GSAD_TLS_CERTIFICATE");
  g_unsetenv ("GSAD_TLS_PRIVATE_KEY");
  g_unsetenv ("GSAD_SESSION_TIMEOUT");
  g_unsetenv ("GSAD_UNIX_SOCKET_GROUP");
  g_unsetenv ("GSAD_UNIX_SOCKET_MODE");
  g_unsetenv ("GSAD_UNIX_SOCKET_OWNER");
  g_unsetenv ("GSAD_UNIX_SOCKET");
  g_unsetenv ("GSAD_JWT_REQUESTED");
}
AfterEach (gsad_args)
{
}

Ensure (gsad_args, should_use_defaults)
{
  gsad_args_t *args = gsad_args_new ();

  gchar *manager_unix_socket_default_path =
    g_build_filename (GVMD_RUN_DIR, "gvmd.sock", NULL);

  assert_that (args, is_not_null);
  assert_that (args->api_only, is_false);
  assert_that (args->client_watch_interval,
               is_equal_to (DEFAULT_CLIENT_WATCH_INTERVAL));
  assert_that (args->debug_tls, is_equal_to (0));
  assert_that (args->dh_params_filename, is_null);
  assert_that (args->do_chroot, is_false);
  assert_that (args->drop, is_null);
  assert_that (args->foreground, is_false);
  assert_that (args->gnutls_priorities, is_null);
  assert_that (args->gsad_address_string, is_null);
  assert_that (args->gsad_log_config_filename,
               is_equal_to_string (GSAD_CONFIG_DIR "gsad_log.conf"));
  assert_that (args->manager_unix_socket_path,
               is_equal_to_string (manager_unix_socket_default_path));
  assert_that (args->gsad_port, is_equal_to (PORT_NOT_SET));
  assert_that (args->gsad_redirect_port, is_equal_to (PORT_NOT_SET));
  assert_that (args->user_session_limit, is_equal_to (0));
  assert_that (args->gsad_vendor_version_string, is_null);
  assert_that (args->hsts_enabled, is_false);
  assert_that (args->hsts_max_age, is_equal_to (DEFAULT_GSAD_HSTS_MAX_AGE));
  assert_that (args->http_coep, is_null);
  assert_that (args->http_coop, is_null);
  assert_that (args->http_corp, is_null);
  assert_that (args->http_cors, is_null);
  assert_that (args->http_csp,
               is_equal_to_string (DEFAULT_GSAD_CONTENT_SECURITY_POLICY));
  assert_that (args->http_frame_opts,
               is_equal_to_string (DEFAULT_GSAD_X_FRAME_OPTIONS));
  assert_that (args->http_only, is_false);
  assert_that (args->ignore_x_real_ip, is_false);
  assert_that (args->no_redirect, is_false);
  assert_that (args->per_ip_connection_limit,
               is_equal_to (DEFAULT_PER_IP_CONNECTION_LIMIT));
  assert_that (args->print_version, is_false);
  assert_that (args->secure_cookie, is_false);
  assert_that (args->ssl_certificate_filename,
               is_equal_to_string (DEFAULT_GSAD_TLS_CERTIFICATE));
  assert_that (args->ssl_private_key_filename,
               is_equal_to_string (DEFAULT_GSAD_TLS_PRIVATE_KEY));
  assert_that (args->session_timeout, is_equal_to (DEFAULT_SESSION_TIMEOUT));
  assert_that (args->unix_socket_group, is_null);
  assert_that (args->unix_socket_mode, is_null);
  assert_that (args->unix_socket_owner, is_null);
  assert_that (args->unix_socket_path, is_null);
  assert_that (args->verbose, is_false);
  assert_that (args->jwt_requested, is_false);

  gsad_args_free (args);
  g_free (manager_unix_socket_default_path);
}

Ensure (gsad_args, should_use_env_variables)
{
  g_setenv ("GSAD_API_ONLY", "true", TRUE);
  g_setenv ("GSAD_CLIENT_WATCH_INTERVAL", "15", TRUE);
  g_setenv ("GSAD_DEBUG_TLS", "2", TRUE);
  g_setenv ("GSAD_DH_PARAMS", "/path/to/dh_params.pem", TRUE);
  g_setenv ("GSAD_DO_CHROOT", "true", TRUE);
  g_setenv ("GSAD_DROP_PRIVILEGES", "someuser", TRUE);
  g_setenv ("GSAD_FOREGROUND", "true", TRUE);
  g_setenv ("GSAD_GNUTLS_PRIORITIES", "123", TRUE);
  g_setenv ("GSAD_ADDRESS", "1.2.3.4,6.6.6.6", TRUE);
  g_setenv ("GSAD_LOG_CONFIG", "/custom/path/gsad_log.conf", TRUE);
  g_setenv ("GSAD_MANAGER_UNIX_SOCKET", "/custom/path/gvmd.sock", TRUE);
  g_setenv ("GSAD_PORT", "123", TRUE);
  g_setenv ("GSAD_REDIRECT_PORT", "234", TRUE);
  g_setenv ("GSAD_USER_SESSION_LIMIT", "10", TRUE);
  g_setenv ("GSAD_HSTS_ENABLED", "true", TRUE);
  g_setenv ("GSAD_HSTS_MAX_AGE", "123", TRUE);
  g_setenv ("GSAD_HTTP_CORS", "CORS", TRUE);
  g_setenv ("GSAD_HTTP_CSP", "CSP", TRUE);
  g_setenv ("GSAD_HTTP_COEP", "COEP", TRUE);
  g_setenv ("GSAD_HTTP_COOP", "COOP", TRUE);
  g_setenv ("GSAD_HTTP_CORP", "CORP", TRUE);
  g_setenv ("GSAD_HTTP_FRAME_OPTS", "FRAME_OPTS", TRUE);
  g_setenv ("GSAD_HTTP_ONLY", "true", TRUE);
  g_setenv ("GSAD_IGNORE_X_REAL_IP", "true", TRUE);
  g_setenv ("GSAD_NO_REDIRECT", "true", TRUE);
  g_setenv ("GSAD_PER_IP_CONNECTION_LIMIT", "123", TRUE);
  g_setenv ("GSAD_SECURE_COOKIE", "true", TRUE);
  g_setenv ("GSAD_TLS_CERTIFICATE", "/custom/path/gsad_cert.pem", TRUE);
  g_setenv ("GSAD_TLS_PRIVATE_KEY", "/custom/path/gsad_key.pem", TRUE);
  g_setenv ("GSAD_SESSION_TIMEOUT", "123", TRUE);
  g_setenv ("GSAD_UNIX_SOCKET_GROUP", "some_group", TRUE);
  g_setenv ("GSAD_UNIX_SOCKET_MODE", "some_mode", TRUE);
  g_setenv ("GSAD_UNIX_SOCKET_OWNER", "some_owner", TRUE);
  g_setenv ("GSAD_UNIX_SOCKET", "some_socket", TRUE);
  g_setenv ("GSAD_JWT_REQUESTED", "true", TRUE);

  gsad_args_t *args = gsad_args_new ();

  assert_that (args, is_not_null);
  assert_that (args->api_only, is_true);
  assert_that (args->client_watch_interval, is_equal_to (15));
  assert_that (args->debug_tls, is_equal_to (2));
  assert_that (args->dh_params_filename,
               is_equal_to_string ("/path/to/dh_params.pem"));
  assert_that (args->do_chroot, is_true);
  assert_that (args->drop, is_equal_to_string ("someuser"));
  assert_that (args->foreground, is_true);
  assert_that (args->gnutls_priorities, is_equal_to_string ("123"));
  assert_that (args->gsad_address_string, is_not_null);
  assert_that (args->gsad_address_string[0], is_equal_to_string ("1.2.3.4"));
  assert_that (args->gsad_address_string[1], is_equal_to_string ("6.6.6.6"));
  assert_that (args->gsad_log_config_filename,
               is_equal_to_string ("/custom/path/gsad_log.conf"));
  assert_that (args->manager_unix_socket_path,
               is_equal_to_string ("/custom/path/gvmd.sock"));
  assert_that (args->gsad_port, is_equal_to (123));
  assert_that (args->gsad_redirect_port, is_equal_to (234));
  assert_that (args->user_session_limit, is_equal_to (10));
  assert_that (args->hsts_enabled, is_true);
  assert_that (args->hsts_max_age, is_equal_to (123));
  assert_that (args->http_coep, is_equal_to_string ("COEP"));
  assert_that (args->http_coop, is_equal_to_string ("COOP"));
  assert_that (args->http_corp, is_equal_to_string ("CORP"));
  assert_that (args->http_cors, is_equal_to_string ("CORS"));
  assert_that (args->http_csp, is_equal_to_string ("CSP"));
  assert_that (args->http_frame_opts, is_equal_to_string ("FRAME_OPTS"));
  assert_that (args->http_only, is_true);
  assert_that (args->ignore_x_real_ip, is_true);
  assert_that (args->no_redirect, is_true);
  assert_that (args->per_ip_connection_limit, is_equal_to (123));
  assert_that (args->print_version, is_false);
  assert_that (args->secure_cookie, is_true);
  assert_that (args->ssl_certificate_filename,
               is_equal_to_string ("/custom/path/gsad_cert.pem"));
  assert_that (args->ssl_private_key_filename,
               is_equal_to_string ("/custom/path/gsad_key.pem"));
  assert_that (args->session_timeout, is_equal_to (123));
  assert_that (args->unix_socket_group, is_equal_to_string ("some_group"));
  assert_that (args->unix_socket_mode, is_equal_to_string ("some_mode"));
  assert_that (args->unix_socket_owner, is_equal_to_string ("some_owner"));
  assert_that (args->unix_socket_path, is_equal_to_string ("some_socket"));
  assert_that (args->verbose, is_false);
  assert_that (args->jwt_requested, is_true);

  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_api_only)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_is_api_only_enabled (args), is_false);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_API_ONLY", "true", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_is_api_only_enabled (args), is_true);
  gsad_args_free (args);

  // command line argument should override env variable
  g_setenv ("GSAD_API_ONLY", "true", TRUE);
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--api-only"};
  gsad_args_parse (2, argv3, args);

  assert_that (gsad_args_is_api_only_enabled (args), is_true);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_client_watch_interval)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_client_watch_interval (args),
               is_equal_to (DEFAULT_CLIENT_WATCH_INTERVAL));
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_CLIENT_WATCH_INTERVAL", "20", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_get_client_watch_interval (args), is_equal_to (20));
  gsad_args_free (args);

  // command line argument should override env variable
  g_setenv ("GSAD_CLIENT_WATCH_INTERVAL", "20", TRUE);
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--client-watch-interval", "10"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_client_watch_interval (args), is_equal_to (10));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_debug_tls)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_is_debug_tls_enabled (args), is_false);
  assert_that (gsad_args_get_tls_debug_level (args), is_equal_to (0));
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_DEBUG_TLS", "2", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_is_debug_tls_enabled (args), is_true);
  assert_that (gsad_args_get_tls_debug_level (args), is_equal_to (2));
  gsad_args_free (args);

  // command line argument should override env variable
  g_setenv ("GSAD_DEBUG_TLS", "2", TRUE);
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--debug-tls", "3"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_is_debug_tls_enabled (args), is_true);
  assert_that (gsad_args_get_tls_debug_level (args), is_equal_to (3));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_dh_params_filename)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_dh_params_filename (args), is_null);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_DH_PARAMS", "/path/to/dhparams.pem", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_get_dh_params_filename (args),
               is_equal_to_string ("/path/to/dhparams.pem"));
  gsad_args_free (args);

  // command line argument should override env variable
  g_setenv ("GSAD_DH_PARAMS", "/path/to/dhparams.pem", TRUE);
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--dh-params", "/path/to/dhparams.pem"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_dh_params_filename (args),
               is_equal_to_string ("/path/to/dhparams.pem"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_do_chroot)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_is_chroot_enabled (args), is_false);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_DO_CHROOT", "true", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_is_chroot_enabled (args), is_true);
  gsad_args_free (args);

  // command line argument should override env variable
  g_setenv ("GSAD_DO_CHROOT", "false", TRUE);
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--do-chroot"};
  gsad_args_parse (2, argv3, args);

  assert_that (gsad_args_is_chroot_enabled (args), is_true);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_drop)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_drop_privileges (args), is_null);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_DROP_PRIVILEGES", "someuser", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_get_drop_privileges (args),
               is_equal_to_string ("someuser"));
  gsad_args_free (args);

  // command line argument should override env variable
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--drop-privileges", "nobody"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_drop_privileges (args),
               is_equal_to_string ("nobody"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_foreground)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_is_run_in_foreground_enabled (args), is_false);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_FOREGROUND", "true", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_is_run_in_foreground_enabled (args), is_true);
  gsad_args_free (args);

  // command line argument should override env variable
  g_setenv ("GSAD_FOREGROUND", "false", TRUE);
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--foreground"};
  gsad_args_parse (2, argv3, args);

  assert_that (gsad_args_is_run_in_foreground_enabled (args), is_true);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gnu_tls_priorities)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_gnutls_priorities (args), is_null);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_GNUTLS_PRIORITIES", "NORMAL:-VERS-ALL", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_get_gnutls_priorities (args),
               is_equal_to_string ("NORMAL:-VERS-ALL"));
  gsad_args_free (args);

  // command line argument should override env variable
  g_setenv ("GSAD_GNUTLS_PRIORITIES", "FOO:BAR", TRUE);
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--gnutls-priorities", "NORMAL:-VERS-ALL"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_gnutls_priorities (args),
               is_equal_to_string ("NORMAL:-VERS-ALL"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_address_strings)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  char **listen_addresses = gsad_args_get_listen_addresses (args);
  assert_that (listen_addresses, is_null);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_ADDRESS", "1.1.1.1", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  listen_addresses = gsad_args_get_listen_addresses (args);
  assert_that (listen_addresses[0], is_equal_to_string ("1.1.1.1"));
  gsad_args_free (args);

  // command line argument should override env variable
  g_setenv ("GSAD_ADDRESS", "1.1.1.1", TRUE);
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--listen", "127.0.0.1"};
  gsad_args_parse (3, argv3, args);

  listen_addresses = gsad_args_get_listen_addresses (args);
  assert_that (listen_addresses[0], is_equal_to_string ("127.0.0.1"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_address_strings_multiple)
{
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad", "--listen", "127.0.0.1", "--listen", "192.168.1.1"};
  gsad_args_parse (5, argv, args);

  char **listen_addresses = gsad_args_get_listen_addresses (args);
  assert_that (listen_addresses[0], is_equal_to_string ("127.0.0.1"));
  assert_that (listen_addresses[1], is_equal_to_string ("192.168.1.1"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_manager_unix_socket_path)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  gchar *manager_unix_socket_default_path =
    g_build_filename (GVMD_RUN_DIR, "gvmd.sock", NULL);
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_manager_unix_socket_path (args),
               is_equal_to_string (manager_unix_socket_default_path));

  g_free (manager_unix_socket_default_path);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_MANAGER_UNIX_SOCKET", "/custom/path/gsad.sock", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_get_manager_unix_socket_path (args),
               is_equal_to_string ("/custom/path/gsad.sock"));
  gsad_args_free (args);

  // command line argument should override env variable
  g_setenv ("GSAD_MANAGER_UNIX_SOCKET", "/custom/path/gsad.sock", TRUE);
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--munix-socket", "/another/path/gsad.sock"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_manager_unix_socket_path (args),
               is_equal_to_string ("/another/path/gsad.sock"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_port)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_port (args),
               is_equal_to (DEFAULT_GSAD_HTTPS_PORT));
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_PORT", "8083", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_get_port (args), is_equal_to (8083));
  gsad_args_free (args);

  // command line argument should override env variable
  g_setenv ("GSAD_PORT", "8083", TRUE);
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--port", "8080"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_port (args), is_equal_to (8080));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_redirect_port)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_redirect_port (args),
               is_equal_to (DEFAULT_GSAD_HTTP_PORT));
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_REDIRECT_PORT", "8080", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_get_redirect_port (args), is_equal_to (8080));
  gsad_args_free (args);

  // command line argument should override env variable
  g_setenv ("GSAD_REDIRECT_PORT", "8080", TRUE);
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--rport", "8443"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_redirect_port (args), is_equal_to (8443));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_gsad_user_session_limit)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_user_session_limit (args), is_equal_to (0));
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_USER_SESSION_LIMIT", "5", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_get_user_session_limit (args), is_equal_to (5));
  gsad_args_free (args);

  // command line argument should override env variable
  g_setenv ("GSAD_USER_SESSION_LIMIT", "2", TRUE);
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--user-session-limit", "5"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_user_session_limit (args), is_equal_to (5));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_hsts_enabled)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_is_http_strict_transport_security_enabled (args),
               is_false);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_HSTS_ENABLED", "true", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_is_http_strict_transport_security_enabled (args),
               is_true);
  gsad_args_free (args);

  // command line argument should override env variable
  g_setenv ("GSAD_HSTS_ENABLED", "false", TRUE);
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--http-sts"};
  gsad_args_parse (2, argv3, args);

  assert_that (gsad_args_is_http_strict_transport_security_enabled (args),
               is_true);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_hsts_max_age)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_http_strict_transport_security_max_age (args),
               is_equal_to (DEFAULT_GSAD_HSTS_MAX_AGE));
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_HSTS_MAX_AGE", "300", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_get_http_strict_transport_security_max_age (args),
               is_equal_to (300));
  gsad_args_free (args);

  // command line argument should override env variable
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--http-sts-max-age", "600"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_http_strict_transport_security_max_age (args),
               is_equal_to (600));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_http_coep)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_http_coep (args), is_null);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_HTTP_COEP", "foo", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_get_http_coep (args), is_equal_to_string ("foo"));
  gsad_args_free (args);

  // command line argument should override env variable
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--http-coep", "bar"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_http_coep (args), is_equal_to_string ("bar"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_http_coop)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_http_coop (args), is_null);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_HTTP_COOP", "foo", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_get_http_coop (args), is_equal_to_string ("foo"));
  gsad_args_free (args);

  // command line argument should override env variable
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--http-coop", "same-origin"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_http_coop (args),
               is_equal_to_string ("same-origin"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_http_corp)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_http_corp (args), is_null);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_HTTP_CORP", "foo", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_get_http_corp (args), is_equal_to_string ("foo"));
  gsad_args_free (args);

  // command line argument should override env variable
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--http-corp", "same-origin"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_http_corp (args),
               is_equal_to_string ("same-origin"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_http_cors)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_http_cors_origin (args), is_null);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_HTTP_CORS", "https://foo.com", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_get_http_cors_origin (args),
               is_equal_to_string ("https://foo.com"));
  gsad_args_free (args);

  // command line argument should override env variable
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--http-cors", "https://example.com"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_http_cors_origin (args),
               is_equal_to_string ("https://example.com"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_http_csp)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_http_content_security_policy (args),
               is_equal_to_string (DEFAULT_GSAD_CONTENT_SECURITY_POLICY));
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_HTTP_CSP", "foo", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_get_http_content_security_policy (args),
               is_equal_to_string ("foo"));
  gsad_args_free (args);

  // command line argument should override env variable
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--http-csp", "default-src 'self'"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_http_content_security_policy (args),
               is_equal_to_string ("default-src 'self'"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_frame_opts)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_http_x_frame_options (args),
               is_equal_to_string (DEFAULT_GSAD_X_FRAME_OPTIONS));
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_HTTP_FRAME_OPTS", "SAMEORIGIN", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_get_http_x_frame_options (args),
               is_equal_to_string ("SAMEORIGIN"));
  gsad_args_free (args);

  // command line argument should override env variable
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--http-frame-opts", "DENY"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_http_x_frame_options (args),
               is_equal_to_string ("DENY"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_http_only)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_is_https_enabled (args), is_true);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_HTTP_ONLY", "true", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_is_https_enabled (args), is_false);
  gsad_args_free (args);

  // command line argument should override env variable
  g_setenv ("GSAD_HTTP_ONLY", "false", TRUE);
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--http-only"};
  gsad_args_parse (2, argv3, args);

  assert_that (gsad_args_is_https_enabled (args), is_false);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_ignore_x_real_ip)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_is_ignore_x_real_ip_enabled (args), is_false);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_IGNORE_X_REAL_IP", "true", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_is_ignore_x_real_ip_enabled (args), is_true);
  gsad_args_free (args);

  // command line argument should override env variable
  g_setenv ("GSAD_IGNORE_X_REAL_IP", "false", TRUE);
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--ignore-x-real-ip"};
  gsad_args_parse (2, argv3, args);

  assert_that (gsad_args_is_ignore_x_real_ip_enabled (args), is_true);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_no_redirect)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_is_redirect_enabled (args), is_true);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_NO_REDIRECT", "true", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_is_redirect_enabled (args), is_false);
  gsad_args_free (args);

  // command line argument should override env variable
  g_setenv ("GSAD_NO_REDIRECT", "false", TRUE);
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--no-redirect"};
  gsad_args_parse (2, argv3, args);

  assert_that (gsad_args_is_redirect_enabled (args), is_false);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_per_ip_connection_limit)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->per_ip_connection_limit,
               is_equal_to (DEFAULT_PER_IP_CONNECTION_LIMIT));
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_PER_IP_CONNECTION_LIMIT", "66", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (args->per_ip_connection_limit, is_equal_to (66));
  gsad_args_free (args);

  // command line argument should override env variable
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--per-ip-connection-limit", "50"};
  gsad_args_parse (3, argv3, args);

  assert_that (args->per_ip_connection_limit, is_equal_to (50));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_print_version)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_is_print_version_enabled (args), is_false);
  gsad_args_free (args);

  // command line argument
  args = gsad_args_new ();
  char *argv2[] = {"gsad", "--version"};
  gsad_args_parse (2, argv2, args);

  assert_that (gsad_args_is_print_version_enabled (args), is_true);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_secure_cookie)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->secure_cookie, is_false);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_SECURE_COOKIE", "true", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (args->secure_cookie, is_true);
  gsad_args_free (args);

  // command line argument should override env variable
  g_setenv ("GSAD_SECURE_COOKIE", "false", TRUE);
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--secure-cookie"};
  gsad_args_parse (2, argv3, args);

  assert_that (args->secure_cookie, is_true);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_tls_certificate_filename)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_tls_certificate_filename (args),
               is_equal_to_string (DEFAULT_GSAD_TLS_CERTIFICATE));
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_TLS_CERTIFICATE", "/path/to/cert.pem", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  // command line argument should override env variable
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--ssl-certificate", "/another/path/to/cert.pem"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_tls_certificate_filename (args),
               is_equal_to_string ("/another/path/to/cert.pem"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_tls_private_key_filename)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_tls_private_key_filename (args),
               is_equal_to_string (DEFAULT_GSAD_TLS_PRIVATE_KEY));
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_TLS_PRIVATE_KEY", "/path/to/key.pem", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_get_tls_private_key_filename (args),
               is_equal_to_string ("/path/to/key.pem"));
  gsad_args_free (args);

  // command line argument should override env variable
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--ssl-private-key", "/another/path/to/key.pem"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_tls_private_key_filename (args),
               is_equal_to_string ("/another/path/to/key.pem"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_timeout)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_session_timeout (args),
               is_equal_to (DEFAULT_SESSION_TIMEOUT));
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_SESSION_TIMEOUT", "90", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_get_session_timeout (args), is_equal_to (90));
  gsad_args_free (args);

  // command line argument should override env variable
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--timeout", "120"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_session_timeout (args), is_equal_to (120));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_unix_socket_group)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->unix_socket_group, is_null);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_UNIX_SOCKET_GROUP", "gsadgroup", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (args->unix_socket_group, is_equal_to_string ("gsadgroup"));
  gsad_args_free (args);

  // command line argument should override env variable
  g_setenv ("GSAD_UNIX_SOCKET_GROUP", "gsadgroup", TRUE);
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--unix-socket-group", "anothergroup"};
  gsad_args_parse (3, argv3, args);

  assert_that (args->unix_socket_group, is_equal_to_string ("anothergroup"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_unix_socket_mode)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->unix_socket_mode, is_null);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_UNIX_SOCKET_MODE", "0666", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (args->unix_socket_mode, is_equal_to_string ("0666"));
  gsad_args_free (args);

  // command line argument should override env variable
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--unix-socket-mode", "0660"};
  gsad_args_parse (3, argv3, args);

  assert_that (args->unix_socket_mode, is_equal_to_string ("0660"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_unix_socket_owner)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->unix_socket_owner, is_null);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_UNIX_SOCKET_OWNER", "gsaduser", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (args->unix_socket_owner, is_equal_to_string ("gsaduser"));
  gsad_args_free (args);

  // command line argument should override env variable
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--unix-socket-owner", "anotheruser"};
  gsad_args_parse (3, argv3, args);

  assert_that (args->unix_socket_owner, is_equal_to_string ("anotheruser"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_unix_socket_path)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->unix_socket_path, is_null);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_UNIX_SOCKET", "/some/path/gsad.sock", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (args->unix_socket_path,
               is_equal_to_string ("/some/path/gsad.sock"));
  gsad_args_free (args);

  // command line argument should override env variable
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--unix-socket", "/another/path/gsad.sock"};
  gsad_args_parse (3, argv3, args);

  assert_that (args->unix_socket_path,
               is_equal_to_string ("/another/path/gsad.sock"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_verbose)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (args->verbose, is_false);
  gsad_args_free (args);

  // command line argument
  args = gsad_args_new ();
  char *argv2[] = {"gsad", "--verbose"};
  gsad_args_parse (2, argv2, args);

  assert_that (args->verbose, is_true);
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_log_config_filename)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_log_config_filename (args),
               is_equal_to_string (GSAD_CONFIG_DIR "gsad_log.conf"));
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_LOG_CONFIG", "/path/to/config.conf", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_get_log_config_filename (args),
               is_equal_to_string ("/path/to/config.conf"));
  gsad_args_free (args);

  // command line argument should override env variable
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--log-config", "/another/path/to/config.conf"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_log_config_filename (args),
               is_equal_to_string ("/another/path/to/config.conf"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_pid_filename)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_pid_filename (args),
               is_equal_to_string (DEFAULT_GSAD_PID_FILE));
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_PID_FILE", "/path/to/gsad.pid", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_get_pid_filename (args),
               is_equal_to_string ("/path/to/gsad.pid"));
  gsad_args_free (args);

  // command line argument should override env variable
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--pid-file", "/another/path/gsad.pid"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_pid_filename (args),
               is_equal_to_string ("/another/path/gsad.pid"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_static_content_directory)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_get_static_content_directory (args),
               is_equal_to_string (DEFAULT_GSAD_STATIC_CONTENT_DIRECTORY));
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_STATIC_CONTENT", "/path/to/static", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_get_static_content_directory (args),
               is_equal_to_string ("/path/to/static"));
  gsad_args_free (args);

  // command line argument should override env variable
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--static-content", "/another/path/to/static"};
  gsad_args_parse (3, argv3, args);

  assert_that (gsad_args_get_static_content_directory (args),
               is_equal_to_string ("/another/path/to/static"));
  gsad_args_free (args);
}

Ensure (gsad_args, should_parse_jwt_requested)
{
  // default
  gsad_args_t *args = gsad_args_new ();
  char *argv[] = {"gsad"};
  gsad_args_parse (1, argv, args);

  assert_that (gsad_args_is_jwt_requested (args), is_false);
  gsad_args_free (args);

  // env variable
  g_setenv ("GSAD_JWT_REQUESTED", "true", TRUE);
  args = gsad_args_new ();
  char *argv2[] = {"gsad"};
  gsad_args_parse (1, argv2, args);

  assert_that (gsad_args_is_jwt_requested (args), is_true);
  gsad_args_free (args);

  // command line argument should override env variable
  g_setenv ("GSAD_JWT_REQUESTED", "false", TRUE);
  args = gsad_args_new ();
  char *argv3[] = {"gsad", "--jwt-requested"};
  gsad_args_parse (2, argv3, args);

  assert_that (gsad_args_is_jwt_requested (args), is_true);
  gsad_args_free (args);
}

Ensure (gsad_args, should_is_redirect_enabled)
{
  gsad_args_t *args = gsad_args_new ();

  args->no_redirect = FALSE;
  args->http_only = TRUE;
  assert_that (gsad_args_is_redirect_enabled (args), is_false);

  args->http_only = FALSE;
  args->no_redirect = TRUE;
  assert_that (gsad_args_is_redirect_enabled (args), is_false);

  args->http_only = FALSE;
  args->no_redirect = FALSE;
  assert_that (gsad_args_is_redirect_enabled (args), is_true);
  gsad_args_free (args);
}

Ensure (gsad_args, should_validate_session_timout)
{
  gsad_args_t *args = gsad_args_new ();
  args->session_timeout = 0;
  assert_that (gsad_args_validate_session_timeout (args), is_equal_to (0));

  args->session_timeout = -1;
  assert_that (gsad_args_validate_session_timeout (args), is_equal_to (1));

  args->session_timeout = GSAD_MAX_SESSION_TIMEOUT + 1;
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
               is_equal_to (DEFAULT_PER_IP_CONNECTION_LIMIT));

  args->per_ip_connection_limit = 50;
  assert_that (gsad_args_get_per_ip_connection_limit (args), is_equal_to (50));

  args->per_ip_connection_limit = 0;
  assert_that (gsad_args_get_per_ip_connection_limit (args), is_equal_to (0));

  args->per_ip_connection_limit = -1;
  assert_that (gsad_args_get_per_ip_connection_limit (args),
               is_equal_to (DEFAULT_PER_IP_CONNECTION_LIMIT));

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

Ensure (gsad_args, should_get_session_timeout)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_session_timeout (args),
               is_equal_to (DEFAULT_SESSION_TIMEOUT));

  args->session_timeout = 120;
  assert_that (gsad_args_get_session_timeout (args), is_equal_to (120));

  args->session_timeout = 0;
  assert_that (gsad_args_get_session_timeout (args), is_equal_to (0));

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_tls_certificate_filename)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_tls_certificate_filename (args),
               is_equal_to_string (DEFAULT_GSAD_TLS_CERTIFICATE));

  g_free (args->ssl_certificate_filename);
  args->ssl_certificate_filename = "/path/to/cert.pem";
  assert_that (gsad_args_get_tls_certificate_filename (args),
               is_equal_to_string ("/path/to/cert.pem"));

  args->ssl_certificate_filename = NULL;
  assert_that (gsad_args_get_tls_certificate_filename (args), is_null);

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_tls_private_key_filename)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_tls_private_key_filename (args),
               is_equal_to_string (DEFAULT_GSAD_TLS_PRIVATE_KEY));

  g_free (args->ssl_private_key_filename);
  args->ssl_private_key_filename = "/path/to/key.pem";
  assert_that (gsad_args_get_tls_private_key_filename (args),
               is_equal_to_string ("/path/to/key.pem"));

  args->ssl_private_key_filename = NULL;
  assert_that (gsad_args_get_tls_private_key_filename (args), is_null);

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_http_x_frame_options)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_http_x_frame_options (args),
               is_equal_to_string (DEFAULT_GSAD_X_FRAME_OPTIONS));

  g_free (args->http_frame_opts);
  args->http_frame_opts = "DENY";
  assert_that (gsad_args_get_http_x_frame_options (args),
               is_equal_to_string ("DENY"));

  args->http_frame_opts = NULL;
  assert_that (gsad_args_get_http_x_frame_options (args), is_null);

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_http_content_security_policy)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_http_content_security_policy (args),
               is_equal_to_string (DEFAULT_GSAD_CONTENT_SECURITY_POLICY));

  g_free (args->http_csp);
  args->http_csp = "default-src 'self'";
  assert_that (gsad_args_get_http_content_security_policy (args),
               is_equal_to_string ("default-src 'self'"));

  args->http_csp = NULL;
  assert_that (gsad_args_get_http_content_security_policy (args), is_null);

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_http_coep)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_http_coep (args), is_null);

  g_free (args->http_coep);
  args->http_coep = "require-corp";
  assert_that (gsad_args_get_http_coep (args),
               is_equal_to_string ("require-corp"));

  args->http_coep = NULL;
  assert_that (gsad_args_get_http_coep (args), is_null);

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_http_coop)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_http_coop (args), is_null);

  g_free (args->http_coop);
  args->http_coop = "same-origin";
  assert_that (gsad_args_get_http_coop (args),
               is_equal_to_string ("same-origin"));

  args->http_coop = NULL;
  assert_that (gsad_args_get_http_coop (args), is_null);

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_http_corp)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_http_corp (args), is_null);

  g_free (args->http_corp);
  args->http_corp = "same-origin";
  assert_that (gsad_args_get_http_corp (args),
               is_equal_to_string ("same-origin"));

  args->http_corp = NULL;
  assert_that (gsad_args_get_http_corp (args), is_null);

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_http_cors_origin)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_http_cors_origin (args), is_null);

  g_free (args->http_cors);
  args->http_cors = "https://example.com";
  assert_that (gsad_args_get_http_cors_origin (args),
               is_equal_to_string ("https://example.com"));

  args->http_cors = NULL;
  assert_that (gsad_args_get_http_cors_origin (args), is_null);

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_tls_debug_level)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_tls_debug_level (args), is_equal_to (0));

  args->debug_tls = 3;
  assert_that (gsad_args_get_tls_debug_level (args), is_equal_to (3));

  args->debug_tls = 0;
  assert_that (gsad_args_get_tls_debug_level (args), is_equal_to (0));

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_user_session_limit)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_user_session_limit (args),
               is_equal_to (DEFAULT_USER_SESSION_LIMIT));

  args->user_session_limit = 5;
  assert_that (gsad_args_get_user_session_limit (args), is_equal_to (5));

  args->user_session_limit = 0;
  assert_that (gsad_args_get_user_session_limit (args), is_equal_to (0));

  args->user_session_limit = -1;
  assert_that (gsad_args_get_user_session_limit (args),
               is_equal_to (DEFAULT_USER_SESSION_LIMIT));

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_listen_addresses)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_listen_addresses (args), is_null);

  g_strfreev (args->gsad_address_string);
  args->gsad_address_string = (char *[]){"127.0.0.1", "::1"};
  char **listen_addresses = gsad_args_get_listen_addresses (args);
  assert_that (listen_addresses, is_not_null);
  assert_that (listen_addresses[0], is_equal_to_string ("127.0.0.1"));
  assert_that (listen_addresses[1], is_equal_to_string ("::1"));
  args->gsad_address_string = NULL;
  gsad_args_free (args);
}

Ensure (gsad_args, should_get_manager_unix_socket_path)
{
  gsad_args_t *args = gsad_args_new ();
  gchar *manager_unix_socket_default_path =
    g_build_filename (GVMD_RUN_DIR, "gvmd.sock", NULL);

  assert_that (gsad_args_get_manager_unix_socket_path (args),
               is_equal_to_string (manager_unix_socket_default_path));

  g_free (args->manager_unix_socket_path);
  args->manager_unix_socket_path = "/var/run/gsad_manager.sock";
  assert_that (gsad_args_get_manager_unix_socket_path (args),
               is_equal_to_string ("/var/run/gsad_manager.sock"));
  args->manager_unix_socket_path = NULL;
  assert_that (gsad_args_get_manager_unix_socket_path (args), is_null);

  g_free (manager_unix_socket_default_path);
  gsad_args_free (args);
}

Ensure (gsad_args, should_get_unix_socket_path)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_unix_socket_path (args), is_null);

  g_free (args->unix_socket_path);
  args->unix_socket_path = "/var/run/gsad.sock";
  assert_that (gsad_args_get_unix_socket_path (args),
               is_equal_to_string ("/var/run/gsad.sock"));
  args->unix_socket_path = NULL;
  assert_that (gsad_args_get_unix_socket_path (args), is_null);

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_unix_socket_owner)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_unix_socket_owner (args), is_null);

  g_free (args->unix_socket_owner);
  args->unix_socket_owner = "gsaduser";
  assert_that (gsad_args_get_unix_socket_owner (args),
               is_equal_to_string ("gsaduser"));
  args->unix_socket_owner = NULL;
  assert_that (gsad_args_get_unix_socket_owner (args), is_null);

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_unix_socket_group)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_unix_socket_group (args), is_null);

  g_free (args->unix_socket_group);
  args->unix_socket_group = "gsadgroup";
  assert_that (gsad_args_get_unix_socket_group (args),
               is_equal_to_string ("gsadgroup"));
  args->unix_socket_group = NULL;
  assert_that (gsad_args_get_unix_socket_group (args), is_null);

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_unix_socket_mode)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_unix_socket_mode (args), is_null);

  g_free (args->unix_socket_mode);
  args->unix_socket_mode = "0660";
  assert_that (gsad_args_get_unix_socket_mode (args),
               is_equal_to_string ("0660"));
  args->unix_socket_mode = NULL;
  assert_that (gsad_args_get_unix_socket_mode (args), is_null);

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_dh_params_filename)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_dh_params_filename (args), is_null);

  g_free (args->dh_params_filename);
  args->dh_params_filename = "/path/to/dhparams.pem";
  assert_that (gsad_args_get_dh_params_filename (args),
               is_equal_to_string ("/path/to/dhparams.pem"));

  args->dh_params_filename = NULL;
  assert_that (gsad_args_get_dh_params_filename (args), is_null);

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_gnutls_priorities)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_gnutls_priorities (args), is_null);

  g_free (args->gnutls_priorities);
  args->gnutls_priorities = "NORMAL:-VERS-ALL:+VERS-TLS1.3";
  assert_that (gsad_args_get_gnutls_priorities (args),
               is_equal_to_string ("NORMAL:-VERS-ALL:+VERS-TLS1.3"));

  args->gnutls_priorities = NULL;
  assert_that (gsad_args_get_gnutls_priorities (args), is_null);

  gsad_args_free (args);
}

Ensure (gsad_args, should_get_drop_privileges)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_get_drop_privileges (args), is_null);

  g_free (args->drop);
  args->drop = "someuser";
  assert_that (gsad_args_get_drop_privileges (args),
               is_equal_to_string ("someuser"));
  args->drop = NULL;
  assert_that (gsad_args_get_drop_privileges (args), is_null);

  gsad_args_free (args);
}

Ensure (gsad_args, should_is_unix_socket_enabled)
{
  gsad_args_t *args = gsad_args_new ();

  g_free (args->unix_socket_path);
  args->unix_socket_path = "/var/run/gsad.sock";
  assert_that (gsad_args_is_unix_socket_enabled (args), is_true);

  args->unix_socket_path = NULL;
  assert_that (gsad_args_is_unix_socket_enabled (args), is_false);

  gsad_args_free (args);
}

Ensure (gsad_args, should_is_https_enabled)
{
  gsad_args_t *args = gsad_args_new ();

  args->http_only = FALSE;
  assert_that (gsad_args_is_https_enabled (args), is_true);

  args->http_only = TRUE;
  assert_that (gsad_args_is_https_enabled (args), is_false);

  gsad_args_free (args);
}

Ensure (gsad_args, should_is_http_strict_transport_security_enabled)
{
  gsad_args_t *args = gsad_args_new ();

  args->http_only = FALSE;
  args->hsts_enabled = TRUE;
  assert_that (gsad_args_is_http_strict_transport_security_enabled (args),
               is_true);

  args->http_only = FALSE;
  args->hsts_enabled = FALSE;
  assert_that (gsad_args_is_http_strict_transport_security_enabled (args),
               is_false);

  args->http_only = TRUE;
  args->hsts_enabled = TRUE;
  assert_that (gsad_args_is_http_strict_transport_security_enabled (args),
               is_false);

  gsad_args_free (args);
}

Ensure (gsad_args, should_is_run_in_foreground_enabled)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_is_run_in_foreground_enabled (args), is_false);

  args->foreground = TRUE;
  assert_that (gsad_args_is_run_in_foreground_enabled (args), is_true);

  args->foreground = FALSE;
  assert_that (gsad_args_is_run_in_foreground_enabled (args), is_false);

  gsad_args_free (args);
}

Ensure (gsad_args, should_is_print_version_enabled)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_is_print_version_enabled (args), is_false);

  args->print_version = TRUE;
  assert_that (gsad_args_is_print_version_enabled (args), is_true);

  args->print_version = FALSE;
  assert_that (gsad_args_is_print_version_enabled (args), is_false);

  gsad_args_free (args);
}

Ensure (gsad_args, should_is_debug_tls_enabled)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_is_debug_tls_enabled (args), is_false);

  args->debug_tls = TRUE;
  assert_that (gsad_args_is_debug_tls_enabled (args), is_true);

  args->debug_tls = FALSE;
  assert_that (gsad_args_is_debug_tls_enabled (args), is_false);

  gsad_args_free (args);
}

Ensure (gsad_args, should_is_ignore_x_real_ip_enabled)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_is_ignore_x_real_ip_enabled (args), is_false);

  args->ignore_x_real_ip = TRUE;
  assert_that (gsad_args_is_ignore_x_real_ip_enabled (args), is_true);

  args->ignore_x_real_ip = FALSE;
  assert_that (gsad_args_is_ignore_x_real_ip_enabled (args), is_false);

  gsad_args_free (args);
}

Ensure (gsad_args, should_is_secure_cookie_enabled)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_is_secure_cookie_enabled (args), is_true);

  args->http_only = TRUE;
  args->secure_cookie = TRUE;
  assert_that (gsad_args_is_secure_cookie_enabled (args), is_true);

  args->http_only = TRUE;
  args->secure_cookie = FALSE;
  assert_that (gsad_args_is_secure_cookie_enabled (args), is_false);

  args->secure_cookie = FALSE;
  args->http_only = FALSE;
  assert_that (gsad_args_is_secure_cookie_enabled (args), is_true);

  args->secure_cookie = FALSE;
  args->http_only = TRUE;
  assert_that (gsad_args_is_secure_cookie_enabled (args), is_false);

  gsad_args_free (args);
}

Ensure (gsad_args, should_is_chroot_enabled)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_is_chroot_enabled (args), is_false);

  args->do_chroot = TRUE;
  assert_that (gsad_args_is_chroot_enabled (args), is_true);

  args->do_chroot = FALSE;
  assert_that (gsad_args_is_chroot_enabled (args), is_false);

  gsad_args_free (args);
}

Ensure (gsad_args, should_is_api_only_enabled)
{
  gsad_args_t *args = gsad_args_new ();
  assert_that (gsad_args_is_api_only_enabled (args), is_false);

  args->api_only = TRUE;
  assert_that (gsad_args_is_api_only_enabled (args), is_true);

  args->api_only = FALSE;
  assert_that (gsad_args_is_api_only_enabled (args), is_false);

  gsad_args_free (args);
}

Ensure (gsad_args, should_validate_tls_private_key)
{
  gsad_args_t *args = gsad_args_new ();
  args->http_only = TRUE;
  g_free (args->ssl_private_key_filename);
  args->ssl_private_key_filename = NULL;
  assert_that (gsad_args_validate_tls_private_key (args), is_equal_to (0));

  args->http_only = FALSE;
  args->ssl_private_key_filename = NULL;
  assert_that (gsad_args_validate_tls_private_key (args), is_equal_to (1));

  args->http_only = FALSE;
  g_free (args->ssl_private_key_filename);
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
  g_free (args->ssl_certificate_filename);
  args->ssl_certificate_filename = NULL;
  assert_that (gsad_args_validate_tls_certificate (args), is_equal_to (0));

  args->http_only = FALSE;
  args->ssl_certificate_filename = NULL;
  assert_that (gsad_args_validate_tls_certificate (args), is_equal_to (1));

  args->http_only = FALSE;
  g_free (args->ssl_certificate_filename);
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
  int ret;

  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, gsad_args, should_use_defaults);
  add_test_with_context (suite, gsad_args, should_use_env_variables);
  add_test_with_context (suite, gsad_args, should_parse_client_watch_interval);
  add_test_with_context (suite, gsad_args, should_parse_debug_tls);
  add_test_with_context (suite, gsad_args, should_parse_dh_params_filename);
  add_test_with_context (suite, gsad_args, should_parse_do_chroot);
  add_test_with_context (suite, gsad_args, should_parse_drop);
  add_test_with_context (suite, gsad_args, should_parse_foreground);
  add_test_with_context (suite, gsad_args, should_parse_gnu_tls_priorities);
  add_test_with_context (suite, gsad_args, should_parse_gsad_address_strings);
  add_test_with_context (suite, gsad_args,
                         should_parse_gsad_address_strings_multiple);
  add_test_with_context (suite, gsad_args,
                         should_parse_gsad_manager_unix_socket_path);
  add_test_with_context (suite, gsad_args, should_parse_gsad_port);
  add_test_with_context (suite, gsad_args, should_parse_gsad_redirect_port);
  add_test_with_context (suite, gsad_args,
                         should_parse_gsad_user_session_limit);
  add_test_with_context (suite, gsad_args, should_parse_hsts_enabled);
  add_test_with_context (suite, gsad_args, should_parse_hsts_max_age);
  add_test_with_context (suite, gsad_args, should_parse_http_coep);
  add_test_with_context (suite, gsad_args, should_parse_http_coop);
  add_test_with_context (suite, gsad_args, should_parse_http_corp);
  add_test_with_context (suite, gsad_args, should_parse_http_cors);
  add_test_with_context (suite, gsad_args, should_parse_http_csp);
  add_test_with_context (suite, gsad_args, should_parse_frame_opts);
  add_test_with_context (suite, gsad_args, should_parse_http_only);
  add_test_with_context (suite, gsad_args, should_parse_ignore_x_real_ip);
  add_test_with_context (suite, gsad_args, should_parse_no_redirect);
  add_test_with_context (suite, gsad_args,
                         should_parse_per_ip_connection_limit);
  add_test_with_context (suite, gsad_args, should_parse_print_version);
  add_test_with_context (suite, gsad_args, should_parse_secure_cookie);
  add_test_with_context (suite, gsad_args,
                         should_parse_tls_certificate_filename);
  add_test_with_context (suite, gsad_args,
                         should_parse_tls_private_key_filename);
  add_test_with_context (suite, gsad_args, should_parse_timeout);
  add_test_with_context (suite, gsad_args, should_parse_unix_socket_group);
  add_test_with_context (suite, gsad_args, should_parse_unix_socket_mode);
  add_test_with_context (suite, gsad_args, should_parse_unix_socket_owner);
  add_test_with_context (suite, gsad_args, should_parse_unix_socket_path);
  add_test_with_context (suite, gsad_args, should_parse_verbose);
  add_test_with_context (suite, gsad_args, should_parse_log_config_filename);
  add_test_with_context (suite, gsad_args, should_parse_pid_filename);
  add_test_with_context (suite, gsad_args,
                         should_parse_static_content_directory);
  add_test_with_context (suite, gsad_args, should_parse_api_only);
  add_test_with_context (suite, gsad_args, should_parse_jwt_requested);

  add_test_with_context (suite, gsad_args, should_is_redirect_enabled);
  add_test_with_context (suite, gsad_args, should_is_unix_socket_enabled);
  add_test_with_context (suite, gsad_args, should_is_https_enabled);
  add_test_with_context (suite, gsad_args,
                         should_is_http_strict_transport_security_enabled);
  add_test_with_context (suite, gsad_args, should_is_run_in_foreground_enabled);
  add_test_with_context (suite, gsad_args, should_is_print_version_enabled);
  add_test_with_context (suite, gsad_args, should_is_debug_tls_enabled);
  add_test_with_context (suite, gsad_args, should_is_ignore_x_real_ip_enabled);
  add_test_with_context (suite, gsad_args, should_is_secure_cookie_enabled);
  add_test_with_context (suite, gsad_args, should_is_chroot_enabled);
  add_test_with_context (suite, gsad_args, should_is_api_only_enabled);

  add_test_with_context (suite, gsad_args, should_validate_session_timout);
  add_test_with_context (suite, gsad_args, should_validate_port);
  add_test_with_context (suite, gsad_args, should_validate_redirect_port);
  add_test_with_context (suite, gsad_args, should_validate_tls_private_key);
  add_test_with_context (suite, gsad_args, should_validate_tls_certificate);

  add_test_with_context (suite, gsad_args, should_get_port);
  add_test_with_context (suite, gsad_args, should_get_redirect_port);
  add_test_with_context (suite, gsad_args,
                         should_get_http_strict_transport_security_max_age);
  add_test_with_context (suite, gsad_args, should_get_per_ip_connection_limit);
  add_test_with_context (suite, gsad_args, should_get_client_watch_interval);
  add_test_with_context (suite, gsad_args, should_get_session_timeout);
  add_test_with_context (suite, gsad_args, should_get_tls_certificate_filename);
  add_test_with_context (suite, gsad_args, should_get_tls_private_key_filename);
  add_test_with_context (suite, gsad_args, should_get_http_x_frame_options);
  add_test_with_context (suite, gsad_args,
                         should_get_http_content_security_policy);
  add_test_with_context (suite, gsad_args, should_get_http_coep);
  add_test_with_context (suite, gsad_args, should_get_http_coop);
  add_test_with_context (suite, gsad_args, should_get_http_corp);
  add_test_with_context (suite, gsad_args, should_get_http_cors_origin);
  add_test_with_context (suite, gsad_args, should_get_tls_debug_level);
  add_test_with_context (suite, gsad_args, should_get_user_session_limit);
  add_test_with_context (suite, gsad_args, should_get_listen_addresses);
  add_test_with_context (suite, gsad_args, should_get_manager_unix_socket_path);
  add_test_with_context (suite, gsad_args, should_get_unix_socket_path);
  add_test_with_context (suite, gsad_args, should_get_unix_socket_owner);
  add_test_with_context (suite, gsad_args, should_get_unix_socket_group);
  add_test_with_context (suite, gsad_args, should_get_unix_socket_mode);
  add_test_with_context (suite, gsad_args, should_get_dh_params_filename);
  add_test_with_context (suite, gsad_args, should_get_gnutls_priorities);
  add_test_with_context (suite, gsad_args, should_get_drop_privileges);

  add_test_with_context (suite, gsad_args, should_free_gsad_args);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
