/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_settings.h"

#include <cgreen/cgreen.h>

Describe (gsad_settings);

BeforeEach (gsad_settings)
{
}
AfterEach (gsad_settings)
{
}

Ensure (gsad_settings, should_use_defaults)
{
  gsad_settings_t *settings = gsad_settings_new ();

  assert_that (settings, is_not_null);
  assert_that (gsad_settings_is_api_only_enabled (settings), is_false);
  assert_that (gsad_settings_is_http_x_real_ip_enabled (settings), is_true);
  assert_that (gsad_settings_get_per_ip_connection_limit (settings),
               is_equal_to (DEFAULT_PER_IP_CONNECTION_LIMIT));
  assert_that (gsad_settings_is_unix_socket_enabled (settings), is_false);
  assert_that (gsad_settings_get_user_session_limit (settings),
               is_equal_to (DEFAULT_USER_SESSION_LIMIT));
  assert_that (gsad_settings_get_session_timeout (settings),
               is_equal_to (DEFAULT_SESSION_TIMEOUT));
  assert_that (gsad_settings_enable_secure_cookie (settings), is_false);
  assert_that (gsad_settings_get_http_content_security_policy (settings),
               is_null);
  assert_that (gsad_settings_get_http_x_frame_options (settings), is_null);
  assert_that (gsad_settings_get_http_cors_origin (settings), is_null);
  assert_that (gsad_settings_get_http_strict_transport_security (settings),
               is_null);
  assert_that (gsad_settings_get_vendor_version (settings),
               is_equal_to_string (""));
  assert_that (gsad_settings_get_client_watch_interval (settings),
               is_equal_to (DEFAULT_CLIENT_WATCH_INTERVAL));
  assert_that (gsad_settings_get_log_config_filename (settings), is_null);

  gsad_settings_free (settings);
}

Ensure (gsad_settings, should_set_session_timeout)
{
  gsad_settings_t *settings = gsad_settings_new ();

  assert_that (gsad_settings_get_session_timeout (settings),
               is_equal_to (DEFAULT_SESSION_TIMEOUT));

  gsad_settings_set_session_timeout (settings, 30);
  assert_that (gsad_settings_get_session_timeout (settings), is_equal_to (30));

  gsad_settings_set_session_timeout (settings, -1);
  assert_that (gsad_settings_get_session_timeout (settings), is_equal_to (-1));

  gsad_settings_free (settings);
}

Ensure (gsad_settings, should_enable_secure_cookie)
{
  gsad_settings_t *settings = gsad_settings_new ();

  assert_that (gsad_settings_enable_secure_cookie (settings), is_false);

  gsad_settings_set_use_secure_cookie (settings, TRUE);
  assert_that (gsad_settings_enable_secure_cookie (settings), is_true);

  gsad_settings_set_use_secure_cookie (settings, FALSE);
  assert_that (gsad_settings_enable_secure_cookie (settings), is_false);

  gsad_settings_free (settings);
}

Ensure (gsad_settings, should_ignore_x_real_ip_be_enabled)
{
  gsad_settings_t *settings = gsad_settings_new ();

  assert_that (gsad_settings_is_http_x_real_ip_enabled (settings), is_true);

  gsad_settings_set_ignore_http_x_real_ip (settings, TRUE);
  assert_that (gsad_settings_is_http_x_real_ip_enabled (settings), is_false);

  gsad_settings_set_ignore_http_x_real_ip (settings, FALSE);
  assert_that (gsad_settings_is_http_x_real_ip_enabled (settings), is_true);

  gsad_settings_free (settings);
}

Ensure (gsad_settings, should_unix_socket_be_enabled)
{
  gsad_settings_t *settings = gsad_settings_new ();

  assert_that (gsad_settings_is_unix_socket_enabled (settings), is_false);

  gsad_settings_set_unix_socket (settings, 5);
  assert_that (gsad_settings_is_unix_socket_enabled (settings), is_true);

  gsad_settings_set_unix_socket (settings, -1);
  assert_that (gsad_settings_is_unix_socket_enabled (settings), is_false);

  gsad_settings_free (settings);
}

Ensure (gsad_settings, should_set_http_content_security_policy)
{
  gsad_settings_t *settings = gsad_settings_new ();

  assert_that (gsad_settings_get_http_content_security_policy (settings),
               is_null);

  gsad_settings_set_http_content_security_policy (settings,
                                                  "default-src 'self'");
  assert_that (gsad_settings_get_http_content_security_policy (settings),
               is_equal_to_string ("default-src 'self'"));

  gsad_settings_set_http_content_security_policy (settings, NULL);
  assert_that (gsad_settings_get_http_content_security_policy (settings),
               is_null);

  gsad_settings_free (settings);
}

Ensure (gsad_settings, should_set_http_x_frame_options)
{
  gsad_settings_t *settings = gsad_settings_new ();

  assert_that (gsad_settings_get_http_x_frame_options (settings), is_null);

  gsad_settings_set_http_x_frame_options (settings, "DENY");
  assert_that (gsad_settings_get_http_x_frame_options (settings),
               is_equal_to_string ("DENY"));

  gsad_settings_set_http_x_frame_options (settings, NULL);
  assert_that (gsad_settings_get_http_x_frame_options (settings), is_null);

  gsad_settings_free (settings);
}

Ensure (gsad_settings, should_set_http_strict_transport_security)
{
  gsad_settings_t *settings = gsad_settings_new ();

  assert_that (gsad_settings_get_http_strict_transport_security (settings),
               is_null);

  gsad_settings_set_http_strict_transport_security (
    settings, "max-age=31536000; includeSubDomains; preload");
  assert_that (
    gsad_settings_get_http_strict_transport_security (settings),
    is_equal_to_string ("max-age=31536000; includeSubDomains; preload"));

  gsad_settings_set_http_strict_transport_security (settings, NULL);
  assert_that (gsad_settings_get_http_strict_transport_security (settings),
               is_null);

  gsad_settings_free (settings);
}

Ensure (gsad_settings, should_set_http_cors_origin)
{
  gsad_settings_t *settings = gsad_settings_new ();

  assert_that (gsad_settings_get_http_cors_origin (settings), is_null);

  gsad_settings_set_http_cors_origin (settings, "https://example.com");
  assert_that (gsad_settings_get_http_cors_origin (settings),
               is_equal_to_string ("https://example.com"));

  gsad_settings_set_http_cors_origin (settings, NULL);
  assert_that (gsad_settings_get_http_cors_origin (settings), is_null);

  gsad_settings_free (settings);
}

Ensure (gsad_settings, should_set_http_guest_chart_x_frame_options)
{
  gsad_settings_t *settings = gsad_settings_new ();

  assert_that (gsad_settings_get_http_guest_chart_x_frame_options (settings),
               is_null);

  gsad_settings_set_http_guest_chart_x_frame_options (settings, "SAMEORIGIN");
  assert_that (gsad_settings_get_http_guest_chart_x_frame_options (settings),
               is_equal_to_string ("SAMEORIGIN"));

  gsad_settings_set_http_guest_chart_x_frame_options (settings, NULL);
  assert_that (gsad_settings_get_http_guest_chart_x_frame_options (settings),
               is_null);

  gsad_settings_free (settings);
}

Ensure (gsad_settings, should_set_http_guest_chart_content_security_policy)
{
  gsad_settings_t *settings = gsad_settings_new ();

  assert_that (
    gsad_settings_get_http_guest_chart_content_security_policy (settings),
    is_null);

  gsad_settings_set_http_guest_chart_content_security_policy (
    settings, "default-src 'self'");
  assert_that (
    gsad_settings_get_http_guest_chart_content_security_policy (settings),
    is_equal_to_string ("default-src 'self'"));

  gsad_settings_set_http_guest_chart_content_security_policy (settings, NULL);
  assert_that (
    gsad_settings_get_http_guest_chart_content_security_policy (settings),
    is_null);

  gsad_settings_free (settings);
}

Ensure (gsad_settings, should_set_user_session_limit)
{
  gsad_settings_t *settings = gsad_settings_new ();

  assert_that (gsad_settings_get_user_session_limit (settings),
               is_equal_to (0));

  gsad_settings_set_user_session_limit (settings, 5);
  assert_that (gsad_settings_get_user_session_limit (settings),
               is_equal_to (5));

  gsad_settings_set_user_session_limit (settings, -1);
  assert_that (gsad_settings_get_user_session_limit (settings),
               is_equal_to (0));

  gsad_settings_free (settings);
}

Ensure (gsad_settings, should_set_per_ip_connection_limit)
{
  gsad_settings_t *settings = gsad_settings_new ();

  assert_that (gsad_settings_get_per_ip_connection_limit (settings),
               is_equal_to (DEFAULT_PER_IP_CONNECTION_LIMIT));

  gsad_settings_set_per_ip_connection_limit (settings, 10);
  assert_that (gsad_settings_get_per_ip_connection_limit (settings),
               is_equal_to (10));

  gsad_settings_set_per_ip_connection_limit (settings, -1);
  assert_that (gsad_settings_get_per_ip_connection_limit (settings),
               is_equal_to (0));

  gsad_settings_free (settings);
}

Ensure (gsad_settings, should_set_unix_socket)
{
  gsad_settings_t *settings = gsad_settings_new ();

  assert_that (gsad_settings_is_unix_socket_enabled (settings), is_false);

  gsad_settings_set_unix_socket (settings, 5);
  assert_that (gsad_settings_is_unix_socket_enabled (settings), is_true);

  gsad_settings_set_unix_socket (settings, -1);
  assert_that (gsad_settings_is_unix_socket_enabled (settings), is_false);

  gsad_settings_free (settings);
}

Ensure (gsad_settings, should_set_vendor_version)
{
  gsad_settings_t *settings = gsad_settings_new ();

  assert_that (gsad_settings_get_vendor_version (settings),
               is_equal_to_string (""));

  gsad_settings_set_vendor_version (settings, "Greenbone Security Assistant");
  assert_that (gsad_settings_get_vendor_version (settings),
               is_equal_to_string ("Greenbone Security Assistant"));

  gsad_settings_set_vendor_version (settings, "GSA");
  assert_that (gsad_settings_get_vendor_version (settings),
               is_equal_to_string ("GSA"));

  gsad_settings_free (settings);
}

Ensure (gsad_settings, should_set_client_watch_interval)
{
  gsad_settings_t *settings = gsad_settings_new ();

  assert_that (gsad_settings_get_client_watch_interval (settings),
               is_equal_to (DEFAULT_CLIENT_WATCH_INTERVAL));

  gsad_settings_set_client_watch_interval (settings, 30);
  assert_that (gsad_settings_get_client_watch_interval (settings),
               is_equal_to (30));

  gsad_settings_set_client_watch_interval (settings, -1);
  assert_that (gsad_settings_get_client_watch_interval (settings),
               is_equal_to (0));

  gsad_settings_free (settings);
}

Ensure (gsad_settings, should_set_log_config_filename)
{
  gsad_settings_t *settings = gsad_settings_new ();

  assert_that (gsad_settings_get_log_config_filename (settings), is_null);

  gsad_settings_set_log_config_filename (settings, "/etc/gsad.conf");
  assert_that (gsad_settings_get_log_config_filename (settings),
               is_equal_to_string ("/etc/gsad.conf"));

  gsad_settings_set_log_config_filename (settings, NULL);
  assert_that (gsad_settings_get_log_config_filename (settings), is_null);

  gsad_settings_free (settings);
}

Ensure (gsad_settings, should_set_pid_filename)
{
  gsad_settings_t *settings = gsad_settings_new ();

  assert_that (gsad_settings_get_pid_filename (settings), is_null);

  gsad_settings_set_pid_filename (settings, "/var/run/gsad.pid");
  assert_that (gsad_settings_get_pid_filename (settings),
               is_equal_to_string ("/var/run/gsad.pid"));

  gsad_settings_set_pid_filename (settings, NULL);
  assert_that (gsad_settings_get_pid_filename (settings), is_null);

  gsad_settings_free (settings);
}

Ensure (gsad_settings, should_set_api_only)
{
  gsad_settings_t *settings = gsad_settings_new ();

  assert_that (gsad_settings_is_api_only_enabled (settings), is_false);

  gsad_settings_set_api_only (settings, TRUE);
  assert_that (gsad_settings_is_api_only_enabled (settings), is_true);

  gsad_settings_set_api_only (settings, FALSE);
  assert_that (gsad_settings_is_api_only_enabled (settings), is_false);

  gsad_settings_free (settings);
}

int
main (int argc, char **argv)
{
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, gsad_settings, should_use_defaults);
  add_test_with_context (suite, gsad_settings, should_set_session_timeout);
  add_test_with_context (suite, gsad_settings, should_enable_secure_cookie);
  add_test_with_context (suite, gsad_settings,
                         should_ignore_x_real_ip_be_enabled);
  add_test_with_context (suite, gsad_settings, should_unix_socket_be_enabled);
  add_test_with_context (suite, gsad_settings,
                         should_set_http_content_security_policy);
  add_test_with_context (suite, gsad_settings, should_set_http_x_frame_options);
  add_test_with_context (suite, gsad_settings,
                         should_set_http_strict_transport_security);
  add_test_with_context (suite, gsad_settings, should_set_http_cors_origin);
  add_test_with_context (suite, gsad_settings,
                         should_set_http_guest_chart_x_frame_options);
  add_test_with_context (suite, gsad_settings,
                         should_set_http_guest_chart_content_security_policy);
  add_test_with_context (suite, gsad_settings, should_set_vendor_version);
  add_test_with_context (suite, gsad_settings, should_set_user_session_limit);
  add_test_with_context (suite, gsad_settings,
                         should_set_per_ip_connection_limit);
  add_test_with_context (suite, gsad_settings, should_set_unix_socket);
  add_test_with_context (suite, gsad_settings,
                         should_set_client_watch_interval);
  add_test_with_context (suite, gsad_settings, should_set_log_config_filename);
  add_test_with_context (suite, gsad_settings, should_set_pid_filename);
  add_test_with_context (suite, gsad_settings, should_set_api_only);

  int ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);
  return ret;
}
