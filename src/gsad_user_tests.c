/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "gsad_user.h"

#include <cgreen/cgreen.h>

Describe (gsad_user);

BeforeEach (gsad_user)
{
}

AfterEach (gsad_user)
{
}

Ensure (gsad_user, should_create_new_user)
{
  gsad_user_t *user = gsad_user_new ();

  assert_that (user, is_not_null);
  assert_that (gsad_user_get_username (user), is_null);
  assert_that (gsad_user_get_password (user), is_null);
  assert_that (gsad_user_get_timezone (user), is_null);
  assert_that (gsad_user_get_capabilities (user), is_null);
  assert_that (gsad_user_get_language (user), is_null);
  assert_that (gsad_user_get_client_address (user), is_null);
  assert_that (gsad_user_get_jwt (user), is_null);
  assert_that (gsad_user_get_token (user), is_null);
  assert_that (gsad_user_get_cookie (user), is_null);
  assert_that (gsad_user_get_time (user), is_equal_to ((time_t) 0));

  gsad_user_free (user);
}

Ensure (gsad_user, should_create_new_user_with_data)
{
  const gchar *username = "testuser";
  const gchar *password = "testpassword";
  const gchar *timezone = "UTC";
  const gchar *capabilities = "capabilities";
  const gchar *language = "en";
  const gchar *address = "127.0.0.1";
  const gchar *jwt = "jwt_token";

  gsad_user_t *user = gsad_user_new_with_data (
    username, password, timezone, capabilities, language, address, jwt);

  assert_that (user, is_not_null);
  assert_that (gsad_user_get_username (user), is_equal_to_string (username));
  assert_that (gsad_user_get_password (user), is_equal_to_string (password));
  assert_that (gsad_user_get_timezone (user), is_equal_to_string (timezone));
  assert_that (gsad_user_get_capabilities (user),
               is_equal_to_string (capabilities));
  assert_that (gsad_user_get_language (user), is_equal_to_string (language));
  assert_that (gsad_user_get_client_address (user),
               is_equal_to_string (address));
  assert_that (gsad_user_get_jwt (user), is_equal_to_string (jwt));
  assert_that (gsad_user_get_token (user), is_not_null);
  assert_that (gsad_user_get_cookie (user), is_not_null);
  assert_that (gsad_user_get_time (user), is_greater_than (0));

  gsad_user_free (user);
}

Ensure (gsad_user, should_copy_user)
{
  const gchar *username = "testuser";
  const gchar *password = "testpassword";
  const gchar *timezone = "UTC";
  const gchar *capabilities = "capabilities";
  const gchar *language = "en";
  const gchar *address = "127.0.0.1";
  const gchar *jwt = "jwt_token";

  gsad_user_t *user = gsad_user_new_with_data (
    username, password, timezone, capabilities, language, address, jwt);

  gsad_user_t *copy = gsad_user_copy (user);

  assert_that (copy, is_not_null);
  assert_that (copy, is_not_equal_to (user));
  assert_that (gsad_user_get_username (copy), is_equal_to_string (username));
  assert_that (gsad_user_get_password (copy), is_equal_to_string (password));
  assert_that (gsad_user_get_timezone (copy), is_equal_to_string (timezone));
  assert_that (gsad_user_get_capabilities (copy),
               is_equal_to_string (capabilities));
  assert_that (gsad_user_get_language (copy), is_equal_to_string (language));
  assert_that (gsad_user_get_client_address (copy),
               is_equal_to_string (address));
  assert_that (gsad_user_get_jwt (copy), is_equal_to_string (jwt));
  assert_that (gsad_user_get_token (copy), is_not_null);
  assert_that (gsad_user_get_cookie (copy), is_not_null);
  assert_that (gsad_user_get_time (copy), is_greater_than (0));

  gsad_user_free (user);
  gsad_user_free (copy);
}

Ensure (gsad_user, should_copy_null_user)
{
  gsad_user_t *copy = gsad_user_copy (NULL);

  assert_that (copy, is_null);
}

Ensure (gsad_user, should_set_timezone)
{
  gsad_user_t *user = gsad_user_new ();

  const gchar *timezone = "UTC";
  gsad_user_set_timezone (user, timezone);

  assert_that (gsad_user_get_timezone (user), is_equal_to_string (timezone));

  gsad_user_free (user);
}

Ensure (gsad_user, should_set_password)
{
  gsad_user_t *user = gsad_user_new ();

  const gchar *password = "newpassword";
  gsad_user_set_password (user, password);

  assert_that (gsad_user_get_password (user), is_equal_to_string (password));

  gsad_user_free (user);
}

Ensure (gsad_user, should_set_language)
{
  gsad_user_t *user = gsad_user_new ();

  const gchar *language = "en";
  gsad_user_set_language (user, language);

  assert_that (gsad_user_get_language (user), is_equal_to_string (language));

  gsad_user_free (user);
}

Ensure (gsad_user, should_set_username)
{
  gsad_user_t *user = gsad_user_new ();

  const gchar *username = "newuser";
  gsad_user_set_username (user, username);

  assert_that (gsad_user_get_username (user), is_equal_to_string (username));

  gsad_user_free (user);
}

int
main (int argc, char **argv)
{
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, gsad_user, should_create_new_user);
  add_test_with_context (suite, gsad_user, should_create_new_user_with_data);
  add_test_with_context (suite, gsad_user, should_copy_user);
  add_test_with_context (suite, gsad_user, should_copy_null_user);
  add_test_with_context (suite, gsad_user, should_set_timezone);
  add_test_with_context (suite, gsad_user, should_set_password);
  add_test_with_context (suite, gsad_user, should_set_language);
  add_test_with_context (suite, gsad_user, should_set_username);

  int ret = run_test_suite (suite, create_text_reporter ());
  destroy_test_suite (suite);
  return ret;
}
