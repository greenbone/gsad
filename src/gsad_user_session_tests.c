/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_session.h"
#include "gsad_session_internal.h"
#include "gsad_settings.h"
#include "gsad_user_internal.h"
#include "gsad_user_session.h"

#include <cgreen/cgreen.h>

int
logout_gmp (const gchar *username, const gchar *password)
{
  return 0;
}

Describe (gsad_user_session);
BeforeEach (gsad_user_session)
{
  gsad_session_init ();
}
AfterEach (gsad_user_session)
{
  gsad_session_cleanup ();
}

Ensure (gsad_user_session, should_allow_to_add_user)
{
  gsad_user_t *user =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");

  int ret = gsad_user_session_add (user);
  assert_that (ret, is_equal_to (0));
  assert_that (gsad_session_get_user_count (), is_equal_to (1));

  gsad_user_t *retrieved_user = NULL;
  ret = gsad_user_session_find (
    gsad_user_get_cookie (user), gsad_user_get_token (user),
    gsad_user_get_client_address (user), &retrieved_user);
  assert_that (ret, is_equal_to (0));
  assert_that (retrieved_user, is_not_null);
  assert_that (retrieved_user, is_not_equal_to (user));
  assert_that (gsad_user_get_username (retrieved_user),
               is_equal_to_string ("username1"));
  assert_that (gsad_user_get_password (retrieved_user),
               is_equal_to_string ("password1"));
  assert_that (gsad_user_get_timezone (retrieved_user),
               is_equal_to_string ("timezone1"));
  assert_that (gsad_user_get_capabilities (retrieved_user),
               is_equal_to_string ("capabilities1"));
  assert_that (gsad_user_get_language (retrieved_user),
               is_equal_to_string ("language1"));
  assert_that (gsad_user_get_client_address (retrieved_user),
               is_equal_to_string ("address1"));
  assert_that (gsad_user_get_jwt (retrieved_user), is_equal_to_string ("jwt1"));

  gsad_user_free (user);
}

Ensure (gsad_user_session,
        should_not_allow_to_add_user_if_session_limit_exceeded)
{
  gsad_user_t *user1 =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");
  gsad_user_t *user2 =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");
  gsad_user_t *user3 =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");

  gsad_settings_t *gsad_global_settings = gsad_settings_get_global_settings ();
  gsad_settings_set_user_session_limit (gsad_global_settings, 2);

  int ret = gsad_user_session_add (user1);
  assert_that (ret, is_equal_to (0));
  assert_that (gsad_session_get_user_count (), is_equal_to (1));

  ret = gsad_user_session_add (user2);
  assert_that (ret, is_equal_to (0));
  assert_that (gsad_session_get_user_count (), is_equal_to (2));

  ret = gsad_user_session_add (user3);
  assert_that (ret, is_equal_to (1));
  assert_that (gsad_session_get_user_count (), is_equal_to (2));

  gsad_user_free (user1);
  gsad_user_free (user2);
  gsad_user_free (user3);
}

Ensure (gsad_user_session, should_remove_expired_sessions)
{
  gsad_user_t *user1 =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");
  gsad_user_t *user2 =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");
  gsad_user_t *user3 =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");

  int ret = gsad_user_session_add (user1);
  assert_that (ret, is_equal_to (0));
  ret = gsad_user_session_add (user2);
  assert_that (ret, is_equal_to (0));
  assert_that (gsad_session_get_user_count (), is_equal_to (2));

  gsad_settings_t *gsad_global_settings = gsad_settings_get_global_settings ();
  gsad_settings_set_session_timeout (gsad_global_settings, -10);

  ret = gsad_user_session_add (user3);
  assert_that (ret, is_equal_to (0));
  assert_that (gsad_session_get_user_count (), is_equal_to (1));

  gsad_user_free (user1);
  gsad_user_free (user2);
  gsad_user_free (user3);
}

Ensure (gsad_user_session, should_check_session_expiration)
{
  gsad_settings_t *gsad_global_settings = gsad_settings_get_global_settings ();
  gsad_user_t *user =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");

  gsad_settings_set_session_timeout (gsad_global_settings, 100);

  assert_that (gsad_user_session_is_expired (user), is_false);

  gsad_settings_set_session_timeout (gsad_global_settings, -10);

  assert_that (gsad_user_session_is_expired (user), is_true);

  gsad_user_free (user);
}

Ensure (gsad_user_session, should_allow_to_get_the_timeout)
{
  int timeout_in_minutes = 10;
  gsad_settings_t *gsad_global_settings = gsad_settings_get_global_settings ();
  gsad_settings_set_session_timeout (gsad_global_settings, timeout_in_minutes);
  gsad_user_t *user =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");
  user->time = 0;
  assert_equal (gsad_user_get_time (user), 0);
  assert_equal (gsad_user_session_get_timeout (user), timeout_in_minutes * 60);

  gsad_user_free (user);
}

Ensure (gsad_user_session,
        should_return_bad_missing_token_for_user_find_without_token)
{
  gsad_user_t *user_return = NULL;
  int ret = gsad_user_session_find ("cookie", NULL, "address", &user_return);
  assert_that (ret, is_equal_to (USER_BAD_MISSING_TOKEN));
  assert_that (user_return, is_null);
}

Ensure (gsad_user_session,
        should_return_expired_token_for_user_find_with_unknown_token)
{
  gsad_user_t *user_return = NULL;
  int ret =
    gsad_user_session_find ("cookie", "unknown_token", "address", &user_return);
  assert_that (ret, is_equal_to (USER_EXPIRED_TOKEN));
  assert_that (user_return, is_null);
}

Ensure (gsad_user_session,
        should_return_expired_token_for_user_find_expired_session)
{
  gsad_user_t *user =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");
  gsad_user_session_add (user);
  assert_that (gsad_session_get_user_count (), is_equal_to (1));

  gsad_settings_t *gsad_global_settings = gsad_settings_get_global_settings ();
  gsad_settings_set_session_timeout (gsad_global_settings, -10);

  gsad_user_t *user_return = NULL;
  int ret = gsad_user_session_find ("cookie", gsad_user_get_token (user),
                                    "address", &user_return);
  assert_that (gsad_session_get_user_count (), is_equal_to (0));
  assert_that (ret, is_equal_to (USER_EXPIRED_TOKEN));
  assert_that (user_return, is_null);

  gsad_user_free (user);
}

Ensure (gsad_user_session,
        should_return_bad_missing_cookie_for_user_find_with_missing_cookie)
{
  gsad_user_t *user =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");
  gsad_user_session_add (user);
  assert_that (gsad_session_get_user_count (), is_equal_to (1));

  gsad_user_t *user_return = NULL;
  int ret = gsad_user_session_find (NULL, gsad_user_get_token (user), "address",
                                    &user_return);
  assert_that (gsad_session_get_user_count (), is_equal_to (1));
  assert_that (ret, is_equal_to (USER_BAD_MISSING_COOKIE));
  assert_that (user_return, is_null);

  gsad_user_free (user);
}

Ensure (gsad_user_session,
        should_return_bad_missing_cookie_for_user_find_with_cookie_mismatch)
{
  gsad_user_t *user =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");
  gsad_user_session_add (user);
  assert_that (gsad_session_get_user_count (), is_equal_to (1));

  gsad_user_t *user_return = NULL;
  int ret = gsad_user_session_find (
    "mismatched_cookie", gsad_user_get_token (user), "address", &user_return);
  assert_that (gsad_session_get_user_count (), is_equal_to (1));
  assert_that (ret, is_equal_to (USER_BAD_MISSING_COOKIE));
  assert_that (user_return, is_null);

  gsad_user_free (user);
}

Ensure (gsad_user_session,
        should_return_ip_address_missmatch_for_user_find_with_no_address)
{
  gsad_user_t *user =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");
  gsad_user_session_add (user);
  assert_that (gsad_session_get_user_count (), is_equal_to (1));

  gsad_user_t *user_return = NULL;
  int ret =
    gsad_user_session_find (gsad_user_get_cookie (user),
                            gsad_user_get_token (user), NULL, &user_return);
  assert_that (gsad_session_get_user_count (), is_equal_to (1));
  assert_that (ret, is_equal_to (USER_IP_ADDRESS_MISSMATCH));
  assert_that (user_return, is_null);

  gsad_user_free (user);
}

Ensure (
  gsad_user_session,
  should_return_ip_address_missmatch_for_user_find_with_ip_address_mismatch)
{
  gsad_user_t *user =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");
  gsad_user_session_add (user);
  assert_that (gsad_session_get_user_count (), is_equal_to (1));

  gsad_user_t *user_return = NULL;
  int ret = gsad_user_session_find (gsad_user_get_cookie (user),
                                    gsad_user_get_token (user),
                                    "mismatched_address", &user_return);
  assert_that (gsad_session_get_user_count (), is_equal_to (1));
  assert_that (ret, is_equal_to (USER_IP_ADDRESS_MISSMATCH));
  assert_that (user_return, is_null);

  gsad_user_free (user);
}

Ensure (gsad_user_session, should_allow_to_find_user)
{
  gsad_settings_t *gsad_global_settings = gsad_settings_get_global_settings ();
  gsad_settings_set_session_timeout (gsad_global_settings, 600);
  gsad_user_t *user =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");
  // set the user time to 10 seconds ago to test
  // that the session of the retrieved user is not renewed when found
  user->time = user->time - 10;
  gsad_user_session_add (user);
  assert_that (gsad_session_get_user_count (), is_equal_to (1));

  gsad_user_t *user_return = NULL;
  int ret = gsad_user_session_find (gsad_user_get_cookie (user),
                                    gsad_user_get_token (user), "address1",
                                    &user_return);
  assert_that (gsad_session_get_user_count (), is_equal_to (1));
  assert_that (ret, is_equal_to (USER_OK));
  assert_that (user_return, is_not_null);

  assert_that (gsad_user_get_username (user_return),
               is_equal_to_string ("username1"));
  assert_that (gsad_user_get_password (user_return),
               is_equal_to_string ("password1"));
  assert_that (gsad_user_get_timezone (user_return),
               is_equal_to_string ("timezone1"));
  assert_that (gsad_user_get_capabilities (user_return),
               is_equal_to_string ("capabilities1"));
  assert_that (gsad_user_get_language (user_return),
               is_equal_to_string ("language1"));
  assert_that (gsad_user_get_client_address (user_return),
               is_equal_to_string ("address1"));
  assert_that (gsad_user_get_jwt (user_return), is_equal_to_string ("jwt1"));
  assert_that (gsad_user_get_time (user_return),
               is_equal_to (gsad_user_get_time (user)));

  gsad_user_free (user_return);
  gsad_user_free (user);
}

Ensure (gsad_user_session, should_allow_to_renew_timeout_with_null_user)
{
  gsad_user_session_renew_timeout (NULL);
  assert_that (gsad_session_get_user_count (), is_equal_to (0));
}

Ensure (gsad_user_session, should_allow_to_renew_timeout)
{
  gsad_user_t *user =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");
  user->time = 0;
  assert_equal (gsad_user_get_time (user), 0);
  gsad_session_add_user (user);

  gsad_user_t *retrieved_user;
  retrieved_user = gsad_session_get_user_by_id (gsad_user_get_token (user));
  assert_that (retrieved_user, is_not_null);
  assert_that (gsad_user_get_time (retrieved_user), is_equal_to (0));

  gsad_user_free (retrieved_user);

  gsad_user_session_renew_timeout (user);

  assert_that (gsad_user_get_time (user), is_not_equal_to (0));

  retrieved_user = gsad_session_get_user_by_id (gsad_user_get_token (user));
  assert_that (retrieved_user, is_not_null);
  assert_that (gsad_user_get_time (retrieved_user), is_not_equal_to (0));

  gsad_user_free (retrieved_user);
  gsad_user_free (user);
}

int
main (int argc, char **argv)
{
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, gsad_user_session, should_allow_to_add_user);
  add_test_with_context (
    suite, gsad_user_session,
    should_not_allow_to_add_user_if_session_limit_exceeded);
  add_test_with_context (suite, gsad_user_session,
                         should_remove_expired_sessions);
  add_test_with_context (suite, gsad_user_session,
                         should_check_session_expiration);
  add_test_with_context (suite, gsad_user_session,
                         should_allow_to_get_the_timeout);
  add_test_with_context (
    suite, gsad_user_session,
    should_return_bad_missing_token_for_user_find_without_token);
  add_test_with_context (
    suite, gsad_user_session,
    should_return_expired_token_for_user_find_with_unknown_token);
  add_test_with_context (
    suite, gsad_user_session,
    should_return_expired_token_for_user_find_expired_session);
  add_test_with_context (
    suite, gsad_user_session,
    should_return_bad_missing_cookie_for_user_find_with_missing_cookie);
  add_test_with_context (
    suite, gsad_user_session,
    should_return_bad_missing_cookie_for_user_find_with_cookie_mismatch);
  add_test_with_context (
    suite, gsad_user_session,
    should_return_ip_address_missmatch_for_user_find_with_no_address);
  add_test_with_context (
    suite, gsad_user_session,
    should_return_ip_address_missmatch_for_user_find_with_ip_address_mismatch);
  add_test_with_context (suite, gsad_user_session, should_allow_to_find_user);
  add_test_with_context (suite, gsad_user_session,
                         should_allow_to_renew_timeout_with_null_user);
  add_test_with_context (suite, gsad_user_session,
                         should_allow_to_renew_timeout);

  int ret = run_test_suite (suite, create_text_reporter ());
  destroy_test_suite (suite);
  return ret;
}
