/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_session.h"
#include "gsad_session_internal.h"
#include "gsad_user.h"
#include "gsad_user_internal.h"

#include <cgreen/cgreen.h>

int
logout_gmp (const gchar *username, const gchar *password)
{
  return 0;
}

void
gsad_user_session_renew_timeout (gsad_user_t *user)
{
  user->time = 0;
}

Describe (gsad_session);
BeforeEach (gsad_session)
{
  gsad_session_init ();
}
AfterEach (gsad_session)
{
  gsad_session_cleanup ();
}

Ensure (gsad_session, should_add_and_get_user)
{
  gsad_user_t *user =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");

  const gchar *token = gsad_user_get_token (user);
  gsad_session_add_user (user);

  assert_that (gsad_session_get_user_count (), is_equal_to (1));

  gsad_user_t *retrieved_user = gsad_session_get_user_by_id (token);
  assert_that (retrieved_user, is_not_null);
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
  gsad_user_free (retrieved_user);
}

Ensure (gsad_session, should_allow_to_add_user_twice)
{
  gsad_user_t *user =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");
  gsad_user_t *user_copy = gsad_user_copy (user);

  gsad_session_add_user (user);
  assert_that (gsad_session_get_user_count (), is_equal_to (1));
  gsad_session_add_user (user_copy);
  assert_that (gsad_session_get_user_count (), is_equal_to (1));

  gsad_user_t *retrieved_user =
    gsad_session_get_user_by_id (gsad_user_get_token (user));
  assert_that (retrieved_user, is_not_null);

  gsad_user_free (retrieved_user);

  gsad_user_t *user2 =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");
  gsad_session_add_user (user2);

  assert_that (gsad_session_get_user_count (), is_equal_to (2));
  retrieved_user = gsad_session_get_user_by_id (gsad_user_get_token (user2));
  assert_that (retrieved_user, is_not_null);

  gsad_user_free (retrieved_user);
  gsad_user_free (user_copy);
  gsad_user_free (user2);
  gsad_user_free (user);
}

Ensure (gsad_session, should_allow_to_add_null_user)
{
  gsad_session_add_user (NULL);
  assert_that (gsad_session_get_user_count (), is_equal_to (0));
}

Ensure (gsad_session, should_allow_to_get_users_by_username)
{
  gsad_user_t *user1 =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");
  gsad_user_t *user2 =
    gsad_user_new_with_data ("username1", "password2", "timezone2",
                             "capabilities2", "language2", "address2", "jwt2");
  gsad_user_t *user3 =
    gsad_user_new_with_data ("username2", "password3", "timezone3",
                             "capabilities3", "language3", "address3", "jwt3");

  gsad_session_add_user (user1);
  gsad_session_add_user (user2);
  gsad_session_add_user (user3);

  GList *users = gsad_session_get_users_by_username ("username1");
  assert_that (g_list_length (users), is_equal_to (2));

  GList *first = users;
  assert_that (gsad_user_get_password ((gsad_user_t *) first->data),
               is_equal_to_string ("password2"));
  first = first->next;
  assert_that (gsad_user_get_password ((gsad_user_t *) first->data),
               is_equal_to_string ("password1"));

  g_list_free_full (users, (GDestroyNotify) gsad_user_free);

  gsad_user_free (user1);
  gsad_user_free (user2);
  gsad_user_free (user3);
}

Ensure (gsad_session,
        should_allow_to_call_gsad_session_get_user_by_id_with_null)
{
  gsad_user_t *retrieved_user = gsad_session_get_user_by_id (NULL);
  assert_that (retrieved_user, is_null);
}

Ensure (gsad_session,
        should_allow_to_call_gsad_session_get_users_by_username_with_null)
{
  GList *users = gsad_session_get_users_by_username (NULL);
  assert_that (users, is_null);
}

Ensure (
  gsad_session,
  should_allow_to_call_gsad_session_get_users_by_username_with_no_matching_user)
{
  GList *users = gsad_session_get_users_by_username ("nonexistent_username");
  assert_that (users, is_null);
}

Ensure (gsad_session, should_allow_to_remove_user)
{
  gsad_user_t *user =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");

  gsad_session_add_user (user);

  assert_that (gsad_session_get_user_count (), is_equal_to (1));

  gsad_session_remove_user (user);

  assert_that (gsad_session_get_user_count (), is_equal_to (0));

  gsad_user_free (user);
}

Ensure (gsad_session, should_allow_to_remove_user_with_null)
{
  gsad_session_remove_user (NULL);
  assert_that (gsad_session_get_user_count (), is_equal_to (0));
}

Ensure (gsad_session, should_remove_other_sessions)
{
  gsad_user_t *user1 =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");
  gsad_user_t *user2 =
    gsad_user_new_with_data ("username1", "password2", "timezone2",
                             "capabilities2", "language2", "address2", "jwt2");
  gsad_user_t *user3 =
    gsad_user_new_with_data ("username1", "password3", "timezone3",
                             "capabilities3", "language3", "address3", "jwt3");

  gsad_session_add_user (user1);
  gsad_session_add_user (user2);
  gsad_session_add_user (user3);

  assert_that (gsad_session_get_user_count (), is_equal_to (3));

  gsad_session_remove_other_sessions (gsad_user_get_token (user1),
                                      gsad_user_get_username (user1));

  assert_that (gsad_session_get_user_count (), is_equal_to (1));

  GList *users = gsad_session_get_users_by_username ("username1");
  assert_that (g_list_length (users), is_equal_to (1));

  g_list_free_full (users, (GDestroyNotify) gsad_user_free);

  gsad_user_free (user1);
  gsad_user_free (user2);
  gsad_user_free (user3);
}

Ensure (gsad_session, should_replace_user)
{
  gsad_user_t *user1 =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");
  gsad_user_t *user2 = gsad_user_copy (user1);
  gsad_user_set_password (user2, "password2");

  assert_string_equal (gsad_user_get_token (user1),
                       gsad_user_get_token (user2));

  gsad_session_add_user (user1);
  assert_that (gsad_session_get_user_count (), is_equal_to (1));

  gsad_session_replace_user_if_exists (user2);
  assert_that (gsad_session_get_user_count (), is_equal_to (1));

  gsad_user_t *retrieved_user =
    gsad_session_get_user_by_id (gsad_user_get_token (user1));
  assert_that (retrieved_user, is_not_null);
  assert_that (gsad_user_get_password (retrieved_user),
               is_equal_to_string ("password2"));

  gsad_user_free (retrieved_user);
  gsad_user_free (user1);
  gsad_user_free (user2);
}

Ensure (gsad_session, should_not_replace_user_if_not_exists)
{
  gsad_user_t *user1 =
    gsad_user_new_with_data ("username1", "password1", "timezone1",
                             "capabilities1", "language1", "address1", "jwt1");
  gsad_user_t *user2 =
    gsad_user_new_with_data ("username1", "password2", "timezone2",
                             "capabilities2", "language2", "address2", "jwt2");

  assert_string_not_equal (gsad_user_get_token (user1),
                           gsad_user_get_token (user2));

  gsad_session_replace_user_if_exists (user1);
  assert_that (gsad_session_get_user_count (), is_equal_to (0));

  gsad_session_add_user (user1);
  assert_that (gsad_session_get_user_count (), is_equal_to (1));

  gsad_session_replace_user_if_exists (user2);
  assert_that (gsad_session_get_user_count (), is_equal_to (1));

  gsad_user_t *retrieved_user;
  retrieved_user = gsad_session_get_user_by_id (gsad_user_get_token (user2));
  assert_that (retrieved_user, is_null);

  retrieved_user = gsad_session_get_user_by_id (gsad_user_get_token (user1));
  assert_that (retrieved_user, is_not_null);
  assert_that (gsad_user_get_password (retrieved_user),
               is_equal_to_string ("password1"));

  gsad_user_free (retrieved_user);
  gsad_user_free (user1);
  gsad_user_free (user2);
}

int
main (int argc, char **argv)
{
  int ret;

  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, gsad_session, should_add_and_get_user);
  add_test_with_context (suite, gsad_session, should_allow_to_add_user_twice);
  add_test_with_context (suite, gsad_session, should_allow_to_add_null_user);
  add_test_with_context (suite, gsad_session,
                         should_allow_to_get_users_by_username);
  add_test_with_context (
    suite, gsad_session,
    should_allow_to_call_gsad_session_get_user_by_id_with_null);
  add_test_with_context (
    suite, gsad_session,
    should_allow_to_call_gsad_session_get_users_by_username_with_null);
  add_test_with_context (
    suite, gsad_session,
    should_allow_to_call_gsad_session_get_users_by_username_with_no_matching_user);
  add_test_with_context (suite, gsad_session, should_allow_to_remove_user);
  add_test_with_context (suite, gsad_session,
                         should_allow_to_remove_user_with_null);
  add_test_with_context (suite, gsad_session, should_remove_other_sessions);
  add_test_with_context (suite, gsad_session, should_replace_user);
  add_test_with_context (suite, gsad_session,
                         should_not_replace_user_if_not_exists);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
