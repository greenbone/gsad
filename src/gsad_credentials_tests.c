/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_credentials.h"
#include "gsad_user.h"

#include <cgreen/cgreen.h>

Describe (gsad_credentials);

BeforeEach (gsad_credentials)
{
}

AfterEach (gsad_credentials)
{
}

Ensure (gsad_credentials, should_allow_to_create_new_credential)
{
  user_t *user = gsad_user_new_with_data ("test_user", "test_token", "utc", "",
                                          "en", "", "123");
  gsad_credentials_t *credentials = gsad_credentials_new (user, "en");
  user_t *cred_user = gsad_credentials_get_user (credentials);

  assert_that (credentials, is_not_null);
  assert_that (cred_user, is_not_equal_to (user)); // Ensure a copy is made
  assert_that (gsad_user_get_username (cred_user),
               is_equal_to_string ("test_user"));
  assert_that (gsad_user_get_token (cred_user),
               is_equal_to_string (gsad_user_get_token (user)));
  assert_that (gsad_user_get_timezone (cred_user), is_equal_to_string ("utc"));
  assert_that (gsad_user_get_language (cred_user), is_equal_to_string ("en"));
  assert_that (gsad_user_get_jwt (cred_user), is_equal_to_string ("123"));
  assert_that (gsad_credentials_get_language (credentials),
               is_equal_to_string ("en"));

  gsad_credentials_free (credentials);
  gsad_user_free (user);
}

Ensure (gsad_credentials, should_allow_to_free_null_credential)
{
  gsad_credentials_free (NULL);
}

int
main (int argc, char **argv)
{
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, gsad_credentials,
                         should_allow_to_create_new_credential);
  add_test_with_context (suite, gsad_credentials,
                         should_allow_to_free_null_credential);

  int ret = run_test_suite (suite, create_text_reporter ());
  destroy_test_suite (suite);
  return ret;
}
