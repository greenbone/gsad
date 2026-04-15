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
  gsad_credentials_t *credentials = gsad_credentials_new ();

  assert_that (credentials, is_not_null);
  assert_that (gsad_credentials_get_user (credentials), is_null);
  assert_that (gsad_credentials_get_jwt (credentials), is_null);
  gsad_credentials_free (credentials);
}

Ensure (gsad_credentials, should_allow_to_free_null_credential)
{
  gsad_credentials_free (NULL);
}

Ensure (gsad_credentials, should_allow_to_set_user)
{
  gsad_credentials_t *credentials = gsad_credentials_new ();
  gsad_user_t *user = gsad_user_new_with_data (
    "testuser", "testpassword", "UTC", "capabilities", "en", "address", "jwt");

  assert_that (credentials, is_not_null);
  assert_that (gsad_credentials_get_user (credentials), is_null);

  gsad_credentials_set_user (credentials, user);

  // ensure a copy of the user is stored in credentials, not the same pointer
  assert_that (gsad_credentials_get_user (credentials), is_not_equal_to (user));
  gsad_user_t *stored_user = gsad_credentials_get_user (credentials);
  assert_that (gsad_user_get_username (stored_user),
               is_equal_to_string ("testuser"));
  assert_that (gsad_user_get_password (stored_user),
               is_equal_to_string ("testpassword"));
  assert_that (gsad_user_get_timezone (stored_user),
               is_equal_to_string ("UTC"));
  assert_that (gsad_user_get_capabilities (stored_user),
               is_equal_to_string ("capabilities"));
  assert_that (gsad_user_get_language (stored_user), is_equal_to_string ("en"));
  assert_that (gsad_user_get_client_address (stored_user),
               is_equal_to_string ("address"));
  assert_that (gsad_user_get_jwt (stored_user), is_equal_to_string ("jwt"));

  gsad_credentials_free (credentials);
  gsad_user_free (user);
}

Ensure (gsad_credentials, should_allow_to_set_jwt)
{
  gsad_credentials_t *credentials = gsad_credentials_new ();

  assert_that (credentials, is_not_null);
  assert_that (gsad_credentials_get_jwt (credentials), is_null);

  gsad_credentials_set_jwt (credentials, "jwt");

  assert_that (gsad_credentials_get_jwt (credentials),
               is_equal_to_string ("jwt"));

  gsad_credentials_free (credentials);
}

int
main (int argc, char **argv)
{
  int ret;

  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, gsad_credentials,
                         should_allow_to_create_new_credential);
  add_test_with_context (suite, gsad_credentials,
                         should_allow_to_free_null_credential);
  add_test_with_context (suite, gsad_credentials, should_allow_to_set_user);
  add_test_with_context (suite, gsad_credentials, should_allow_to_set_jwt);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
