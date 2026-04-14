/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_utils.h"

#include <cgreen/cgreen.h>

Describe (gsad_utils);

BeforeEach (gsad_utils)
{
}
AfterEach (gsad_utils)
{
}

Ensure (gsad_utils, credential_username_is_valid_success)
{
  assert_that (credential_username_is_valid ("H"), is_true);
  assert_that (credential_username_is_valid ("@"), is_true);
  assert_that (credential_username_is_valid ("Hannes"), is_true);
  assert_that (credential_username_is_valid ("Test-_\\.@"), is_true);
  assert_that (credential_username_is_valid ("Hannes_H"), is_true);
}

Ensure (gsad_utils, credential_username_is_valid_failure)
{
  assert_that (credential_username_is_valid (NULL), is_false);
  assert_that (credential_username_is_valid (""), is_false);
  assert_that (credential_username_is_valid ("ß"), is_false);
  assert_that (credential_username_is_valid ("Jürgen"), is_false);
  assert_that (credential_username_is_valid ("Hannes&"), is_false);
}

Ensure (gsad_utils, null_or_value)
{
  assert_that (null_or_value (NULL), is_equal_to_string ("NULL"));
  assert_that (null_or_value ("test"), is_equal_to_string ("test"));
}

int
main (int argc, char **argv)
{
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, gsad_utils,
                         credential_username_is_valid_success);
  add_test_with_context (suite, gsad_utils,
                         credential_username_is_valid_failure);
  add_test_with_context (suite, gsad_utils, null_or_value);

  int ret = run_test_suite (suite, create_text_reporter ());
  destroy_test_suite (suite);
  return ret;
}
