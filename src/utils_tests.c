/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "utils.h"

#include <cgreen/cgreen.h>

Describe (utils);

BeforeEach (utils)
{
}
AfterEach (utils)
{
}

Ensure (utils, credential_username_is_valid_success)
{
  assert_that (credential_username_is_valid ("H"), is_true);
  assert_that (credential_username_is_valid ("@"), is_true);
  assert_that (credential_username_is_valid ("Hannes"), is_true);
  assert_that (credential_username_is_valid ("Test-_\\.@"), is_true);
  assert_that (credential_username_is_valid ("Hannes_H"), is_true);
}

Ensure (utils, credential_username_is_valid_failure)
{
  assert_that (credential_username_is_valid (NULL), is_false);
  assert_that (credential_username_is_valid (""), is_false);
  assert_that (credential_username_is_valid ("ß"), is_false);
  assert_that (credential_username_is_valid ("Jürgen"), is_false);
  assert_that (credential_username_is_valid ("Hannes&"), is_false);
}

int
main (int argc, char **argv)
{
  TestSuite *suite = create_test_suite ();
  add_test_with_context (suite, utils, credential_username_is_valid_success);
  add_test_with_context (suite, utils, credential_username_is_valid_failure);
  return run_test_suite (suite, create_text_reporter ());
}
