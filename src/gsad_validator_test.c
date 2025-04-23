/* Copyright (C) 2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "gsad_validator.c"

#include <cgreen/cgreen.h>

Describe (gsad_validator);
BeforeEach (gsad_validator)
{
  init_validator ();
}
AfterEach (gsad_validator)
{
  reset_validator ();
}

Ensure (gsad_validator, validate_name)
{
  validator_t validator = get_validator ();
  assert_that (gvm_validate (validator, "name", "foo"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", "12345"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", "äüöÄÜÖß"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", "()[]"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", "-–"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", ":;.…?!"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", "“”\"‘’''"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", " "), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", "a\tb"), is_equal_to (2));
  assert_that (gvm_validate (validator, "name", "a\rb"), is_equal_to (2));
  assert_that (gvm_validate (validator, "name", "a\nb"), is_equal_to (2));
  assert_that (gvm_validate (validator, "name", "/"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", "\\"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", "@"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", "$%&=<>^+*#"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", "foo bar 123 baz"),
               is_equal_to (0));
}

Ensure (gsad_validator, validate_comment)
{
  validator_t validator = get_validator ();
  assert_that (gvm_validate (validator, "comment", "foo"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "12345"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "äüöÄÜÖß"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "()[]"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "-–"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", ":;.…?!"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "“”\"‘’''"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", " "), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "a\tb"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "a\rb"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "a\nb"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "/"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "\\"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "@"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "$%&=<>^+*#"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "foo bar\nbaz\t123"),
               is_equal_to (0));
}

Ensure (gsad_validator, validate_agent_installer_id)
{
  validator_t validator = get_validator ();
  assert_that (gvm_validate (validator, "agent_installer_id", "a1b2c3d4"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "agent_installer_id",
                             "123e4567-e89b-12d3-a456-426614174000"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "agent_installer_id", ""),
               is_equal_to (2));
  assert_that (
    gvm_validate (validator, "agent_installer_id", "invalid id with space"),
    is_equal_to (2));
}

int
main (int argc, char **argv)
{
  TestSuite *suite = create_test_suite ();
  add_test_with_context (suite, gsad_validator, validate_name);
  add_test_with_context (suite, gsad_validator, validate_comment);
  add_test_with_context (suite, gsad_validator, validate_agent_installer_id);
  return run_test_suite (suite, create_text_reporter ());
}
