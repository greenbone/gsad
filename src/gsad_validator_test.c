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

Ensure (gsad_validator, validate_agent_list_ids)
{
  validator_t validator = get_validator ();
  assert_that (gvm_validate (validator, "agent_ids:value", "a1b2c3d4"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "agent_ids:value",
                             "123e4567-e89b-12d3-a456-426614174000"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "agent_ids:value", ""),
               is_equal_to (2));
  assert_that (
    gvm_validate (validator, "agent_ids:value", "invalid id with space"),
    is_equal_to (2));
}

Ensure (gsad_validator, validate_kdcs_name_and_value)
{
  validator_t validator = get_validator ();

  // valid KDC values (allowing anything, as per regex "(?s)^.*$")
  assert_that (gvm_validate (validator, "kdcs:value", "127.0.0.1"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "kdcs:value", "kdc1"), is_equal_to (0));
  assert_that (gvm_validate (validator, "kdcs:value", "kdc.example.internal"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "kdcs:value", ""), is_equal_to (0));

  // invalid example for edge case
  assert_that (gvm_validate (validator, "kdcs:value", NULL), is_equal_to (5));

  // "kdcs:name" uses alias to "number", expect it to fail non-numeric
  assert_that (gvm_validate (validator, "kdcs:name", "1"), is_equal_to (0));
  assert_that (gvm_validate (validator, "kdcs:name", "abc"), is_equal_to (2));
  assert_that (gvm_validate (validator, "kdcs:name", ""), is_equal_to (2));
}

Ensure (gsad_validator, validate_oci_image_references)
{
  validator_t validator = get_validator ();

  assert_that (gvm_validate (validator, "image_references",
                             "oci://myregistry.com/myrepo/myrepo2/myimage:tag"),
               is_equal_to (0));
  assert_that (
    gvm_validate (validator, "image_references", "oci://192.168.0.4:12345"),
    is_equal_to (0));
  assert_that (gvm_validate (validator, "image_references",
                             "oci://[0001:1:1:1::1]:12345/myregistry.com"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "image_references",
                             "oci://[0001:1:1:1::1]/?myregistry.com"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "image_references", ""),
               is_equal_to (2));
}

Ensure (gsad_validator, validate_ca_pub)
{
  validator_t validator = get_validator ();

  assert_that (gvm_validate (validator, "ca_pub", ""), is_equal_to (0));
  assert_that (gvm_validate (validator, "ca_pub", "foobar"), is_equal_to (0));
  assert_that (gvm_validate (validator, "ca_pub", "123"), is_equal_to (0));
}

int
main (int argc, char **argv)
{
  TestSuite *suite = create_test_suite ();
  add_test_with_context (suite, gsad_validator, validate_name);
  add_test_with_context (suite, gsad_validator, validate_comment);
  add_test_with_context (suite, gsad_validator, validate_agent_installer_id);
  add_test_with_context (suite, gsad_validator, validate_agent_list_ids);
  add_test_with_context (suite, gsad_validator, validate_kdcs_name_and_value);
  add_test_with_context (suite, gsad_validator, validate_oci_image_references);
  add_test_with_context (suite, gsad_validator, validate_ca_pub);
  return run_test_suite (suite, create_text_reporter ());
}
