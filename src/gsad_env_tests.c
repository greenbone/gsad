/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_env.h"

#include <cgreen/cgreen.h>

Describe (gsad_env);
BeforeEach (gsad_env)
{
  g_unsetenv ("TEST_ENV_BOOLEAN");
  g_unsetenv ("TEST_ENV_STRING");
  g_unsetenv ("TEST_ENV_STRING_ARRAY");
}
AfterEach (gsad_env)
{
  g_unsetenv ("TEST_ENV_BOOLEAN");
  g_unsetenv ("TEST_ENV_STRING");
  g_unsetenv ("TEST_ENV_STRING_ARRAY");
}

Ensure (gsad_env, should_get_boolean_value_for_unset_environment_variable)
{
  assert_false (gsad_env_get_boolean ("TEST_ENV_BOOLEAN", FALSE));
  assert_true (gsad_env_get_boolean ("TEST_ENV_BOOLEAN", TRUE));
}

Ensure (gsad_env, should_get_string_value_for_unset_environment_variable)
{
  gchar *value = gsad_env_get_string ("TEST_ENV_STRING", "default");
  assert_that (value, is_equal_to_string ("default"));
  g_free (value);

  value = gsad_env_get_string ("TEST_ENV_STRING", NULL);
  assert_that (value, is_null);
  g_free (value);
}

Ensure (gsad_env, should_get_boolean_value_for_set_environment_variable)
{
  g_setenv ("TEST_ENV_BOOLEAN", "true", TRUE);
  assert_true (gsad_env_get_boolean ("TEST_ENV_BOOLEAN", FALSE));

  g_setenv ("TEST_ENV_BOOLEAN", "1", TRUE);
  assert_true (gsad_env_get_boolean ("TEST_ENV_BOOLEAN", FALSE));

  g_setenv ("TEST_ENV_BOOLEAN", "false", TRUE);
  assert_false (gsad_env_get_boolean ("TEST_ENV_BOOLEAN", TRUE));

  g_setenv ("TEST_ENV_BOOLEAN", "0", TRUE);
  assert_false (gsad_env_get_boolean ("TEST_ENV_BOOLEAN", TRUE));
}

Ensure (gsad_env, should_get_string_value_for_set_environment_variable)
{
  g_setenv ("TEST_ENV_STRING", "value", TRUE);
  gchar *value = gsad_env_get_string ("TEST_ENV_STRING", "default");
  assert_that (value, is_equal_to_string ("value"));
  g_free (value);
}

Ensure (gsad_env, should_get_default_value_for_unset_environment_variable)
{
  int value = gsad_env_get_int ("TEST_ENV_STRING", 42);
  assert_that (value, is_equal_to (42));
}

Ensure (gsad_env, should_get_integer_value_for_set_environment_variable)
{
  g_setenv ("TEST_ENV_STRING", "123", TRUE);
  int value = gsad_env_get_int ("TEST_ENV_STRING", 42);
  assert_that (value, is_equal_to (123));
}

Ensure (gsad_env, should_get_default_value_for_non_integer_environment_variable)
{
  g_setenv ("TEST_ENV_STRING", "not_an_int", TRUE);
  int value = gsad_env_get_int ("TEST_ENV_STRING", 42);
  assert_that (value, is_equal_to (42));

  g_setenv ("TEST_ENV_STRING", "123value", TRUE);
  value = gsad_env_get_int ("TEST_ENV_STRING", 42);
  assert_that (value, is_equal_to (42));
}

Ensure (gsad_env, should_get_string_array_value_for_unset_environment_variable)
{
  gchar **value = gsad_env_get_string_array ("TEST_ENV_STRING_ARRAY", ",",
                                             "default1,default2");
  assert_that (value, is_not_null);
  assert_that (value[0], is_equal_to_string ("default1"));
  assert_that (value[1], is_equal_to_string ("default2"));
  assert_that (value[2], is_null);
  g_strfreev (value);
}

Ensure (gsad_env, should_get_string_array_value_for_set_environment_variable)
{
  g_setenv ("TEST_ENV_STRING_ARRAY", "value1,value2", TRUE);
  gchar **value = gsad_env_get_string_array ("TEST_ENV_STRING_ARRAY", ",",
                                             "default1,default2");
  assert_that (value, is_not_null);
  assert_that (value[0], is_equal_to_string ("value1"));
  assert_that (value[1], is_equal_to_string ("value2"));
  assert_that (value[2], is_null);
  g_strfreev (value);
}

Ensure (
  gsad_env,
  should_get_default_value_for_unset_environment_variable_with_null_default)
{
  gchar **value =
    gsad_env_get_string_array ("TEST_ENV_STRING_ARRAY", ",", NULL);
  assert_that (value, is_null);
}

int
main (int argc, char **argv)
{
  int ret;

  TestSuite *suite = create_test_suite ();

  add_test_with_context (
    suite, gsad_env, should_get_boolean_value_for_unset_environment_variable);
  add_test_with_context (
    suite, gsad_env, should_get_string_value_for_unset_environment_variable);
  add_test_with_context (suite, gsad_env,
                         should_get_boolean_value_for_set_environment_variable);
  add_test_with_context (suite, gsad_env,
                         should_get_string_value_for_set_environment_variable);
  add_test_with_context (
    suite, gsad_env, should_get_default_value_for_unset_environment_variable);
  add_test_with_context (suite, gsad_env,
                         should_get_integer_value_for_set_environment_variable);
  add_test_with_context (
    suite, gsad_env,
    should_get_default_value_for_non_integer_environment_variable);
  add_test_with_context (
    suite, gsad_env,
    should_get_string_array_value_for_unset_environment_variable);
  add_test_with_context (
    suite, gsad_env,
    should_get_string_array_value_for_set_environment_variable);
  add_test_with_context (
    suite, gsad_env,
    should_get_default_value_for_unset_environment_variable_with_null_default);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
