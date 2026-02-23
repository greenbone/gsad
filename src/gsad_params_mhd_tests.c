/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_params.h"
#include "gsad_params_mhd.h"

#include <cgreen/cgreen.h>

Describe (gsad_params_mhd);

BeforeEach (gsad_params_mhd)
{
}
AfterEach (gsad_params_mhd)
{
}

static void
check_param (params_t *params, const char *name, const char *value)
{
  param_t *param = params_get (params, name);
  assert_that (param, is_not_null);
  assert_that (param->value, is_equal_to_string (value));
  assert_that (param->value_size, is_equal_to (strlen (value)));
}

static void
check_sized_param (params_t *params, const char *name, const char *value,
                   int value_size)
{
  param_t *param = params_get (params, name);
  assert_that (param, is_not_null);
  assert_that (param->value, is_equal_to_contents_of (value, value_size));
  assert_that (param->value_size, is_equal_to (value_size));
}

static void
check_empty_param (params_t *params, const char *name)
{
  param_t *param = params_get (params, name);
  assert_that (param, is_not_null);
  assert_that (param->value, is_equal_to_string (""));
  assert_that (param->value_size, is_equal_to (0));
}

Ensure (gsad_params_mhd, should_handle_single_params_in_params_mhd_add)
{
  params_t *params = params_new ();
  ;
  enum MHD_Result result;

  // Default cases without colon
  result = params_mhd_add (params, MHD_GET_ARGUMENT_KIND, "name", "ABC");
  assert_that (result, is_equal_to (MHD_YES));
  result = params_mhd_add (params, MHD_GET_ARGUMENT_KIND, "comment", "DEFGH");
  assert_that (result, is_equal_to (MHD_YES));
  check_param (params, "name", "ABC");
  check_param (params, "comment", "DEFGH");

  // Special case with colon
  result = params_mhd_add (params, MHD_GET_ARGUMENT_KIND, "file:", "XYZ");
  assert_that (result, is_equal_to (MHD_YES));
  check_param (params, "file:", "XYZ");

  params_free (params);
}

Ensure (gsad_params_mhd,
        should_handle_valueless_single_params_in_params_mhd_add)
{
  params_t *params = params_new ();
  enum MHD_Result result;

  // Default case without colon
  result = params_mhd_add (params, MHD_GET_ARGUMENT_KIND, "name", NULL);
  assert_that (result, is_equal_to (MHD_YES));
  check_empty_param (params, "name");

  // Special case with colon
  result = params_mhd_add (params, MHD_GET_ARGUMENT_KIND, "file:", NULL);
  assert_that (result, is_equal_to (MHD_YES));
  check_empty_param (params, "file:");

  params_free (params);
}

Ensure (gsad_params_mhd, should_handle_single_params_in_params_mhd_append)
{
  params_t *params = params_new ();
  enum MHD_Result result;

  // Default case without colon
  result = params_mhd_append (params, "name", "", "ABCxx", 3, 0);
  assert_that (result, is_equal_to (MHD_YES));
  check_param (params, "name", "ABC"); // also checks for 0-termination
  result = params_mhd_append (params, "name", "", "DEFxx", 3, 3);
  assert_that (result, is_equal_to (MHD_YES));
  check_param (params, "name", "ABCDEF"); // also checks for 0-termination
  result = params_mhd_append (params, "name", "", "\0GHIxx", 4, 6);
  check_sized_param (params, "name", "ABCDEF\0GHI", 10);

  // Special case with colon
  result = params_mhd_append (params, "file:", "", "123xx", 3, 0);
  assert_that (result, is_equal_to (MHD_YES));
  check_param (params, "file:", "123"); // also checks for 0-termination
  result = params_mhd_append (params, "file:", "", "456xx", 3, 3);
  assert_that (result, is_equal_to (MHD_YES));
  check_param (params, "file:", "123456"); // also checks for 0-termination
  result = params_mhd_append (params, "file:", "", "\000789xx", 4, 6);
  check_sized_param (params, "file:", "123456\000789", 10);

  params_free (params);
}

Ensure (gsad_params_mhd,
        should_handle_valueless_single_params_in_params_mhd_append)
{
  params_t *params = params_new ();
  enum MHD_Result result;

  // Default case without colon
  result = params_mhd_append (params, "name", "", NULL, 0, 0);
  assert_that (result, is_equal_to (MHD_YES));
  check_empty_param (params, "name");
  result = params_mhd_append (params, "name", "", "ABCxx", 3, 0);
  assert_that (result, is_equal_to (MHD_YES));
  check_param (params, "name", "ABC"); // also checks for 0-termination

  // Special case with colon
  result = params_mhd_append (params, "file:", "", NULL, 0, 0);
  assert_that (result, is_equal_to (MHD_YES));
  check_empty_param (params, "file:");
  result = params_mhd_append (params, "file:", "", "123xx", 3, 0);
  assert_that (result, is_equal_to (MHD_YES));
  check_param (params, "file:", "123"); // also checks for 0-termination

  params_free (params);
}

Ensure (gsad_params_mhd, should_handle_hashtable_params_in_params_mhd_add)
{
  params_t *params = params_new ();
  enum MHD_Result result;
  param_t *param;

  result =
    params_mhd_add (params, MHD_GET_ARGUMENT_KIND, "bulk_selected:a", "123");
  assert_that (result, is_equal_to (MHD_YES));

  result =
    params_mhd_add (params, MHD_GET_ARGUMENT_KIND, "bulk_selected:bb", "456");
  assert_that (result, is_equal_to (MHD_YES));

  result =
    params_mhd_add (params, MHD_GET_ARGUMENT_KIND, "bulk_selected:ccc", "789");
  assert_that (result, is_equal_to (MHD_YES));

  param = params_get (params, "bulk_selected:");
  assert_that (param, is_not_null);

  check_param (param->values, "a", "123");
  check_param (param->values, "bb", "456");
  check_param (param->values, "ccc", "789");

  params_free (params);
}

Ensure (gsad_params_mhd,
        should_handle_valueless_hashtable_params_in_params_mhd_add)
{
  params_t *params = params_new ();
  enum MHD_Result result;
  param_t *param;

  result =
    params_mhd_add (params, MHD_GET_ARGUMENT_KIND, "bulk_selected:a", NULL);
  assert_that (result, is_equal_to (MHD_YES));

  result =
    params_mhd_add (params, MHD_GET_ARGUMENT_KIND, "bulk_selected:bb", NULL);
  assert_that (result, is_equal_to (MHD_YES));

  param = params_get (params, "bulk_selected:");
  assert_that (param, is_not_null);

  check_param (param->values, "a", "");
  check_param (param->values, "bb", "");

  params_free (params);
}

Ensure (gsad_params_mhd, should_handle_hashtable_params_in_params_mhd_append)
{
  params_t *params = params_new ();
  enum MHD_Result result;
  param_t *param;

  result = params_mhd_append (params, "bulk_selected:a", "", "ABC", 3, 0);
  assert_that (result, is_equal_to (MHD_YES));
  result = params_mhd_append (params, "bulk_selected:a", "", "DEF", 3, 3);
  assert_that (result, is_equal_to (MHD_YES));
  result = params_mhd_append (params, "bulk_selected:a", "", "\0GHI", 4, 6);
  assert_that (result, is_equal_to (MHD_YES));

  result = params_mhd_append (params, "bulk_selected:bb", "", "123", 3, 0);
  assert_that (result, is_equal_to (MHD_YES));
  result = params_mhd_append (params, "bulk_selected:bb", "", "456", 3, 3);
  assert_that (result, is_equal_to (MHD_YES));

  param = params_get (params, "bulk_selected:");
  assert_that (param, is_not_null);

  check_sized_param (param->values, "a", "ABCDEF\0GHI", 10);
  check_param (param->values, "bb", "123456");

  params_free (params);
}

Ensure (gsad_params_mhd,
        should_handle_valueless_hashtable_params_in_params_mhd_append)
{
  params_t *params = params_new ();
  enum MHD_Result result;
  param_t *param;

  result = params_mhd_append (params, "bulk_selected:a", "", NULL, 0, 0);
  assert_that (result, is_equal_to (MHD_YES));

  result = params_mhd_append (params, "bulk_selected:bb", "", NULL, 0, 0);
  assert_that (result, is_equal_to (MHD_YES));
  result = params_mhd_append (params, "bulk_selected:bb", "", "123", 3, 0);
  assert_that (result, is_equal_to (MHD_YES));

  param = params_get (params, "bulk_selected:");
  assert_that (param, is_not_null);

  check_empty_param (param->values, "a");
  check_param (param->values, "bb", "123");

  params_free (params);
}

Ensure (gsad_params_mhd, should_handle_array_params_in_params_mhd_add)
{
  params_t *params = params_new ();
  enum MHD_Result result;
  param_t *param;

  result = params_mhd_add (params, MHD_GET_ARGUMENT_KIND, "alert_ids:", "123");
  assert_that (result, is_equal_to (MHD_YES));
  result = params_mhd_add (params, MHD_GET_ARGUMENT_KIND, "alert_ids:", "456");
  assert_that (result, is_equal_to (MHD_YES));

  param = params_get (params, "alert_ids:");
  assert_that (param, is_not_null);
  assert_that (param->values, is_not_null);

  check_param (param->values, "1", "123");
  check_param (param->values, "2", "456");

  params_free (params);
}

Ensure (gsad_params_mhd, should_handle_valueless_array_params_in_params_mhd_add)
{
  params_t *params = params_new ();
  enum MHD_Result result;
  param_t *param;

  result = params_mhd_add (params, MHD_GET_ARGUMENT_KIND, "alert_ids:", NULL);
  assert_that (result, is_equal_to (MHD_YES));
  result = params_mhd_add (params, MHD_GET_ARGUMENT_KIND, "alert_ids:", NULL);
  assert_that (result, is_equal_to (MHD_YES));

  param = params_get (params, "alert_ids:");
  assert_that (param, is_not_null);
  assert_that (param->values, is_not_null);

  check_empty_param (param->values, "1");
  check_empty_param (param->values, "2");

  params_free (params);
}

Ensure (gsad_params_mhd, should_handle_array_params_in_params_mhd_append)
{
  params_t *params = params_new ();
  enum MHD_Result result;
  param_t *param;

  result = params_mhd_append (params, "alert_ids:", "", "ABC", 3, 0);
  assert_that (result, is_equal_to (MHD_YES));
  result = params_mhd_append (params, "alert_ids:", "", "\0DEF", 4, 3);
  assert_that (result, is_equal_to (MHD_YES));
  result = params_mhd_append (params, "alert_ids:", "", "GHI", 3, 0);
  assert_that (result, is_equal_to (MHD_YES));

  param = params_get (params, "alert_ids:");
  assert_that (param, is_not_null);
  assert_that (param->values, is_not_null);

  check_sized_param (param->values, "1", "ABC\0DEF", 7);
  check_param (param->values, "2", "GHI");

  params_free (params);
}

Ensure (gsad_params_mhd,
        should_handle_valueless_array_params_in_params_mhd_append)
{
  params_t *params = params_new ();
  enum MHD_Result result;
  param_t *param;

  result = params_mhd_append (params, "alert_ids:", "", NULL, 0, 0);
  assert_that (result, is_equal_to (MHD_YES));
  result = params_mhd_append (params, "alert_ids:", "", NULL, 0, 0);
  assert_that (result, is_equal_to (MHD_YES));

  param = params_get (params, "alert_ids:");
  assert_that (param, is_not_null);
  assert_that (param->values, is_not_null);

  check_empty_param (param->values, "1");
  check_empty_param (param->values, "2");

  params_free (params);
}

int
main (int argc, char **argv)
{
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, gsad_params_mhd,
                         should_handle_single_params_in_params_mhd_add);
  add_test_with_context (
    suite, gsad_params_mhd,
    should_handle_valueless_single_params_in_params_mhd_add);

  add_test_with_context (suite, gsad_params_mhd,
                         should_handle_single_params_in_params_mhd_append);
  add_test_with_context (
    suite, gsad_params_mhd,
    should_handle_valueless_single_params_in_params_mhd_append);

  add_test_with_context (suite, gsad_params_mhd,
                         should_handle_hashtable_params_in_params_mhd_add);
  add_test_with_context (
    suite, gsad_params_mhd,
    should_handle_valueless_hashtable_params_in_params_mhd_add);

  add_test_with_context (suite, gsad_params_mhd,
                         should_handle_hashtable_params_in_params_mhd_append);
  add_test_with_context (
    suite, gsad_params_mhd,
    should_handle_valueless_hashtable_params_in_params_mhd_append);

  add_test_with_context (suite, gsad_params_mhd,
                         should_handle_array_params_in_params_mhd_add);
  add_test_with_context (
    suite, gsad_params_mhd,
    should_handle_valueless_array_params_in_params_mhd_add);

  add_test_with_context (suite, gsad_params_mhd,
                         should_handle_array_params_in_params_mhd_append);
  add_test_with_context (
    suite, gsad_params_mhd,
    should_handle_valueless_array_params_in_params_mhd_append);

  int ret = run_test_suite (suite, create_text_reporter ());
  destroy_test_suite (suite);
  return ret;
}
