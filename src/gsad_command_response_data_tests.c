/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_command_response_data.h"

#include <cgreen/cgreen.h>
#include <microhttpd.h> /* for MHD_HTTP_OK */

Describe (gsad_command_response_data);
BeforeEach (gsad_command_response_data)
{
}
AfterEach (gsad_command_response_data)
{
}

Ensure (gsad_command_response_data, should_allow_to_create_new)
{
  gsad_command_response_data_t *data = gsad_command_response_data_new ();
  assert_that (data, is_not_null);
  assert_that (gsad_command_response_data_is_allow_caching (data), is_false);
  assert_that (gsad_command_response_data_get_content_type (data),
               is_equal_to (GSAD_CONTENT_TYPE_TEXT_HTML));
  assert_that (gsad_command_response_data_get_content_type_string (data),
               is_null);
  assert_that (gsad_command_response_data_get_content_disposition (data),
               is_null);
  assert_that (gsad_command_response_data_get_status_code (data),
               is_equal_to (MHD_HTTP_OK));
  assert_that (gsad_command_response_data_get_content_length (data),
               is_equal_to (0));

  gsad_command_response_data_free (data);
}

Ensure (gsad_command_response_data, should_allow_to_set_and_get_allow_caching)
{
  gsad_command_response_data_t *data = gsad_command_response_data_new ();

  assert_that (gsad_command_response_data_is_allow_caching (data), is_false);

  gsad_command_response_data_set_allow_caching (data, TRUE);
  assert_that (gsad_command_response_data_is_allow_caching (data), is_true);

  gsad_command_response_data_set_allow_caching (data, FALSE);
  assert_that (gsad_command_response_data_is_allow_caching (data), is_false);

  gsad_command_response_data_free (data);
}

Ensure (gsad_command_response_data, should_allow_to_set_and_get_content_type)
{
  gsad_command_response_data_t *data = gsad_command_response_data_new ();

  assert_that (gsad_command_response_data_get_content_type (data),
               is_equal_to (GSAD_CONTENT_TYPE_TEXT_HTML));

  gsad_command_response_data_set_content_type (data,
                                               GSAD_CONTENT_TYPE_APP_JSON);
  assert_that (gsad_command_response_data_get_content_type (data),
               is_equal_to (GSAD_CONTENT_TYPE_APP_JSON));

  gsad_command_response_data_free (data);
}

Ensure (gsad_command_response_data, should_allow_to_set_and_get_status_code)
{
  gsad_command_response_data_t *data = gsad_command_response_data_new ();

  assert_that (gsad_command_response_data_get_status_code (data),
               is_equal_to (MHD_HTTP_OK));

  gsad_command_response_data_set_status_code (data, MHD_HTTP_NOT_FOUND);
  assert_that (gsad_command_response_data_get_status_code (data),
               is_equal_to (MHD_HTTP_NOT_FOUND));

  gsad_command_response_data_free (data);
}

Ensure (gsad_command_response_data, should_allow_to_set_and_get_content_length)
{
  gsad_command_response_data_t *data = gsad_command_response_data_new ();

  gsize content_length = gsad_command_response_data_get_content_length (data);
  assert_that (content_length, is_equal_to (0));

  gsad_command_response_data_set_content_length (data, 12345);
  content_length = gsad_command_response_data_get_content_length (data);
  assert_that (content_length, is_equal_to (12345));

  gsad_command_response_data_free (data);
}

Ensure (gsad_command_response_data,
        should_allow_to_set_and_get_content_disposition)
{
  gsad_command_response_data_t *data = gsad_command_response_data_new ();

  assert_that (gsad_command_response_data_get_content_disposition (data),
               is_null);

  const gchar *content_disposition = "attachment; filename=\"example.txt\"";
  gsad_command_response_data_set_content_disposition (
    data, g_strdup (content_disposition));
  assert_that (gsad_command_response_data_get_content_disposition (data),
               is_equal_to_string (content_disposition));

  gsad_command_response_data_free (data);
}

Ensure (gsad_command_response_data,
        should_allow_to_set_and_get_content_type_string)
{
  gsad_command_response_data_t *data = gsad_command_response_data_new ();

  assert_that (gsad_command_response_data_get_content_type_string (data),
               is_null);

  const gchar *content_type_string = "application/vnd.api+json";
  gsad_command_response_data_set_content_type_string (
    data, g_strdup (content_type_string));
  assert_that (gsad_command_response_data_get_content_type_string (data),
               is_equal_to_string (content_type_string));

  gsad_command_response_data_free (data);
}

Ensure (gsad_command_response_data, should_allow_to_free_null_data)
{
  gsad_command_response_data_free (NULL);
}

int
main (int argc, char **argv)
{
  int ret;

  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, gsad_command_response_data,
                         should_allow_to_create_new);
  add_test_with_context (suite, gsad_command_response_data,
                         should_allow_to_set_and_get_allow_caching);
  add_test_with_context (suite, gsad_command_response_data,
                         should_allow_to_set_and_get_status_code);
  add_test_with_context (suite, gsad_command_response_data,
                         should_allow_to_set_and_get_content_type);
  add_test_with_context (suite, gsad_command_response_data,
                         should_allow_to_set_and_get_content_length);
  add_test_with_context (suite, gsad_command_response_data,
                         should_allow_to_set_and_get_content_disposition);
  add_test_with_context (suite, gsad_command_response_data,
                         should_allow_to_set_and_get_content_type_string);
  add_test_with_context (suite, gsad_command_response_data,
                         should_allow_to_free_null_data);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
