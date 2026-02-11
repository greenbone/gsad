/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_connection_info.h"

#include <cgreen/cgreen.h>

Describe (gsad_connection_info);

BeforeEach (gsad_connection_info)
{
}

AfterEach (gsad_connection_info)
{
}

Ensure (gsad_connection_info, should_allow_to_create_connection_info_for_post)
{
  gsad_connection_info_t *con_info =
    gsad_connection_info_new (METHOD_TYPE_POST, "/some-url");

  assert_that (con_info, is_not_null);
  assert_that (gsad_connection_info_get_method_type (con_info),
               is_equal_to (METHOD_TYPE_POST));
  assert_that (gsad_connection_info_get_params (con_info), is_not_null);
  assert_that (gsad_connection_info_get_postprocessor (con_info), is_null);
  assert_that (gsad_connection_info_get_cookie (con_info), is_null);
  assert_that (gsad_connection_info_get_language (con_info), is_null);
  assert_that (gsad_connection_info_get_url (con_info),
               is_equal_to_string ("/some-url"));

  gsad_connection_info_free (con_info);
}

Ensure (gsad_connection_info, should_allow_to_create_connection_info_for_get)
{
  gsad_connection_info_t *con_info =
    gsad_connection_info_new (METHOD_TYPE_GET, "/some-url");

  assert_that (con_info, is_not_null);
  assert_that (gsad_connection_info_get_method_type (con_info),
               is_equal_to (METHOD_TYPE_GET));
  assert_that (gsad_connection_info_get_params (con_info), is_not_null);
  assert_that (gsad_connection_info_get_postprocessor (con_info), is_null);
  assert_that (gsad_connection_info_get_cookie (con_info), is_null);
  assert_that (gsad_connection_info_get_language (con_info), is_null);
  assert_that (gsad_connection_info_get_url (con_info),
               is_equal_to_string ("/some-url"));

  gsad_connection_info_free (con_info);
}

Ensure (gsad_connection_info, should_allow_to_free_null_connection_info)
{
  gsad_connection_info_free (NULL);
}

Ensure (gsad_connection_info, should_allow_to_create_connection_info_unknown)
{
  gsad_connection_info_t *con_info =
    gsad_connection_info_new (METHOD_TYPE_UNKNOWN, "/some-url");

  assert_that (con_info, is_not_null);
  assert_that (gsad_connection_info_get_method_type (con_info),
               is_equal_to (METHOD_TYPE_UNKNOWN));
  assert_that (gsad_connection_info_get_params (con_info), is_not_null);
  assert_that (gsad_connection_info_get_postprocessor (con_info), is_null);
  assert_that (gsad_connection_info_get_cookie (con_info), is_null);
  assert_that (gsad_connection_info_get_language (con_info), is_null);
  assert_that (gsad_connection_info_get_url (con_info),
               is_equal_to_string ("/some-url"));

  gsad_connection_info_free (con_info);
}

Ensure (gsad_connection_info, should_set_and_get_postprocessor)
{
  gsad_connection_info_t *con_info =
    gsad_connection_info_new (METHOD_TYPE_POST, "/some-url");
  struct MHD_PostProcessor *postprocessor =
    MHD_create_post_processor (NULL, 1024, NULL, NULL);

  gsad_connection_info_set_postprocessor (con_info, postprocessor);
  assert_that (gsad_connection_info_get_postprocessor (con_info),
               is_equal_to (postprocessor));

  gsad_connection_info_free (con_info);
}

Ensure (gsad_connection_info, should_set_and_get_cookie)
{
  gsad_connection_info_t *con_info =
    gsad_connection_info_new (METHOD_TYPE_POST, "/some-url");

  gsad_connection_info_set_cookie (con_info, "test_cookie");
  assert_that (gsad_connection_info_get_cookie (con_info),
               is_equal_to_string ("test_cookie"));

  gsad_connection_info_free (con_info);
}

Ensure (gsad_connection_info, should_set_and_get_language)
{
  gsad_connection_info_t *con_info =
    gsad_connection_info_new (METHOD_TYPE_POST, "/some-url");

  gsad_connection_info_set_language (con_info, "en-US");
  assert_that (gsad_connection_info_get_language (con_info),
               is_equal_to_string ("en-US"));

  gsad_connection_info_free (con_info);
}

int
main (int argc, char **argv)
{
  TestSuite *suite = create_test_suite ();
  int ret = run_test_suite (suite, create_text_reporter ());

  add_test_with_context (suite, gsad_connection_info,
                         should_allow_to_create_connection_info_for_post);
  add_test_with_context (suite, gsad_connection_info,
                         should_allow_to_create_connection_info_for_get);
  add_test_with_context (suite, gsad_connection_info,
                         should_allow_to_create_connection_info_unknown);
  add_test_with_context (suite, gsad_connection_info,
                         should_set_and_get_postprocessor);
  add_test_with_context (suite, gsad_connection_info,
                         should_set_and_get_cookie);
  add_test_with_context (suite, gsad_connection_info,
                         should_set_and_get_language);
  add_test_with_context (suite, gsad_connection_info,
                         should_allow_to_free_null_connection_info);

  destroy_test_suite (suite);
  return ret;
}
