/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_http_handler_internal.h"
#include "gsad_http_url_handler.h"
#include "gsad_http_url_handler_internal.h"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

typedef struct call
{
  http_handler_t *next;
  http_connection_t *connection;
  gsad_connection_info_t *con_info;
  void *data;
} call_t;

call_t *last_call;

Describe (gsad_http_url_handler);

BeforeEach (gsad_http_url_handler)
{
  last_call = NULL;
}

AfterEach (gsad_http_url_handler)
{
}

void
record_call (http_handler_t *next, http_connection_t *connection,
             gsad_connection_info_t *con_info, void *data)
{
  call_t *call = g_malloc0 (sizeof (call_t));
  call->next = next;
  call->connection = connection;
  call->con_info = con_info;
  call->data = data;
  last_call = call;
}

call_t *
get_last_call ()
{
  return last_call;
}

static http_result_t
dummy_handle (http_handler_t *next, http_connection_t *connection,
              gsad_connection_info_t *con_info, void *data)
{
  record_call (next, connection, con_info, data);
  http_result_t result =
    (http_result_t) mock (next, connection, con_info, data);
  return result;
}

Ensure (gsad_http_url_handler, should_allow_to_create_url_handler)
{
  http_handler_t *dummy_handler = http_handler_new (dummy_handle);
  http_handler_t *url_handler =
    gsad_http_url_handler_new ("^/test-url$", dummy_handler);

  assert_that (url_handler->handle, is_not_null);
  assert_that (url_handler->next, is_null);

  gsad_http_url_handler_map_t *map =
    (gsad_http_url_handler_map_t *) url_handler->data;
  assert_that (map->handler, is_equal_to (dummy_handler));
  assert_that (map->gregexp, is_not_null);

  assert_that (get_last_call (), is_null);

  http_handler_free (url_handler);
}

Ensure (gsad_http_url_handler, should_allow_to_create_url_handler_from_func)
{
  http_handler_t *url_handler =
    gsad_http_url_handler_from_func ("^/test-url$", dummy_handle);

  assert_that (url_handler->handle, is_not_null);
  assert_that (url_handler->next, is_null);

  gsad_http_url_handler_map_t *map =
    (gsad_http_url_handler_map_t *) url_handler->data;
  assert_that (map->handler, is_not_null);
  assert_that (map->gregexp, is_not_null);

  assert_that (get_last_call (), is_null);

  http_handler_free (url_handler);
}

Ensure (gsad_http_url_handler, should_ignore_non_matching_url)
{
  always_expect (dummy_handle, will_return (MHD_YES));
  gsad_connection_info_t *con_info =
    gsad_connection_info_new (METHOD_TYPE_GET, "/foo");
  http_handler_t *dummy_handler = http_handler_new (dummy_handle);
  http_handler_t *url_handler =
    gsad_http_url_handler_new ("^/test-url$", dummy_handler);

  gsad_http_url_handler_map_t *map =
    (gsad_http_url_handler_map_t *) url_handler->data;
  assert_that (map->handler, is_equal_to (dummy_handler));
  assert_that (http_handler_start (url_handler, NULL, con_info, NULL),
               is_equal_to (MHD_NO));

  assert_that (get_last_call (), is_null);

  http_handler_free (url_handler);
  gsad_connection_info_free (con_info);
}

Ensure (gsad_http_url_handler, should_handle_matching_url)
{
  expect (dummy_handle, will_return (MHD_YES));
  gsad_connection_info_t *con_info =
    gsad_connection_info_new (METHOD_TYPE_GET, "/test-url");
  http_handler_t *dummy_handler = http_handler_new (dummy_handle);
  http_handler_t *url_handler =
    gsad_http_url_handler_new ("^/test-url$", dummy_handler);

  assert_that (http_handler_start (url_handler, NULL, con_info, NULL),
               is_equal_to (MHD_YES));

  call_t *call = get_last_call ();
  assert_that (call, is_not_null);
  assert_that (call->next, is_equal_to (dummy_handler));
  assert_that (call->connection, is_null);
  assert_that (call->con_info, is_equal_to (con_info));
  assert_that (call->data, is_null);

  http_handler_free (url_handler);
  gsad_connection_info_free (con_info);
}

Ensure (gsad_http_url_handler, should_call_next_handler_if_url_does_not_match)
{
  always_expect (dummy_handle, will_return (MHD_YES));

  gsad_connection_info_t *con_info =
    gsad_connection_info_new (METHOD_TYPE_GET, "/foo");
  http_handler_t *dummy_handler = http_handler_new (dummy_handle);
  http_handler_t *url_handler =
    gsad_http_url_handler_new ("^/test-url$", dummy_handler);

  http_handler_t *next_handler = http_handler_new (dummy_handle);
  http_handler_set_next (url_handler, next_handler);

  assert_that (next_handler->handle, is_equal_to (dummy_handle));
  assert_that (url_handler->next, is_equal_to (next_handler));
  assert_that (http_handler_start (url_handler, NULL, con_info, NULL),
               is_equal_to (MHD_YES));

  call_t *call = get_last_call ();
  assert_that (call, is_not_null);
  assert_that (call->next, is_equal_to (next_handler));
  assert_that (call->connection, is_null);
  assert_that (call->con_info, is_equal_to (con_info));
  assert_that (call->data, is_null);

  http_handler_free (url_handler);
  gsad_connection_info_free (con_info);
}

int
main (int argc, char **argv)
{
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, gsad_http_url_handler,
                         should_allow_to_create_url_handler);
  add_test_with_context (suite, gsad_http_url_handler,
                         should_allow_to_create_url_handler_from_func);
  add_test_with_context (suite, gsad_http_url_handler,
                         should_ignore_non_matching_url);
  add_test_with_context (suite, gsad_http_url_handler,
                         should_handle_matching_url);
  add_test_with_context (suite, gsad_http_url_handler,
                         should_call_next_handler_if_url_does_not_match);

  int ret = run_test_suite (suite, create_text_reporter ());
  destroy_test_suite (suite);
  return ret;
}
