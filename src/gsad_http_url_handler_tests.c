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
  gsad_http_handler_t *handler_next;
  void *handler_data;
  gsad_http_connection_t *connection;
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
record_call (gsad_http_handler_t *handler_next, void *handler_data,
             gsad_http_connection_t *connection,
             gsad_connection_info_t *con_info, void *data)
{
  call_t *call = g_malloc0 (sizeof (call_t));
  call->handler_next = handler_next;
  call->handler_data = handler_data;
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

static gsad_http_result_t
dummy_handle (gsad_http_handler_t *handler_next, void *handler_data,
              gsad_http_connection_t *connection,
              gsad_connection_info_t *con_info, void *data)
{
  record_call (handler_next, handler_data, connection, con_info, data);
  gsad_http_result_t result = (gsad_http_result_t) mock (
    handler_next, handler_data, connection, con_info, data);
  return result;
}

void
dummy_free (void *data)
{
  mock (data);
  g_free (data);
}

Ensure (gsad_http_url_handler, should_allow_to_create_url_handler)
{
  gsad_http_handler_t *dummy_handler = gsad_http_handler_new (dummy_handle);
  gsad_http_handler_t *url_handler =
    gsad_http_url_handler_new ("^/test-url$", dummy_handler);

  assert_that (url_handler->handle, is_not_null);
  assert_that (url_handler->next, is_null);

  gsad_http_url_handler_map_t *map =
    (gsad_http_url_handler_map_t *) url_handler->data;
  assert_that (map->handler, is_equal_to (dummy_handler));
  assert_that (map->gregexp, is_not_null);

  assert_that (get_last_call (), is_null);

  gsad_http_handler_free (url_handler);
}

Ensure (gsad_http_url_handler, should_allow_to_create_url_handler_from_func)
{
  gsad_http_handler_t *url_handler =
    gsad_http_url_handler_from_func ("^/test-url$", dummy_handle);

  assert_that (url_handler->handle, is_not_null);
  assert_that (url_handler->next, is_null);

  gsad_http_url_handler_map_t *map =
    (gsad_http_url_handler_map_t *) url_handler->data;
  assert_that (map->handler, is_not_null);
  assert_that (map->gregexp, is_not_null);

  assert_that (get_last_call (), is_null);

  gsad_http_handler_free (url_handler);
}

Ensure (gsad_http_url_handler, should_ignore_non_matching_url)
{
  always_expect (dummy_handle, will_return (MHD_YES));
  gsad_connection_info_t *con_info =
    gsad_connection_info_new (METHOD_TYPE_GET, "/foo");
  gsad_http_handler_t *dummy_handler = gsad_http_handler_new (dummy_handle);
  gsad_http_handler_t *url_handler =
    gsad_http_url_handler_new ("^/test-url$", dummy_handler);

  gsad_http_url_handler_map_t *map =
    (gsad_http_url_handler_map_t *) url_handler->data;
  assert_that (map->handler, is_equal_to (dummy_handler));
  assert_that (gsad_http_handler_call (url_handler, NULL, con_info, NULL),
               is_equal_to (MHD_NO));

  assert_that (get_last_call (), is_null);

  gsad_http_handler_free (url_handler);
  gsad_connection_info_free (con_info);
}

Ensure (gsad_http_url_handler, should_handle_matching_url)
{
  expect (dummy_handle, will_return (MHD_YES));
  gsad_connection_info_t *con_info =
    gsad_connection_info_new (METHOD_TYPE_GET, "/test-url");
  gsad_http_handler_t *dummy_handler = gsad_http_handler_new (dummy_handle);
  gsad_http_handler_t *url_handler =
    gsad_http_url_handler_new ("^/test-url$", dummy_handler);

  assert_that (gsad_http_handler_call (url_handler, NULL, con_info, NULL),
               is_equal_to (MHD_YES));

  call_t *call = get_last_call ();
  assert_that (call, is_not_null);
  assert_that (call->handler_next, is_null);
  assert_that (call->handler_data, is_null);
  assert_that (call->connection, is_null);
  assert_that (call->con_info, is_equal_to (con_info));
  assert_that (call->data, is_null);

  gsad_http_handler_free (url_handler);
  gsad_connection_info_free (con_info);
}

Ensure (gsad_http_url_handler, should_call_next_handler_if_url_does_not_match)
{
  always_expect (dummy_handle, will_return (MHD_YES));

  gsad_connection_info_t *con_info =
    gsad_connection_info_new (METHOD_TYPE_GET, "/foo");
  gsad_http_handler_t *dummy_handler = gsad_http_handler_new (dummy_handle);
  gsad_http_handler_t *url_handler =
    gsad_http_url_handler_new ("^/test-url$", dummy_handler);

  gsad_http_handler_t *next_handler = gsad_http_handler_new (dummy_handle);
  gsad_http_handler_add (url_handler, next_handler);

  assert_that (next_handler->handle, is_equal_to (dummy_handle));
  assert_that (next_handler->next, is_null);
  assert_that (url_handler->next, is_equal_to (next_handler));

  assert_that (gsad_http_handler_call (url_handler, NULL, con_info, NULL),
               is_equal_to (MHD_YES));

  call_t *call = get_last_call ();
  assert_that (call, is_not_null);
  assert_that (call->handler_next, is_null);
  assert_that (call->handler_data, is_null);
  assert_that (call->connection, is_null);
  assert_that (call->con_info, is_equal_to (con_info));
  assert_that (call->data, is_null);

  gsad_http_handler_free (url_handler);
  gsad_connection_info_free (con_info);
}

Ensure (gsad_http_url_handler, should_allow_to_create_simple_url_handler_chain)
{
  /* url_handler:
   *  - map: "^/test-url1$" -> dummy_handler1
   *  - next: dummy_handler2
   */
  gsad_http_handler_t *dummy_handler1 = gsad_http_handler_new (dummy_handle);
  gsad_http_handler_t *dummy_handler2 = gsad_http_handler_new (dummy_handle);
  gsad_http_handler_t *url_handler =
    gsad_http_url_handler_new ("^/test-url$", dummy_handler1);

  assert_that (url_handler->handle, is_not_null);
  assert_that (url_handler->next, is_null);

  gsad_http_url_handler_map_t *map =
    (gsad_http_url_handler_map_t *) url_handler->data;
  assert_that (map->handler, is_equal_to (dummy_handler1));
  assert_that (map->gregexp, is_not_null);

  gsad_http_handler_add (url_handler, dummy_handler2);
  assert_that (url_handler->next, is_equal_to (dummy_handler2));
  assert_that (url_handler->free_next, is_true);
  assert_that (dummy_handler1->next, is_equal_to (dummy_handler2));
  assert_that (dummy_handler1->free_next, is_false);

  assert_that (get_last_call (), is_null);

  gsad_http_handler_free (url_handler);
}

Ensure (gsad_http_url_handler, should_allow_to_create_url_handler_chain)
{
  /* url_handler1:
   *  - map: "^/test-url1$" -> dummy_handler1
        - next: url_handler2
   *  - next: url_handler2
   *    - map: "^/test-url2$" -> dummy_handler2
   *      - next: dummy_handler3
   *    - next: dummy_handler3
   */
  gsad_http_handler_t *dummy_handler1 = gsad_http_handler_new (dummy_handle);
  gsad_http_handler_t *dummy_handler2 = gsad_http_handler_new (dummy_handle);
  gsad_http_handler_t *dummy_handler3 = gsad_http_handler_new (dummy_handle);
  gsad_http_handler_t *url_handler1 =
    gsad_http_url_handler_new ("^/test-url$", dummy_handler1);
  gsad_http_handler_t *url_handler2 =
    gsad_http_url_handler_new ("^/test-url2$", dummy_handler2);

  assert_that (url_handler1->handle, is_not_null);
  assert_that (url_handler1->next, is_null);
  assert_that (url_handler2->handle, is_not_null);
  assert_that (url_handler2->next, is_null);

  gsad_http_url_handler_map_t *map1 =
    (gsad_http_url_handler_map_t *) url_handler1->data;
  assert_that (map1->handler, is_equal_to (dummy_handler1));
  assert_that (map1->gregexp, is_not_null);

  gsad_http_url_handler_map_t *map2 =
    (gsad_http_url_handler_map_t *) url_handler2->data;
  assert_that (map2->handler, is_equal_to (dummy_handler2));
  assert_that (map2->gregexp, is_not_null);

  gsad_http_handler_add (url_handler1, url_handler2);
  gsad_http_handler_add (url_handler2, dummy_handler3);

  assert_that (url_handler1->next, is_equal_to (url_handler2));
  assert_that (url_handler1->free_next, is_true);
  assert_that (dummy_handler1->next, is_equal_to (url_handler2));
  assert_that (dummy_handler1->free_next, is_false);
  assert_that (url_handler2->next, is_equal_to (dummy_handler3));
  assert_that (url_handler2->free_next, is_true);
  assert_that (dummy_handler2->next, is_equal_to (dummy_handler3));
  assert_that (dummy_handler2->free_next, is_false);
  assert_that (dummy_handler3->next, is_null);
  assert_that (dummy_handler3->free_next, is_true);

  assert_that (get_last_call (), is_null);

  gsad_http_handler_free (url_handler1);
}

Ensure (gsad_http_url_handler, should_allow_to_free_chain_and_data)
{
  void *some_data = g_malloc0 (1);
  expect (dummy_free, when (data, is_equal_to (some_data)));
  gsad_http_handler_t *dummy_handler =
    gsad_http_handler_new_with_data (dummy_handle, NULL, dummy_free, some_data);
  gsad_http_handler_t *url_handler =
    gsad_http_url_handler_new ("^/test-url$", dummy_handler);

  gsad_http_url_handler_map_t *map =
    (gsad_http_url_handler_map_t *) url_handler->data;
  map->handler->data = some_data;

  assert_that (get_last_call (), is_null);

  gsad_http_handler_free (url_handler);
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
  add_test_with_context (suite, gsad_http_url_handler,
                         should_allow_to_create_simple_url_handler_chain);
  add_test_with_context (suite, gsad_http_url_handler,
                         should_allow_to_create_url_handler_chain);
  add_test_with_context (suite, gsad_http_url_handler,
                         should_allow_to_free_chain_and_data);

  int ret = run_test_suite (suite, create_text_reporter ());
  destroy_test_suite (suite);
  return ret;
}
