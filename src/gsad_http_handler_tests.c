/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_http_handler.h"
#include "gsad_http_handler_internal.h"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

typedef struct call
{
  http_handler_t *handler_next;
  void *handler_data;
  http_connection_t *connection;
  gsad_connection_info_t *con_info;
  void *data;
} call_t;

GList *calls;

Describe (gsad_http_handler);

BeforeEach (gsad_http_handler)
{
  calls = NULL;
}

AfterEach (gsad_http_handler)
{
  g_list_free (calls);
}

void
record_call (http_handler_t *handler_next, void *handler_data,
             http_connection_t *connection, gsad_connection_info_t *con_info,
             void *data)
{
  call_t *call = g_malloc0 (sizeof (call_t));
  call->handler_next = handler_next;
  call->handler_data = handler_data;
  call->connection = connection;
  call->con_info = con_info;
  call->data = data;
  calls = g_list_append (calls, call);
}

call_t *
get_nth_call (int nth)
{
  return g_list_nth_data (calls, nth);
}

call_t *
get_last_call ()
{
  GList *last = g_list_last (calls);
  if (last)
    {
      return last->data;
    }
  return NULL;
}

int
get_call_count ()
{
  return g_list_length (calls);
}

static http_result_t
dummy_handle (http_handler_t *handler_next, void *handler_data,
              http_connection_t *connection, gsad_connection_info_t *con_info,
              void *data)
{
  record_call (handler_next, handler_data, connection, con_info, data);
  http_result_t result = (http_result_t) mock (handler_next, handler_data,
                                               connection, con_info, data);
  return result;
}

static http_result_t
dummy_call_next (http_handler_t *handler_next, void *handler_data,
                 http_connection_t *connection,
                 gsad_connection_info_t *con_info, void *data)
{
  record_call (handler_next, handler_data, connection, con_info, data);
  return http_handler_call (handler_next, connection, con_info, data);
}

static void
dummy_free (void *data)
{
  mock (data);
}

Ensure (gsad_http_handler, should_allow_to_create_new_handler)
{
  http_handler_t *handler = http_handler_new (dummy_handle);

  assert_that (handler, is_not_null);
  assert_that (handler->handle, is_equal_to (dummy_handle));
  assert_that (handler->free, is_null);
  assert_that (handler->data, is_null);
  assert_that (handler->next, is_null);

  assert_that (get_last_call (), is_null);

  http_handler_free (handler);
}

Ensure (gsad_http_handler, should_allow_to_create_new_handler_with_data)
{
  void *some_data = g_malloc0 (1);
  http_handler_t *handler =
    http_handler_new_with_data (dummy_handle, dummy_free, some_data);

  expect (dummy_free, when (data, is_equal_to (some_data)));

  assert_that (handler, is_not_null);
  assert_that (handler->handle, is_equal_to (dummy_handle));
  assert_that (handler->free, is_equal_to (dummy_free));
  assert_that (handler->data, is_equal_to (some_data));
  assert_that (handler->next, is_null);

  assert_that (get_call_count (), is_equal_to (0));
  assert_that (get_last_call (), is_null);

  http_handler_free (handler);
}

Ensure (gsad_http_handler, should_allow_to_set_next_handler)
{
  http_handler_t *handler1 = http_handler_new (dummy_handle);
  http_handler_t *handler2 = http_handler_new (dummy_handle);
  http_handler_t *handler3 = http_handler_new (dummy_handle);

  http_handler_set_next (handler1, handler2);

  assert_that (handler1->next, is_equal_to (handler2));
  assert_that (handler2->next, is_null);

  assert_that (get_call_count (), is_equal_to (0));
  assert_that (get_last_call (), is_null);

  http_handler_set_next (handler1, handler3);
  assert_that (handler1->next, is_equal_to (handler3));
  assert_that (handler3->next, is_null);

  assert_that (get_call_count (), is_equal_to (0));
  assert_that (get_last_call (), is_null);

  http_handler_free (handler1);
  http_handler_free (handler2);
}

Ensure (gsad_http_handler, should_allow_to_add_handler)
{
  http_handler_t *handler1 = http_handler_new (dummy_handle);
  http_handler_t *handler2 = http_handler_new (dummy_handle);
  http_handler_t *handler3 = http_handler_new (dummy_handle);

  http_handler_add (handler1, handler2);
  http_handler_add (handler1, handler3);

  assert_that (handler1->next, is_equal_to (handler2));
  assert_that (handler2->next, is_equal_to (handler3));
  assert_that (handler3->next, is_null);

  assert_that (get_call_count (), is_equal_to (0));
  assert_that (get_last_call (), is_null);

  http_handler_free (handler1);
}

Ensure (gsad_http_handler, should_start_handling)
{
  void *some_data = g_malloc0 (1);
  always_expect (dummy_handle, will_return (MHD_YES));
  http_handler_t *handler1 = http_handler_new (dummy_handle);
  http_handler_t *handler2 = http_handler_new (dummy_handle);

  http_handler_add (handler1, handler2);

  assert_that (handler1->next, is_equal_to (handler2));

  http_result_t result = http_handler_call (handler1, NULL, NULL, some_data);

  assert_that (result, is_equal_to (MHD_YES));
  assert_that (get_call_count (), is_equal_to (1));

  call_t *call = get_last_call ();
  assert_that (call, is_not_null);
  assert_that (call->handler_next, is_equal_to (handler2));
  assert_that (call->handler_data, is_null);
  assert_that (call->connection, is_null);
  assert_that (call->con_info, is_null);
  assert_that (call->data, is_equal_to (some_data));

  http_handler_free (handler1);
  g_free (some_data);
}

Ensure (gsad_http_handler, should_return_no_if_handler_is_null_when_calling_it)
{
  assert_that (http_handler_call (NULL, NULL, NULL, NULL),
               is_equal_to (MHD_NO));
}

Ensure (gsad_http_handler, should_call_handler_chain)
{
  void *some_data = g_malloc0 (1);
  always_expect (dummy_handle, will_return (MHD_YES));
  http_handler_t *handler1 = http_handler_new (dummy_call_next);
  http_handler_t *handler2 = http_handler_new (dummy_handle);

  http_handler_add (handler1, handler2);
  assert_that (handler1->next, is_equal_to (handler2));

  http_result_t result = http_handler_call (handler1, NULL, NULL, some_data);

  assert_that (result, is_equal_to (MHD_YES));
  assert_that (get_call_count (), is_equal_to (2));

  call_t *first_call = get_nth_call (0);
  assert_that (first_call, is_not_null);
  assert_that (first_call->handler_next, is_equal_to (handler2));
  assert_that (first_call->handler_data, is_null);
  assert_that (first_call->connection, is_null);
  assert_that (first_call->con_info, is_null);
  assert_that (first_call->data, is_equal_to (some_data));

  call_t *second_call = get_nth_call (1);
  assert_that (second_call, is_not_null);
  assert_that (second_call->handler_next, is_null);
  assert_that (second_call->handler_data, is_null);
  assert_that (second_call->connection, is_null);
  assert_that (second_call->con_info, is_null);
  assert_that (second_call->data, is_equal_to (some_data));

  http_handler_free (handler1);
  g_free (some_data);
}

Ensure (gsad_http_handler, should_call_handler_chain_with_handler_data)
{
  void *some_data = g_malloc0 (0);
  void *handler1_data = g_malloc0 (1);
  void *handler2_data = g_malloc0 (1);
  always_expect (dummy_handle, will_return (MHD_YES));
  http_handler_t *handler1 =
    http_handler_new_with_data (dummy_call_next, g_free, handler1_data);
  http_handler_t *handler2 =
    http_handler_new_with_data (dummy_handle, g_free, handler2_data);

  http_handler_add (handler1, handler2);
  assert_that (handler1->next, is_equal_to (handler2));

  http_result_t result = http_handler_call (handler1, NULL, NULL, some_data);

  assert_that (result, is_equal_to (MHD_YES));
  assert_that (get_call_count (), is_equal_to (2));

  call_t *first_call = get_nth_call (0);
  assert_that (first_call, is_not_null);
  assert_that (first_call->handler_next, is_equal_to (handler2));
  assert_that (first_call->handler_data, is_equal_to (handler1_data));
  assert_that (first_call->connection, is_null);
  assert_that (first_call->con_info, is_null);
  assert_that (first_call->data, is_equal_to (some_data));

  call_t *second_call = get_nth_call (1);
  assert_that (second_call, is_not_null);
  assert_that (second_call->handler_next, is_null);
  assert_that (second_call->handler_data, is_equal_to (handler2_data));
  assert_that (second_call->connection, is_null);
  assert_that (second_call->con_info, is_null);
  assert_that (second_call->data, is_equal_to (some_data));

  http_handler_free (handler1);
  g_free (some_data);
}

Ensure (gsad_http_handler, should_allow_to_free_null_handler)
{
  http_handler_free (NULL);
}

int
main (int argc, char **argv)
{
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, gsad_http_handler,
                         should_allow_to_create_new_handler);
  add_test_with_context (suite, gsad_http_handler,
                         should_allow_to_create_new_handler_with_data);
  add_test_with_context (suite, gsad_http_handler,
                         should_allow_to_set_next_handler);
  add_test_with_context (suite, gsad_http_handler, should_allow_to_add_handler);
  add_test_with_context (suite, gsad_http_handler, should_start_handling);
  add_test_with_context (suite, gsad_http_handler,
                         should_return_no_if_handler_is_null_when_calling_it);
  add_test_with_context (suite, gsad_http_handler, should_call_handler_chain);
  add_test_with_context (suite, gsad_http_handler,
                         should_call_handler_chain_with_handler_data);

  add_test_with_context (suite, gsad_http_handler,
                         should_allow_to_free_null_handler);

  int ret = run_test_suite (suite, create_text_reporter ());
  destroy_test_suite (suite);
  return ret;
}
