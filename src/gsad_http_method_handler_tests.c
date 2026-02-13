/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_http_handler_internal.h"
#include "gsad_http_method_handler.h"
#include "gsad_http_method_handler_internal.h"

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

GList *calls;

Describe (gsad_http_method_handler);

BeforeEach (gsad_http_method_handler)
{
  calls = NULL;
}

AfterEach (gsad_http_method_handler)
{
  g_list_free (calls);
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

static gsad_http_result_t
dummy_handle_yes (gsad_http_handler_t *handler_next, void *handler_data,
                  gsad_http_connection_t *connection,
                  gsad_connection_info_t *con_info, void *data)
{
  record_call (handler_next, handler_data, connection, con_info, data);
  return MHD_YES;
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

Ensure (gsad_http_method_handler, should_create_new_handler)
{
  gsad_http_handler_t *method_handler = gsad_http_method_handler_new ();
  gsad_http_method_handler_t *handler_data =
    (gsad_http_method_handler_t *) method_handler->data;

  assert_that (handler_data, is_not_null);
  assert_that (method_handler, is_not_null);
  assert_that (method_handler->handle, is_not_null);
  assert_that (method_handler->next, is_null);
  assert_that (handler_data->get, is_null);
  assert_that (handler_data->post, is_null);

  gsad_http_handler_free (method_handler);
}

Ensure (gsad_http_method_handler, should_create_new_get_handler)
{
  gsad_http_handler_t *method_handler =
    gsad_http_method_handler_new_from_get_func (dummy_handle);
  gsad_http_method_handler_t *handler_data =
    (gsad_http_method_handler_t *) method_handler->data;

  assert_that (handler_data, is_not_null);
  assert_that (method_handler, is_not_null);
  assert_that (method_handler->handle, is_not_null);
  assert_that (method_handler->next, is_null);
  assert_that (handler_data->get, is_not_null);
  assert_that (handler_data->get->handle, is_equal_to (dummy_handle));
  assert_that (handler_data->post, is_null);

  gsad_http_handler_free (method_handler);
}

Ensure (gsad_http_method_handler, should_create_new_post_handler)
{
  gsad_http_handler_t *method_handler =
    gsad_http_method_handler_new_from_post_func (dummy_handle);
  gsad_http_method_handler_t *handler_data =
    (gsad_http_method_handler_t *) method_handler->data;

  assert_that (handler_data, is_not_null);
  assert_that (method_handler, is_not_null);
  assert_that (method_handler->handle, is_not_null);
  assert_that (method_handler->next, is_null);
  assert_that (handler_data->get, is_null);
  assert_that (handler_data->post, is_not_null);
  assert_that (handler_data->post->handle, is_equal_to (dummy_handle));

  gsad_http_handler_free (method_handler);
}

Ensure (gsad_http_method_handler, should_create_new_handler_with_handlers)
{
  gsad_http_handler_t *get_handler = gsad_http_handler_new (dummy_handle);
  gsad_http_handler_t *post_handler = gsad_http_handler_new (dummy_handle);
  gsad_http_handler_t *method_handler =
    gsad_http_method_handler_new_with_handlers (get_handler, post_handler);
  gsad_http_method_handler_t *handler_data =
    (gsad_http_method_handler_t *) method_handler->data;

  assert_that (handler_data, is_not_null);
  assert_that (method_handler, is_not_null);
  assert_that (method_handler->handle, is_not_null);
  assert_that (method_handler->next, is_null);
  assert_that (handler_data->get, is_not_null);
  assert_that (handler_data->get->handle, is_equal_to (dummy_handle));
  assert_that (handler_data->post, is_not_null);
  assert_that (handler_data->post->handle, is_equal_to (dummy_handle));

  gsad_http_handler_free (method_handler);
}

Ensure (gsad_http_method_handler, should_call_get_handler_for_get_method)
{
  gsad_http_handler_t *method_handler =
    gsad_http_method_handler_new_from_get_func (dummy_handle);
  gsad_connection_info_t *con_info =
    gsad_connection_info_new (METHOD_TYPE_GET, "/some-url");

  expect (dummy_handle, will_return (MHD_YES));
  gsad_http_result_t result =
    gsad_http_handler_call (method_handler, NULL, con_info, NULL);
  assert_that (result, is_equal_to (MHD_YES));
  assert_that (get_call_count (), is_equal_to (1));

  call_t *call = get_last_call ();
  assert_that (call, is_not_null);
  assert_that (call->handler_next, is_null);
  assert_that (call->handler_data, is_null);
  assert_that (call->connection, is_null);
  assert_that (call->con_info, is_equal_to (con_info));
  assert_that (call->data, is_null);

  gsad_http_handler_free (method_handler);
}

Ensure (gsad_http_method_handler, should_call_post_handler_for_post_method)
{
  gsad_http_handler_t *method_handler =
    gsad_http_method_handler_new_from_post_func (dummy_handle);
  gsad_connection_info_t *con_info =
    gsad_connection_info_new (METHOD_TYPE_POST, "/some-url");

  expect (dummy_handle, will_return (MHD_YES));
  gsad_http_result_t result =
    gsad_http_handler_call (method_handler, NULL, con_info, NULL);
  assert_that (result, is_equal_to (MHD_YES));
  assert_that (get_call_count (), is_equal_to (1));

  call_t *call = get_last_call ();
  assert_that (call, is_not_null);
  assert_that (call->handler_next, is_null);
  assert_that (call->handler_data, is_null);
  assert_that (call->connection, is_null);
  assert_that (call->con_info, is_equal_to (con_info));
  assert_that (call->data, is_null);

  gsad_http_handler_free (method_handler);
}

Ensure (gsad_http_method_handler, should_not_call_handlers_for_other_methods)
{
  gsad_http_handler_t *get_handler = gsad_http_handler_new (dummy_handle_yes);
  gsad_http_handler_t *post_handler = gsad_http_handler_new (dummy_handle_yes);
  gsad_http_handler_t *method_handler =
    gsad_http_method_handler_new_with_handlers (get_handler, post_handler);
  gsad_connection_info_t *con_info =
    gsad_connection_info_new (METHOD_TYPE_UNKNOWN, "/some-url");

  gsad_http_result_t result =
    gsad_http_handler_call (method_handler, NULL, con_info, NULL);
  assert_that (result, is_equal_to (MHD_NO));
  assert_that (get_call_count (), is_equal_to (0));

  gsad_http_handler_free (method_handler);
}

Ensure (gsad_http_method_handler, should_call_next_handler_for_other_methods)
{
  gsad_http_handler_t *get_handler = gsad_http_handler_new (dummy_handle_yes);
  gsad_http_handler_t *post_handler = gsad_http_handler_new (dummy_handle_yes);
  gsad_http_handler_t *method_handler =
    gsad_http_method_handler_new_with_handlers (get_handler, post_handler);
  gsad_http_handler_t *next_handler = gsad_http_handler_new (dummy_handle);
  gsad_http_handler_set_next (method_handler, next_handler);
  gsad_connection_info_t *con_info =
    gsad_connection_info_new (METHOD_TYPE_UNKNOWN, "/some-url");

  expect (dummy_handle, will_return (MHD_YES));
  gsad_http_result_t result =
    gsad_http_handler_call (method_handler, NULL, con_info, NULL);
  assert_that (result, is_equal_to (MHD_YES));
  assert_that (get_call_count (), is_equal_to (1));

  call_t *call = get_last_call ();
  assert_that (call, is_not_null);
  assert_that (call->handler_next, is_null);
  assert_that (call->handler_data, is_null);
  assert_that (call->connection, is_null);
  assert_that (call->con_info, is_equal_to (con_info));
  assert_that (call->data, is_null);

  gsad_http_handler_free (method_handler);
}

int
main (int argc, char **argv)
{
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, gsad_http_method_handler,
                         should_create_new_handler);
  add_test_with_context (suite, gsad_http_method_handler,
                         should_create_new_get_handler);
  add_test_with_context (suite, gsad_http_method_handler,
                         should_create_new_post_handler);
  add_test_with_context (suite, gsad_http_method_handler,
                         should_create_new_handler_with_handlers);
  add_test_with_context (suite, gsad_http_method_handler,
                         should_call_get_handler_for_get_method);
  add_test_with_context (suite, gsad_http_method_handler,
                         should_call_post_handler_for_post_method);
  add_test_with_context (suite, gsad_http_method_handler,
                         should_not_call_handlers_for_other_methods);
  add_test_with_context (suite, gsad_http_method_handler,
                         should_call_next_handler_for_other_methods);

  int ret = run_test_suite (suite, create_text_reporter ());
  destroy_test_suite (suite);
  return ret;
}
