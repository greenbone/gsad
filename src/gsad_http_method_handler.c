/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_http_method_handler.h"

#include "gsad_http_handler_internal.h"

#undef G_LOG_DOMAIN

#define G_LOG_DOMAIN "gsad http method handler"

typedef struct method_router
{
  http_handler_t *get;
  http_handler_t *post;
} method_router_t;

http_result_t
handle_get_post (http_handler_t *handler_next, void *handler_data,
                 http_connection_t *connection,
                 gsad_connection_info_t *con_info, void *data)
{
  method_router_t *routes = (method_router_t *) handler_data;

  if (gsad_connection_info_get_method_type (con_info) == METHOD_TYPE_GET)
    {
      g_debug ("method router handling GET");
      return http_handler_call (routes->get, connection, con_info, data);
    }
  if (gsad_connection_info_get_method_type (con_info) == METHOD_TYPE_POST)
    {
      g_debug ("method router handling POST");
      return http_handler_call (routes->post, connection, con_info, data);
    }
  return http_handler_call (handler_next, connection, con_info, data);
}

void
method_router_free (void *data)
{
  method_router_t *routes = (method_router_t *) data;

  http_handler_free (routes->get);
  http_handler_free (routes->post);

  g_free (routes);
}

http_handler_t *
method_router_new ()
{
  method_router_t *router = g_malloc0 (sizeof (method_router_t));
  router->get = NULL;
  router->post = NULL;
  return http_handler_new_with_data (handle_get_post, method_router_free,
                                     router);
}

void
method_router_set_get_handler (http_handler_t *router, http_handler_t *handler)
{
  method_router_t *method_router = (method_router_t *) router->data;
  method_router->get = handler;
}

void
method_router_set_post_handler (http_handler_t *router, http_handler_t *handler)
{
  method_router_t *method_router = (method_router_t *) router->data;
  method_router->post = handler;
}
