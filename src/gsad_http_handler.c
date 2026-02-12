/* Copyright (C) 2016-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_http_handler.c
 * @brief HTTP handling of GSA.
 */

#include "gsad_http_handler.h"

#include "gsad_http_handler_internal.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "gsad http handler"

/**
 * @file gsad_http_handler.c
 * @brief HTTP URL handling/routing
 */

typedef struct method_router
{
  http_handler_t *get;
  http_handler_t *post;
} method_router_t;

http_handler_t *
http_handler_add (http_handler_t *handlers, http_handler_t *next)
{
  http_handler_t *handler = handlers;

  if (handler == NULL)
    {
      return next;
    }

  while (handler->next != NULL)
    {
      handler = handler->next;
    }

  handler->next = next;

  return handlers;
}

http_handler_t *
http_handler_set_next (http_handler_t *handler, http_handler_t *next)
{
  if (handler == NULL)
    {
      return next;
    }
  handler->next = next;
  return next;
}

http_result_t
http_handler_call (http_handler_t *handler, http_connection_t *connection,
                   gsad_connection_info_t *con_info, void *data)
{
  if (handler == NULL)
    {
      return MHD_NO;
    }
  return handler->handle (handler->next, handler->data, connection, con_info,
                          data);
}

http_handler_t *
http_handler_new_with_data (http_handler_func_t func,
                            http_handler_free_func_t freefunc, void *data)
{
  http_handler_t *handler = g_malloc0 (sizeof (http_handler_t));
  handler->handle = func;
  handler->free = freefunc;
  handler->data = data;
  handler->next = NULL;
  return handler;
}

http_handler_t *
http_handler_new (http_handler_func_t func)
{
  return http_handler_new_with_data (func, NULL, NULL);
}

void
http_handler_free (http_handler_t *handler)
{
  if (!handler)
    return;

  if (handler->next)
    {
      // free the chain
      http_handler_free (handler->next);
    }
  if (handler->free)
    {
      handler->free (handler->data);
    }
  g_free (handler);
}

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
