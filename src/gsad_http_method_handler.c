/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_http_method_handler.h"

#include "gsad_http_handler_internal.h"
#include "gsad_http_method_handler_internal.h"

#undef G_LOG_DOMAIN

#define G_LOG_DOMAIN "gsad http method handler"

/**
 * @brief Handler function for routing based on HTTP method.
 *
 * This function checks the HTTP method of the incoming request and routes it to
 * the appropriate handler based on the method. If the method is GET, it routes
 * to the GET handler. If the method is POST, it routes to the POST handler. If
 * the method is neither GET nor POST, it routes to the next handler in the
 * chain.
 *
 * @param[in] handler_next The next handler in the chain to call if the method
 * does not match.
 * @param[in] handler_data The method router containing the GET and POST
 * handlers.
 * @param[in] connection The http connection object.
 * @param[in] con_info Connection information object containing details about
 * the request.
 * @param[in] data Additional data to pass to the handlers.
 *
 * @return MHD_YES if the request was handled successfully, MHD_NO otherwise.
 */
static gsad_http_result_t
handle_get_post (gsad_http_handler_t *handler_next, void *handler_data,
                 gsad_http_connection_t *connection,
                 gsad_connection_info_t *con_info, void *data)
{
  gsad_http_method_handler_t *routes =
    (gsad_http_method_handler_t *) handler_data;

  if (routes->get != NULL
      && gsad_connection_info_get_method_type (con_info) == METHOD_TYPE_GET)
    {
      g_debug ("Handling GET method");
      return gsad_http_handler_call (routes->get, connection, con_info, data);
    }
  else if (routes->post != NULL
           && gsad_connection_info_get_method_type (con_info)
                == METHOD_TYPE_POST)
    {
      g_debug ("Handling POST method");
      return gsad_http_handler_call (routes->post, connection, con_info, data);
    }
  return gsad_http_handler_call (handler_next, connection, con_info, data);
}

static void
gsad_http_method_handler_set_leaf (gsad_http_handler_t *handler,
                                   gsad_http_handler_t *next,
                                   gboolean free_next)
{
  gsad_http_method_handler_t *routes =
    (gsad_http_method_handler_t *) handler->data;
  if (routes->get != NULL)
    {
      // Set the next handler for the GET handler chain
      // We set free_next to FALSE here because the method handler is
      // responsible for freeing the GET and POST handlers, so we don't want the
      // GET handler to free the next handler in the chain.
      routes->get->set_leaf (routes->get, next, FALSE);
    }
  if (routes->post != NULL)
    {
      // Set the next handler for the POST handler chain
      // We set free_next to FALSE here because the method handler is
      // responsible for freeing the GET and POST handlers, so we don't want the
      // POST handler to free the next handler in the chain.
      routes->post->set_leaf (routes->post, next, FALSE);
    }
  gsad_http_handler_set_leaf (handler, next, free_next);
}

/**
 * @brief Create a new method handler with the specified GET and POST handlers.
 *
 * This function creates a new method handler and sets the GET and POST handlers
 * to the specified handlers. The method handler will route incoming requests to
 * the appropriate handler based on the HTTP method of the request.
 *
 * @param[in] get_handler The handler to route GET requests to.
 * @param[in] post_handler The handler to route POST requests to.
 *
 * @return A new method handler with the specified GET and POST handlers.
 */
gsad_http_handler_t *
gsad_http_method_handler_new_with_handlers (gsad_http_handler_t *get_handler,
                                            gsad_http_handler_t *post_handler)
{
  gsad_http_method_handler_t *router =
    g_malloc0 (sizeof (gsad_http_method_handler_t));
  router->get = get_handler;
  router->post = post_handler;
  return gsad_http_handler_new_with_data (
    handle_get_post, gsad_http_method_handler_set_leaf,
    gsad_http_method_handler_free, router);
}

/**
 * @brief Create a new method handler for POST request handling with the
 * specified handler.
 *
 * This is a convenience function for creating a method handler with only a POST
 * handler.
 *
 * @param[in] post_handler The handler to route POST requests to.
 *
 * @return A new method handler with the specified POST handler.
 */
gsad_http_handler_t *
gsad_http_method_handler_new_post (gsad_http_handler_t *post_handler)
{
  return gsad_http_method_handler_new_with_handlers (NULL, post_handler);
}

/**
 * @brief Create a new method handler for GET request handling with the
 * specified handler.
 *
 * This is a convenience function for creating a method handler with only a GET
 * handler.
 *
 * @param[in] get_handler The handler to route GET requests to.
 *
 * @return A new method handler with the specified GET handler.
 */
gsad_http_handler_t *
gsad_http_method_handler_new_get (gsad_http_handler_t *get_handler)
{
  return gsad_http_method_handler_new_with_handlers (get_handler, NULL);
}

/**
 * @brief Create a new method handler for GET request handling with the
 * specified handler function.
 *
 * @param[in] get_func The handler function to handle GET requests.
 *
 * @return A new method handler with the specified GET handler function.
 */
gsad_http_handler_t *
gsad_http_method_handler_new_get_from_func (gsad_http_handler_func_t get_func)
{
  return gsad_http_method_handler_new_get (gsad_http_handler_new (get_func));
}

/**
 * @brief Create a new method handler for POST request handling with the
 * specified handler function.
 *
 * @param[in] post_func The handler function to handle POST requests.
 *
 * @return A new method handler with the specified POST handler function.
 */
gsad_http_handler_t *
gsad_http_method_handler_new_post_from_func (gsad_http_handler_func_t post_func)
{
  gsad_http_handler_t *post_handler = gsad_http_handler_new (post_func);
  return gsad_http_method_handler_new_post (post_handler);
}

/**
 * @brief Free function for the method handler
 *
 * This function is called when the method handler is freed. It frees the GET
 * and POST handlers and then frees the method handler itself.
 *
 * @param[in] handler The method handler to free.
 *
 * @param[in] data The method handler to free.
 */
void
gsad_http_method_handler_free (void *data)
{
  gsad_http_method_handler_t *routes = (gsad_http_method_handler_t *) data;

  gsad_http_handler_free (routes->get);
  gsad_http_handler_free (routes->post);

  g_free (routes);
}
