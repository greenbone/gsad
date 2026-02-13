/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_http_method_handler.h"

#include "gsad_http_handler_internal.h"

#undef G_LOG_DOMAIN

#define G_LOG_DOMAIN "gsad http method handler"

/**
 * @brief Struct for the method handler data.
 */
typedef struct gsad_http_method_handler
{
  gsad_http_handler_t *get;  ///< Handler for GET requests.
  gsad_http_handler_t *post; ///< Handler for POST requests.
} gsad_http_method_handler_t;

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
gsad_http_result_t
handle_get_post (gsad_http_handler_t *handler_next, void *handler_data,
                 gsad_http_connection_t *connection,
                 gsad_connection_info_t *con_info, void *data)
{
  gsad_http_method_handler_t *routes =
    (gsad_http_method_handler_t *) handler_data;

  if (gsad_connection_info_get_method_type (con_info) == METHOD_TYPE_GET)
    {
      g_debug ("method router handling GET");
      return gsad_http_handler_call (routes->get, connection, con_info, data);
    }
  if (gsad_connection_info_get_method_type (con_info) == METHOD_TYPE_POST)
    {
      g_debug ("method router handling POST");
      return gsad_http_handler_call (routes->post, connection, con_info, data);
    }
  return gsad_http_handler_call (handler_next, connection, con_info, data);
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

/**
 * @brief Create a new method handler
 *
 * This function creates a new method handler with the GET and POST handlers set
 * to NULL. The caller can then set the GET and POST handlers using the
 * gsad_http_method_handler_set_get_handler and
 * gsad_http_method_handler_set_post_handler functions.
 *
 * @return A new method handler.
 */
gsad_http_handler_t *
gsad_http_method_handler_new ()
{
  gsad_http_method_handler_t *router =
    g_malloc0 (sizeof (gsad_http_method_handler_t));
  router->get = NULL;
  router->post = NULL;
  return gsad_http_handler_new_with_data (
    handle_get_post, gsad_http_method_handler_free, router);
}

/**
 * @brief Set the GET handler for the method handler
 *
 * @param[in] router The method handler to set the GET handler for.
 * @param[in] handler The GET handler to set.
 */
void
gsad_http_method_handler_set_get_handler (const gsad_http_handler_t *router,
                                          gsad_http_handler_t *handler)
{
  gsad_http_method_handler_t *method_handler =
    (gsad_http_method_handler_t *) router->data;
  method_handler->get = handler;
}

/**
 * @brief Set the POST handler for the method handler
 *
 * @param[in] router The method handler to set the POST handler for.
 * @param[in] handler The POST handler to set.
 */
void
gsad_http_method_handler_set_post_handler (const gsad_http_handler_t *router,
                                           gsad_http_handler_t *handler)
{
  gsad_http_method_handler_t *method_handler =
    (gsad_http_method_handler_t *) router->data;
  method_handler->post = handler;
}
