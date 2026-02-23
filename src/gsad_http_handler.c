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

/**
 * @brief Set the next handler
 *
 * @param[in] handler The handler to set the next handler for.
 * @param[in] next The handler to set as the next handler.
 * @param[in] free_next Whether to free the next handler when the handler is
 * freed.
 */
void
gsad_http_handler_set_next (gsad_http_handler_t *handler,
                            gsad_http_handler_t *next, gboolean free_next)
{
  handler->free_next = free_next;
  handler->next = next;
}

/**
 * @brief Default set_leaf function for http handlers.
 *
 * @param[in] handler The handler to set the next handler for.
 * @param[in] next The handler to set as the next handler.
 * @param[in] free_next Whether to free the next handler when the parent handler
 * is freed.
 */
void
gsad_http_handler_set_leaf (gsad_http_handler_t *handler,
                            gsad_http_handler_t *next, gboolean free_next)
{
  if (handler->next)
    {
      // there are more handlers in the chaing, so we are not the leaf handler.
      // Set the leaf handler in the next handler in the chain.
      handler->next->set_leaf (handler->next, next, free_next);
    }
  else
    {
      // we are the leaf handler, so we set the next handler as the leaf
      // handler.
      gsad_http_handler_set_next (handler, next, free_next);
    }
}

/**
 * @brief Add a handler to the end of the handler chain.
 *
 * @param[in] handler The handler (chain) to add the next handler.
 * @param[in] next The handler to add as the next handler.
 * @param[in] free_next Whether to free the next handler when the parent
 * handler is freed.
 *
 * @return The next handler
 */
gsad_http_handler_t *
gsad_http_handler_add_full (gsad_http_handler_t *handler,
                            gsad_http_handler_t *next, gboolean free_next)
{
  if (handler == NULL)
    {
      return next;
    }

  handler->set_leaf (handler, next, free_next);
  return next;
}

/**
 * @brief Add a handler to the end of the handler chain.
 *
 * @param[in] handler The handler (chain) to add the next handler.
 * @param[in] next The handler to add as the next handler.
 *
 * @return The next handler
 */
gsad_http_handler_t *
gsad_http_handler_add (gsad_http_handler_t *handler, gsad_http_handler_t *next)
{
  return gsad_http_handler_add_full (handler, next, TRUE);
}

/**
 * @brief Add a handler to the end of the handler chain by creating a new
 * handler with the given function.
 *
 * @param[in] handler The handler (chain) to add the next handler.
 * @param[in] func The function to call when the next handler is called.
 *
 * @return The next handler
 */
gsad_http_handler_t *
gsad_http_handler_add_from_func (gsad_http_handler_t *handler,
                                 gsad_http_handler_func_t func)
{
  return gsad_http_handler_add (handler, gsad_http_handler_new (func));
}

/**
 * @brief Call the handler chain.
 *
 * Calls the handler chain with the given connection, connection info and data.
 *
 * @param[in] handler The head of the handler chain to call.
 * @param[in] connection The connection to pass to the handlers.
 * @param[in] con_info The connection info to pass to the handlers.
 * @param[in] data The data to pass to the handlers.
 *
 * @return MHD_YES if the request was handled successfully, MHD_NO otherwise.
 */
gsad_http_result_t
gsad_http_handler_call (gsad_http_handler_t *handler,
                        gsad_http_connection_t *connection,
                        gsad_connection_info_t *con_info, void *data)
{
  if (handler == NULL)
    {
      return MHD_NO;
    }
  return handler->handle (handler->next, handler->data, connection, con_info,
                          data);
}

/**
 * @brief Create a new HTTP handler with handler data
 *
 * @param[in] func The function to call when the handler is called.
 * @param[in] free_func The function to call to free the handler data when the
 * handler is freed. Can be NULL if no special cleanup is needed.
 * @param[in] set_leaf_func The function to call to set the leaf handler in the
 * chain. Can be NULL to not support setting leaf handlers.
 * @param[in] handler_data The handler_data to pass to the handler function when
 * the handler is called.
 */
gsad_http_handler_t *
gsad_http_handler_new_with_data (
  gsad_http_handler_func_t func,
  gsad_http_handler_set_leaf_func_t set_leaf_func,
  gsad_http_handler_free_func_t free_func, void *handler_data)
{
  gsad_http_handler_t *handler = g_malloc0 (sizeof (gsad_http_handler_t));
  handler->handle = func;
  handler->data = handler_data;
  handler->free = free_func;
  handler->free_next = TRUE;
  handler->set_leaf =
    set_leaf_func ? set_leaf_func : gsad_http_handler_set_leaf;
  handler->next = NULL;
  return handler;
}

/**
 * @brief Create a new HTTP handler without handler data
 *
 * This is a convenience function for creating a handler without handler data.
 * It simply calls gsad_http_handler_new_with_data with NULL for the free
 * function and handler data.
 *
 * @param[in] func The function to call when the handler is called.
 *
 * @return A new HTTP handler that calls the given function when called.
 */
gsad_http_handler_t *
gsad_http_handler_new (gsad_http_handler_func_t func)
{
  return gsad_http_handler_new_with_data (func, NULL, NULL, NULL);
}

/**
 * @brief Free an HTTP handler and its handler chain.
 *
 * Frees the given handler and all handlers in its chain. If the handler has a
 * free function, it will be called with the handler data before freeing the
 * handler.
 *
 * @param[in] handler The handler to free.
 */
void
gsad_http_handler_free (gsad_http_handler_t *handler)
{
  if (!handler)
    return;

  if (handler->free_next && handler->next)
    {
      // free the chain
      gsad_http_handler_free (handler->next);
    }
  handler->next = NULL;
  if (handler->free)
    {
      handler->free (handler->data);
      handler->data = NULL;
    }
  g_free (handler);
}
