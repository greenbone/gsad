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
 * @brief Add a handler to the end of the handler chain.
 *
 * If the handler chain is empty, the new handler will be the first handler.
 * Otherwise, the new handler will be added to the end of the chain.
 *
 * @param[in] handlers The handler chain to add to.
 * @param[in] next The handler to add to the end of the chain.
 *
 * @return The head of the handler chain.
 */
gsad_http_handler_t *
gsad_http_handler_add (gsad_http_handler_t *handlers, gsad_http_handler_t *next)
{
  gsad_http_handler_t *handler = handlers;

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

/**
 * @brief Set the next handler in the chain.
 *
 * If the handler is NULL, the next handler will be returned. Otherwise, the
 * next handler will be set and returned.
 *
 * @param[in] handler The handler to set the next handler for.
 * @param[in] next The handler to set as the next handler.
 *
 * @return The next handler in the chain.
 */
gsad_http_handler_t *
gsad_http_handler_set_next (gsad_http_handler_t *handler,
                            gsad_http_handler_t *next)
{
  if (handler == NULL)
    {
      return next;
    }
  handler->next = next;
  return next;
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
 * @param[in] freefunc The function to call to free the handler data when the
 * handler is freed. Can be NULL if no special cleanup is needed.
 * @param[in] handler_data The handler_data to pass to the handler function when
 * the handler is called.
 */
gsad_http_handler_t *
gsad_http_handler_new_with_data (gsad_http_handler_func_t func,
                                 gsad_http_handler_free_func_t freefunc,
                                 void *handler_data)
{
  gsad_http_handler_t *handler = g_malloc0 (sizeof (gsad_http_handler_t));
  handler->handle = func;
  handler->free = freefunc;
  handler->data = handler_data;
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
gad_http_handler_new (gsad_http_handler_func_t func)
{
  return gsad_http_handler_new_with_data (func, NULL, NULL);
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

  if (handler->next)
    {
      // free the chain
      gsad_http_handler_free (handler->next);
    }
  if (handler->free)
    {
      handler->free (handler->data);
    }
  g_free (handler);
}
