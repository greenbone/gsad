/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_http_url_handler.h"

#include "gsad_http_handler_internal.h"
#include "gsad_http_url_handler_internal.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "gsad http url handler"

/**
 * @brief Handler function for URL matching.
 *
 * This function checks if the request URL matches the regular expression in the
 * map. If it matches, the handler in the map is called. If it does not match,
 * the next handler in the chain is called.
 *
 * @param[in] current Current handler in the chain.
 * @param[in] connection The http connection object.
 * @param[in] con_info Connection information object containing details about
 * the request.
 * @param[in] data The URL map containing the regular expression and the handler
 * to call if the URL matches.
 */
http_result_t
gsad_http_url_handler_handle_url (http_handler_t *handler_next,
                                  void *handler_data,
                                  http_connection_t *connection,
                                  gsad_connection_info_t *con_info, void *data)
{
  gsad_http_url_handler_map_t *map =
    (gsad_http_url_handler_map_t *) handler_data;
  const gchar *url = gsad_connection_info_get_url (con_info);

  g_debug ("checking url map for url %s against %s\n", url,
           g_regex_get_pattern (map->gregexp));

  if (g_regex_match (map->gregexp, url, 0, NULL))
    {
      g_debug ("Found url handler for url %s\n", url);

      return http_handler_call (map->handler, connection, con_info, data);
    }

  return http_handler_call (handler_next, connection, con_info, data);
}

/**
 * @brief Create a new URL handler map.
 *
 * Maps a regular expression to a handler. The handler will be called if the URL
 * matches the regular expression.
 */
static gsad_http_url_handler_map_t *
gsad_http_url_handler_map_new (http_handler_t *handler, const gchar *regexp)
{
  gsad_http_url_handler_map_t *map =
    g_malloc0 (sizeof (gsad_http_url_handler_map_t));
  map->gregexp = g_regex_new (regexp, 0, 0, NULL);
  map->handler = handler;
  return map;
}

/**
 * @brief Free a URL handler map.
 *
 * @param[in] data The URL handler map to free.
 */
void
gsad_http_handler_url_map_free (void *data)
{
  if (!data)
    return;

  gsad_http_url_handler_map_t *map = (gsad_http_url_handler_map_t *) data;

  g_regex_unref (map->gregexp);
  http_handler_free (map->handler); /* free the chain */
  g_free (map);
}

/**
 * @brief Create a new handler for URL matching.
 *
 * @param regexp Regular expression to match the URL against.
 * @param handler Handler to use if the URL matches the regular expression.
 * If the URL does not match the regular expression, the next handler in the
 * chain will be called.
 *
 * @return A new http_handler_t object that handles the given URL.
 */
http_handler_t *
gsad_http_url_handler_new (const gchar *regexp, http_handler_t *handler)
{
  gsad_http_url_handler_map_t *map =
    gsad_http_url_handler_map_new (handler, regexp);
  return http_handler_new_with_data (&gsad_http_url_handler_handle_url,
                                     gsad_http_handler_url_map_free, map);
}

/**
 * @brief Create a new handler for URL matching from a handler function.
 *
 * @param[in] regexp Regular expression to match the URL against.
 * @param[in] func Handler function to call if the URL matches the regular
 * expression. If the URL does not match the regular expression, the next
 * handler in the chain will be called.
 *
 * @return A new http_handler_t object that handles the given URL.
 */
http_handler_t *
gsad_http_url_handler_from_func (const gchar *regexp, http_handler_func_t func)
{
  http_handler_t *handler = http_handler_new (func);
  return gsad_http_url_handler_new (regexp, handler);
}
