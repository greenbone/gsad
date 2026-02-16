/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_HTTP_HANDLER_INTERNAL_H
#define _GSAD_HTTP_HANDLER_INTERNAL_H

#include "gsad_http_handler.h"

/**
 * @brief Struct for handling HTTP requests.
 */
typedef struct gsad_http_handler
{
  gsad_http_handler_t *next; ///< next handler in the chain. to be called if the
                             // current handler does not handle the request
  gboolean free_next; ///< whether to free the next handler in the chain when
                      ///< this handler is freed
  gsad_http_handler_set_leaf_func_t
    set_leaf; ///< function to set the leaf handler(s) in the chain
  gsad_http_handler_func_t
    handle; ///< function to call when the handler is called
  gsad_http_handler_free_func_t free; ///< function to call to free the handler
                                      ///< data when the handler is freed
  void
    *data; ///< data to pass to the handler function when the handler is called
} gsad_http_handler_t;

gsad_http_handler_t *
gsad_http_handler_add_full (gsad_http_handler_t *, gsad_http_handler_t *,
                            gboolean);

void
gsad_http_handler_set_leaf (gsad_http_handler_t *handler,
                            gsad_http_handler_t *next, gboolean free_next);

#endif /* _GSAD_HTTP_HANDLER_INTERNAL_H */
