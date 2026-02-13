/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_HTTP_METHOD_HANDLER_INTERNAL_H
#define _GSAD_HTTP_METHOD_HANDLER_INTERNAL_H

#include "gsad_http_handler.h"

/**
 * @brief Struct for the method handler data.
 */
typedef struct gsad_http_method_handler
{
  gsad_http_handler_t *get;  ///< Handler for GET requests.
  gsad_http_handler_t *post; ///< Handler for POST requests.
} gsad_http_method_handler_t;

void
gsad_http_method_handler_free (void *);

#endif /* _GSAD_HTTP_METHOD_HANDLER_INTERNAL_H */
