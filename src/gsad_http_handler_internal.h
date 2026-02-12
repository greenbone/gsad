/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_HTTP_HANDLER_INTERNAL_H
#define _GSAD_HTTP_HANDLER_INTERNAL_H

#include "gsad_http_handler.h"

typedef struct http_handler
{
  http_handler_t *next;
  http_handler_func_t handle;
  http_handler_free_func_t free;
  void *data;
} http_handler_t;

#endif /* _GSAD_HTTP_HANDLER_INTERNAL_H */
