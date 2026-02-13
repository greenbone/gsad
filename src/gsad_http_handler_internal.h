/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_HTTP_HANDLER_INTERNAL_H
#define _GSAD_HTTP_HANDLER_INTERNAL_H

#include "gsad_http_handler.h"

typedef struct gsad_http_handler
{
  gsad_http_handler_t *next;
  gsad_http_handler_func_t handle;
  gsad_http_handler_free_func_t free;
  void *data;
} gsad_http_handler_t;

#endif /* _GSAD_HTTP_HANDLER_INTERNAL_H */
