/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_HTTP_URL_HANDLER_INTERNAL_H
#define _GSAD_HTTP_URL_HANDLER_INTERNAL_H

#include "gsad_http_handler.h"

/**
 * @brief URL regexp to handler function mapping
 *
 * Instances of url_map contain a compiled glib perl compatible regular
 * expression and a http handler function.
 */
typedef struct gsad_http_url_handler_map
{
  GRegex *gregexp;
  gsad_http_handler_t *handler;
} gsad_http_url_handler_map_t;

#endif /* _GSAD_HTTP_URL_HANDLER_INTERNAL_H */
