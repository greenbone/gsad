/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_HTTP_URL_HANDLER_H
#define _GSAD_HTTP_URL_HANDLER_H

#include "gsad_http_handler.h"

http_handler_t *
gsad_http_url_handler_new (const gchar *, http_handler_t *);

http_handler_t *
gsad_http_url_handler_from_func (const gchar *, http_handler_func_t);

#endif /* _GSAD_HTTP_URL_HANDLER_H */
