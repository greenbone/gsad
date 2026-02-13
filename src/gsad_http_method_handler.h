/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_HTTP_METHOD_HANDLER_H
#define _GSAD_HTTP_METHOD_HANDLER_H

#include "gsad_http_handler.h"

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "gsad http method handler"

http_handler_t *
method_router_new ();

void
method_router_set_get_handler (http_handler_t *router, http_handler_t *handler);

void
method_router_set_post_handler (http_handler_t *router,
                                http_handler_t *handler);

#endif /* _GSAD_HTTP_METHOD_HANDLER_H */
