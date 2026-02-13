/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_HTTP_HANDLE_REQUEST_H
#define _GSAD_HTTP_HANDLE_REQUEST_H

#include "gsad_http_handler.h"

http_result_t
gsad_http_handle_request (void *, http_connection_t *, const gchar *,
                          const gchar *, const gchar *, const gchar *, size_t *,
                          void **);

http_handler_t *
init_http_handlers ();

void
cleanup_http_handlers ();

#endif /* _GSAD_HTTP_HANDLE_REQUEST_H */
