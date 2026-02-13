/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_HTTP_HANDLE_REQUEST_H
#define _GSAD_HTTP_HANDLE_REQUEST_H

#include "gsad_http_handler.h"

gsad_http_result_t
gsad_http_handle_request (void *, gsad_http_connection_t *, const gchar *,
                          const gchar *, const gchar *, const gchar *, size_t *,
                          void **);

gsad_http_handler_t *
gsad_http_request_init_handlers ();

void
gsad_http_request_cleanup_handlers ();

#endif /* _GSAD_HTTP_HANDLE_REQUEST_H */
