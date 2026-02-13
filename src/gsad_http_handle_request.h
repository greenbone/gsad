/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_HTTP_HANDLE_REQUEST_H
#define _GSAD_HTTP_HANDLE_REQUEST_H

#include "gsad_http_handler.h"

http_result_t
handle_request (void *cls, http_connection_t *connection, const gchar *url,
                const gchar *method, const gchar *version,
                const gchar *upload_data, size_t *upload_data_size,
                void **con_cls);

http_handler_t *
init_http_handlers ();

void
cleanup_http_handlers ();

#endif /* _GSAD_HTTP_HANDLE_REQUEST_H */
