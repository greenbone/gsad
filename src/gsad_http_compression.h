/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_HTTP_COMPRESSION_H
#define _GSAD_HTTP_COMPRESSION_H

#include "gsad_http.h"

gboolean
gsad_http_may_compress (gsad_http_connection_t *, const gchar *);

gboolean
gsad_http_may_deflate (gsad_http_connection_t *);

gboolean
gsad_http_may_brotli (gsad_http_connection_t *);

int
gsad_http_compress_response_deflate (const size_t, const gchar *, size_t *,
                                     gchar **comp);

int
gsad_http_compress_response_brotli (const size_t, const gchar *, size_t *,
                                    gchar **comp);

#endif /* _GSAD_HTTP_COMPRESSION_H */
