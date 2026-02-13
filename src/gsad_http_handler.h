/* Copyright (C) 2016-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_http_handler.c
 * @brief HTTP handling of GSA.
 */

#ifndef _GSAD_HTTP_HANDLER_H
#define _GSAD_HTTP_HANDLER_H

#include "gsad_http.h"

typedef struct http_handler http_handler_t;

typedef void (*http_handler_free_func_t) (void *);

typedef http_result_t (*http_handler_func_t) (http_handler_t *, void *,
                                              http_connection_t *,
                                              gsad_connection_info_t *, void *);

http_handler_t *http_handler_new (http_handler_func_t);

http_handler_t *
http_handler_new_with_data (http_handler_func_t, http_handler_free_func_t,
                            void *);

http_handler_t *
http_handler_add (http_handler_t *, http_handler_t *);

http_handler_t *
http_handler_set_next (http_handler_t *, http_handler_t *);

http_result_t
http_handler_call (http_handler_t *, http_connection_t *,
                   gsad_connection_info_t *, void *);

void
http_handler_free (http_handler_t *);

#endif /* _GSAD_HTTP_HANDLER_H */
