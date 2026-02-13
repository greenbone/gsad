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

typedef struct gsad_http_handler gsad_http_handler_t;

typedef void (*gsad_http_handler_free_func_t) (void *);

typedef gsad_http_result_t (*gsad_http_handler_func_t) (
  gsad_http_handler_t *, void *, gsad_http_connection_t *,
  gsad_connection_info_t *, void *);

gsad_http_handler_t *gsad_http_handler_new (gsad_http_handler_func_t);

gsad_http_handler_t *
gsad_http_handler_new_with_data (gsad_http_handler_func_t,
                                 gsad_http_handler_free_func_t, void *);

gsad_http_handler_t *
gsad_http_handler_add (gsad_http_handler_t *, gsad_http_handler_t *);

gsad_http_handler_t *
gsad_http_handler_set_next (gsad_http_handler_t *, gsad_http_handler_t *);

gsad_http_result_t
gsad_http_handler_call (gsad_http_handler_t *, gsad_http_connection_t *,
                        gsad_connection_info_t *, void *);

void
gsad_http_handler_free (gsad_http_handler_t *);

#endif /* _GSAD_HTTP_HANDLER_H */
