/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_HTTP_METHOD_HANDLER_H
#define _GSAD_HTTP_METHOD_HANDLER_H

#include "gsad_http_handler.h"

gsad_http_handler_t *
gsad_http_method_handler_new_with_handlers (gsad_http_handler_t *,
                                            gsad_http_handler_t *);

gsad_http_handler_t *
  gsad_http_method_handler_new_get_from_func (gsad_http_handler_func_t);

gsad_http_handler_t *
  gsad_http_method_handler_new_post_from_func (gsad_http_handler_func_t);

gsad_http_handler_t *
gsad_http_method_handler_new_get (gsad_http_handler_t *);

gsad_http_handler_t *
gsad_http_method_handler_new_post (gsad_http_handler_t *);

#endif /* _GSAD_HTTP_METHOD_HANDLER_H */
