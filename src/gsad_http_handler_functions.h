/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_HTTP_HANDLER_FUNCTIONS_H
#define _GSAD_HTTP_HANDLER_FUNCTIONS_H

#include "gsad_http_handler.h"

http_result_t
handle_validate (http_handler_t *, void *, http_connection_t *,
                 gsad_connection_info_t *, void *);

http_result_t
handle_invalid_method (http_handler_t *, void *, http_connection_t *,
                       gsad_connection_info_t *, void *);

http_result_t
handle_get_user (http_handler_t *, void *, http_connection_t *,
                 gsad_connection_info_t *, void *);

http_result_t
handle_setup_user (http_handler_t *, void *, http_connection_t *,
                   gsad_connection_info_t *, void *);

http_result_t
handle_setup_credentials (http_handler_t *, void *, http_connection_t *,
                          gsad_connection_info_t *, void *);

http_result_t
handle_logout (http_handler_t *, void *, http_connection_t *,
               gsad_connection_info_t *, void *);

http_result_t
handle_system_report (http_handler_t *, void *, http_connection_t *,
                      gsad_connection_info_t *, void *);

http_result_t
handle_index (http_handler_t *, void *, http_connection_t *,
              gsad_connection_info_t *, void *);

http_result_t
handle_static_file (http_handler_t *, void *, http_connection_t *,
                    gsad_connection_info_t *, void *);

http_result_t
handle_static_content (http_handler_t *, void *, http_connection_t *,
                       gsad_connection_info_t *, void *);

http_result_t
handle_static_config (http_handler_t *, void *, http_connection_t *,
                      gsad_connection_info_t *, void *);

http_result_t
handle_gmp_get (http_handler_t *, void *, http_connection_t *,
                gsad_connection_info_t *, void *);

http_result_t
handle_gmp_post (http_handler_t *, void *, http_connection_t *,
                 gsad_connection_info_t *, void *);

void
init_validator (void);

void
cleanup_validator (void);

#endif /* _GSAD_HTTP_HANDLER_FUNCTIONS_H */
