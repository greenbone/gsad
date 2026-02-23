/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_HTTP_HANDLER_FUNCTIONS_H
#define _GSAD_HTTP_HANDLER_FUNCTIONS_H

#include "gsad_http_handler.h"

gsad_http_result_t
gsad_http_handle_validate (gsad_http_handler_t *, void *,
                           gsad_http_connection_t *, gsad_connection_info_t *,
                           void *);

gsad_http_result_t
gsad_http_handle_invalid_method (gsad_http_handler_t *, void *,
                                 gsad_http_connection_t *,
                                 gsad_connection_info_t *, void *);

gsad_http_result_t
gsad_http_handle_get_user (gsad_http_handler_t *, void *,
                           gsad_http_connection_t *, gsad_connection_info_t *,
                           void *);

gsad_http_result_t
gsad_http_handle_setup_user (gsad_http_handler_t *, void *,
                             gsad_http_connection_t *, gsad_connection_info_t *,
                             void *);

gsad_http_result_t
gsad_http_handle_setup_credentials (gsad_http_handler_t *, void *,
                                    gsad_http_connection_t *,
                                    gsad_connection_info_t *, void *);

gsad_http_result_t
gsad_http_handle_logout (gsad_http_handler_t *, void *,
                         gsad_http_connection_t *, gsad_connection_info_t *,
                         void *);

gsad_http_result_t
gsad_http_handle_system_report (gsad_http_handler_t *, void *,
                                gsad_http_connection_t *,
                                gsad_connection_info_t *, void *);

gsad_http_result_t
gsad_http_handle_index (gsad_http_handler_t *, void *, gsad_http_connection_t *,
                        gsad_connection_info_t *, void *);

gsad_http_result_t
gsad_http_handle_static_file (gsad_http_handler_t *, void *,
                              gsad_http_connection_t *,
                              gsad_connection_info_t *, void *);

gsad_http_result_t
gsad_http_handle_static_content (gsad_http_handler_t *, void *,
                                 gsad_http_connection_t *,
                                 gsad_connection_info_t *, void *);

gsad_http_result_t
gsad_http_handle_static_config (gsad_http_handler_t *, void *,
                                gsad_http_connection_t *,
                                gsad_connection_info_t *, void *);

gsad_http_result_t
gsad_http_handle_gmp_get (gsad_http_handler_t *, void *,
                          gsad_http_connection_t *, gsad_connection_info_t *,
                          void *);

gsad_http_result_t
gsad_http_handle_gmp_post (gsad_http_handler_t *, void *,
                           gsad_http_connection_t *, gsad_connection_info_t *,
                           void *);

gsad_http_result_t
gsad_http_handle_not_found (gsad_http_handler_t *, void *,
                            gsad_http_connection_t *, gsad_connection_info_t *,
                            void *);
void
gsad_http_init_validator (void);

void
gsad_http_cleanup_validator (void);

#endif /* _GSAD_HTTP_HANDLER_FUNCTIONS_H */
