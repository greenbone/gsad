/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_CONNECTION_INFO_H
#define _GSAD_CONNECTION_INFO_H

#include "gsad_params.h"

#include <glib.h>
#include <microhttpd.h>

/**
 * @brief Connection information for GSA HTTP requests.
 *
 * This file defines the gsad_connection_info_t structure and related functions
 * to manage connection information during HTTP request handling in GSA.
 */

/**
 * @brief Method type for HTTP requests.
 */
typedef enum gsad_method_type
{
  METHOD_TYPE_UNKNOWN =
    0, ///< Other/Unknown method types. Currently only GET and POST are used.
  METHOD_TYPE_POST = 1, ///< POST method.
  METHOD_TYPE_GET = 2   ///< GET method.
} gsad_method_type_t;

/**
 * @brief Connection information.
 *
 * These objects are used to hold connection information
 * during the multiple calls of the request handler that
 * refer to the same request.
 *
 * Once a request is finished, the object will be freed.
 */
typedef struct gsad_connection_info gsad_connection_info_t;

gsad_connection_info_t *
gsad_connection_info_new (gsad_method_type_t, const gchar *);

void
gsad_connection_info_free (gsad_connection_info_t *);

enum gsad_method_type
gsad_connection_info_get_method_type (const gsad_connection_info_t *);

params_t *
gsad_connection_info_get_params (const gsad_connection_info_t *);

struct MHD_PostProcessor *
gsad_connection_info_get_postprocessor (const gsad_connection_info_t *);

void
gsad_connection_info_set_postprocessor (gsad_connection_info_t *,
                                        struct MHD_PostProcessor *);

const gchar *
gsad_connection_info_get_cookie (const gsad_connection_info_t *);

void
gsad_connection_info_set_cookie (gsad_connection_info_t *, const gchar *);

const gchar *
gsad_connection_info_get_language (const gsad_connection_info_t *);

void
gsad_connection_info_set_language (gsad_connection_info_t *, const gchar *);

const gchar *
gsad_connection_info_get_url (const gsad_connection_info_t *);

#endif /* _GSAD_CONNECTION_INFO_H */
