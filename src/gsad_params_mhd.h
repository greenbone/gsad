/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_PARAMS_MHD_H
#define _GSAD_PARAMS_MHD_H

#include "gsad_http.h"
#include "gsad_params.h"

#include <microhttpd.h>

http_result_t
params_mhd_add (void *, enum MHD_ValueKind kind, const gchar *, const gchar *);

void
params_mhd_validate (void *);

http_result_t
params_mhd_append (params_t *, const gchar *, const gchar *, const gchar *, int,
                   int);

#endif /* _GSAD_PARAMS_MHD_H */
