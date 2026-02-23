/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_LOGGING_H
#define _GSAD_LOGGING_H

#include "gsad_settings.h"

#include <glib.h> /* for GSList */

typedef GSList gsad_log_config_t;

gsad_log_config_t *
gsad_logging_init (gsad_settings_t *);

void
gsad_logging_cleanup (gsad_log_config_t *);

#endif /* _GSAD_LOGGING_H */
