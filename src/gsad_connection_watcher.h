/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_CONNECTION_WATCHER_H
#define _GSAD_CONNECTION_WATCHER_H

#include "gsad_settings.h" /* for gsad_settings_get_client_watch_interval */
#include "gvm/util/serverutils.h" /* for gvm_connection_t */

typedef struct gsad_connection_watcher gsad_connection_watcher_t;

gsad_connection_watcher_t *
gsad_connection_watcher_new (gsad_settings_t *, gvm_connection_t *, int);

void
gsad_connection_watcher_start (gsad_connection_watcher_t *);

void
gsad_connection_watcher_stop (gsad_connection_watcher_t *);

void
gsad_connection_watcher_free (gsad_connection_watcher_t *);

#endif /* _GSAD_CONNECTION_WATCHER_H */
