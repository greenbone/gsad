/* Copyright (C) 2009-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_base.h
 * @brief Headers/structs used generally in GSA.
 */

#ifndef _GSAD_BASE_H
#define _GSAD_BASE_H

#include "gsad_cmd.h"  /* for cmd_response_data_t */
#include "gsad_user.h" /* for credentials_t */

#include <glib.h>
#include <sys/time.h>

int
gsad_base_init ();

int
gsad_base_cleanup ();

void
set_chroot_state (int);

char *
ctime_r_strip_newline (time_t *, char *);

#endif /* not _GSAD_BASE_H */
