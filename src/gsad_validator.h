/* Copyright (C) 2009-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_VALIDATOR_H
#define _GSAD_VALIDATOR_H

#include "validator.h"

/**
 * @brief Initialise the parameter validator.
 */
void
gsad_init_validator ();

validator_t
gsad_get_validator ();

void
gsad_reset_validator ();

#endif /* not _GSAD_VALIDATOR_H */
