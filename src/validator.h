/* Copyright (C) 2009-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file validator.h
 * @brief Headers/structs for a string validator.
 */

#ifndef _VALIDATOR_H
#define _VALIDATOR_H

#include <glib.h>

/**
 * @brief A set of name rule pairs.
 */
typedef GHashTable *validator_t;

/**
 * @brief A validator rule.
 */
struct validator_rule
{
  gchar *alias_for;   ///< Name of the rule for which this is an alias.
  gchar *regex;       ///< Regular expression.
  gboolean is_binary; ///< Whether to expect raw byte data, skip UTF-8 checks.
};

/**
 * @brief A validator rule.
 */
typedef struct validator_rule validator_rule_t;

validator_t
gvm_validator_new ();

void
gvm_validator_add (validator_t, const char *, const char *);

void
gvm_validator_add_binary (validator_t, const char *);

int
gvm_validator_alias (validator_t, const char *, const char *);

gchar *
gvm_validator_alias_for (validator_t, const char *);

int
gvm_validate (validator_t, const char *, const char *);

void gvm_validator_free (validator_t);

#endif /* not _VALIDATOR_H */
