/* Copyright (C) 2016-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_params.h
 * @brief Http Parameter handling in GSA
 */

#ifndef _GSAD_PARAMS_H
#define _GSAD_PARAMS_H

#include <glib.h>
#include <microhttpd.h>

#define params_t GHashTable

/* Params. */

/**
 * @brief Request parameter.
 */
struct param
{
  gchar *value;          /**< Value. */
  gchar *original_value; /**< Original value, before validation. */
  gchar *filename;       /**< Filename. */
  params_t *values;      /**< Multiple binary values. */
  int valid;             /**< Validation flag. */
  int valid_utf8;        /**< UTF8 validation flag. */
  int value_size;        /**< Size of value, excluding trailing NULL. */
  int array_len;         /**< The number of items of "array" params */
};

/**
 * @brief Request parameter.
 */
typedef struct param param_t;

params_t *
params_new ();

void
params_free (params_t *);

int
params_given (params_t *, const gchar *);

const gchar *
params_value (params_t *, const gchar *);

int
params_value_size (params_t *, const gchar *);

gboolean
params_value_bool (params_t *, const gchar *);

const gchar *
params_original_value (params_t *, const gchar *);

params_t *
params_values (params_t *, const gchar *);

param_t *
params_get (params_t *, const gchar *);

int
params_valid (params_t *, const gchar *);

param_t *
params_add (params_t *, const gchar *, const gchar *);

void
params_remove (params_t *, const gchar *);

param_t *
params_append_bin (params_t *, const gchar *, const gchar *, int);

#define params_iterator_t GHashTableIter

#define params_iterator_init g_hash_table_iter_init

gboolean
params_iterator_next (params_iterator_t *, gchar **, param_t **);

#endif /* _GSAD_PARAMS_H */
