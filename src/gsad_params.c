/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_params.h"

/**
 * @brief Free a param.
 *
 * @param[in]  param  Param.
 */
static void
param_free (gpointer param)
{
  g_free (((param_t *) param)->value);
  g_free (((param_t *) param)->original_value);
  g_free (((param_t *) param)->filename);
  params_free (((param_t *) param)->values);
  g_free (param);
}

/**
 * @brief Make a params.
 *
 * @return Freshly allocated params.  Free with params_free.
 */
params_t *
params_new ()
{
  return g_hash_table_new_full (g_str_hash, g_str_equal, g_free, param_free);
}

/**
 * @brief Make a params.
 *
 * @param[in]  params  Params.
 */
void
params_free (params_t *params)
{
  if (params)
    g_hash_table_destroy (params);
}

/**
 * @brief Get param.
 *
 * @param[in]  params  Params.
 * @param[in]  name    Name.
 *
 * @return Param if present, else NULL.
 */
param_t *
params_get (params_t *params, const gchar *name)
{
  param_t *param;
  param = g_hash_table_lookup (params, name);
  return param;
}

/**
 * @brief Get whether a param was given at all.
 *
 * @param[in]  params  Params.
 * @param[in]  name    Name.
 *
 * @return 1 if given, else 0.
 */
int
params_given (params_t *params, const gchar *name)
{
  param_t *param;
  param = g_hash_table_lookup (params, name);
  return param ? 1 : 0;
}

/**
 * @brief Get value of param.
 *
 * @param[in]  params  Params.
 * @param[in]  name    Name.
 *
 * @return Value if param present, else NULL.
 */
const gchar *
params_value (params_t *params, const gchar *name)
{
  param_t *param;
  param = g_hash_table_lookup (params, name);
  return param ? param->value : NULL;
}

/**
 * @brief Get boolean value of param.
 *
 * @param[in]  params  Params.
 * @param[in]  name    Name.
 *
 * @return 1 if param present and != 0, else 0.
 */
gboolean
params_value_bool (params_t *params, const gchar *name)
{
  param_t *param;
  param = g_hash_table_lookup (params, name);

  return (param && param->value) ? strcmp (param->value, "0") != 0 : 0;
}
/**
 * @brief Get the size of the value of param.
 *
 * @param[in]  params  Params.
 * @param[in]  name    Name.
 *
 * @return Size if param present, else -1.
 */
int
params_value_size (params_t *params, const gchar *name)
{
  param_t *param;
  param = g_hash_table_lookup (params, name);
  return param ? param->value_size : -1;
}

/**
 * @brief Get original value of param, before validation.
 *
 * Only set if validation failed.
 *
 * @param[in]  params  Params.
 * @param[in]  name    Name.
 *
 * @return Value if param present, else NULL.
 */
const gchar *
params_original_value (params_t *params, const gchar *name)
{
  param_t *param;
  param = g_hash_table_lookup (params, name);
  return param ? param->original_value : NULL;
}

/**
 * @brief Get values of param.
 *
 * @param[in]  params  Params.
 * @param[in]  name    Name.
 *
 * @return Values if param present, else NULL.
 */
params_t *
params_values (params_t *params, const gchar *name)
{
  param_t *param;
  param = g_hash_table_lookup (params, name);
  return param ? param->values : NULL;
}

/**
 * @brief Get whether a param is valid.
 *
 * @param[in]  params  Params.
 * @param[in]  name    Name.
 *
 * @return 1 if param present and valid, else 0.
 */
int
params_valid (params_t *params, const gchar *name)
{
  param_t *param;
  param = g_hash_table_lookup (params, name);
  return param ? param->valid : 0;
}

/**
 * @brief Add a param.
 *
 * @param[in]  params  Params.
 * @param[in]  name    Name.
 * @param[in]  value   Value.  Must be a string.
 */
param_t *
params_add (params_t *params, const gchar *name, const gchar *value)
{
  param_t *param;

  if (name == NULL)
    name = "";
  if (value == NULL)
    value = "";

  param = g_malloc0 (sizeof (param_t));
  param->valid = 0;
  param->valid_utf8 = 0;
  param->value = g_strdup (value);
  param->value_size = strlen (value);
  param->array_len = 0;
  g_hash_table_insert (params, g_strdup (name), param);
  return param;
}

void
params_remove (params_t *params, const gchar *name)
{
  g_hash_table_remove (params, name);
}

/**
 * @brief Append binary data to a param.
 *
 * Appended data always has an extra NULL terminator.
 *
 * @param[in]  params        Params.
 * @param[in]  name          Name.
 * @param[in]  chunk_data    Data to append.
 * @param[in]  chunk_size    Number of bytes to copy.
 * @param[in]  chunk_offset  Offset in bytes into data from which to start.
 *
 * @return Param appended to, or NULL on memory error.
 */
param_t *
params_append_bin (params_t *params, const gchar *name, const gchar *chunk_data,
                   int chunk_size, int chunk_offset)
{
  param_t *param;
  gchar *new_value;

  param = params_get (params, name);

  if (param == NULL)
    {
      gchar *value;

      value = g_malloc0 (chunk_size + 1);
      memcpy (value + chunk_offset, chunk_data, chunk_size);

      param = params_add (params, name, "");
      g_free (param->value);
      param->value = value;
      param->value_size = chunk_size;
      return param;
    }

  new_value = g_realloc (param->value, param->value_size + chunk_size + 1);
  if (new_value == NULL)
    return NULL;
  param->value = new_value;
  memcpy (param->value + chunk_offset, chunk_data, chunk_size);
  param->value[chunk_offset + chunk_size] = '\0';
  param->value_size += chunk_size;

  return param;
}

/**
 * @brief Increment a params iterator.
 *
 * @param[in]   iterator  Iterator.
 * @param[out]  name      Name of param.
 * @param[out]  param     Param.
 *
 * @return TRUE if there was a next element, else FALSE.
 */
gboolean
params_iterator_next (params_iterator_t *iterator, gchar **name,
                      param_t **param)
{
  return g_hash_table_iter_next (iterator, (gpointer *) name,
                                 (gpointer *) param);
}
