/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_env.h"

#include "gsad_utils.h" /* for str_equal */

#include <stdio.h>

/**
 * @brief Get a boolean value from an environment variable.
 *
 * The environment variable is considered true if it is set to "1" or "true"
 * (case-sensitive), and false otherwise. If the environment variable is not
 * set, the provided default value will be returned.
 *
 * @param[in] name The name of the environment variable to retrieve.
 * @param[in] default_value The default value to return if the environment
 * variable is not set
 *
 * @return The boolean value of the environment variable, or the default value
 * if the environment variable is not set.
 */
gboolean
gsad_env_get_boolean (const gchar *name, gboolean default_value)
{
  const gchar *env_var_value = g_getenv (name);
  if (!env_var_value)
    {
      return default_value;
    }
  return str_equal (env_var_value, "1") || str_equal (env_var_value, "true");
}

/**
 * @brief Get a string value from an environment variable.
 *
 * If the environment variable is not set, the provided default value will be
 * returned.
 *
 * @param[in] name The name of the environment variable to retrieve.
 * @param[in] default_value The default value to return if the environment
 * variable is not set
 *
 * @return The string value of the environment variable, or the default value if
 * the environment variable is not set. The returned string is owned by the
 * caller and should be freed.
 */
gchar *
gsad_env_get_string (const gchar *name, const gchar *default_value)
{
  const gchar *env_var_value = g_getenv (name);
  if (!env_var_value)
    {
      return g_strdup (default_value);
    }
  return g_strdup (env_var_value);
}

/**
 * @brief Get an array of strings from an environment variable, splitting the
 * value by a specified separator character.
 *
 * If the environment variable is not set, the provided default value will be
 * used instead.
 *
 * @param[in] name The name of the environment variable to retrieve.
 * @param[in] separator The character to use as a separator for splitting the
 * value.
 * @param[in] default_value The default value to use if the environment variable
 * is not set
 *
 * @return A NULL-terminated array of strings. The caller is responsible for
 * freeing the array using g_strfreev().
 */
gchar **
gsad_env_get_string_array (const gchar *name, const gchar *separator,
                           const gchar *default_value)
{
  const gchar *env_var_value = g_getenv (name);
  if (!env_var_value)
    {
      env_var_value = default_value;
      if (!env_var_value)
        {
          return NULL;
        }
    }
  return g_strsplit (env_var_value, separator, -1);
}

/**
 * @brief Get an integer value from an environment variable.
 *
 * If the environment variable is not set, the provided default value will be
 * returned. If the environment variable is set but does not contain a valid
 * integer, a warning will be logged and the default value will be returned.
 *
 * @param[in] name The name of the environment variable to retrieve.
 * @param[in] default_value The default value to return if the environment
 * variable is not set or does not contain a valid integer.
 *
 * @return The integer value of the environment variable, or the default value
 * if the environment variable is not set or does not contain a valid integer.
 */
int
gsad_env_get_int (const gchar *name, int default_value)
{
  const gchar *env_var_value = g_getenv (name);
  if (!env_var_value)
    {
      return default_value;
    }
  char *endptr;
  long int_value = strtol (env_var_value, &endptr, 10);
  if (*endptr != '\0')
    {
      g_warning ("Environment variable '%s' has non-integer value: '%s'. Using "
                 "default '%d'.",
                 name, env_var_value, default_value);
      return default_value;
    }
  if (int_value > INT_MAX)
    {
      g_warning ("Environment variable '%s' has integer value '%ld' which is "
                 "greater than INT_MAX. Using INT_MAX '%d' instead.",
                 name, int_value, INT_MAX);
      return INT_MAX;
    }
  if (int_value < INT_MIN)
    {
      g_warning ("Environment variable '%s' has integer value '%ld' which is "
                 "less than INT_MIN. Using INT_MIN '%d' instead.",
                 name, int_value, INT_MIN);
      return INT_MIN;
    }
  return (int) int_value;
}
