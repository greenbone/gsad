/* Copyright (C) 2018-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file utils.c
 * @brief Utility functions in GSAD
 */

#include "utils.h"

#include <ctype.h>
#include <string.h> // For strcmp

/**
 * @brief Check if two strings are equal
 *
 * @return TRUE if string are equal
 */
gboolean
str_equal (const gchar *str1, const gchar *str2)
{
  return strcmp (str1, str2) == 0;
}

/**
 * @brief Capitalize a type or command name and replace underscores.
 *
 * @param[in]  input  The input string.
 *
 * @return The newly allocated capitalized type or command name.
 */
gchar *
capitalize (const char *input)
{
  gchar *output;
  if (input == NULL)
    return NULL;
  else
    {
      int first_letter = 1;
      int pos = 0;
      output = g_strdup (input);

      while (output[pos])
        {
          if (g_ascii_isalpha (output[pos]) && first_letter)
            {
              output[pos] = g_ascii_toupper (output[pos]);
              first_letter = 0;
            }
          else if (output[pos] == '_')
            {
              output[pos] = ' ';
              first_letter = 1;
            }
          pos++;
        }
      return output;
    }
}

/**
 * @brief Test if a username is valid to use in a credential.
 *
 * Valid usernames may only contain alphanumeric characters and a few
 * special ones to avoid problems with installer package generation.
 *
 * @param[in]  username  The username string to test.
 *
 * @return Returns TRUE if the username is valid, FALSE otherwise.
 */
gboolean
credential_username_is_valid (const gchar *username)
{
  const char *s;
  s = username;

  if (s == NULL || !strcmp (s, ""))
    return FALSE;

  while (*s)
    if (isalnum (*s) || strchr ("-_\\.@", *s))
      s++;
    else
      return FALSE;

  return TRUE;
}
