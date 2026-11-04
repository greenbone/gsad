/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "multi_target_wire.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>

static int
valid_id (const char *id)
{
  size_t i;
  if (id == NULL || strlen (id) != 36)
    return 0;
  for (i = 0; i < 36; ++i)
    if (i == 8 || i == 13 || i == 18 || i == 23)
      {
        if (id[i] != '-') return 0;
      }
    else if (!((id[i] >= '0' && id[i] <= '9')
               || (id[i] >= 'a' && id[i] <= 'f')
               || (id[i] >= 'A' && id[i] <= 'F')))
      return 0;
  return 1;
}

static int
same_uuid (const char *left, const char *right)
{
  size_t i;
  for (i = 0; i < 36; ++i)
    if (tolower ((unsigned char) left[i])
        != tolower ((unsigned char) right[i]))
      return 0;
  return 1;
}

int
gsad_multi_target_xml (const char *const *ids, size_t count,
                       char *buffer, size_t buffer_size)
{
  size_t i, used = 0;
  int written;
  if (ids == NULL || buffer == NULL || buffer_size == 0
      || count == 0 || count > 32)
    return -1;
  buffer[0] = '\0';
  for (i = 0; i < count; ++i)
    {
      size_t j;
      if (!valid_id (ids[i])) return -1;
      for (j = 0; j < i; ++j)
        if (same_uuid (ids[i], ids[j])) return -1;
      written = snprintf (buffer + used, buffer_size - used,
                          "<target id=\"%s\"/>", ids[i]);
      if (written < 0 || (size_t) written >= buffer_size - used)
        return -1;
      used += (size_t) written;
    }
  return (int) used;
}
