/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "asset_override_wire.h"
#include <stdio.h>
#include <string.h>

static int
valid_id (const char *id)
{
  size_t i;
  if (id == 0 || strlen (id) != 36) return 0;
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

int
gsad_asset_override_xml (const char *asset_id, const char *service,
                         const char *credential_id,
                         char *buffer, size_t buffer_size)
{
  int written;
  if (!valid_id (asset_id) || service == 0 || credential_id == 0
      || buffer == 0 || buffer_size == 0)
    return -1;
  if (strcmp (service, "ssh") && strcmp (service, "ssh_elevate")
      && strcmp (service, "smb")
      && strcmp (service, "esxi") && strcmp (service, "snmp")
      && strcmp (service, "krb5"))
    return -1;
  if (strcmp (credential_id, "0") && !valid_id (credential_id))
    return -1;
  written = snprintf (buffer, buffer_size,
    "<modify_asset asset_id=\"%s\"><credential_override service=\"%s\" "
    "credential_id=\"%s\"/></modify_asset>",
    asset_id, service, credential_id);
  if (written < 0 || (size_t) written >= buffer_size)
    return -1;
  return written;
}
