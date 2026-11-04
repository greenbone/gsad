/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "../src/asset_override_wire.h"
#include <assert.h>
#include <string.h>

int
main (void)
{
  char output[256];
  const char *asset = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
  const char *credential = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
  assert (gsad_asset_override_xml (asset, "ssh", credential,
                                   output, sizeof (output)) > 0);
  assert (strstr (output, "credential_override service=\"ssh\"") != 0);
  assert (gsad_asset_override_xml (asset, "ssh_elevate", credential,
                                   output, sizeof (output)) > 0);
  assert (gsad_asset_override_xml (asset, "ssh", "0", output,
                                   sizeof (output)) > 0);
  assert (gsad_asset_override_xml (asset, "ssh\"/>", credential,
                                   output, sizeof (output)) == -1);
  assert (gsad_asset_override_xml (asset, "ssh", credential,
                                   output, 5) == -1);
  return 0;
}
