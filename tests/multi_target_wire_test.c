/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "../src/multi_target_wire.h"
#include <assert.h>
#include <string.h>

int
main (void)
{
  const char *ids[] = {
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
  };
  const char *bad[] = {"\"/><delete_task/>"};
  const char *case_duplicate[] = {ids[0], "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"};
  char output[128];
  assert (gsad_multi_target_xml (ids, 2, output, sizeof (output)) > 0);
  assert (strcmp (output,
    "<target id=\"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\"/>"
    "<target id=\"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\"/>") == 0);
  assert (gsad_multi_target_xml (ids, 2, output, 3) == -1);
  assert (gsad_multi_target_xml (bad, 1, output, sizeof (output)) == -1);
  assert (gsad_multi_target_xml (case_duplicate, 2, output,
                                 sizeof (output)) == -1);
  return 0;
}
