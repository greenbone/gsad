/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef GSAD_ASSET_OVERRIDE_WIRE_H
#define GSAD_ASSET_OVERRIDE_WIRE_H
#include <stddef.h>
/* Returns bytes written or -1. The proposed GMP credential_override element
 * needs a matching gvmd command handler before this can be wired into GSAD. */
int gsad_asset_override_xml (const char *asset_id, const char *service,
                             const char *credential_id,
                             char *buffer, size_t buffer_size);
#endif
