/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef GSAD_MULTI_TARGET_WIRE_H
#define GSAD_MULTI_TARGET_WIRE_H
#include <stddef.h>

/* Return bytes written, excluding NUL, or -1 for invalid input/space.
 * Emits repeated GMP target elements for a proposed gvmd extension. */
int gsad_multi_target_xml (const char *const *ids, size_t count,
                           char *buffer, size_t buffer_size);
#endif
