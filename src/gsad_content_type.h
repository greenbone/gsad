/* Copyright (C) 2016-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_content_type.h
 * @brief Headers for content type
 */

#ifndef _GSAD_CONTENT_TYPE_H
#define _GSAD_CONTENT_TYPE_H

/**
 * @brief Content types.
 */
enum content_type
{
  GSAD_CONTENT_TYPE_APP_DEB,
  GSAD_CONTENT_TYPE_APP_EXE,
  GSAD_CONTENT_TYPE_APP_XHTML,
  GSAD_CONTENT_TYPE_APP_KEY,
  GSAD_CONTENT_TYPE_APP_NBE,
  GSAD_CONTENT_TYPE_APP_PDF,
  GSAD_CONTENT_TYPE_APP_RPM,
  GSAD_CONTENT_TYPE_APP_XML,
  GSAD_CONTENT_TYPE_DONE,   ///< Special marker.
  GSAD_CONTENT_TYPE_STRING, ///< Special marker for using content type string.
  GSAD_CONTENT_TYPE_IMAGE_PNG,
  GSAD_CONTENT_TYPE_TEXT_CSS,
  GSAD_CONTENT_TYPE_TEXT_HTML,
  GSAD_CONTENT_TYPE_TEXT_JS,
  GSAD_CONTENT_TYPE_TEXT_PLAIN,
  GSAD_CONTENT_TYPE_OCTET_STREAM,
  GSAD_CONTENT_TYPE_IMAGE_SVG,
  GSAD_CONTENT_TYPE_IMAGE_GIF,
  GSAD_CONTENT_TYPE_APP_JSON,
};

typedef enum content_type content_type_t;

#endif /* _GSAD_CONTENT_TYPE_H */
