/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_http_compression.h"

#include <zlib.h>

#ifdef HAVE_BROTLI
#include <brotli/encode.h>
#endif

/**
 * @brief Check whether may compress response.
 *
 * @param[in]  con       HTTP Connection
 * @param[in]  encoding  Desired encoding.
 *
 * @return 1 if may, else 0.
 */
gboolean
gsad_http_may_compress (gsad_http_connection_t *con, const gchar *encoding)
{
  const gchar *all, *one;

  all = MHD_lookup_connection_value (con, MHD_HEADER_KIND,
                                     MHD_HTTP_HEADER_ACCEPT_ENCODING);
  if (all == NULL)
    return 0;
  if (strcmp (all, "*") == 0)
    return 1;

  one = strstr (all, encoding);
  if (one == NULL)
    return 0;

  if (((one == all) || (one[-1] == ',') || (one[-1] == ' '))
      && ((one[strlen (encoding)] == '\0') || (one[strlen (encoding)] == ',')
          || (one[strlen (encoding)] == ';')))
    return 1;

  return 0;
}

/**
 * @brief Check whether may compress response.
 *
 * @param[in]  con  HTTP Connection
 *
 * @return 1 if may, else 0.
 */
gboolean
gsad_http_may_deflate (gsad_http_connection_t *con)
{
  return gsad_http_may_compress (con, "deflate");
}

#ifdef HAVE_BROTLI
/**
 * @brief Check whether may compress response.
 *
 * @param[in]  con  HTTP Connection
 *
 * @return 1 if may, else 0.
 */
gboolean
gsad_http_may_brotli (gsad_http_connection_t *con)
{
  return gsad_http_may_compress (con, "br");
}
#endif

/**
 * @brief Compress response with zlib.
 *
 * @param[in]  res_len   Response length.
 * @param[in]  res       Response.
 * @param[out] comp_len  Compressed length.
 * @param[out] comp      Compressed response.
 *
 * @return 1 on success, else 0.
 */
int
gsad_http_compress_response_deflate (const size_t res_len, const gchar *res,
                                     size_t *comp_len, gchar **comp)
{
  Bytef *cbuf;
  uLongf cbuf_size;
  int ret;

  cbuf_size = compressBound (res_len);
  cbuf = g_malloc (cbuf_size);

  ret = compress (cbuf, &cbuf_size, (const Bytef *) res, res_len);

  if ((ret == Z_OK) && (cbuf_size < res_len))
    {
      *comp = (char *) cbuf;
      *comp_len = cbuf_size;
      return 1;
    }

  free (cbuf);
  return 0;
}

#ifdef HAVE_BROTLI
/**
 * @brief Compress response with Brotli.
 *
 * @param[in]  res_len   Response length.
 * @param[in]  res       Response.
 * @param[out] comp_len  Compressed length.
 * @param[out] comp      Compressed response.
 *
 * @return 1 on success, else 0.
 */
int
gsad_http_compress_response_brotli (const size_t res_len, const gchar *res,
                                    size_t *comp_len, gchar **comp)
{
  size_t cbuf_size;
  uint8_t *cbuf;
  int ret;

  cbuf_size = BrotliEncoderMaxCompressedSize (res_len);
  cbuf = g_malloc (cbuf_size);

  ret = BrotliEncoderCompress (BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW,
                               BROTLI_DEFAULT_MODE, res_len, (uint8_t *) res,
                               &cbuf_size, cbuf);

  if ((ret == BROTLI_TRUE) && (cbuf_size < res_len))
    {
      *comp = (char *) cbuf;
      *comp_len = cbuf_size;
      return 1;
    }

  g_free (cbuf);
  return 0;
}
#endif
