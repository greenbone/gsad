/* Copyright (C) 2016-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_command_response_data.c
 * @brief Response data handling
 */

#include "gsad_command_response_data.h"

#include <microhttpd.h> /* for MHD_HTTP_OK */

/**
 * @brief Response information for commands.
 */
struct gsad_command_response_data
{
  gboolean allow_caching;      ///> Whether the response may be cached.
  int http_status_code;        ///> HTTP status code.
  content_type_t content_type; ///> Content type. Default is text/html
  gchar *content_type_string;  ///> Content type as string. Default is NULL.
  gsize content_length;        ///> Content length of the response
  gchar *content_disposition;  ///> Content disposition
};

/**
 * @brief Initializes a gsad_commad_response_data_t struct.
 *
 * @param[in]  data  The gsad_commad_response_data_t struct to initialize
 */
static void
gsad_command_response_data_init (gsad_command_response_data_t *data)
{
  data->allow_caching = FALSE;
  data->http_status_code = MHD_HTTP_OK;
  data->content_type = GSAD_CONTENT_TYPE_TEXT_HTML;
  data->content_type_string = NULL;
  data->content_disposition = NULL;
  data->content_length = 0;
}

/**
 * @brief Allocates memory for a gsad_commad_response_data_t sturct and
 * initializes it
 *
 * @return Pointer to the newly allocated gsad_command_response_data_t struct
 */
gsad_command_response_data_t *
gsad_command_response_data_new ()
{
  gsad_command_response_data_t *data =
    g_malloc0 (sizeof (gsad_command_response_data_t));
  gsad_command_response_data_init (data);
  return data;
}

/**
 * @brief Frees the memory of a gsad_commad_response_data_t struct
 *
 * If content_disposition of data is not NULL the content_disposition is also
 * being freed.
 *
 * @param[in] data The gsad_commad_response_data_t struct to free
 */
void
gsad_command_response_data_free (gsad_command_response_data_t *data)
{
  if (!data)
    {
      return;
    }

  g_free (data->content_disposition);
  g_free (data->content_type_string);
  g_free (data);
}

/**
 * @brief Set allow_caching flag of gsad_commad_response_data_t struct
 *
 * @param[in]  data           Command response data struct
 * @param[in]  allow_caching  allow_caching flag to set
 */
void
gsad_command_response_data_set_allow_caching (
  gsad_command_response_data_t *data, gboolean allow_caching)
{
  data->allow_caching = (allow_caching != FALSE);
}

/**
 * @brief Get allow_caching flag of gsad_command_response_data_t struct
 *
 * @param[in]  data  Command response data struct
 *
 * @return The allow_caching flag
 */
gboolean
gsad_command_response_data_is_allow_caching (gsad_command_response_data_t *data)
{
  return data->allow_caching;
}

/**
 * @brief Set content type of gsad_command_response_data_t struct
 *
 * @param[in]  data          Command response data struct
 * @param[in]  content_type  Content Type to set
 */
void
gsad_command_response_data_set_content_type (gsad_command_response_data_t *data,
                                             content_type_t content_type)
{
  data->content_type = content_type;
}

/**
 * @brief Get content type of gsad_command_response_data_t struct
 *
 * @param[in]  data  Command response data struct
 *
 * @return The content type
 */
content_type_t
gsad_command_response_data_get_content_type (gsad_command_response_data_t *data)
{
  return data->content_type;
}

/**
 * @brief Set status code of gsad_command_response_data_t struct
 *
 * @param[in]  data              Command response data struct
 * @param[in]  http_status_code  HTTP status code
 */
void
gsad_command_response_data_set_status_code (gsad_command_response_data_t *data,
                                            int http_status_code)
{
  data->http_status_code = http_status_code;
}

/**
 * @brief Get http status code of gsad_command_response_data_t struct
 *
 * @param[in]  data  Command response data struct
 *
 * @return  HTTP status code
 */
int
gsad_command_response_data_get_status_code (gsad_command_response_data_t *data)
{
  return data->http_status_code;
}

/**
 * @brief Set response content length of gsad_command_response_data_t struct
 *
 * @param[in]  data            Command response data struct
 * @param[in]  content_length  Content length of the response
 */
void
gsad_command_response_data_set_content_length (
  gsad_command_response_data_t *data, gsize content_length)
{
  data->content_length = content_length;
}

/**
 * @brief Get response content length of gsad_command_response_data_t struct
 *
 * @param[in]  data  Command response data struct
 *
 * @return Content length of the response
 */
gsize
gsad_command_response_data_get_content_length (
  gsad_command_response_data_t *data)
{
  return data->content_length;
}

/**
 * @brief Set content disposition of gsad_command_response_data_t struct
 *
 * @param[in]  data                 Command response data struct
 * @param[in]  content_disposition  Content disposition
 */
void
gsad_command_response_data_set_content_disposition (
  gsad_command_response_data_t *data, gchar *content_disposition)
{
  data->content_disposition = content_disposition;
}

/**
 * @brief Get content disposition of gsad_command_response_data_t struct
 *
 * @param[in]  data  Command response data struct
 *
 * @return  Size of the response
 */
const gchar *
gsad_command_response_data_get_content_disposition (
  gsad_command_response_data_t *data)
{
  return data->content_disposition;
}

/**
 * @brief Set a content type as string
 *
 * If content type is set as a string content_type is set to
 * GSAD_CONTENT_TYPE_STRING.
 *
 * @param[in]  data                  Command response data struct
 * @param[in]  content_type_string   Content type as string
 */
void
gsad_command_response_data_set_content_type_string (
  gsad_command_response_data_t *data, gchar *content_type_string)
{
  data->content_type = GSAD_CONTENT_TYPE_STRING;
  data->content_type_string = content_type_string;
}

/**
 * @brief Get a content type string if set
 *
 * @param[in]  data  Command response data struct
 * @return Content type string if set
 */
const gchar *
gsad_command_response_data_get_content_type_string (
  gsad_command_response_data_t *data)
{
  return data->content_type_string;
}
