/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_connection_info.h"

struct gsad_connection_info
{
  gsad_method_type_t method_type;          ///< 1=POST, 2=GET.
  gchar *url;                              ///< Request URL.
  params_t *params;                        ///< Request parameters.
  struct MHD_PostProcessor *postprocessor; ///< POST processor.
};

/**
 * @brief Create a new connection information object.
 *
 * @return A new gsad_connection_info_t object.
 */
gsad_connection_info_t *
gsad_connection_info_new (gsad_method_type_t method_type, const gchar *url)
{
  gsad_connection_info_t *con_info = g_malloc (sizeof (gsad_connection_info_t));
  con_info->postprocessor = NULL;
  con_info->params = params_new ();
  con_info->method_type = method_type;
  con_info->url = g_strdup (url);
  return con_info;
}

/**
 * @brief Free a connection information object.
 *
 * @param[in] con_info Connection information to free.
 */
void
gsad_connection_info_free (gsad_connection_info_t *con_info)
{
  if (con_info == NULL)
    return;

  if (con_info->postprocessor != NULL)
    MHD_destroy_post_processor (con_info->postprocessor);

  params_free (con_info->params);
  g_free (con_info->url);
  g_free (con_info);
}

/**
 * @brief Get the method type of a connection information object.
 *
 * @param[in] con_info Connection information.
 *
 * @return Method type of the connection information.
 */
gsad_method_type_t
gsad_connection_info_get_method_type (const gsad_connection_info_t *con_info)
{
  g_return_val_if_fail (con_info != NULL, METHOD_TYPE_UNKNOWN);
  return con_info->method_type;
}

/**
 * @brief Get the parameters of a connection information object.
 *
 * @param[in] con_info Connection information.
 *
 * @return Parameters of the connection information. The parameters are owned by
 * the connection information and should not be freed by the caller.
 */
params_t *
gsad_connection_info_get_params (const gsad_connection_info_t *con_info)
{
  g_return_val_if_fail (con_info != NULL, NULL);
  return con_info->params;
}

/**
 * @brief Get the POST processor of a connection information object.
 *
 * @param[in] con_info Connection information.
 *
 * @return POST processor of the connection information, or NULL if not set. The
 * POST processor is owned by the connection information and should not be freed
 * by the caller.
 */
struct MHD_PostProcessor *
gsad_connection_info_get_postprocessor (const gsad_connection_info_t *con_info)
{
  g_return_val_if_fail (con_info != NULL, NULL);
  return con_info->postprocessor;
}

/**
 * @brief Set the POST processor of a connection information object.
 *
 * @param[in] con_info Connection information.
 * @param[in] postprocessor POST processor to set. The connection information
 * takes ownership of the POST processor and will
 * free it when the connection information is freed.
 */
void
gsad_connection_info_set_postprocessor (gsad_connection_info_t *con_info,
                                        struct MHD_PostProcessor *postprocessor)
{
  g_return_if_fail (con_info != NULL);
  if (con_info->postprocessor != NULL)
    MHD_destroy_post_processor (con_info->postprocessor);
  con_info->postprocessor = postprocessor;
}

/**
 * @brief Get the URL of a connection information object.
 *
 * @param[in] con_info Connection information.
 *
 * @return URL of the connection information. The URL is owned by the connection
 * information and should not be freed by the caller.
 */
const gchar *
gsad_connection_info_get_url (const gsad_connection_info_t *con_info)
{
  g_return_val_if_fail (con_info != NULL, NULL);
  return con_info->url;
}
