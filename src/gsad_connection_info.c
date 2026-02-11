/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_connection_info.h"

struct gsad_connection_info
{
  struct MHD_PostProcessor *postprocessor; ///< POST processor.
  params_t *params;                        ///< Request parameters.
  char *cookie;                            ///< Value of SID cookie param.
  char *language;                          ///< Language code e.g. en
  enum method_type method_type;            ///< 1=POST, 2=GET.
  gchar *redirect;                         ///< Redirect URL.
};

/**
 * @brief Create a new connection information object.
 *
 * @return A new gsad_connection_info_t object.
 */
gsad_connection_info_t *
gsad_connection_info_new (enum method_type method_type)
{
  gsad_connection_info_t *con_info =
    g_malloc0 (sizeof (gsad_connection_info_t));
  con_info->postprocessor = NULL;
  con_info->params = params_new ();
  con_info->cookie = NULL;
  con_info->language = NULL;
  con_info->method_type = method_type;
  con_info->redirect = NULL;
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
  g_free (con_info->cookie);
  g_free (con_info->language);
  g_free (con_info->redirect);
  g_free (con_info);
}

/**
 * @brief Get the method type of a connection information object.
 *
 * @param[in] con_info Connection information.
 *
 * @return Method type of the connection information.
 */
enum method_type
gsad_connection_info_get_method_type (const gsad_connection_info_t *con_info)
{
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
  if (con_info->postprocessor != NULL)
    MHD_destroy_post_processor (con_info->postprocessor);
  con_info->postprocessor = postprocessor;
}

/**
 * @brief Get the cookie value of a connection information object.
 *
 * @param[in] con_info Connection information.
 *
 * @return Cookie value of the connection information, or NULL if not set. The
 * cookie value is owned by the connection information and should not be freed
 * by the caller.
 */
const gchar *
gsad_connection_info_get_cookie (const gsad_connection_info_t *con_info)
{
  return con_info->cookie;
}

/**
 * @brief Set the cookie value of a connection information object.
 *
 * @param[in] con_info Connection information.
 * @param[in] cookie Cookie value to set. The connection information will copy
 * the cookie value and take ownership of the copy. The connection information
 * will free the copy when the connection information is freed. The caller
 * retains ownership of the original cookie value and is responsible for freeing
 * it if necessary.
 */
void
gsad_connection_info_set_cookie (gsad_connection_info_t *con_info,
                                 const gchar *cookie)
{
  g_free (con_info->cookie);
  con_info->cookie = g_strdup (cookie);
}

/**
 * @brief Get the language of a connection information object.
 *
 * @param[in] con_info Connection information.
 *
 * @return Language of the connection information, or NULL if not set. The
 * language is owned by the connection information and should not be freed by
 * the caller.
 */
const gchar *
gsad_connection_info_get_language (const gsad_connection_info_t *con_info)
{
  return con_info->language;
}

/**
 * @brief Set the language of a connection information object.
 *
 * @param[in] con_info Connection information.
 * @param[in] language Language to set. The connection information will copy the
 * language and take ownership of the copy. The connection information will free
 * the copy when the connection information is freed. The caller retains
 * ownership of the original language and is responsible for freeing it if
 * necessary.
 */
void
gsad_connection_info_set_language (gsad_connection_info_t *con_info,
                                   const gchar *language)
{
  g_free (con_info->language);
  con_info->language = g_strdup (language);
}
