/* Copyright (C) 2009-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "gsad_validator.h"

/**
 * @brief Parameter validator.
 */
static validator_t validator;

/**
 * @brief Initialise the parameter validator.
 */
void
init_validator ()
{
  validator = gvm_validator_new ();

  gvm_validator_add (validator, "cmd",
                     "^((bulk_delete)"
                     "|(bulk_export)"
                     "|(change_password)"
                     "|(clone)"
                     "|(create_asset)"
                     "|(create_config)"
                     "|(create_container_task)"
                     "|(create_credential)"
                     "|(create_alert)"
                     "|(create_filter)"
                     "|(create_group)"
                     "|(create_host)"
                     "|(create_note)"
                     "|(create_oci_image_target)"
                     "|(create_override)"
                     "|(create_permission)"
                     "|(create_permissions)"
                     "|(create_port_list)"
                     "|(create_port_range)"
                     "|(create_report)"
                     "|(create_report_config)"
                     "|(create_role)"
                     "|(create_scanner)"
                     "|(create_schedule)"
                     "|(create_tag)"
                     "|(create_tags)"
                     "|(create_target)"
                     "|(create_task)"
                     "|(create_ticket)"
                     "|(create_tls_certificate)"
                     "|(create_user)"
                     "|(create_agent_group)"
                     "|(create_agent_group_task)"
                     "|(cvss_calculator)"
                     "|(delete_agent)"
                     "|(delete_agent_group)"
                     "|(delete_asset)"
                     "|(delete_config)"
                     "|(delete_credential)"
                     "|(delete_alert)"
                     "|(delete_filter)"
                     "|(delete_from_trash)"
                     "|(delete_group)"
                     "|(delete_note)"
                     "|(delete_oci_image_target)"
                     "|(delete_override)"
                     "|(delete_permission)"
                     "|(delete_port_list)"
                     "|(delete_port_range)"
                     "|(delete_report)"
                     "|(delete_report_config)"
                     "|(delete_report_format)"
                     "|(delete_role)"
                     "|(delete_scanner)"
                     "|(delete_schedule)"
                     "|(delete_tag)"
                     "|(delete_target)"
                     "|(delete_task)"
                     "|(delete_ticket)"
                     "|(delete_tls_certificate)"
                     "|(delete_user)"
                     "|(download_credential)"
                     "|(download_ssl_cert)"
                     "|(download_ca_pub)"
                     "|(download_key_pub)"
                     "|(edit_alert)"
                     "|(edit_config_family)"
                     "|(edit_config_family_all)"
                     "|(auth_settings)"
                     "|(empty_trashcan)"
                     "|(export_alert)"
                     "|(export_alerts)"
                     "|(export_asset)"
                     "|(export_assets)"
                     "|(export_config)"
                     "|(export_configs)"
                     "|(export_credential)"
                     "|(export_credentials)"
                     "|(export_filter)"
                     "|(export_filters)"
                     "|(export_group)"
                     "|(export_groups)"
                     "|(export_note)"
                     "|(export_notes)"
                     "|(export_oci_image_target)"
                     "|(export_oci_image_targets)"
                     "|(export_omp_doc)"
                     "|(export_override)"
                     "|(export_overrides)"
                     "|(export_permission)"
                     "|(export_permissions)"
                     "|(export_port_list)"
                     "|(export_port_lists)"
                     "|(export_preference_file)"
                     "|(export_report_config)"
                     "|(export_report_configs)"
                     "|(export_report_format)"
                     "|(export_report_formats)"
                     "|(export_result)"
                     "|(export_results)"
                     "|(export_role)"
                     "|(export_roles)"
                     "|(export_scanner)"
                     "|(export_scanners)"
                     "|(export_schedule)"
                     "|(export_schedules)"
                     "|(export_tag)"
                     "|(export_tags)"
                     "|(export_target)"
                     "|(export_targets)"
                     "|(export_task)"
                     "|(export_tasks)"
                     "|(export_user)"
                     "|(export_users)"
                     "|(get_agent)"
                     "|(get_agents)"
                     "|(get_agent_group)"
                     "|(get_agent_groups)"
                     "|(get_agent_installers)"
                     "|(get_agent_installer)"
                     "|(get_agent_installer_file)"
                     "|(get_aggregate)"
                     "|(get_alert)"
                     "|(get_alerts)"
                     "|(get_asset)"
                     "|(get_assets)"
                     "|(get_capabilities)"
                     "|(get_config)"
                     "|(get_config_family)"
                     "|(get_config_nvt)"
                     "|(get_configs)"
                     "|(get_credential)"
                     "|(get_credentials)"
                     "|(get_feeds)"
                     "|(get_filter)"
                     "|(get_filters)"
                     "|(get_group)"
                     "|(get_groups)"
                     "|(get_info)"
                     "|(get_license)"
                     "|(get_note)"
                     "|(get_notes)"
                     "|(get_nvt_families)"
                     "|(get_oci_image_target)"
                     "|(get_oci_image_targets)"
                     "|(get_override)"
                     "|(get_overrides)"
                     "|(get_permission)"
                     "|(get_permissions)"
                     "|(get_port_list)"
                     "|(get_port_lists)"
                     "|(get_report)"
                     "|(get_reports)"
                     "|(get_report_config)"
                     "|(get_report_configs)"
                     "|(get_report_format)"
                     "|(get_report_formats)"
                     "|(get_resource_names)"
                     "|(get_result)"
                     "|(get_results)"
                     "|(get_role)"
                     "|(get_roles)"
                     "|(get_scanner)"
                     "|(get_scanners)"
                     "|(get_schedule)"
                     "|(get_schedules)"
                     "|(get_setting)"
                     "|(get_settings)"
                     "|(get_system_reports)"
                     "|(get_system_report)"
                     "|(get_tag)"
                     "|(get_tags)"
                     "|(get_target)"
                     "|(get_targets)"
                     "|(get_task)"
                     "|(get_tasks)"
                     "|(get_ticket)"
                     "|(get_tickets)"
                     "|(get_tls_certificate)"
                     "|(get_tls_certificates)"
                     "|(get_trash_agent_group)"
                     "|(get_trash_alerts)"
                     "|(get_trash_configs)"
                     "|(get_trash_credentials)"
                     "|(get_trash_filters)"
                     "|(get_trash_groups)"
                     "|(get_trash_notes)"
                     "|(get_trash_oci_image_targets)"
                     "|(get_trash_overrides)"
                     "|(get_trash_permissions)"
                     "|(get_trash_port_lists)"
                     "|(get_trash_report_configs)"
                     "|(get_trash_report_formats)"
                     "|(get_trash_roles)"
                     "|(get_trash_scanners)"
                     "|(get_trash_schedules)"
                     "|(get_trash_tags)"
                     "|(get_trash_targets)"
                     "|(get_trash_tasks)"
                     "|(get_trash_tickets)"
                     "|(get_user)"
                     "|(get_users)"
                     "|(get_vulns)"
                     "|(import_config)"
                     "|(import_port_list)"
                     "|(import_report_format)"
                     "|(login)"
                     "|(modify_agent)"
                     "|(modify_agent_control_scan_config)"
                     "|(move_task)"
                     "|(new_alert)"
                     "|(ping)"
                     "|(renew_session)"
                     "|(report_alert)"
                     "|(restore)"
                     "|(resume_task)"
                     "|(run_wizard)"
                     "|(test_alert)"
                     "|(save_agent_list)"
                     "|(save_agent_group)"
                     "|(save_agent_group_task)"
                     "|(save_alert)"
                     "|(save_asset)"
                     "|(save_auth)"
                     "|(save_setting)"
                     "|(save_config)"
                     "|(save_config_family)"
                     "|(save_config_nvt)"
                     "|(save_container_task)"
                     "|(save_credential)"
                     "|(save_filter)"
                     "|(save_group)"
                     "|(save_license)"
                     "|(save_my_settings)"
                     "|(save_note)"
                     "|(save_oci_image_target)"
                     "|(save_override)"
                     "|(save_permission)"
                     "|(save_port_list)"
                     "|(save_report_config)"
                     "|(save_report_format)"
                     "|(save_role)"
                     "|(save_scanner)"
                     "|(save_schedule)"
                     "|(save_tag)"
                     "|(save_target)"
                     "|(save_task)"
                     "|(save_ticket)"
                     "|(save_tls_certificate)"
                     "|(save_user)"
                     "|(start_task)"
                     "|(stop_task)"
                     "|(sync_feed)"
                     "|(sync_scap)"
                     "|(sync_cert)"
                     "|(sync_config)"
                     "|(toggle_tag)"
                     "|(verify_scanner)"
                     "|(wizard)"
                     "|(wizard_get))$");

  gvm_validator_add (validator, "action_message", "(?s)^.*$");
  gvm_validator_add (validator, "action_status", "(?s)^.*$");
  gvm_validator_add (validator, "active", "^(-1|-2|[0-9]+)$");
  gvm_validator_add (validator, "aggregate_mode", "^[a-z0-9_]+$");
  gvm_validator_add (
    validator, "aggregate_type",
    "^(agent|agent_group|agent_installer|alert|config|credential|filter|group|"
    "host|nvt|note|os|override|permission|port_list|report|report_config|"
    "report_format|result|role|scanner|schedule|"
    "tag|target|task|user|cve|cpe|ovaldef|cert_bund_adv|dfn_cert_adv|"
    "vuln|tls_certificate)$");
  gvm_validator_add (
    validator, "alive_tests",
    "^(Scan Config Default|ICMP Ping|TCP-ACK Service Ping|TCP-SYN Service "
    "Ping|ARP Ping|ICMP & TCP-ACK Service Ping|ICMP & ARP Ping|TCP-ACK Service "
    "& ARP Ping|ICMP, TCP-ACK Service & ARP Ping|Consider Alive)$");
  gvm_validator_add (validator, "apply_filter", "^(no|no_pagination|full)$");
  gvm_validator_add (validator, "asset_name", "(?s)^.*$");
  gvm_validator_add (validator, "asset_type", "^(host|os)$");
  gvm_validator_add (validator, "asset_id",
                     "^([[:alnum:]\\-_.:\\/~()']|&amp;)+$");
  gvm_validator_add (validator, "auth_algorithm", "^(md5|sha1)$");
  gvm_validator_add (validator, "auth_method", "^(0|1|2)$");
  /* Defined in RFC 2253. */
  gvm_validator_add (validator, "authdn", "^.{0,200}%s.{0,200}$");
  gvm_validator_add (validator, "auto_delete", "^(no|keep)$");
  gvm_validator_add (validator, "auto_delete_data", "^.*$");
  gvm_validator_add (validator, "boolean", "^(0|1)$");
  gvm_validator_add (validator, "bulk_selected:name", "^.*$");
  gvm_validator_add (validator, "bulk_selected:value", "(?s)^.*$");
  gvm_validator_add (validator, "caller", "^.*$");
  gvm_validator_add (validator, "certificate", "(?s)^.*$");
  gvm_validator_add (validator, "chart_gen:name", "^.*$");
  gvm_validator_add (validator, "chart_gen:value", "(?s)^.*$");
  gvm_validator_add (validator, "chart_init:name", "^.*$");
  gvm_validator_add (validator, "chart_init:value", "(?s)^.*$");
  gvm_validator_add (validator, "setting_value", "^.*$");
  gvm_validator_add (validator, "setting_name", "^.*$");
  gvm_validator_add (validator, "comment", "^[[:graph:][:space:]]*$");
  gvm_validator_add (validator, "config_id", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "condition", "^[[:alnum:] ]*$");
  gvm_validator_add (validator, "credential_id", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "create_credentials_type", "^(gen|pass|key)$");
  gvm_validator_add (validator, "credential_type",
                     "^(cc|up|usk|smime|pgp|snmp|krb5|pw)$");
  gvm_validator_add (validator, "credential_login", "^[-_[:alnum:]\\.@\\\\]*$");
  gvm_validator_add (validator, "condition_data:name", "^.*$");
  gvm_validator_add (validator, "condition_data:value", "(?s)^.*$");
  gvm_validator_add (validator, "cvss_av", "^(L|A|N)$");
  gvm_validator_add (validator, "cvss_ac", "^(H|M|L)$");
  gvm_validator_add (validator, "cvss_au", "^(M|S|N)$");
  gvm_validator_add (validator, "cvss_c", "^(N|P|C)$");
  gvm_validator_add (validator, "cvss_i", "^(N|P|C)$");
  gvm_validator_add (validator, "cvss_a", "^(N|P|C)$");
  gvm_validator_add (
    validator, "cvss_vector",
    "^AV:(L|A|N)/AC:(H|M|L)/A(u|U):(M|S|N)/C:(N|P|C)/I:(N|P|C)/A:(N|P|C)$");
  gvm_validator_add (validator, "min_qod", "^(|100|[1-9]?[0-9]|)$");
  gvm_validator_add (validator, "day_of_month", "^(0??[1-9]|[12][0-9]|30|31)$");
  gvm_validator_add (validator, "days", "^(-1|[0-9]+)$");
  gvm_validator_add (validator, "data_column", "^[_[:alnum:]]+$");
  gvm_validator_add (validator, "data_columns:name", "^[0123456789]{1,5}$");
  gvm_validator_add (validator, "data_columns:value", "^[_[:alnum:]]+$");
  gvm_validator_add (validator, "default_severity",
                     "^(|10\\.0|[0-9]\\.[0-9])$");
  gvm_validator_add (validator, "delta_states", "^(c|g|n|s){0,4}$");
  gvm_validator_add (validator, "details_fname",
                     "^([[:alnum:]_-]|%[%CcDFMmNTtUu])+$");
  gvm_validator_add (validator, "domain", "^[-[:alnum:]\\.]+$");
  gvm_validator_add (validator, "email", "^[^@ ]{1,150}@[^@ ]{1,150}$");
  gvm_validator_add (
    validator, "email_list",
    "^[^@ ]{1,150}@[^@ ]{1,150}(, *[^@ ]{1,150}@[^@ ]{1,150})*$");
  gvm_validator_add (validator, "alert_id", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "alert_id_optional", "^(--|[a-z0-9\\-]+)$");
  gvm_validator_add (validator, "event_data:name", "^.*$");
  gvm_validator_add (validator, "event_data:value", "(?s)^.*$");
  gvm_validator_add (validator, "family", "^[-_[:alnum:] :.]+$");
  gvm_validator_add (validator, "family_page", "^[-_[:alnum:] :.]+$");
  gvm_validator_add (validator, "exclude_file", "(?s)^.*$");
  gvm_validator_add (validator, "exclude_file:name",
                     "^.*[[0-9abcdefABCDEF\\-]*]:.*$");
  gvm_validator_add (validator, "exclude_file:value", "^yes$");
  gvm_validator_add (validator, "file", "(?s)^.*$");
  gvm_validator_add (validator, "file:name", "^.*[[0-9abcdefABCDEF\\-]*]:.*$");
  gvm_validator_add (validator, "file:value", "^yes$");
  gvm_validator_add (validator, "settings_changed:name", "^.*$");
  gvm_validator_add (validator, "settings_changed:value", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "settings_default:name", "^.*$");
  gvm_validator_add (validator, "settings_default:value", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "settings_filter:name", "^.*$");
  gvm_validator_add (validator, "settings_filter:value", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "first", "^[0-9]+$");
  gvm_validator_add (validator, "first_group", "^[0-9]+$");
  gvm_validator_add (validator, "first_result", "^[0-9]+$");
  gvm_validator_add (validator, "filter", "^.*$");
  gvm_validator_add (validator, "format_id", "^[a-z0-9\\-]+$");
  /* Validator for  save_auth group, e.g. "method:ldap_connect". */
  gvm_validator_add (validator, "group",
                     "^method:(ldap_connect|radius_connect)$");
  gvm_validator_add (validator, "group_column", "^[_[:alnum:]]+$");
  gvm_validator_add (validator, "max", "^(-?[0-9]+|)$");
  gvm_validator_add (validator, "max_results", "^[0-9]+$");
  gvm_validator_add (validator, "format", "^[-[:alnum:]]+$");
  gvm_validator_add (validator, "host", "^[-_[:alnum:]:\\.]+$");
  gvm_validator_add (validator, "hostport", "^[-_[:alnum:]\\. :]+$");
  gvm_validator_add (validator, "hostpath", "^[-_[:alnum:]\\. :/]+$");
  gvm_validator_add (validator, "hosts", "^[-_[:alnum:],: \\./]+$");
  gvm_validator_add (validator, "hosts_allow", "^(0|1)$");
  gvm_validator_add (validator, "hosts_opt", "^[-_[:alnum:],: \\./]*$");
  gvm_validator_add (validator, "hosts_ordering",
                     "^(sequential|random|reverse)$");
  gvm_validator_add (validator, "hour", "^([01]?[0-9]|2[0-3])$");
  gvm_validator_add (validator, "howto_use", "(?s)^.*$");
  gvm_validator_add (validator, "howto_install", "(?s)^.*$");
  gvm_validator_add (validator, "id", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "id_optional", "^(--|[a-z0-9\\-]+)$");
  gvm_validator_add (validator, "optional_id", "^[a-z0-9\\-]*$");
  gvm_validator_add (validator, "id_or_empty", "^(|[a-z0-9\\-]+)$");
  gvm_validator_add (validator, "id_list:name", "^ *[0-9]+ *$");
  gvm_validator_add (validator, "id_list:value",
                     "^[[:alnum:]\\-_ ]+:[a-z0-9\\-]+$");
  gvm_validator_add (validator, "include_id_list:name", "^[[:alnum:]\\-_ ]+$");
  gvm_validator_add (validator, "include_id_list:value", "^(0|1)$");
  gvm_validator_add (validator, "installer_sig", "(?s)^.*$");
  gvm_validator_add (validator, "isodate", "^.*$");
  gvm_validator_add (validator, "lang",
                     "^(Browser Language|"
                     "([a-z]{2,3})(_[A-Z]{2})?(@[[:alnum:]_-]+)?"
                     "(:([a-z]{2,3})(_[A-Z]{2})?(@[[:alnum:]_-]+)?)*)$");
  gvm_validator_add (validator, "list_fname",
                     "^([[:alnum:]_-]|%[%CcDFMmNTtUu])+$");
  /* Used for users, credentials, and scanner login name. */
  gvm_validator_add (validator, "login", "^[[:alnum:]\\-_@.]+$");
  gvm_validator_add (validator, "lsc_password", "^.*$");
  gvm_validator_add (validator, "max_result", "^[0-9]+$");
  gvm_validator_add (validator, "max_groups", "^-?[0-9]+$");
  gvm_validator_add (validator, "minute", "^[0-5]{0,1}[0-9]{1,1}$");
  gvm_validator_add (validator, "month", "^((0??[1-9])|1[012])$");
  gvm_validator_add (validator, "note_optional", "(?s)^(.)*$");
  gvm_validator_add (validator, "note_required", "(?s)^(.)+$");
  gvm_validator_add (validator, "note_id", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "override_id", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "name", "^[[:graph:] ]*$");
  gvm_validator_add (validator, "info_name", "(?s)^.*$");
  gvm_validator_add (validator, "info_type", "(?s)^.*$");
  gvm_validator_add (validator, "info_id",
                     "^([[:alnum:]\\-_.:\\/~()']|&amp;)+$");
  gvm_validator_add (validator, "details", "^[0-1]$");
  /* Number is special cased in params_mhd_validate to remove the space. */
  gvm_validator_add (validator, "number", "^ *[0-9]+ *$");
  gvm_validator_add (validator, "image_references",
                     "^[-_[:alnum:],: \\./\\[\\]]+$");
  gvm_validator_add (validator, "optional_number", "^[0-9]*$");
  gvm_validator_add (validator, "oid", "^([0-9.]{1,80}|CVE-[-0-9]{1,14})$");
  gvm_validator_add (validator, "page", "^[_[:alnum:] ]+$");
  gvm_validator_add (validator, "package_format", "^(pem|key|rpm|deb|exe)$");
  gvm_validator_add (validator, "password", "^.*$");
  gvm_validator_add (validator, "password:value", "(?s)^.*$");
  gvm_validator_add (validator, "port", "^.*$");
  gvm_validator_add (validator, "port_range", "^((default)|([-0-9, TU:]+))$");
  gvm_validator_add (validator, "port_type", "^(tcp|udp)$");
  /** @todo Better regex. */
  gvm_validator_add (validator, "preference_name", "^.*$");
  gvm_validator_add (validator, "preference:name", "^([^:]*:[^:]*:.*){0,400}$");
  gvm_validator_add (validator, "preference:value", "(?s)^.*$");
  gvm_validator_add (validator, "prev_action", "(?s)^.*$");
  gvm_validator_add (validator, "privacy_algorithm", "^(aes|des|)$");
  gvm_validator_add (validator, "private_key", "(?s)^.*$");
  gvm_validator_add (validator, "public_key", "(?s)^.*$");
  gvm_validator_add (validator, "pw", "^[[:alnum:]]+$");
  gvm_validator_add (validator, "xml_file", "(?s)^.*$");
  gvm_validator_add (validator, "definitions_file", "(?s)^.*$");
  gvm_validator_add (validator, "ca_pub", "(?s)^.*$");
  gvm_validator_add (validator, "kdc", "(?s)^.*$");
  gvm_validator_alias (validator, "kdcs:name", "number");
  gvm_validator_alias (validator, "kdcs:value", "kdc");
  gvm_validator_add (validator, "key_pub", "(?s)^.*$");
  gvm_validator_add (validator, "key_priv", "(?s)^.*$");
  gvm_validator_add (validator, "radiuskey", "^.*$");
  gvm_validator_add (validator, "range_type",
                     "^(duration|until_end|from_start|start_to_end)$");
  gvm_validator_add (validator, "realm", "(?s)^.*$");
  gvm_validator_add (validator, "related:name", "^.*$");
  gvm_validator_add (validator, "related:value", "^.*$");
  gvm_validator_add (validator, "report_fname",
                     "^([[:alnum:]_-]|%[%CcDFMmNTtUu])+$");
  gvm_validator_add (validator, "report_config_id", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "report_format_id", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "report_section",
                     "^(summary|results|hosts|ports"
                     "|closed_cves|os|apps|errors"
                     "|topology|ssl_certs|cves)$");
  gvm_validator_add (validator, "resource_type", "(?s)^.*$");
  gvm_validator_add (validator, "result_id", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "role", "^[[:alnum:] ]+$");
  gvm_validator_add (validator, "param:name", "^(.*){0,400}$");
  gvm_validator_add (validator, "param:value", "(?s)^.*$");
  gvm_validator_add (validator, "param_using_default:name", "^(.*){0,400}$");
  gvm_validator_add (validator, "param_using_default:value", "(?s)^.*$");
  gvm_validator_add (validator, "permission", "^([_a-z]+|Super)$");
  gvm_validator_add (validator, "permission_type", "^(read|write)$");
  gvm_validator_add (validator, "port_list_id", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "port_range_id", "^[a-z0-9\\-]+$");
  gvm_validator_add (
    validator, "resource_type",
    "^(agent|agent_group|agent_installer|alert|asset|audit_report|audit|"
    "cert_bund_adv|config|cpe|credential|cve|dfn_cert_adv|filter|group|"
    "host|info|nvt|note|oci_image_target|os|ovaldef|override|permission|"
    "policy|port_list|report|report_config|report_format|result|role|scanner|"
    "schedule|tag|target|task|ticket|tls_certificate|user|vuln|)$");
  gvm_validator_add (validator, "resource_id", "^[[:alnum:]\\-_.:\\/~]*$");
  gvm_validator_add (validator, "resources_action", "^(|add|set|remove)$");
  gvm_validator_add (
    validator, "optional_resource_type",
    "^(alert|asset|cert_bund_adv|config|cpe|credential|cve|dfn_cert_adv|"
    "filter|group|host|info|nvt|note|os|ovaldef|override|permission|port_list|"
    "report|report_config|report_format|result|role|scanner|schedule|tag|"
    "target|task|ticket|"
    "tls_certificate|user|vuln|)?$");
  gvm_validator_add (validator, "select:value", "^.*$");
  gvm_validator_add (validator, "ssl_cert", "^.*$");
  gvm_validator_add (validator, "method_data:name", "^.*$");
  gvm_validator_add (validator, "method_data:value", "(?s)^.*$");
  gvm_validator_add (validator, "nvt:name", "(?s)^.*$");
  gvm_validator_add (validator, "restrict_credential_type", "^[a-z0-9\\_|]+$");
  gvm_validator_add (validator, "subject_type", "^(group|role|user)$");
  gvm_validator_add (validator, "summary", "^.*$");
  gvm_validator_add (validator, "tag_id", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "tag_name", "^[\\:\\-_[:alnum:], \\./]+$");
  gvm_validator_add (validator, "tag_value",
                     "^[\\-_@%[:alnum:], \\.\\/\\\\]*$");
  gvm_validator_add (validator, "target_id", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "oci_image_target_id", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "task_id", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "term", "^.*");
  gvm_validator_add (validator, "text", "^.*");
  gvm_validator_add (validator, "text_columns:name", "^[0123456789]+$");
  gvm_validator_add (validator, "text_columns:value", "^[_[:alnum:]]+$");
  gvm_validator_add (validator, "ticket_status", "^(Open|Fixed|Closed)$");
  gvm_validator_add (validator, "trend", "^(0|1)$");
  gvm_validator_add (validator, "trend:value", "^(0|1)$");
  gvm_validator_add (validator, "type", "^(assets)$");
  gvm_validator_add (validator, "search_phrase",
                     "^[[:alnum:][:punct:] äöüÄÖÜß]*$");
  gvm_validator_add (validator, "sort_field", "^[_[:alnum:] ]+$");
  gvm_validator_add (validator, "sort_order", "^(ascending|descending)$");
  gvm_validator_add (validator, "sort_stat", "^[_[:alnum:] ]+$");
  gvm_validator_add (validator, "sort_fields:name", "^[0123456789]+$");
  gvm_validator_add (validator, "sort_fields:value", "^[_[:alnum:] ]+$");
  gvm_validator_add (validator, "sort_orders:name", "^[0123456789]+$");
  gvm_validator_add (validator, "sort_orders:value",
                     "^(ascending|descending)$");
  gvm_validator_add (validator, "sort_stats:name", "^[0123456789]+$");
  gvm_validator_add (validator, "sort_stats:value", "^[_[:alnum:] ]+$");
  gvm_validator_add (validator, "target_source",
                     "^(asset_hosts|file|import|manual)$");
  gvm_validator_add (validator, "target_exclude_source", "^(file|manual)$");
  gvm_validator_add (validator, "timezone", "^.*$");
  gvm_validator_add (validator, "token", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "scanner_id", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "cve_scanner_id", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "schedule_id", "^[a-z0-9\\-]+$");
  gvm_validator_add (validator, "severity",
                     "^(-1(\\.0)?|[0-9](\\.[0-9])?|10(\\.0)?)$");
  gvm_validator_add (validator, "severity_optional",
                     "^(-1(\\.0)?|[0-9](\\.[0-9])?|10(\\.0)?)?$");
  gvm_validator_add (validator, "uuid", "^[0-9abcdefABCDEF\\-]{1,40}$");
  gvm_validator_add (validator, "usage_type", "^(audit|policy|scan|)$");
  /* This must be "login" with space and comma. */
  gvm_validator_add (validator, "users", "^[[:alnum:]\\-_@., ]*$");
  gvm_validator_add (validator, "x_field", "^[\\[\\]_[:alnum:]]+$");
  gvm_validator_add (validator, "y_fields:name", "^[0-9]+$");
  gvm_validator_add (validator, "y_fields:value", "^[\\[\\]_[:alnum:]]+$");
  gvm_validator_add (validator, "year", "^[0-9]+$");
  gvm_validator_add (validator, "z_fields:name", "^[0-9]+$");
  gvm_validator_add (validator, "z_fields:value", "^[\\[\\]_[:alnum:]]+$");
  gvm_validator_add (validator, "calendar_unit",
                     "^(second|minute|hour|day|week|month|year|decade)$");
  gvm_validator_add (validator, "chart_title", "(?s)^.*$");
  gvm_validator_add (validator, "icalendar", "(?s)^BEGIN:VCALENDAR.+$");
  gvm_validator_add (validator, "time_format", "^(12|24|system_default)$");
  gvm_validator_add (validator, "date_format", "^(wmdy|wdmy|system_default)$");

  /* Binary data params that should not use no UTF-8 validation */
  gvm_validator_add_binary (validator, "certificate_bin");
  gvm_validator_add_binary (validator, "installer");
  gvm_validator_add_binary (validator, "method_data:pkcs12:");

  /* Beware, the rule must be defined before the alias. */

  gvm_validator_alias (validator, "optional_task_id", "optional_id");
  gvm_validator_alias (validator, "add_tag", "boolean");
  gvm_validator_alias (validator, "agent_installer_id", "id");
  gvm_validator_alias (validator, "authorized", "boolean");
  gvm_validator_alias (validator, "agent_ids:name", "number");
  gvm_validator_alias (validator, "agent_ids:value", "id");
  gvm_validator_alias (validator, "scheduler_cron_times:name", "number");
  gvm_validator_alias (validator, "scheduler_cron_times:value", "name");

  gvm_validator_alias (validator, "agent_control_id", "id");
  gvm_validator_alias (validator, "attempts", "number");
  gvm_validator_alias (validator, "delay_in_seconds", "number");
  gvm_validator_alias (validator, "bulk_size", "number");
  gvm_validator_alias (validator, "bulk_throttle_time_in_ms", "number");
  gvm_validator_alias (validator, "indexer_dir_depth", "number");
  gvm_validator_alias (validator, "interval_in_seconds", "number");
  gvm_validator_alias (validator, "miss_until_inactive", "number");
  gvm_validator_alias (validator, "max_jitter_in_seconds", "number");
  gvm_validator_alias (validator, "schedule", "number");
  gvm_validator_alias (validator, "agent_group_id", "id");
  gvm_validator_alias (validator, "alert_id_2", "alert_id");
  gvm_validator_alias (validator, "alert_id_optional:name", "number");
  gvm_validator_alias (validator, "alert_id_optional:value",
                       "alert_id_optional");
  gvm_validator_alias (validator, "alerts", "optional_number");
  gvm_validator_alias (validator, "alert_ids:name", "number");
  gvm_validator_alias (validator, "alert_ids:value", "alert_id_optional");
  gvm_validator_alias (validator, "allow_insecure", "boolean");
  gvm_validator_alias (validator, "allow_simultaneous_ips", "boolean");
  gvm_validator_alias (validator, "alterable", "boolean");
  gvm_validator_alias (validator, "apply_overrides", "boolean");
  gvm_validator_alias (validator, "autogenerate", "boolean");
  gvm_validator_alias (validator, "auto_cache_rebuild", "boolean");
  gvm_validator_alias (validator, "base", "name");
  gvm_validator_alias (validator, "build_filter", "boolean");
  /* the "bulk_[...].x" parameters are used to identify the image type
   *  form element used to submit the form for process_bulk */
  gvm_validator_alias (validator, "bulk_create.x", "number");
  gvm_validator_alias (validator, "bulk_delete.x", "number");
  gvm_validator_alias (validator, "bulk_export.x", "number");
  gvm_validator_alias (validator, "bulk_trash.x", "number");
  gvm_validator_alias (validator, "bulk_select", "number");
  gvm_validator_alias (validator, "change_community", "boolean");
  gvm_validator_alias (validator, "change_passphrase", "boolean");
  gvm_validator_alias (validator, "change_password", "boolean");
  gvm_validator_alias (validator, "change_privacy_password", "boolean");
  gvm_validator_alias (validator, "charts", "boolean");
  gvm_validator_alias (validator, "chart_type", "name");
  gvm_validator_alias (validator, "chart_template", "name");
  gvm_validator_alias (validator, "community", "lsc_password");
  gvm_validator_alias (validator, "closed_note", "note_optional");
  gvm_validator_alias (validator, "custom_severity", "boolean");
  gvm_validator_alias (validator, "current_user", "boolean");
  gvm_validator_alias (validator, "dashboard_name", "name");
  gvm_validator_alias (validator, "debug", "boolean");
  gvm_validator_alias (validator, "delta_state_changed", "boolean");
  gvm_validator_alias (validator, "delta_state_gone", "boolean");
  gvm_validator_alias (validator, "delta_state_new", "boolean");
  gvm_validator_alias (validator, "delta_state_same", "boolean");
  gvm_validator_alias (validator, "duration", "optional_number");
  gvm_validator_alias (validator, "duration_unit", "calendar_unit");
  gvm_validator_alias (validator, "dynamic_severity", "boolean");
  gvm_validator_alias (validator, "enable", "boolean");
  gvm_validator_alias (validator, "enable_stop", "boolean");
  gvm_validator_alias (validator, "end_time", "isodate");
  gvm_validator_alias (validator, "esxi_credential_id", "credential_id");
  gvm_validator_alias (validator, "filter_extra", "filter");
  gvm_validator_alias (validator, "filter_id", "id");
  gvm_validator_alias (validator, "filterbox", "boolean");
  gvm_validator_alias (validator, "fixed_note", "note_optional");
  gvm_validator_alias (validator, "from_file", "boolean");
  gvm_validator_alias (validator, "force_wizard", "boolean");
  gvm_validator_alias (validator, "get_name", "name");
  gvm_validator_alias (validator, "grant_full", "boolean");
  gvm_validator_alias (validator, "group_id", "id");
  gvm_validator_alias (validator, "group_ids:name", "number");
  gvm_validator_alias (validator, "group_ids:value", "id_optional");
  gvm_validator_alias (validator, "groups", "optional_number");
  gvm_validator_alias (validator, "hosts_manual", "hosts");
  gvm_validator_alias (validator, "hosts_filter", "filter");
  gvm_validator_alias (validator, "exclude_hosts", "hosts_opt");
  gvm_validator_alias (validator, "in_assets", "boolean");
  gvm_validator_alias (validator, "in_use", "boolean");
  gvm_validator_alias (validator, "include_related", "number");
  gvm_validator_alias (validator, "include_certificate_data", "boolean");
  gvm_validator_alias (validator, "inheritor_id", "id");
  gvm_validator_alias (validator, "ignore_pagination", "boolean");
  gvm_validator_alias (validator, "event", "condition");
  gvm_validator_alias (validator, "access_hosts", "hosts_opt");
  gvm_validator_alias (validator, "max_checks", "number");
  gvm_validator_alias (validator, "max_hosts", "number");
  gvm_validator_alias (validator, "method", "condition");
  gvm_validator_alias (validator, "modify_password", "number");
  gvm_validator_alias (validator, "ldaphost", "hostport");
  gvm_validator_alias (validator, "ldaps_only", "boolean");
  gvm_validator_alias (validator, "lean", "boolean");
  gvm_validator_alias (validator, "level_high", "boolean");
  gvm_validator_alias (validator, "level_medium", "boolean");
  gvm_validator_alias (validator, "level_low", "boolean");
  gvm_validator_alias (validator, "level_log", "boolean");
  gvm_validator_alias (validator, "level_false_positive", "boolean");
  gvm_validator_alias (validator, "method_data:to_address:", "email_list");
  gvm_validator_alias (validator, "method_data:from_address:", "email");
  gvm_validator_alias (validator, "new_severity", "severity_optional");
  gvm_validator_alias (validator, "new_severity_from_list",
                       "severity_optional");
  gvm_validator_alias (validator, "next", "page");
  gvm_validator_alias (validator, "next_next", "page");
  gvm_validator_alias (validator, "next_error", "page");
  gvm_validator_alias (validator, "next_id", "info_id");
  gvm_validator_alias (validator, "next_type", "resource_type");
  gvm_validator_alias (validator, "next_subtype", "info_type");
  gvm_validator_alias (validator, "next_xml", "boolean");
  gvm_validator_alias (validator, "note", "note_required");
  gvm_validator_alias (validator, "notes", "boolean");
  gvm_validator_alias (validator, "no_chart_links", "boolean");
  gvm_validator_alias (validator, "no_filter_history", "boolean");
  gvm_validator_alias (validator, "no_redirect", "boolean");
  gvm_validator_alias (validator, "nvt:value", "uuid");
  gvm_validator_alias (validator, "old_login", "login");
  gvm_validator_alias (validator, "old_password", "password");
  gvm_validator_alias (validator, "open_note", "note_optional");
  gvm_validator_alias (validator, "original_overrides", "boolean");
  gvm_validator_alias (validator, "owner", "name");
  gvm_validator_alias (validator, "passphrase", "lsc_password");
  gvm_validator_alias (validator, "password:name", "preference_name");
  gvm_validator_alias (validator, "permission", "name");
  gvm_validator_alias (validator, "permission_id", "id");
  gvm_validator_alias (validator, "permission_group_id", "id");
  gvm_validator_alias (validator, "permission_role_id", "id");
  gvm_validator_alias (validator, "permission_user_id", "id");
  gvm_validator_alias (validator, "port_manual", "port");
  gvm_validator_alias (validator, "port_range_end", "number");
  gvm_validator_alias (validator, "port_range_start", "number");
  gvm_validator_alias (validator, "pos", "number");
  gvm_validator_alias (validator, "privacy_password", "lsc_password");
  gvm_validator_alias (validator, "radiushost", "hostport");
  gvm_validator_alias (validator, "restrict_type", "resource_type");
  gvm_validator_alias (validator, "resource_ids:name", "number");
  gvm_validator_alias (validator, "resource_ids:value", "info_id");
  gvm_validator_alias (validator, "result_hosts_only", "boolean");
  gvm_validator_alias (validator, "report_format_ids:name", "number");
  gvm_validator_alias (validator, "report_format_ids:value",
                       "report_format_id");
  gvm_validator_alias (validator, "report_id", "id");
  gvm_validator_alias (validator, "_and_report_id", "id");
  gvm_validator_alias (validator, "delta_report_id", "id");
  gvm_validator_alias (validator, "result_task_id", "optional_task_id");
  gvm_validator_alias (validator, "result_uuid", "optional_id");
  gvm_validator_alias (validator, "report_result_id", "result_id");
  gvm_validator_alias (validator, "report_uuid", "result_id");
  gvm_validator_alias (validator, "replace_task_id", "boolean");
  gvm_validator_alias (validator, "reverse_lookup_only", "boolean");
  gvm_validator_alias (validator, "reverse_lookup_unify", "boolean");
  gvm_validator_alias (validator, "role_id", "id");
  gvm_validator_alias (validator, "role_ids:name", "number");
  gvm_validator_alias (validator, "role_ids:value", "id_optional");
  gvm_validator_alias (validator, "roles", "optional_number");
  gvm_validator_alias (validator, "period", "optional_number");
  gvm_validator_alias (validator, "period_unit", "calendar_unit");
  gvm_validator_alias (validator, "scanner_host", "hostpath");
  gvm_validator_alias (validator, "scanner_type", "number");
  gvm_validator_alias (validator, "schedules_only", "boolean");
  gvm_validator_alias (validator, "schedule_periods", "number");
  gvm_validator_alias (validator, "select:name", "family");
  gvm_validator_alias (validator, "setting_id", "id");
  gvm_validator_alias (validator, "show_all", "boolean");
  gvm_validator_alias (validator, "slave_id", "id");
  gvm_validator_alias (validator, "smb_credential_id", "credential_id");
  gvm_validator_alias (validator, "krb5_credential_id", "credential_id");
  gvm_validator_alias (validator, "snmp_credential_id", "credential_id");
  gvm_validator_alias (validator, "ssh_credential_id", "credential_id");
  gvm_validator_alias (validator, "ssh_elevate_credential_id", "credential_id");
  gvm_validator_alias (validator, "subgroup_column", "group_column");
  gvm_validator_alias (validator, "subject_id", "id");
  gvm_validator_alias (validator, "subject_id_optional", "id_optional");
  gvm_validator_alias (validator, "subtype", "asset_type");
  gvm_validator_alias (validator, "start_time", "isodate");
  gvm_validator_alias (validator, "task_uuid", "optional_id");
  gvm_validator_alias (validator, "ticket_id", "id");
  gvm_validator_alias (validator, "timeout", "boolean");
  gvm_validator_alias (validator, "tls_certificate_id", "id");
  gvm_validator_alias (validator, "trend:name", "family");
  gvm_validator_alias (validator, "trust", "boolean");
  gvm_validator_alias (validator, "user_id", "id");
  gvm_validator_alias (validator, "user_id_optional", "id_optional");
  gvm_validator_alias (validator, "xml", "boolean");
  gvm_validator_alias (validator, "esc_filter", "filter");
}

validator_t
get_validator ()
{
  return validator;
}

void
reset_validator ()
{
  validator = NULL;
}
