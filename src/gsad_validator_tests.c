/* Copyright (C) 2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_validator.h"

#include <cgreen/cgreen.h>

Describe (gsad_validator);
BeforeEach (gsad_validator)
{
  gsad_init_validator ();
}

AfterEach (gsad_validator)
{
  gsad_reset_validator ();
}

Ensure (gsad_validator, validate_name)
{
  validator_t validator = gsad_get_validator ();
  assert_that (gvm_validate (validator, "name", "foo"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", "12345"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", "äüöÄÜÖß"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", "()[]"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", "-–"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", ":;.…?!"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", "“”\"‘’''"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", " "), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", "a\tb"), is_equal_to (2));
  assert_that (gvm_validate (validator, "name", "a\rb"), is_equal_to (2));
  assert_that (gvm_validate (validator, "name", "a\nb"), is_equal_to (2));
  assert_that (gvm_validate (validator, "name", "/"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", "\\"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", "@"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", "$%&=<>^+*#"), is_equal_to (0));
  assert_that (gvm_validate (validator, "name", "foo bar 123 baz"),
               is_equal_to (0));
}

Ensure (gsad_validator, validate_comment)
{
  validator_t validator = gsad_get_validator ();
  assert_that (gvm_validate (validator, "comment", "foo"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "12345"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "äüöÄÜÖß"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "()[]"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "-–"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", ":;.…?!"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "“”\"‘’''"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", " "), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "a\tb"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "a\rb"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "a\nb"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "/"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "\\"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "@"), is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "$%&=<>^+*#"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "comment", "foo bar\nbaz\t123"),
               is_equal_to (0));
}

Ensure (gsad_validator, validate_agent_list_ids)
{
  validator_t validator = gsad_get_validator ();
  assert_that (gvm_validate (validator, "agent_ids:value", "a1b2c3d4"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "agent_ids:value",
                             "123e4567-e89b-12d3-a456-426614174000"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "agent_ids:value", ""),
               is_equal_to (2));
  assert_that (
    gvm_validate (validator, "agent_ids:value", "invalid id with space"),
    is_equal_to (2));
}

Ensure (gsad_validator, validate_kdcs_name_and_value)
{
  validator_t validator = gsad_get_validator ();

  // valid KDC values (allowing anything, as per regex "(?s)^.*$")
  assert_that (gvm_validate (validator, "kdcs:value", "127.0.0.1"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "kdcs:value", "kdc1"), is_equal_to (0));
  assert_that (gvm_validate (validator, "kdcs:value", "kdc.example.internal"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "kdcs:value", ""), is_equal_to (0));

  // invalid example for edge case
  assert_that (gvm_validate (validator, "kdcs:value", NULL), is_equal_to (5));

  // "kdcs:name" uses alias to "number", expect it to fail non-numeric
  assert_that (gvm_validate (validator, "kdcs:name", "1"), is_equal_to (0));
  assert_that (gvm_validate (validator, "kdcs:name", "abc"), is_equal_to (2));
  assert_that (gvm_validate (validator, "kdcs:name", ""), is_equal_to (2));
}

Ensure (gsad_validator, validate_oci_image_references)
{
  validator_t validator = gsad_get_validator ();

  assert_that (gvm_validate (validator, "image_references",
                             "oci://myregistry.com/myrepo/myrepo2/myimage:tag"),
               is_equal_to (0));
  assert_that (
    gvm_validate (validator, "image_references", "oci://192.168.0.4:12345"),
    is_equal_to (0));
  assert_that (gvm_validate (validator, "image_references",
                             "oci://[0001:1:1:1::1]:12345/myregistry.com"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "image_references",
                             "oci://[0001:1:1:1::1]/?myregistry.com"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "image_references", ""),
               is_equal_to (2));
}

Ensure (gsad_validator, validate_ca_pub)
{
  validator_t validator = gsad_get_validator ();

  assert_that (gvm_validate (validator, "ca_pub", ""), is_equal_to (0));
  assert_that (gvm_validate (validator, "ca_pub", "foobar"), is_equal_to (0));
  assert_that (gvm_validate (validator, "ca_pub", "123"), is_equal_to (0));
}

Ensure (gsad_validator, alias_boolean_accept_invalid_certs)
{
  validator_t validator = gsad_get_validator ();
  assert_that (gvm_validate (validator, "accept_invalid_certs", "0"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "accept_invalid_certs", "1"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "accept_invalid_certs", "yes"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "accept_invalid_certs", ""),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "accept_invalid_certs", NULL),
               is_equal_to (5));
}

Ensure (gsad_validator, alias_number_agent_ids_name)
{
  validator_t validator = gsad_get_validator ();
  assert_that (gvm_validate (validator, "agent_ids:name", "0"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "agent_ids:name", "42"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "agent_ids:name", "-1"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "agent_ids:name", "abc"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "agent_ids:name", ""), is_equal_to (2));
}

Ensure (gsad_validator, alias_id_optional_alert_id_optional_value)
{
  validator_t validator = gsad_get_validator ();
  assert_that (gvm_validate (validator, "alert_id_optional:value", "--"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "alert_id_optional:value", "abc-123"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "alert_id_optional:value", ""),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "alert_id_optional:value", "ABC"),
               is_equal_to (2)); /* uppercase not allowed */
}

Ensure (gsad_validator, alias_id_report_format_ids_value)
{
  validator_t validator = gsad_get_validator ();
  assert_that (gvm_validate (validator, "report_format_ids:value", "id-1"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "report_format_ids:value",
                             "123e4567-e89b-12d3-a456-426614174000"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "report_format_ids:value", ""),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "report_format_ids:value", "UPPER"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "report_format_ids:value", "bad id"),
               is_equal_to (2));
}

Ensure (gsad_validator, alias_uuid_nvt_value)
{
  validator_t validator = gsad_get_validator ();
  assert_that (gvm_validate (validator, "nvt:value",
                             "123e4567-e89b-12d3-a456-426614174000"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "nvt:value", "deadbeef"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "nvt:value", "g-not-hex"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "nvt:value", ""), is_equal_to (2));
}

Ensure (gsad_validator, alias_email_list_method_data_to_address)
{
  validator_t validator = gsad_get_validator ();
  assert_that (gvm_validate (validator, "method_data:to_address:", "a@b.com"),
               is_equal_to (0));
  assert_that (
    gvm_validate (validator, "method_data:to_address:", "a@b.com, c@d.org"),
    is_equal_to (0));
  assert_that (gvm_validate (validator, "method_data:to_address:", ""),
               is_equal_to (2));
  assert_that (
    gvm_validate (validator, "method_data:to_address:", "not-an-email"),
    is_equal_to (2));
}

Ensure (gsad_validator, alias_hosts_hosts_manual)
{
  validator_t validator = gsad_get_validator ();
  assert_that (
    gvm_validate (validator, "hosts_manual", "192.168.0.1,example.com"),
    is_equal_to (0));
  assert_that (gvm_validate (validator, "hosts_manual", "fe80::1"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "hosts_manual", ""), is_equal_to (2));
}

Ensure (gsad_validator, alias_hostpath_scanner_host)
{
  validator_t validator = gsad_get_validator ();
  assert_that (gvm_validate (validator, "scanner_host", "192.168.1.10:3000"),
               is_equal_to (0));
  assert_that (
    gvm_validate (validator, "scanner_host", "unix:///var/run/openvas.sock"),
    is_equal_to (0));
  assert_that (gvm_validate (validator, "scanner_host", ""), is_equal_to (2));
}

Ensure (gsad_validator, validate_language_type)
{
  validator_t validator = gsad_get_validator ();

  assert_that (gvm_validate (validator, "language_type", "en"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "language_type", "de"),
               is_equal_to (0));

  assert_that (gvm_validate (validator, "language_type", "EN"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "language_type", "tr"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "language_type", "english"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "language_type", ""), is_equal_to (2));
  assert_that (gvm_validate (validator, "language_type", NULL),
               is_equal_to (5));
}

Ensure (gsad_validator, validate_web_application_urls)
{
  validator_t validator = gsad_get_validator ();

  assert_that (
    gvm_validate (validator, "web_application_urls", "https://example.com"),
    is_equal_to (0));
  assert_that (
    gvm_validate (validator, "web_application_urls", "http://localhost:8080"),
    is_equal_to (0));
  assert_that (gvm_validate (validator, "web_application_urls",
                             "https://example.com/app?x=1&y=2"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "web_application_urls",
                             "https://example.com,https://example.com/app"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "web_application_urls",
                             "https://[0001:1:1:1::1]:8443/app"),
               is_equal_to (0));

  assert_that (gvm_validate (validator, "web_application_urls", ""),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "web_application_urls",
                             "https://example.com/<script>"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "web_application_urls",
                             "https://example.com/with space"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "web_application_urls", NULL),
               is_equal_to (5));
}

Ensure (gsad_validator, alias_web_application_target_fields)
{
  validator_t validator = gsad_get_validator ();

  assert_that (gvm_validate (validator, "urls", "https://example.com"),
               is_equal_to (0));
  assert_that (
    gvm_validate (validator, "exclude_urls", "https://example.com/logout"),
    is_equal_to (0));
  assert_that (gvm_validate (validator, "urls",
                             "https://example.com,https://example.com/app"),
               is_equal_to (0));

  assert_that (gvm_validate (validator, "urls", "https://example.com/<script>"),
               is_equal_to (2));
}

Ensure (gsad_validator, validate_scan_mode)
{
  validator_t validator = gsad_get_validator ();

  assert_that (gvm_validate (validator, "scan_mode", "active"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "scan_mode", "safe"), is_equal_to (0));
  assert_that (gvm_validate (validator, "scan_mode", ""), is_equal_to (2));
  assert_that (gvm_validate (validator, "scan_mode", "invalid"),
               is_equal_to (2));
}

Ensure (gsad_validator, validate_ajax_spider_timeout)
{
  validator_t validator = gsad_get_validator ();

  assert_that (gvm_validate (validator, "ajax_spider_timeout", "0"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "ajax_spider_timeout", "30"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "ajax_spider_timeout", "-1"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "ajax_spider_timeout", "abc"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "ajax_spider_timeout", ""),
               is_equal_to (2));
}

Ensure (gsad_validator, validate_ad_credential_type)
{
  validator_t validator = gsad_get_validator ();

  assert_that (gvm_validate (validator, "credential_type", "ad"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "credential_type", "cc"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "credential_type", "up"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "credential_type", "usk"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "credential_type", "smime"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "credential_type", "pgp"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "credential_type", "snmp"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "credential_type", "krb5"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "credential_type", "pw"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "credential_type", "cs_cc"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "credential_type", "cs_up"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "credential_type", "cs_usk"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "credential_type", "cs_smime"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "credential_type", "cs_pgp"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "credential_type", "cs_snmp"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "credential_type", "cs_krb5"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "credential_type", "cs_pw"),
               is_equal_to (0));

  assert_that (gvm_validate (validator, "credential_type", "AD"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "credential_type", "cs_ad"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "credential_type", "ad_extra"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "credential_type", ""),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "credential_type", NULL),
               is_equal_to (5));
}

Ensure (gsad_validator, validate_ad_host)
{
  validator_t validator = gsad_get_validator ();

  assert_that (gvm_validate (validator, "ad_host", "dc.example.com"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "ad_host", "192.0.2.10"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "ad_host", "2001:db8::1"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "ad_host", "dc-01"), is_equal_to (0));

  assert_that (gvm_validate (validator, "ad_host", ""), is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_host", "dc example.com"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_host", "ldaps://dc.example.com"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_host", "[2001:db8::1]"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_host", NULL), is_equal_to (5));
}

Ensure (gsad_validator, validate_ad_port_format)
{
  validator_t validator = gsad_get_validator ();

  assert_that (gvm_validate (validator, "ad_port", ""), is_equal_to (0));
  assert_that (gvm_validate (validator, "ad_port", "1"), is_equal_to (0));
  assert_that (gvm_validate (validator, "ad_port", "389"), is_equal_to (0));
  assert_that (gvm_validate (validator, "ad_port", "636"), is_equal_to (0));
  assert_that (gvm_validate (validator, "ad_port", "65535"), is_equal_to (0));
  assert_that (gvm_validate (validator, "ad_port", "00389"), is_equal_to (0));
  assert_that (gvm_validate (validator, "ad_port", "0"), is_equal_to (0));
  assert_that (gvm_validate (validator, "ad_port", "65536"), is_equal_to (0));

  assert_that (gvm_validate (validator, "ad_port", "-1"), is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_port", "+389"), is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_port", "389.0"), is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_port", " 389"), is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_port", "389 "), is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_port", "ldap"), is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_port", NULL), is_equal_to (5));
}

Ensure (gsad_validator, validate_ad_bind_dn)
{
  validator_t validator = gsad_get_validator ();

  assert_that (gvm_validate (validator, "ad_bind_dn",
                             "CN=Service Account,OU=Users,DC=example,DC=com"),
               is_equal_to (0));
  assert_that (
    gvm_validate (validator, "ad_bind_dn", "CN=Doe\\, Jane,DC=example,DC=com"),
    is_equal_to (0));
  assert_that (gvm_validate (validator, "ad_bind_dn", "svc@example.com"),
               is_equal_to (0));

  assert_that (gvm_validate (validator, "ad_bind_dn", ""), is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_bind_dn",
                             "CN=Service\nAccount,DC=example,DC=com"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_bind_dn", NULL), is_equal_to (5));
}

Ensure (gsad_validator, validate_ad_bind_password)
{
  validator_t validator = gsad_get_validator ();

  assert_that (gvm_validate (validator, "ad_bind_password", "secret"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "ad_bind_password", "p<&>\"'\\word"),
               is_equal_to (0));

  assert_that (gvm_validate (validator, "ad_bind_password", "first\nsecond"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_bind_password", ""),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_bind_password", NULL),
               is_equal_to (5));
}

Ensure (gsad_validator, validate_ad_base_dn)
{
  validator_t validator = gsad_get_validator ();

  assert_that (gvm_validate (validator, "ad_base_dn", "DC=example,DC=com"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "ad_base_dn",
                             "OU=Corporate Users,DC=example,DC=com"),
               is_equal_to (0));

  assert_that (gvm_validate (validator, "ad_base_dn", ""), is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_base_dn", "DC=example\nDC=com"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_base_dn", NULL), is_equal_to (5));
}

Ensure (gsad_validator, validate_ad_tls_mode)
{
  validator_t validator = gsad_get_validator ();

  assert_that (gvm_validate (validator, "ad_tls_mode", "ldaps"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "ad_tls_mode", "starttls"),
               is_equal_to (0));

  assert_that (gvm_validate (validator, "ad_tls_mode", ""), is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_tls_mode", "ldap"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_tls_mode", "none"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_tls_mode", "LDAPS"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_tls_mode", "StartTLS"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_tls_mode", "ldaps-extra"),
               is_equal_to (2));
  assert_that (gvm_validate (validator, "ad_tls_mode", NULL), is_equal_to (5));
}

Ensure (gsad_validator, validate_ad_ca_certificate_not_null)
{
  validator_t validator = gsad_get_validator ();

  assert_that (gvm_validate (validator, "ad_ca_certificate", ""),
               is_equal_to (0));
  assert_that (
    gvm_validate (validator, "ad_ca_certificate", "not a certificate"),
    is_equal_to (0));
  assert_that (gvm_validate (validator, "ad_ca_certificate",
                             "-----BEGIN CERTIFICATE-----\n"
                             "YWJj\n"
                             "-----END CERTIFICATE-----\n"),
               is_equal_to (0));
  assert_that (gvm_validate (validator, "ad_ca_certificate", NULL),
               is_equal_to (5));
}

int
main (int argc, char **argv)
{
  int ret;

  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, gsad_validator, validate_name);
  add_test_with_context (suite, gsad_validator, validate_comment);
  add_test_with_context (suite, gsad_validator, validate_agent_list_ids);
  add_test_with_context (suite, gsad_validator, validate_kdcs_name_and_value);
  add_test_with_context (suite, gsad_validator, validate_oci_image_references);
  add_test_with_context (suite, gsad_validator, validate_ca_pub);
  add_test_with_context (suite, gsad_validator,
                         alias_boolean_accept_invalid_certs);
  add_test_with_context (suite, gsad_validator, alias_number_agent_ids_name);
  add_test_with_context (suite, gsad_validator,
                         alias_id_optional_alert_id_optional_value);
  add_test_with_context (suite, gsad_validator,
                         alias_id_report_format_ids_value);
  add_test_with_context (suite, gsad_validator, alias_uuid_nvt_value);
  add_test_with_context (suite, gsad_validator,
                         alias_email_list_method_data_to_address);
  add_test_with_context (suite, gsad_validator, alias_hosts_hosts_manual);
  add_test_with_context (suite, gsad_validator, alias_hostpath_scanner_host);
  add_test_with_context (suite, gsad_validator, validate_language_type);
  add_test_with_context (suite, gsad_validator, validate_web_application_urls);
  add_test_with_context (suite, gsad_validator,
                         alias_web_application_target_fields);
  add_test_with_context (suite, gsad_validator, validate_scan_mode);
  add_test_with_context (suite, gsad_validator, validate_ajax_spider_timeout);
  add_test_with_context (suite, gsad_validator, validate_ad_credential_type);
  add_test_with_context (suite, gsad_validator, validate_ad_host);
  add_test_with_context (suite, gsad_validator, validate_ad_port_format);
  add_test_with_context (suite, gsad_validator, validate_ad_bind_dn);
  add_test_with_context (suite, gsad_validator, validate_ad_bind_password);
  add_test_with_context (suite, gsad_validator, validate_ad_base_dn);
  add_test_with_context (suite, gsad_validator, validate_ad_tls_mode);
  add_test_with_context (suite, gsad_validator,
                         validate_ad_ca_certificate_not_null);
  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
