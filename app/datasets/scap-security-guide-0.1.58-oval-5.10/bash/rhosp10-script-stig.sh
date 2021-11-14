#!/usr/bin/env bash
###############################################################################
#
# Bash Remediation Script for [DRAFT] STIG for Red Hat OpenStack Plaform 10
#
# Profile Description:
# Controls for scanning against classified STIG for rhosp10
#
# Profile ID:  stig
# Benchmark ID:  RHEL-10-OSP
# Benchmark Version:  0.1.58
# XCCDF Version:  1.1
#
# This file was generated by OpenSCAP 1.3.5 using:
# $ oscap xccdf generate fix --profile stig --fix-type bash xccdf-file.xml
#
# This Bash Remediation Script is generated from an OpenSCAP profile without preliminary evaluation.
# It attempts to fix every selected rule, even if the system is already compliant.
#
# How to apply this Bash Remediation Script:
# $ sudo ./remediation-script.sh
#
###############################################################################

###############################################################################
# BEGIN fix (1 / 36) for 'cinder_conf_file_perms'
###############################################################################
(>&2 echo "Remediating rule 1/36: 'cinder_conf_file_perms'")
for file in /etc/cinder/cinder.conf \
		/etc/cinder/rootwrap.conf; do
	chown root "$file"
	chgrp cinder "$file"
done

# END fix for 'cinder_conf_file_perms'

###############################################################################
# BEGIN fix (2 / 36) for 'cinder_file_ownership'
###############################################################################
(>&2 echo "Remediating rule 2/36: 'cinder_file_ownership'")
(>&2 echo "FIX FOR THIS RULE 'cinder_file_ownership' IS MISSING!")

# END fix for 'cinder_file_ownership'

###############################################################################
# BEGIN fix (3 / 36) for 'cinder_file_perms'
###############################################################################
(>&2 echo "Remediating rule 3/36: 'cinder_file_perms'")
(>&2 echo "FIX FOR THIS RULE 'cinder_file_perms' IS MISSING!")

# END fix for 'cinder_file_perms'

###############################################################################
# BEGIN fix (4 / 36) for 'cinder_glance_tls'
###############################################################################
(>&2 echo "Remediating rule 4/36: 'cinder_glance_tls'")
(>&2 echo "FIX FOR THIS RULE 'cinder_glance_tls' IS MISSING!")

# END fix for 'cinder_glance_tls'

###############################################################################
# BEGIN fix (5 / 36) for 'cinder_nas_secure_file_permissions'
###############################################################################
(>&2 echo "Remediating rule 5/36: 'cinder_nas_secure_file_permissions'")
(>&2 echo "FIX FOR THIS RULE 'cinder_nas_secure_file_permissions' IS MISSING!")

# END fix for 'cinder_nas_secure_file_permissions'

###############################################################################
# BEGIN fix (6 / 36) for 'cinder_nova_tls'
###############################################################################
(>&2 echo "Remediating rule 6/36: 'cinder_nova_tls'")
(>&2 echo "FIX FOR THIS RULE 'cinder_nova_tls' IS MISSING!")

# END fix for 'cinder_nova_tls'

###############################################################################
# BEGIN fix (7 / 36) for 'cinder_osapi_max_request_body'
###############################################################################
(>&2 echo "Remediating rule 7/36: 'cinder_osapi_max_request_body'")
(>&2 echo "FIX FOR THIS RULE 'cinder_osapi_max_request_body' IS MISSING!")

# END fix for 'cinder_osapi_max_request_body'

###############################################################################
# BEGIN fix (8 / 36) for 'cinder_tls_enabled'
###############################################################################
(>&2 echo "Remediating rule 8/36: 'cinder_tls_enabled'")
(>&2 echo "FIX FOR THIS RULE 'cinder_tls_enabled' IS MISSING!")

# END fix for 'cinder_tls_enabled'

###############################################################################
# BEGIN fix (9 / 36) for 'cinder_using_keystone'
###############################################################################
(>&2 echo "Remediating rule 9/36: 'cinder_using_keystone'")
(>&2 echo "FIX FOR THIS RULE 'cinder_using_keystone' IS MISSING!")

# END fix for 'cinder_using_keystone'

###############################################################################
# BEGIN fix (10 / 36) for 'horizon_csrf_cookie_secure'
###############################################################################
(>&2 echo "Remediating rule 10/36: 'horizon_csrf_cookie_secure'")
(>&2 echo "FIX FOR THIS RULE 'horizon_csrf_cookie_secure' IS MISSING!")

# END fix for 'horizon_csrf_cookie_secure'

###############################################################################
# BEGIN fix (11 / 36) for 'horizon_disable_password_reveal'
###############################################################################
(>&2 echo "Remediating rule 11/36: 'horizon_disable_password_reveal'")
(>&2 echo "FIX FOR THIS RULE 'horizon_disable_password_reveal' IS MISSING!")

# END fix for 'horizon_disable_password_reveal'

###############################################################################
# BEGIN fix (12 / 36) for 'horizon_file_ownership'
###############################################################################
(>&2 echo "Remediating rule 12/36: 'horizon_file_ownership'")
(>&2 echo "FIX FOR THIS RULE 'horizon_file_ownership' IS MISSING!")

# END fix for 'horizon_file_ownership'

###############################################################################
# BEGIN fix (13 / 36) for 'horizon_file_perms'
###############################################################################
(>&2 echo "Remediating rule 13/36: 'horizon_file_perms'")
(>&2 echo "FIX FOR THIS RULE 'horizon_file_perms' IS MISSING!")

# END fix for 'horizon_file_perms'

###############################################################################
# BEGIN fix (14 / 36) for 'horizon_password_autocomplete'
###############################################################################
(>&2 echo "Remediating rule 14/36: 'horizon_password_autocomplete'")
(>&2 echo "FIX FOR THIS RULE 'horizon_password_autocomplete' IS MISSING!")

# END fix for 'horizon_password_autocomplete'

###############################################################################
# BEGIN fix (15 / 36) for 'horizon_session_cookie_httponly'
###############################################################################
(>&2 echo "Remediating rule 15/36: 'horizon_session_cookie_httponly'")
(>&2 echo "FIX FOR THIS RULE 'horizon_session_cookie_httponly' IS MISSING!")

# END fix for 'horizon_session_cookie_httponly'

###############################################################################
# BEGIN fix (16 / 36) for 'horizon_session_cookie_secure'
###############################################################################
(>&2 echo "Remediating rule 16/36: 'horizon_session_cookie_secure'")
(>&2 echo "FIX FOR THIS RULE 'horizon_session_cookie_secure' IS MISSING!")

# END fix for 'horizon_session_cookie_secure'

###############################################################################
# BEGIN fix (17 / 36) for 'horizon_use_ssl'
###############################################################################
(>&2 echo "Remediating rule 17/36: 'horizon_use_ssl'")
(>&2 echo "FIX FOR THIS RULE 'horizon_use_ssl' IS MISSING!")

# END fix for 'horizon_use_ssl'

###############################################################################
# BEGIN fix (18 / 36) for 'keystone_algorithm_hashing'
###############################################################################
(>&2 echo "Remediating rule 18/36: 'keystone_algorithm_hashing'")
(>&2 echo "FIX FOR THIS RULE 'keystone_algorithm_hashing' IS MISSING!")

# END fix for 'keystone_algorithm_hashing'

###############################################################################
# BEGIN fix (19 / 36) for 'keystone_disable_admin_token'
###############################################################################
(>&2 echo "Remediating rule 19/36: 'keystone_disable_admin_token'")
(>&2 echo "FIX FOR THIS RULE 'keystone_disable_admin_token' IS MISSING!")

# END fix for 'keystone_disable_admin_token'

###############################################################################
# BEGIN fix (20 / 36) for 'keystone_disable_user_account_days_inactive'
###############################################################################
(>&2 echo "Remediating rule 20/36: 'keystone_disable_user_account_days_inactive'")
(>&2 echo "FIX FOR THIS RULE 'keystone_disable_user_account_days_inactive' IS MISSING!")

# END fix for 'keystone_disable_user_account_days_inactive'

###############################################################################
# BEGIN fix (21 / 36) for 'keystone_file_ownership'
###############################################################################
(>&2 echo "Remediating rule 21/36: 'keystone_file_ownership'")
(>&2 echo "FIX FOR THIS RULE 'keystone_file_ownership' IS MISSING!")

# END fix for 'keystone_file_ownership'

###############################################################################
# BEGIN fix (22 / 36) for 'keystone_file_perms'
###############################################################################
(>&2 echo "Remediating rule 22/36: 'keystone_file_perms'")
(>&2 echo "FIX FOR THIS RULE 'keystone_file_perms' IS MISSING!")

# END fix for 'keystone_file_perms'

###############################################################################
# BEGIN fix (23 / 36) for 'keystone_lockout_duration'
###############################################################################
(>&2 echo "Remediating rule 23/36: 'keystone_lockout_duration'")
(>&2 echo "FIX FOR THIS RULE 'keystone_lockout_duration' IS MISSING!")

# END fix for 'keystone_lockout_duration'

###############################################################################
# BEGIN fix (24 / 36) for 'keystone_lockout_failure_attempts'
###############################################################################
(>&2 echo "Remediating rule 24/36: 'keystone_lockout_failure_attempts'")
(>&2 echo "FIX FOR THIS RULE 'keystone_lockout_failure_attempts' IS MISSING!")

# END fix for 'keystone_lockout_failure_attempts'

###############################################################################
# BEGIN fix (25 / 36) for 'keystone_max_request_body_size'
###############################################################################
(>&2 echo "Remediating rule 25/36: 'keystone_max_request_body_size'")
(>&2 echo "FIX FOR THIS RULE 'keystone_max_request_body_size' IS MISSING!")

# END fix for 'keystone_max_request_body_size'

###############################################################################
# BEGIN fix (26 / 36) for 'keystone_use_ssl'
###############################################################################
(>&2 echo "Remediating rule 26/36: 'keystone_use_ssl'")
(>&2 echo "FIX FOR THIS RULE 'keystone_use_ssl' IS MISSING!")

# END fix for 'keystone_use_ssl'

###############################################################################
# BEGIN fix (27 / 36) for 'neutron_api_use_ssl'
###############################################################################
(>&2 echo "Remediating rule 27/36: 'neutron_api_use_ssl'")
(>&2 echo "FIX FOR THIS RULE 'neutron_api_use_ssl' IS MISSING!")

# END fix for 'neutron_api_use_ssl'

###############################################################################
# BEGIN fix (28 / 36) for 'neutron_file_ownership'
###############################################################################
(>&2 echo "Remediating rule 28/36: 'neutron_file_ownership'")
(>&2 echo "FIX FOR THIS RULE 'neutron_file_ownership' IS MISSING!")

# END fix for 'neutron_file_ownership'

###############################################################################
# BEGIN fix (29 / 36) for 'neutron_file_perms'
###############################################################################
(>&2 echo "Remediating rule 29/36: 'neutron_file_perms'")
(>&2 echo "FIX FOR THIS RULE 'neutron_file_perms' IS MISSING!")

# END fix for 'neutron_file_perms'

###############################################################################
# BEGIN fix (30 / 36) for 'neutron_use_https'
###############################################################################
(>&2 echo "Remediating rule 30/36: 'neutron_use_https'")
(>&2 echo "FIX FOR THIS RULE 'neutron_use_https' IS MISSING!")

# END fix for 'neutron_use_https'

###############################################################################
# BEGIN fix (31 / 36) for 'neutron_use_keystone'
###############################################################################
(>&2 echo "Remediating rule 31/36: 'neutron_use_keystone'")
(>&2 echo "FIX FOR THIS RULE 'neutron_use_keystone' IS MISSING!")

# END fix for 'neutron_use_keystone'

###############################################################################
# BEGIN fix (32 / 36) for 'nova_file_ownership'
###############################################################################
(>&2 echo "Remediating rule 32/36: 'nova_file_ownership'")
(>&2 echo "FIX FOR THIS RULE 'nova_file_ownership' IS MISSING!")

# END fix for 'nova_file_ownership'

###############################################################################
# BEGIN fix (33 / 36) for 'nova_file_perms'
###############################################################################
(>&2 echo "Remediating rule 33/36: 'nova_file_perms'")
(>&2 echo "FIX FOR THIS RULE 'nova_file_perms' IS MISSING!")

# END fix for 'nova_file_perms'

###############################################################################
# BEGIN fix (34 / 36) for 'nova_secure_authentication'
###############################################################################
(>&2 echo "Remediating rule 34/36: 'nova_secure_authentication'")
(>&2 echo "FIX FOR THIS RULE 'nova_secure_authentication' IS MISSING!")

# END fix for 'nova_secure_authentication'

###############################################################################
# BEGIN fix (35 / 36) for 'nova_secure_glance'
###############################################################################
(>&2 echo "Remediating rule 35/36: 'nova_secure_glance'")
(>&2 echo "FIX FOR THIS RULE 'nova_secure_glance' IS MISSING!")

# END fix for 'nova_secure_glance'

###############################################################################
# BEGIN fix (36 / 36) for 'nova_use_keystone'
###############################################################################
(>&2 echo "Remediating rule 36/36: 'nova_use_keystone'")
(>&2 echo "FIX FOR THIS RULE 'nova_use_keystone' IS MISSING!")

# END fix for 'nova_use_keystone'

