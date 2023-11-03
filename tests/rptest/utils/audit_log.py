# Copyright 2023 Redpanda Data, Inc.
#
# Use of this software is governed by the Business Source License
# included in the file licenses/BSL.md
#
# As of the Change Date specified in that file, in accordance with
# the Business Source License, use of this software will be governed
# by the Apache License, Version 2.0

from functools import reduce
from typing import Optional

from rptest.services import tls
from rptest.services.redpanda import SecurityConfig


class AuditLogConfig:
    """Configuration for the audit log system"""
    def __init__(self,
                 enabled: bool = True,
                 num_partitions: Optional[int] = 8,
                 event_types: [str] = ['management']):
        """Initializes the config
        
        Parameters
        ----------
        enabled: bool, default=True
            Whether or not system is enabled

        num_partitions: int, default=8
            Number of partitions to create

        event_types: [str], default=['management']
            The event types to start with enabled
        """
        self.enabled = enabled
        self.num_partitions = num_partitions
        self.event_types = event_types

    def to_conf(self) -> {str, str}:
        """Converts conf to dict
        
        Returns
        -------
        {str, str}
            Key,value dictionary of configs
        """
        cfg = {
            'audit_enabled': self.enabled,
            'audit_enabled_event_types': self.event_types
        }

        if self.num_partitions is not None:
            cfg['audit_log_num_partitions']: self.num_partitions

        return cfg


class AuditLogTestSecurityConfig(SecurityConfig):
    """Used to setup security config for audit log tests
    """
    def __init__(self,
                 admin_cert: Optional[tls.Certificate] = None,
                 user_creds: Optional[tuple[str, str, str]] = None,
                 user_cert: Optional[tls.Certificate] = None):
        """
        Creates and initializes security config

        Parameters
        ----------
        admin_cert: Optional[tls.Certificate], default=None
            The certificate to use to authenticate an admin (super users)
        
        user_creds: Optional[tuple[str, str, str]], default=None
            The username, password, and SASL mechanism for a normal user

        user_cert: Optional[tls.Certificate], default=None
           The certificate to use to authenticate a normal user

        Asserts
        -------
        Will assert of a combination of password and certificate credentials
        are provided
        """
        super(AuditLogTestSecurityConfig, self).__init__()
        self._user_creds = user_creds
        self._user_cert = user_cert
        self._admin_cert = admin_cert

        if (self._user_creds is not None):
            assert self._user_cert is None and self._admin_cert is None, "Cannot set certs and password"
            self.enable_sasl = True
            self.kafka_enable_authorization = True
            self.endpoint_authn_method = 'sasl'
        elif (self._user_cert is not None or self._admin_cert is not None):
            assert self._user_cert is not None and self._admin_cert is not None, "Must set both certs"
            self.enable_sasl = False
            self.kafka_enable_authorization = True
            self.endpoint_authn_method = 'mtls_identity'
            self.require_client_auth = True

    @staticmethod
    def default_credentials():
        username = 'username'
        password = 'password'
        algorithm = 'SCRAM-SHA-256'
        return AuditLogTestSecurityConfig(user_creds=(username, password,
                                                      algorithm))

    def check_configuration(self):
        """Used by test harness to ensure auth is sufficent for audit logging
        """
        return self._user_creds is not None or (self._user_cert is not None and
                                                self._admin_cert is not None)

    @property
    def admin_cert(self) -> Optional[tls.Certificate]:
        """
        Returns
        -------
        The certificate to use for an admin (superuser)
        """
        return self._admin_cert

    @property
    def user_creds(self) -> Optional[tuple[str, str, str]]:
        """
        Returns
        -------
        The username, password, and sasl mechanism for a normal user
        """
        return self._user_creds

    @property
    def user_cert(self) -> Optional[tls.Certificate]:
        """
        Returns
        -------
        The certificate to use for a normal user
        """
        return self._user_cert


def aggregate_count(records):
    """Aggregate count of records by checking for 'count' field
        """
    def combine(acc, x):
        return acc + (1 if 'count' not in x else x['count'])

    return reduce(combine, records, 0)


def ocsf_message_match(class_uid: int, record, **kwargs) -> bool:
    if record['class_uid'] != class_uid:
        return False

    kwargs['record'] = record

    if class_uid == 6003:
        return _match_api_event(**kwargs)
    elif class_uid == 6002:
        return _match_app_lifecycle(**kwargs)
    elif class_uid == 3003:
        return _match_authn(**kwargs)
    else:
        assert f"Unknown class_uid {class_uid}"


def _match_api_event(record, service_name, api_operation, resource_entry,
                     principal: Optional[str]) -> bool:
    return record['api']['service']['name'] == service_name and \
        record['api']['operation'] == api_operation and \
            resource_entry in record['resources'] and \
                (record['actor']['user']['name'] == principal if principal is not None else True)


def _match_app_lifecycle(record, is_start: bool,
                         feature: Optional[str]) -> bool:
    expected_activity_id = 3 if is_start else 4

    return record['activity_id'] == expected_activity_id and \
    ((feature is not None and 'feature' in record['app'] and record['app']['feature']['name'] == feature) or \
        (feature is None and 'feature' not in record['app']))


def _match_authn(record, service_name: str, principal: str, protocol_id: int,
                 protocol_name: Optional[str], success: bool,
                 credential_uid: Optional[str]):
    expected_status_id = 1 if success else 2

    return record['service']['name'] == service_name and \
        record['user']['name'] == principal and \
            record['auth_protocol_id'] == protocol_id and \
                (record['auth_protocol'] == protocol_name if protocol_name is not None else True) and \
                    record['status_id'] == expected_status_id and \
                        (record['user']['credential_uid'] == credential_uid if credential_uid is not None else True)
