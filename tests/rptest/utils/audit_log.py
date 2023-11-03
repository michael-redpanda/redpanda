# Copyright 2023 Redpanda Data, Inc.
#
# Use of this software is governed by the Business Source License
# included in the file licenses/BSL.md
#
# As of the Change Date specified in that file, in accordance with
# the Business Source License, use of this software will be governed
# by the Apache License, Version 2.0

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
