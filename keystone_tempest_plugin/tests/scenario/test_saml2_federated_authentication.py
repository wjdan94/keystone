# Copyright 2016 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from tempest import config
from keystone_tempest_plugin.tests import base

from lxml import etree


CONF = config.CONF


class TestSaml2FederatedAuthentication(base.BaseIdentityTest):

    ECP_SAML2_NAMESPACES = {
        'ecp': 'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp',
        'S': 'http://schemas.xmlsoap.org/soap/envelope/',
        'paos': 'urn:liberty:paos:2003-08'
   }

    ECP_SERVICE_PROVIDER_CONSUMER_URL = ('/S:Envelope/S:Header/paos:Request/'
                                         '@responseConsumerURL')

    ECP_IDP_CONSUMER_URL = ('/S:Envelope/S:Header/ecp:Response/'
                            '@AssertionConsumerServiceURL')

    def setUp(self):
        super(TestSaml2FederatedAuthentication, self).setUp()
        self.idp_url = CONF.scenario.fed_idp_ecp_url
        self.username = CONF.scenario.fed_idp_username
        self.password = CONF.scenario.fed_idp_password
        self.idp_id = CONF.scenario.fed_idp_id
        self.protocol_id = CONF.scenario.fed_protocol_id

    def _assert_consumer_url(self, saml2_authn_request, idp_authn_response):
        sp_consumer_url = saml2_authn_request.xpath(
            self.ECP_SERVICE_PROVIDER_CONSUMER_URL,
            namespaces=self.ECP_SAML2_NAMESPACES)
        self.assertEqual(1, len(sp_consumer_url))

        idp_consumer_url = idp_authn_response.xpath(
            self.ECP_IDP_CONSUMER_URL,
            namespaces=self.ECP_SAML2_NAMESPACES)
        self.assertEqual(1, len(idp_consumer_url))

        self.assertEqual(sp_consumer_url[0], idp_consumer_url[0])

    def test_request_unscoped_token(self):
        saml2_authn_request = (
            self.saml2_client.send_service_provider_request(self.idp_id,
                self.protocol_id))
        saml2_idp_authn_response = (
            self.saml2_client.send_identity_provider_authn_request(
                saml2_authn_request, self.idp_url, self.username,
                self.password))
        self._assert_consumer_url(
            saml2_authn_request, saml2_idp_authn_response)
