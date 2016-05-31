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

import json

from lxml import etree

from tempest.lib.common import rest_client

from keystone_tempest_plugin.services.identity import clients


class Saml2Client(rest_client.RestClient):

    HTTP_MOVED_TEMPORARILY = 302
    HTTP_SEE_OTHER = 303

    ECP_SP_EMPTY_REQUEST_HEADERS = {
        'Accept': 'text/html, application/vnd.paos+xml',
        'PAOS': ('ver="urn:liberty:paos:2003-08";"urn:oasis:names:tc:'
        'SAML:2.0:profiles:SSO:ecp"')
    }

    ECP_RELAY_STATE = '//ecp:RelayState'

    ECP_SAML2_NAMESPACES = {
        'ecp': 'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp',
        'S': 'http://schemas.xmlsoap.org/soap/envelope/',
        'paos': 'urn:liberty:paos:2003-08'
   }

    ECP_SERVICE_PROVIDER_CONSUMER_URL = ('/S:Envelope/S:Header/paos:Request/'
                                         '@responseConsumerURL')

    def _idp_auth_subpath(self, idp_id, protocol_id):
        return 'OS-FEDERATION/identity_providers/%s/protocols/%s/auth' % (
            idp_id, protocol_id)

    def send_service_provider_request(self, idp_id, protocol_id):
       resp, body = self.get(
            self._idp_auth_subpath(idp_id, protocol_id),
            headers=self.ECP_SP_EMPTY_REQUEST_HEADERS
        )

       # Parse body response as XML
       saml2_authn_request = etree.XML(body)

       relay_state = saml2_authn_request.xpath(
           self.ECP_RELAY_STATE, namespaces=self.ECP_SAML2_NAMESPACES)
       sp_response_consumer_url = saml2_authn_request.xpath(
           self.ECP_SERVICE_PROVIDER_CONSUMER_URL,
           namespaces=self.ECP_SAML2_NAMESPACES)
       return relay_state[0], sp_response_consumer_url[0]
