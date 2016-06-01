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

import base64
import json

from lxml import etree

from tempest.lib.common import rest_client

from keystone_tempest_plugin.services.identity import clients


class Saml2Client(clients.Federation):

    HTTP_MOVED_TEMPORARILY = 302
    HTTP_SEE_OTHER = 303

    ECP_SP_EMPTY_REQUEST_HEADERS = {
        'Accept': 'text/html, application/vnd.paos+xml',
        'PAOS': ('ver="urn:liberty:paos:2003-08";"urn:oasis:names:tc:'
        'SAML:2.0:profiles:SSO:ecp"')
    }

    ECP_RELAY_STATE = '//ecp:RelayState'


    def _idp_auth_subpath(self, idp_id, protocol_id):
        return '%s/identity_providers/%s/protocols/%s/auth' % (
            self.subpath_prefix, idp_id, protocol_id)

    def send_service_provider_request(self, idp_id, protocol_id):
        resp, body = self.get(
             self._idp_auth_subpath(idp_id, protocol_id),
             headers=self.ECP_SP_EMPTY_REQUEST_HEADERS
         )

        # Parse body response as XML
        return etree.XML(body)

        saml2_authn_request = etree.XML(body)

        relay_state = saml2_authn_request.xpath(
            self.ECP_RELAY_STATE, namespaces=self.ECP_SAML2_NAMESPACES)
        return relay_state[0], sp_response_consumer_url[0]

    def _prepare_idp_saml2_request(self, saml2_authn_request):
        header = saml2_authn_request[0]
        saml2_authn_request.remove(header)

    def _basic_auth(self, username, password):
        b64string = base64.encodestring(
            '%s:%s' % (username, password)).replace('\n', '')
        return 'Basic %s' % b64string

    def send_identity_provider_authn_request(self, saml2_authn_request,
                                             idp_url, username, password):

        self._prepare_idp_saml2_request(saml2_authn_request)

        # Send HTTP basic authn request to the identity provider
        headers = {
            'Content-Type': 'text/xml',
            'Authorization': self._basic_auth(username, password)
        }
        resp, body = self.raw_request(
             idp_url,
             'POST',
             headers=headers,
             body=etree.tostring(saml2_authn_request)
        )

        # Parse body response as XML
        return etree.XML(body)

    def send_service_provider_saml2_authn_response(self):
        pass
