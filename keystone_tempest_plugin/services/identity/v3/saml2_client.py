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
import copy
import json
import requests

from lxml import etree

from tempest.lib.common import rest_client

from keystone_tempest_plugin.services.identity import clients


class Saml2Client(clients.Federation):

    ECP_SP_EMPTY_REQUEST_HEADERS = {
        'Accept': 'text/html, application/vnd.paos+xml',
        'PAOS': ('ver="urn:liberty:paos:2003-08";"urn:oasis:names:tc:'
        'SAML:2.0:profiles:SSO:ecp"')
    }

    ECP_SP_SAML2_REQUEST_HEADERS = {'Content-Type': 'application/vnd.paos+xml'}

    def _idp_auth_subpath(self, idp_id, protocol_id):
        return '%s/identity_providers/%s/protocols/%s/auth' % (
            self.subpath_prefix, idp_id, protocol_id)

    def send_service_provider_request(self, idp_id, protocol_id):
        resp, body = self.get(
             self._idp_auth_subpath(idp_id, protocol_id),
             headers=self.ECP_SP_EMPTY_REQUEST_HEADERS
        )
        self.expected_success(200, resp.status)

        # Parse body response as XML
        return resp, etree.XML(body)

    def _prepare_sp_saml2_authn_response(self, saml2_idp_authn_response,
                                         relay_state):
        saml2_idp_authn_response[0][0] = relay_state

    def _prepare_idp_saml2_request(self, idp_saml2_request):
        header = idp_saml2_request[0]
        idp_saml2_request.remove(header)

    def _basic_auth(self, username, password):
        b64string = base64.encodestring(
            '%s:%s' % (username, password)).replace('\n', '')
        return 'Basic %s' % b64string

    def send_identity_provider_authn_request(self, saml2_authn_request,
                                             idp_url, username, password):

        idp_saml2_request = copy.deepcopy(saml2_authn_request)
        self._prepare_idp_saml2_request(idp_saml2_request)

        # Send HTTP basic authn request to the identity provider
        headers = {
            'Content-Type': 'text/xml',
            'Authorization': self._basic_auth(username, password)
        }
        resp, body = self.raw_request(
             idp_url,
             'POST',
             headers=headers,
             body=etree.tostring(idp_saml2_request)
        )
        self.expected_success(200, resp.status)

        # Parse body response as XML
        return resp, etree.XML(body)

    def send_service_provider_saml2_authn_response(
        self, saml2_idp_authn_response, relay_state, idp_consumer_url):

        self._prepare_sp_saml2_authn_response(
            saml2_idp_authn_response, relay_state)

        # TODO(rodrigods): change to self.raw_request() when it receives
        # support to not follow redirect responses.
        resp = requests.post(
            idp_consumer_url,
            headers=self.ECP_SP_SAML2_REQUEST_HEADERS,
            data=etree.tostring(saml2_idp_authn_response),
            # Do not follow HTTP redirect
            allow_redirects=False
        )
        print('$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$')
        print(resp.__dict__)
        print(resp.raw)
        return resp.headers, resp.content

    def send_service_provider_saml2_authn_request(self, sp_url):
        resp, body = self.raw_request(
            sp_url,
            'GET',
            headers=self.ECP_SP_SAML2_REQUEST_HEADERS
        )
        self.expected_success(200, resp.status)
        body = json.load(body)
        return rest_client.ResponseBody(resp, body)
