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

import copy
import requests

from lxml import etree

from tempest.lib.services.identity.v3 import token_client
from oslo_serialization import jsonutils as json

class Saml2Client(object):

    ECP_SP_EMPTY_REQUEST_HEADERS = {
        'Accept': 'text/html, application/vnd.paos+xml',
        'PAOS': ('ver="urn:liberty:paos:2003-08";"urn:oasis:names:tc:'
                 'SAML:2.0:profiles:SSO:ecp"')
    }

    ECP_SP_SAML2_REQUEST_HEADERS = {'Content-Type': 'application/vnd.paos+xml'}

    ECP_SAML2_ASSERTION_HEADERS =  {'Accept': 'application/json'}

    IDP_AUTH_URL = 'http://localhost:5000/v3/auth/tokens'

    def __init__(self):
        self.reset_session()
        self.token_client = token_client.V3TokenClient(self.IDP_AUTH_URL)

    def get_token(self, **kwargs):
        return self.token_client.get_token(**kwargs)

    def auth(self, **kwargs):
        return self.token_client.auth(**kwargs)

    def reset_session(self):
        self.session = requests.Session()

    def _idp_auth_url(self, keystone_v3_endpoint, idp_id, protocol_id):
        subpath = 'OS-FEDERATION/identity_providers/%s/protocols/%s/auth' % (
            idp_id, protocol_id)
        return '%s/%s' % (keystone_v3_endpoint, subpath)

    def send_service_provider_request(self, keystone_v3_endpoint,
                                      idp_id, protocol_id):
        return self.session.get(
            self._idp_auth_url(keystone_v3_endpoint, idp_id, protocol_id),
            headers=self.ECP_SP_EMPTY_REQUEST_HEADERS
        )

    def _prepare_sp_saml2_authn_response(self, saml2_idp_authn_response,
                                         relay_state):
        saml2_idp_authn_response[0][0] = relay_state

    def _prepare_idp_saml2_request(self, idp_saml2_request):
        header = idp_saml2_request[0]
        idp_saml2_request.remove(header)

    def send_identity_provider_authn_request(self, saml2_authn_request,
                                             idp_url, username, password):

        idp_saml2_request = copy.deepcopy(saml2_authn_request)
        self._prepare_idp_saml2_request(idp_saml2_request)

        return self.session.post(
            idp_url,
            headers={'Content-Type': 'text/xml'},
            data=etree.tostring(idp_saml2_request),
            auth=(username, password)
        )

    def send_service_provider_saml2_authn_response(
            self, saml2_idp_authn_response, relay_state, idp_consumer_url):

        self._prepare_sp_saml2_authn_response(
            saml2_idp_authn_response, relay_state)

        return self.session.post(
            idp_consumer_url,
            headers=self.ECP_SP_SAML2_REQUEST_HEADERS,
            data=etree.tostring(saml2_idp_authn_response),
            # Do not follow HTTP redirect
            allow_redirects=False
        )

    def get_ecp_assertion(self, idp_ecp_url, sp_id, token=None):
        """Obtains an assertion from the authentication service
        :param sp_id: registered Service Provider id in Identity Provider
        :param token: a token to perform K2K Federation.
        Accepts one combinations of credentials.
        - token, sp_id
        Validation is left to the Service Provider side.
        """
        body = {
            "auth": {
                "identity": {
                    "methods": [
                        "token"
                    ],
                    "token": {
                        "id": token
                    }
                },
                "scope": {
                    "service_provider": {
                        "id": sp_id
                    }
                }
            }
        }

        resp = self.session.post(url=idp_ecp_url,
                                headers=self.ECP_SAML2_ASSERTION_HEADERS,
                                data=json.dumps(body, sort_keys=True))

        return resp, resp.content

    def send_service_provider_saml2_assertion(
            self, saml2_idp_assertion, sp_ecp_url):

        return self.session.post(
            url=sp_ecp_url,
            headers=self.ECP_SP_SAML2_REQUEST_HEADERS,
            data=saml2_idp_assertion,
            allow_redirects=False)

    def send_service_provider_unscoped_token_request(self, sp_url):
        return self.session.get(
            sp_url,
            headers=self.ECP_SP_SAML2_REQUEST_HEADERS
        )
