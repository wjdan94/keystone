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

from lxml import etree

from tempest import config

from keystone_tempest_plugin.tests import base

from oslo_serialization import jsonutils as json

CONF = config.CONF


class TestSaml2EcpFederatedAuthentication(base.BaseIdentityTest):

    HTTP_MOVED_TEMPORARILY = 302

    HTTP_SEE_OTHER = 303

    ECP_SAML2_NAMESPACES = {
        'ecp': 'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp',
        'S': 'http://schemas.xmlsoap.org/soap/envelope/',
        'paos': 'urn:liberty:paos:2003-08'
    }

    ECP_SERVICE_PROVIDER_CONSUMER_URL = ('/S:Envelope/S:Header/paos:Request/'
                                         '@responseConsumerURL')

    ECP_IDP_CONSUMER_URL = ('/S:Envelope/S:Header/ecp:Response/'
                            '@AssertionConsumerServiceURL')

    ECP_RELAY_STATE = '//ecp:RelayState'

    def setUp(self):
        super(TestSaml2EcpFederatedAuthentication, self).setUp()
        self.keystone_v3_endpoint = CONF.identity.uri_v3
        self.idp_url = CONF.scenario.fed_idp_ecp_url
        self.username = CONF.scenario.fed_idp_username
        self.password = CONF.scenario.fed_idp_password
        self.idp_id = CONF.scenario.fed_idp_id
        self.protocol_id = CONF.scenario.fed_protocol_id
        self.project_name = CONF.scenario.fed_idp_project_name

        # Reset client's session to avoid getting gargabe from another runs
        self.saml2_client.reset_session()

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
        return idp_consumer_url[0]
    
    def _request_unscoped_token(self):
        resp = self.saml2_client.send_service_provider_request(
            self.keystone_v3_endpoint, self.idp_id, self.protocol_id)
        self.assertEqual(200, resp.status_code)
        saml2_authn_request = etree.XML(resp.content)

        resp = self.saml2_client.send_identity_provider_authn_request(
            saml2_authn_request, self.idp_url, self.username, self.password)
        self.assertEqual(200, resp.status_code)
        saml2_idp_authn_response = etree.XML(resp.content)

        # Assert that both saml2_authn_request and saml2_idp_authn_response
        # have the same consumer URL.
        idp_consumer_url = self._assert_consumer_url(
            saml2_authn_request, saml2_idp_authn_response)

        relay_state = saml2_authn_request.xpath(
            self.ECP_RELAY_STATE, namespaces=self.ECP_SAML2_NAMESPACES)[0]

        resp = self.saml2_client.send_service_provider_saml2_authn_response(
            saml2_idp_authn_response, relay_state, idp_consumer_url)
        # Must receive a redirect from service provider
        self.assertIn(resp.status_code,
                      [self.HTTP_MOVED_TEMPORARILY, self.HTTP_SEE_OTHER])

        sp_url = resp.headers['location']
        resp = (
            self.saml2_client.send_service_provider_unscoped_token_request(
                sp_url))
        # We can receive multiple types of errors here, the response depends on
        # the mapping and the username used to authenticate in the identity
        # provider. If everything works well, we receive an unscoped token.
        self.assertEqual(201, resp.status_code)
        self.assertIn('X-Subject-Token', resp.headers)
        self.assertNotEmpty(resp.json())

        return resp
    
    def _request_unscoped_k2k_token(self):
        idp_token, resp = self.saml2_client.get_token(auth_data=True,
                                                project_name=self.project_name,
                                                password=self.password,
                                                username=self.username)
        
	sp_url = resp['service_providers'][0]['auth_url']
        sp_id = resp['service_providers'][0]['id']
        sp_ecp_url = resp['service_providers'][0]['sp_url']
	sp_ip = resp['service_providers'][0]['sp_url'].split('/')[2]        
	
	resp, assertion = self.saml2_client.get_ecp_assertion(idp_ecp_url=self.idp_url,
                                                        sp_id=sp_id, token=idp_token)
        self.assertEqual(200, resp.status_code)

        resp = self.saml2_client.send_service_provider_saml2_assertion(sp_ecp_url=sp_ecp_url,
                                                        saml2_idp_assertion=assertion)
        self.assertIn(resp.status_code,
                      [self.HTTP_MOVED_TEMPORARILY, self.HTTP_SEE_OTHER])
        resp = self.saml2_client.send_service_provider_unscoped_token_request(sp_url)

        self.assertEqual(201, resp.status_code)
        self.assertIn('X-Subject-Token', resp.headers)
        self.assertNotEmpty(resp.json())

        return resp


    def test_request_unscoped_token(self):
        self._request_unscoped_token()

    def test_request_unscoped_k2k_token(self):
	self._request_unscoped_k2k_token()

    def test_request_scoped_token(self):
        resp = self._request_unscoped_token()
        token_id = resp.headers['X-Subject-Token']
        domains = self.auth_client.get_available_domains_scopes(token_id)[
            'domains']
        self.assertNotEmpty(domains)

        # Get a scoped token to one of the listed domains
        self.tokens_client.auth(
            domain_id=domains[0]['id'], token=token_id)

        projects = self.auth_client.get_available_projects_scopes(token_id)[
            'projects']
        self.assertNotEmpty(projects)

        # Get a scoped token to one of the listed projects
        self.tokens_client.auth(
            project_id=projects[0]['id'], token=token_id)
	
    def test_request_scoped_k2k_token(self):
        resp = self._request_unscoped_k2k_token()
	unscoped_token = resp.headers['x-subject-token']
	
	headers = {'x-auth-token': unscoped_token,
                   'Content-Type': 'application/json'}
        resp = self.saml2_client.auth(token=unscoped_token)
	
	return resp
