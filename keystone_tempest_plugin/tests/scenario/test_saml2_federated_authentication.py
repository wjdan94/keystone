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


CONF = config.CONF


class TestSaml2FederatedAuthentication(base.BaseIdentityTest):

    def setUp(self):
        super(TestSaml2FederatedAuthentication, self).setUp()
        self.idp_id = CONF.scenario_group.fed_idp_id
        self.protocol_id = CONF.scenario_group.fed_protocol_id

    def test_request_unscoped_token(self):
        relay_state, sp_response_consumer_url = (
            self.saml2_client.send_service_provider_request(self.idp_id,
                self.protocol_id))

        print(relay_state, sp_response_consumer_url)