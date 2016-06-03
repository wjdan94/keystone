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

from tempest.lib.common import rest_client

from keystone_tempest_plugin.services.identity import clients


class AuthClient(clients.Identity):

    def get_available_projects_scopes(self, token_id):
        """Get projects that are available to be scoped to based on a token."""
        resp, body = self.get(
            'auth/projects', headers={'X-Auth-Token': token_id})
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return rest_client.ResponseBody(resp, body)

    def get_available_domains_scopes(self, token_id):
        """Get domains that are available to be scoped to based on a token."""
        resp, body = self.get(
            'auth/domains', headers={'X-Auth-Token': token_id})
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return rest_client.ResponseBody(resp, body)
