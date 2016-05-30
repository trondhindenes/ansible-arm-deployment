#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2015 Trond Hindenes <trond@hindenes.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: arm_get_adobject
short_description: Get details about an object in Azure AD
description:
    - Get details about an object in Azure AD
version_added: 2.0
author: Trond Hindenes (@trondhindenes) <trond@hindenes.com>
options:
  client_id:
    description:
      - Azure AD client id to use for auth
    required: True
  client_secret:
    description:
      - Azure AD client client secret to use for auth
    required: True
  tenant_id:
    description:
      - Azure AD tenant id guid to use for auth
    required: True
  subscription_id:
    description:
      - Azure subscription id guid to use for auth
    required: True
  aad_upn:
    description:
      - The Azure AD UPN to lookup
    required: True
notes:
  - This module requres Azure v.1.0 on the target node (see https://azure.microsoft.com/en-us/documentation/articles/python-how-to-install/)
'''

EXAMPLES = '''
'''

import requests

HAS_ARM = False

try:
    from azure.mgmt.resource.resources.models import ResourceGroup
    from azure.mgmt.resource.resources import ResourceManagementClient
    from azure.common.credentials import ServicePrincipalCredentials

    HAS_ARM = True
except ImportError:
    pass


def get_token_from_client_credentials(endpoint, client_id, client_secret):
    payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'resource': 'https://graph.windows.net/',
    }
    response = requests.post(endpoint, data=payload).json()
    return response['access_token']


def main():
    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(required=True),
            client_secret=dict(required=True),
            tenant_id=dict(required=True),
            subscription_id=dict(required=True),
            aad_upn=dict(required=True),
        ),
        # Implementing check-mode using HEAD is impossible, since size/date is not 100% reliable
        supports_check_mode=False,
    )

    if not HAS_ARM:
        module.fail_json(msg='azure python sdk required for this module')

    client_id = module.params.get('client_id')
    client_secret = module.params.get('client_secret')
    tenant_id = module.params.get('tenant_id')
    subscription_id = module.params.get('subscription_id')
    aad_upn = module.params.get('aad_upn')

    # try:
    endpoint = 'https://login.microsoftonline.com/' + tenant_id + '/oauth2/token'
    # authenticate to azure
    auth_token = get_token_from_client_credentials(
        endpoint=endpoint,
        client_id=client_id,
        client_secret=client_secret,
    )

    creds = ServicePrincipalCredentials(client_id=client_id, secret=client_secret, tenant=tenant_id)

    # construct resource client
    if aad_upn:
        uri = "https://graph.windows.net/" + tenant_id + "/users/" + aad_upn + "?api-version=1.6"

    try:
        result = requests.get(url=uri, headers=
        {"content-type": "application/json", "authorization": "bearer " + auth_token})
    except:
        module.fail_json(msg='Something bad happened')

    if result:
        module.exit_json(changed=False, content=result.json())
    else:
        module.fail_json(msg='Something bad happened')


# Import module snippets
from ansible.module_utils.basic import *

main()
