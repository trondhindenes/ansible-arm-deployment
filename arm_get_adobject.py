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
import os.path
import ConfigParser
from os.path import expanduser
import json

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
            client_id = dict(required=False),
            client_secret = dict(required=False),
            tenant_id = dict(required=False),
            subscription_id = dict(required=False),
            profile= dict(required=False),
            ad_user = dict(required=False),
            password = dict(required=False),
            aad_upn=dict(required=True),
        ),
        # Implementing check-mode using HEAD is impossible, since size/date is not 100% reliable
        supports_check_mode=False,
    )

    creds_params = {}
    if not HAS_ARM:
        module.fail_json(msg='azure python sdk required for this module')

    if module.params['client_id']:
        creds_params['client_id'] = module.params.get('client_id')
    if module.params['client_secret']:
        creds_params['client_secret'] = module.params.get('client_secret')
    if module.params['tenant_id']:
        creds_params['tenant_id'] = module.params.get('tenant_id')
    if module.params['subscription_id']:
        creds_params['subscription_id'] = module.params.get('subscription_id')
    if module.params['profile']:
        profile = module.params.get('profile')
    if module.params['ad_user']:
        creds_params['ad_user'] = module.params.get('ad_user')
    if module.params['password']:
        creds_params['password'] = module.params.get('password')
    aad_upn = module.params.get('aad_upn')

    if profile:
      path = expanduser("~/.azure/credentials")
      try:
            config = ConfigParser.SafeConfigParser()
            config.read(path)
      except Exception as exc:
          self.fail("Failed to access {0}. Check that the file exists and you have read access. {1}".format(path, str(exc)))
    if not config.has_section(profile):
        self.fail("Config file does not appear to have section " + profile)
    for key, val in config.items(profile):
        creds_params[key] = val

    if 'client_id' in creds_params and 'client_secret' in creds_params:
      endpoint='https://login.microsoftonline.com/' + creds_params['tenant_id'] + '/oauth2/token'
      auth_token = get_token_from_client_credentials(
          endpoint=endpoint,
          client_id=creds_params['client_id'],
          client_secret=creds_params['client_secret'],
      )
    elif 'ad_user' in creds_params and 'password' in creds_params:
        endpoint='https://login.microsoftonline.com/common/oauth2/token'
        auth_token = get_token_from_client_credentials(
            endpoint=endpoint,
            client_id=creds_params['ad_user'],
            client_secret=creds_params['password'],
        )


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
