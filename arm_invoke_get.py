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
module: arm_invoke_get
short_description: Get the (json) result of an arm resource/resource group
description: 
    - Get the (json) result of an arm resource/resource group
      Authentication options are the same as for the in-box modules. See explanation at http://docs.ansible.com/ansible/azure_rm_deployment_module.html
version_added: 2.0
author: Trond Hindenes (@trondhindenes) <trond@hindenes.com>
options:
  client_id:
    description:
      - Azure AD client id to use for auth
    required: False
  client_secret:
    description:
      - Azure AD client client secret to use for auth
    required: False
  tenant_id:
    description:
      - Azure AD tenant id guid to use for auth
    required: False
  subscription_id:
    description:
      - Azure subscription id guid to use for auth
    required: False
  profile:
    description: Security profile found in ~/.azure/credentials file. This can be used instead of the other auth-related options
    required: False
  ad_user:
    description: Azure AD Username
    required: False
  password:
    description: Password of the ad_user user
    required: False
  resource_group_name:
    description:
      - Resource Group for deployment. Required if using "resource url", not if using "raw_url"
    required: False
  resource_url:
    description:
      - The portion of the request url after RG, for example providers/microsoft.sql/servers/myserver/databases/mydb?api-version=2014-04-01-preview
    required: False
  raw_url:
    description:
        - Use if you want to specify the whole uri, e.g /subscriptions/xxx/providers/microsoft.sql?api-version=2014-01-preview. Useful when getting stuff which isn't inside a resource group. Mutually excludes "resource_url"
    required: False        
notes:
  - This module requres Azure v.2.0.0RC3 on the target node (see https://azure.microsoft.com/en-us/documentation/articles/python-how-to-install/)
'''

EXAMPLES = '''
- hosts: localhost
  tasks:
    - name: deploy
      arm_deploy:
        resource_group_name: "arm-python"
        resource_url: "providers/microsoft.sql/servers/myserver/databases/mydb?api-version=2014-04-01-preview"
        tenant_id: "<tenant id guid>"
        client_id: "<client id guid>"
        client_secret: '<client secret code>'
        subscription_id: "<subscription id guid>"
'''

import sys
import time
import requests
import os.path
import ConfigParser
from os.path import expanduser

HAS_ARM = False

try:
    from azure.mgmt.resource.resources.models import ResourceGroup
    from azure.mgmt.resource.resources import ResourceManagementClient, ResourceManagementClientConfiguration
    from azure.common.credentials import ServicePrincipalCredentials, UserPassCredentials
    HAS_ARM = True
except ImportError:
    pass

def get_token_from_client_credentials(endpoint, client_id, client_secret):
    payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'resource': 'https://management.core.windows.net/',
    }
    response = requests.post(endpoint, data=payload).json()
    return response['access_token']
    


def main():
    module = AnsibleModule(
        argument_spec = dict(
            client_id=dict(required=False),
            client_secret=dict(required=False),
            tenant_id=dict(required=False),
            subscription_id=dict(required=False),
            profile=dict(required=False),
            ad_user=dict(required=False),
            password=dict(required=False),
            resource_group_name = dict(required=False),
            resource_url = dict(required=False),
            raw_url = dict(required=False)
        ),
        # Implementing check-mode using HEAD is impossible, since size/date is not 100% reliable
        supports_check_mode = False,
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
    else:
        profile = None
    if module.params['ad_user']:
        creds_params['ad_user'] = module.params.get('ad_user')
    if module.params['password']:
        creds_params['password'] = module.params.get('password')

    resource_group_name = module.params.get('resource_group_name')
    resource_url = module.params.get('resource_url')
    if module.params['raw_url']:
        raw_url = module.params.get('raw_url')
    else:
        raw_url = None
    
    url_method = 'get'
    #try:

    creds = None

    #authenticate to azure
    if profile:
        path = expanduser("~/.azure/credentials")
        try:
                config = ConfigParser.SafeConfigParser()
                config.read(path)
        except Exception as exc:
            module.fail_json(msg="Failed to access profile " + str(path))
        if not config.has_section(profile):
            module.fail_json(msg="section not found in profile")
        for key, val in config.items(profile):
            creds_params[key] = val

    if 'client_id' in creds_params and 'client_secret' in creds_params:
            endpoint='https://login.microsoftonline.com/' + creds_params['tenant_id'] + '/oauth2/token'
            auth_token = get_token_from_client_credentials(
                endpoint=endpoint,
                client_id=creds_params['client_id'],
                client_secret=creds_params['client_secret'],
                )
            creds = ServicePrincipalCredentials(client_id=creds_params['client_id'], secret=creds_params['client_secret'],
                    tenant=creds_params['tenant_id'])

    elif 'ad_user' in creds_params and 'password' in creds_params:
        creds = UserPassCredentials(creds_params['ad_user'], creds_params['password'])
        auth_token = creds.token['access_token']

    #at this point, we should have creds and a subscription id
    if not creds:
        module.fail_json(msg="Unable to login to Azure with the current parameters/options")
    if not creds_params['subscription_id']:
        module.fail_json(msg="Unable to select a working Azure subscription given the current parameters/options")

    #construct resource client
    config = ResourceManagementClientConfiguration(creds, creds_params['subscription_id'])
    resource_client = ResourceManagementClient(config)
    
    #Check rg
    try:
        rg_list_result = resource_client.resource_groups.get(resource_group_name)
        rg_does_exist = 'True'
    except:
        rg_does_exist = 'False'
    
    #Create RG if necessary
    if resource_url:
        if (rg_does_exist == 'False'):
            module.fail_json(msg="Resoruce group does not exist")

    if raw_url:
        url = "https://management.azure.com" + raw_url
    else:
        url = "https://management.azure.com/subscriptions/" + creds_params['subscription_id'] + "/resourceGroups/" + resource_group_name + "/" + resource_url
    headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'Authorization': 'Bearer ' + auth_token
    }
    
    class Object(object):
        pass

    returnobj = Object()

    #Check if the resource exists
    result = None
    does_exist_request = requests.get(url, headers=headers)
    if does_exist_request.status_code in (400, 404):
        does_exist = False
    else:
        does_exist = True

    if (does_exist == False):
        module.exit_json(changed=False, status_code=None, url=url, content=None)
    
    if (does_exist == True):
        module.exit_json(changed=False, status_code=does_exist_request.status_code, url=url, content=does_exist_request.json())

# Import module snippets
from ansible.module_utils.basic import *

main()
