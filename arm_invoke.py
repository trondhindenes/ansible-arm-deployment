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
module: arm_invoke
short_description: Invoke an azure resource manager operation
description: 
    - Invoke an azure resource manager operation against a resource provider
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
  src_json:
    description:
      - Path to file containing template json
    required: True
  resource_group_name:
    description:
      - Resource Group for deployment
    required: True
  resource_url:
    description:
      - The portion of the request url after RG, for example providers/microsoft.sql/servers/myserver/databases/mydb?api-version=2014-04-01-preview
    required: False
notes:
  - This module requres Azure v.1.0 on the target node (see https://azure.microsoft.com/en-us/documentation/articles/python-how-to-install/)
'''

EXAMPLES = '''
- hosts: localhost
  tasks:
    - name: deploy
      arm_deploy:
        resource_group_name: "arm-python"
        resource_url: "providers/microsoft.sql/servers/myserver/databases/mydb?api-version=2014-04-01-preview"
        tenant_id: "<tenant id guid>"
        src_json: /tmp/template.json
        client_id: "<client id guid>"
        client_secret: '<client secret code>'
        subscription_id: "<subscription id guid>"
'''

import sys
import time
import requests
import os.path

    HAS_ARM = False

try:
    import azure.mgmt.resource
    from azure.mgmt.common import SubscriptionCloudCredentials
    import azure.mgmt.compute
    import azure.mgmt.network
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
            client_id = dict(required=True),
            client_secret = dict(required=True),
            tenant_id = dict(required=True),
            subscription_id = dict(required=True),
            src_json = dict(),
            resource_group_name = dict(required=True),
            resource_group_location = dict(),
            resource_url = dict(required=True)
        ),
        # Implementing check-mode using HEAD is impossible, since size/date is not 100% reliable
        supports_check_mode = False,
    )

    if not HAS_ARM:
        module.fail_json(msg='azure python sdk required for this module')

    client_id = module.params.get('client_id')
    client_secret = module.params.get('client_secret')
    tenant_id = module.params.get('tenant_id')
    subscription_id = module.params.get('subscription_id')
    if module.params['src_json']:
        src_json = module.params.get('src_json')
    else:
        src_json = 'none'
    resource_group_name = module.params.get('resource_group_name')
    resource_url = module.params.get('resource_url')
    if module.params['resource_group_location']:
        resource_group_location = module.params.get('resource_group_location')
    else:
        resource_group_location = 'none'
    url_method = 'put'
    #try:
    endpoint='https://login.microsoftonline.com/' + tenant_id + '/oauth2/token'
    #authenticate to azure
    auth_token = get_token_from_client_credentials(
    endpoint=endpoint ,
    client_id=client_id,
    client_secret=client_secret,
    )
    
    creds = SubscriptionCloudCredentials(subscription_id, auth_token)
    
    #construct resource client 
    resource_client = azure.mgmt.resource.ResourceManagementClient(creds)
    
    #Check rg
    try:
        rg_list_result = resource_client.resource_groups.get(resource_group_name)
        rg_does_exist = 'True'
    except:
        rg_does_exist = 'False'
    
    
        
    #Create RG if necessary
    if (rg_does_exist == 'False'):
        if (resource_group_location == 'none'):
            module.fail_json(msg='Resource group does not exist, and resource_group_location isnt specified')

        result = resource_client.resource_groups.create_or_update(
            resource_group_name,
            azure.mgmt.resource.ResourceGroup(
            location=resource_group_location,
            ),
        )
    
    #read template file and params file
    jsonfilefile = open(src_json)
    jsonpayload = jsonfilefile.read()
    jsonfilefile.close()
    
    url = "https://management.azure.com/subscriptions/" + subscription_id + "/resourceGroups/" + resource_group_name + "/" + resource_url
    headers = {'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + auth_token
    }
    
    class Object(object):
      pass

    returnobj = Object()
    
    
    if (src_json == 'none'):
      result = requests.put(url,headers=headers)
    else:
      result = requests.put(url,headers=headers, data=jsonpayload)
    
    returnobj.status_code = result.status_code
    returnobj.url = url
    
    if((result.status_code == 200) or (result.status_code == 201)):
      returnobj.changed = True
      module.exit_json(changed=True, status_code=result.status_code, url=url)
    else:
      module.fail_json(msg='Error',status_code=result.status_code, url=url)

    module.exit_json(changed=True, status=result.text, token=auth_token, url=url)

# Import module snippets
from ansible.module_utils.basic import *

main()
