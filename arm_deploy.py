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
module: arm_deploy
short_description: Invoke Azure Resource Manager deployment
description: 
    - Invokes an Azure Resource Manager (arm) deployment using a template file and optionally a parameter file.
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
  template_src_json:
    description:
      - Path to file containing template json
    required: True
  param_src_json:
    description:
      - Path to file containing template parameter json
    required: False
  resource_group_name:
    description:
      - Resource Group for deployment
    required: True
  resource_group_location:
    description:
      - Resource Group location (only needed if Ansible creates the resource group)
    required: False
  deployment_name:
    description:
      - Name of the deployment (this is only used for referencing the deployment)
    required: True
notes:
  - This module requres Azure v.1.0 on the target node (see https://azure.microsoft.com/en-us/documentation/articles/python-how-to-install/)
'''

EXAMPLES = '''
- hosts: localhost
  tasks:
    - name: deploy
      arm_deploy:
        resource_group_name: "arm-python"
        deployment_name: "arm-python"
        tenant_id: "<tenant id guid>"
        template_src_json: /tmp/template.json
        client_id: "<client id guid>"
        client_secret: '<client secret code>'
        subscription_id: "<subscription id guid>"
        param_src_json: "param.json2"
'''

import sys
import time
import requests
import os.path

try:
    import azure.mgmt.resource
    from azure.mgmt.common import SubscriptionCloudCredentials
    import azure.mgmt.compute
    import azure.mgmt.network
    HAS_ARM = True
except ImportError:
    HAS_ARM = False

if not HAS_ARM:
    module.fail_json(msg='azure python sdk required for this module')


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
            template_src_json = dict(required=True),
            param_src_json = dict(),
            resource_group_name = dict(required=True),
            resource_group_location = dict(),
            deployment_name = dict(required=True)
        ),
        # Implementing check-mode using HEAD is impossible, since size/date is not 100% reliable
        supports_check_mode = False,
    )

    client_id = module.params.get('client_id')
    client_secret = module.params.get('client_secret')
    tenant_id = module.params.get('tenant_id')
    subscription_id = module.params.get('subscription_id')
    template_src_json = module.params.get('template_src_json')
    if module.params['param_src_json']:
        param_src_json = module.params.get('param_src_json')
    else:
        param_src_json = 'none'
    resource_group_name = module.params.get('resource_group_name')
    deployment_name = module.params.get('deployment_name')
    if module.params['resource_group_location']:
        resource_group_location = module.params.get('resource_group_location')
    else:
        resource_group_location = 'none'
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
    templatefile = open(template_src_json)
    template = templatefile.read()
    templatefile.close()
    
    #If param file doesnt exist, use an empty json thingy
    if (param_src_json == 'none'):
      param = '{}'
    elif (os.path.isfile(param_src_json)):
      paramfile = open(param_src_json)
      param = paramfile.read()
      paramfile.close()
    else:
      param = '{}'
    
    
    #create deployment props
    properties = azure.mgmt.resource.resourcemanagement.DeploymentProperties(
      mode="incremental",
      template=template,
      parameters=param
    )
    deploy_parameter = azure.mgmt.resource.Deployment()
    deploy_parameter.properties=properties
    
    #invoke the thing
    result = resource_client.deployments.create_or_update(
    resource_group_name=resource_group_name,
    deployment_name=deployment_name,
    parameters=deploy_parameter
    )

    while True:
        status = resource_client.deployments.get(resource_group_name,deployment_name)
        time.sleep(1)
        print(status.deployment.properties.provisioning_state)
        if status.deployment.properties.provisioning_state == 'Succeeded':
            break
        if status.deployment.properties.provisioning_state == 'Failed':
            module.fail_json(msg='Deployment failed with status code' + status.deployment.properties.statuscode)
            break
    #except:
    #    module.fail_json(msg=sys.exc_info()[0],endpoint=endpoint)



    module.exit_json(changed=True, status=status.request_id)

# Import module snippets
from ansible.module_utils.basic import *

main()
