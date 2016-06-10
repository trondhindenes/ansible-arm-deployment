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
  - This module requres Azure v.2.0.0RC3 on the target node (see https://azure.microsoft.com/en-us/documentation/articles/python-how-to-install/)
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
import ConfigParser
from os.path import expanduser
import json


HAS_ARM = False

try:
    from azure.mgmt.resource.resources.models import ResourceGroup, DeploymentProperties, DeploymentMode
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
            client_id = dict(required=False),
            client_secret = dict(required=False),
            tenant_id = dict(required=False),
            subscription_id = dict(required=False),
            profile= dict(required=False),
            ad_user = dict(required=False),
            password = dict(required=False),
            template_src_json = dict(required=True),
            param_src_json = dict(),
            resource_group_name = dict(required=True),
            resource_group_location = dict(),
            deployment_name = dict(required=True)
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
    
    #authenticate to azure
    
    if profile:
        path = expanduser("~/.azure/credentials")
        try:
            config = ConfigParser.SafeConfigParser()
            config.read(path)
        except Exception as exc:
            module.fail_json("Failed to access {0}. Check that the file exists and you have read access. {1}".format(path, str(exc)))

        if not config.has_section(profile):
            module.fail_json(("Config file does not appear to have section " + profile)
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

    # at this point, we should have creds and a subscription id
    if not creds:
        module.fail_json(msg="Unable to login to Azure with the current parameters/options")
    if not creds_params['subscription_id']:
        module.fail_json(
            msg="Unable to select a working Azure subscription given the current parameters/options")

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
    if (rg_does_exist == 'False'):
        if (resource_group_location == 'none'):
            module.fail_json(msg='Resource group does not exist, and resource_group_location isnt specified')

        result = resource_client.resource_groups.create_or_update(
            resource_group_name,
            ResourceGroup(
                location=resource_group_location,
            ),
        )
    
    #read template file and params file
    templatefile = open(template_src_json, 'r')
    template = templatefile.read()
    templatefile.close()
    #templatedata = "".join(line.rstrip() for line in template)
    templatedata = json.loads(template)
    
    #If param file doesnt exist, use an empty json thingy
    if (param_src_json == 'none'):
        paramdata = None
    elif (os.path.isfile(param_src_json)):
      paramfile = open(param_src_json, 'r')
      paramtxt = paramfile.read()
      paramfile.close()
      paramdata = json.loads(paramtxt)
    else:
        paramdata = None

    #invoke the thing
    result = resource_client.deployments.create_or_update(
        resource_group_name,
        deployment_name,
        properties=DeploymentProperties(
            mode=DeploymentMode.incremental,
            template=templatedata,
            parameters=paramdata)
    )

    if result and result._exception and result._exception.message:
        module.fail_json(msg=result._exception.message)

    while True:
        try:
            status = resource_client.deployments.get(resource_group_name, deployment_name)
        except:
            time.sleep(1)
            status = resource_client.deployments.get(resource_group_name, deployment_name)
        time.sleep(1)
        if status.properties.provisioning_state == 'Succeeded':
            break
        if status.properties.provisioning_state == 'Failed':
            module.fail_json(msg='Deployment failed')
            break

    module.exit_json(changed=True, correlation_id=status.properties.correlation_id)

# Import module snippets
from ansible.module_utils.basic import *

main()
