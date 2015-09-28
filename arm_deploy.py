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
short_description: Copy a file to a vCenter datastore
description: 
    - Upload files to a vCenter datastore
version_added: 2.0
author: Dag Wieers (@dagwieers) <dag@wieers.com>
options:
  host:
    description:
      - The vCenter server on which the datastore is available.
    required: true
  login:
    description:
      - The login name to authenticate on the vCenter server.
    required: true
  password:
    description:
      - The password to authenticate on the vCenter server.
    required: true
  src:
    description:
      - The file to push to vCenter
    required: true
  datacenter:
    description:
      - The datacenter on the vCenter server that holds the datastore.
    required: true
  datastore:
    description:
      - The datastore on the vCenter server to push files to.
    required: true
  path:
    description:
      - The file to push to the datastore on the vCenter server.
    required: true
notes:
  - "This module ought to be run from a system that can access vCenter directly and has the file to transfer.
    It can be the normal remote target or you can change it either by using C(transport: local) or using C(delegate_to)."
  - Tested on vSphere 5.5
'''

EXAMPLES = '''
- vsphere_copy: host=vhost login=vuser password=vpass src=/some/local/file datacenter='DC1 Someplace' datastore=datastore1 path=some/remote/file
  transport: local
- vsphere_copy: host=vhost login=vuser password=vpass src=/other/local/file datacenter='DC2 Someplace' datastore=datastore2 path=other/remote/file
  delegate_to: other_system
'''

import sys
import time
import requests

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
            param_src_json = dict(required=True),
            resource_group_name = dict(required=True),
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
    param_src_json = module.params.get('param_src_json')
    resource_group_name = module.params.get('resource_group_name')
    deployment_name = module.params.get('deployment_name')

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
    
    #read template file and params file
    templatefile = open(template_src_json)
    template = templatefile.read()
    paramfile = open(param_src_json)
    param = paramfile.read()
    templatefile.close()
    paramfile.close()
    
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
    #except:
    #    module.fail_json(msg=sys.exc_info()[0],endpoint=endpoint)

    module.exit_json(changed=True, status=status.request_id)

# Import module snippets
from ansible.module_utils.basic import *

main()
