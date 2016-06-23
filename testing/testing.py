from azure.mgmt.resource.resources import ResourceManagementClient
from azure.common.credentials import ServicePrincipalCredentials, UserPassCredentials

creds_params = {}
creds_params['ad_user'] = "ansiblesvc@trondhindenes.onmicrosoft.com"
creds_params['password'] = "e6PHLue6PHLu"
creds_params['subscription_id'] = "16e5778d-af9e-4a60-8b83-33fc7b7fa535"

creds = UserPassCredentials(creds_params['ad_user'], creds_params['password'])
resource_client = ResourceManagementClient(credentials=creds, subscription_id=creds_params['subscription_id'])