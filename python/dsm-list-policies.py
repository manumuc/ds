""" for using curl: 
curl -X POST https://!!!!!!-----set your host!!!!!!!!!!!!!!!/api/firewallrules/search \
-H 'Cache-Control: no-cache' \
-H 'api-secret-key: !!!!!!-----set your ap-key!!!!!!!!!!!!!!!' \
-H 'api-version: v1' \
-H 'content-type: application/json' \
-d '{
  "searchCriteria": [{
    "idTest":"equal",
    "idValue":3
  }]
}'
"""

import deepsecurity as api
from deepsecurity.rest import ApiException as api_exception


def get_policies_list(api, configuration, api_version, api_exception):
    """ Gets a list of policies on the Deep Security Manager
    :return: A PoliciesApi object that contains a list of policies.
    """

    try:
        # Create a PoliciesApi object
        policies_api = api.PoliciesApi(api.ApiClient(configuration))

        # List policies using version v1 of the API
        policies_list = policies_api.list_policies(api_version)

        # View the list of policies
        return policies_list

    except api_exception as e:
        return "Exception: " + str(e)

if __name__ == '__main__':
    # Add Deep Security Manager host information to the api client configuration
    configuration = api.Configuration()
    configuration.host = ' https://!!!!!!-----set your host!!!!!!!!!!!!!!!/api'

    # Authentication
    configuration.api_key['api-secret-key'] = '!!!!!!-----set your ap-key!!!!!!!!!!!!!!!'

    # Version
    api_version = 'v1'
    print(get_policies_list(api, configuration, api_version, api_exception))

Open a Command Prompt (Windows) or terminal (Linux) and enter the following command:

python first_steps_get_example.py

