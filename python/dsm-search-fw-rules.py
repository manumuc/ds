import deepsecurity as api
from deepsecurity.rest import ApiException as api_exception

def search_firewall_rules(api, configuration, api_version, api_exception):
    """ Searches the firewall rules for any rule that contains DHCP in the rule name.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :return: A list containing all firewall rules that match the search criteria.
    """

    # Define the search criteria
    search_criteria = api.SearchCriteria()
    search_criteria.field_name = "name"
    search_criteria.string_value = "%DHCP%"
    search_criteria.string_test = "equal"
    search_criteria.string_wildcards = True

    # Create search filter to find the rule
    search_filter = api.SearchFilter(None,[search_criteria])

    # Create a FirewallRulesApi object
    firewall_rules_api = api.FirewallRulesApi(api.ApiClient(configuration))

    try:
        # Perform the search
        firewall_rules = firewall_rules_api.search_firewall_rules(api_version, search_filter=search_filter)
        firewall_rules_list = []
        for rule in firewall_rules.firewall_rules:
            firewall_rules_list.append(rule)
        return firewall_rules

    except api_exception as e:
        return "Exception: " + str(e)

if __name__ == '__main__':
    # Add Deep Security Manager host information to the api client configuration
    configuration = api.Configuration()
    configuration.host = 'https://!!!!!-----enter-your-dsm-here-------!!!!!!!!!!!!!!/api'

    # Authentication
    configuration.api_key['api-secret-key'] = '!!!!!-----enter-your-api-key-here-------!!!!!!!!!!!!!!'

    # Version
    api_version = 'v1'
    print(search_firewall_rules(api, configuration, api_version, api_exception))
