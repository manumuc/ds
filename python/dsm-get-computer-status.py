""" 
UNFINISHED
to determine whether an agent or appliance is installed, check for the agent and appliance fingerprint
no fingerprint indicates that the agent or appliance is not installed and threfore the agent is not protected - agentFingerPrint <> ""

If an agent is installed check the status ("active"..running correctly; "error" or "inactive" indicats problems; 
offline can mean that the DSM cannot communicate with the DSA) - computerStatu


Use ComputerAPI to obtain computer object


Check AgentFingerPrint and AplicanceFingerprint property of the computer

if computer.agent_finger_print == None and computer.appliance_finger_print == None:

agent_status = computer.computer_status.agent_status
if computer.agent_finger_print != None and agent_status != "active":
    ...
appliance_status = computer.computer_status.appliance_status
if computer.appliance_finger_print != None and appliance_status != "active":
    ...

Obtain the ComputerStatus object from the Computer object and check the AgentStatus property. Any value other than ACTIVE can indicate a problem.
Note: Because the value of the computerStatus field of a computer is an object (ComputerStatus), you cannot search on this field.

omputers_api = api.ComputersApi(api.ApiClient(configuration))
computers = computers_api.list_computers(api_version, expand=expand.list(), overrides=False)


Optionally, obtain the AgentStatusMessages of the ComputerStatus object and the AgentTasks property of the Computer object for useful information.
"""

import deepsecurity as api
from deepsecurity.rest import ApiException as api_exception

# Include computer status information in the returned Computer objects
expand = api.Expand(api.Expand.computer_status)

# Get all computers
computers_api = api.ComputersApi(api.ApiClient(configuration))
computers = computers_api.list_computers(api_version, expand=expand.list(), overrides=False)

for computer in computers.computers:
    computer_info = []

    # Report on computers with no agent or appliance
    if computer.agent_finger_print is None and computer.appliance_finger_print is None:
        # Hostname and protection type
        computer_info.append(computer.host_name)
        computer_info.append("None")

        # Agent/appliance status and status messages
        computer_info.append("No agent/appliance")
        status_messages = ""
        if computer.computer_status is not None and computer.computer_status.agent_status is not None:
            status_messages = str(computer.computer_status.agent_status_messages)
        computer_info.append(status_messages)

    else:
        # Report on problem agents and appliances
        agent_status = computer.computer_status.agent_status
        appliance_status = computer.computer_status.appliance_status

        # Agent is installed but is not active
        if computer.agent_finger_print is not None and agent_status != "active":
            # Hostname and protection type
            computer_info.append(computer.host_name)
            computer_info.append("Agent")

            # Agent status, status messages, and tasks
            if computer.computer_status.agent_status is not None:
                computer_info.append(computer.computer_status.agent_status)
            else:
                computer_info.append("")

            if computer.computer_status.agent_status_messages is not None:
                computer_info.append(str(computer.computer_status.agent_status_messages))
            else:
                computer_info.append("")

            if computer.tasks is not None:
                computer_info.append(str(computer.tasks.agent_tasks))
            else:
                computer_info.append("")

        # Appliance is installed but is not active
        if computer.appliance_finger_print is not None and appliance_status != "active":
            # Hostname and protection type
            computer_info.append(computer.host_name)
            computer_info.append("Appliance")

            # Appliance status, status messages, and tasks
            if computer.computer_status.appliance_status is not None:
                computer_info.append(computer.computer_status.appliance_status)
            else:
                computer_info.append("")

            if computer.computer_status.appliance_status_messages is not None:
                computer_info.append(str(computer.computer_status.appliance_status_messages))
            else:
                computer_info.append("")

            if computer.tasks is not None:
                computer_info.append(str(computer.tasks.appliance_tasks))
            else:
                computer_info.append("")
