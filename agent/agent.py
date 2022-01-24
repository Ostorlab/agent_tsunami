"""Agent implementation for tsunami scanner."""

from ostorlab.agent import agent
from ostorlab.agent.message import message as msg
from tsunami import tsunami


# class AgentTsunami(agent.Agent):
#     """Tsunami agent."""
#
#     def process(self, message: msg.Message) -> None:
#         """
#         Based on the type of the selector, the method start a tsunami scan using python subprocess, wait for the scan
#         to finish, parse and emit the result.
#
#         Args:
#             message: message received with the agent selector and its data.
#         """
#         if message.selector == 'v3.network.ip.v4':
#             tsunami_scanner = tsunami.Tsunami()
#             tsunami_scanner.start_scan(targ)
#             print(message.data['content'])
def process(message) -> None:
    """
    Based on the type of the selector, the method start a tsunami scan using python subprocess, wait for the scan
    to finish, parse and emit the result.

    Args:
        message: message received with the agent selector and its data.
    """
    if message['selector'] == 'v3.network.ip.v4':
        tsunami_scanner = tsunami.Tsunami(target=message['data']['address'], target_type='v4')
        tsunami_scanner.start_scan()


message = {
    'selector': 'v3.network.ip.v4',
    'data': {
        "address": "192.168.11.105"
    }
}

process(message)
