# from dstack_sdk import TappdClient, AsyncTappdClient
# import json
# import sys

# quote_in = sys.argv[1]

# data = {}

# # Synchronous client
# client = TappdClient()

# # Caution: You don't need to do this most of the time.
# http_client = TappdClient('http://localhost:8000')

# # Asynchronous client
# async_client = AsyncTappdClient()

# # Get the information of the Base Image.
# info = client.info()  # or await async_client.info()
# print(info.app_id)  # Application ID
# print(info.tcb_info.mrtd)  # Access TCB info directly
# print(info.tcb_info.event_log[0].event)  # Access event log entries

# # Derive a key with optional path and subject
# key_result = client.derive_key('<unique-id>')  # or await async_client.derive_key('<unique-id>')
# print(key_result.key)  # X.509 private key in PEM format
# print(key_result.certificate_chain)  # Certificate chain
# key_bytes = key_result.toBytes()  # Get key as bytes

# # Generate TDX quote
# quote_result = client.tdx_quote(quote_in, 'raw')  # or await async_client.tdx_quote('some-data', 'sha256')
# print(quote_result.quote)  # TDX quote in hex format
# data['tdx_quote'] = quote_result.quote
# print(quote_result.event_log)  # Event log
# data['event_log'] = quote_result.event_log
# rtmrs = quote_result.replay_rtmrs()  # Replay RTMRs

# print('=====================')
# json_data = json.dumps(data)
# print(json_data)
from dstack_sdk import TappdClient

#Synchronous client
client = TappdClient()
#Generate TDX quote
quote_result = client.tdx_quote('Indeed a bug!', 'raw')  # or await async_client.tdx_quote('some-data', 'sha256')
print(quote_result.quote)  # TDX quote in hex format