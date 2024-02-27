from dotenv import load_dotenv
import os
import ipinfo

load_dotenv()

ipinfo_token = os.getenv('IPINFO_TOKEN')

handler = ipinfo.getHandler(ipinfo_token)


detail = handler.getDetails('205.196.6.166')

for prop in ['hostname', 'city', 'loc']:
    if hasattr(detail, prop):
        print(prop, getattr(detail, prop))
        
# print(detail.hostname)
# print(detail.city)
# print(detail.loc)