import adguard_connector
from dotenv import load_dotenv
import asyncio
import os

load_dotenv()


async def main():
    dns_manager = adguard_connector.AdGuardHome(os.environ.get('IP'), port=int(os.environ.get('PORT')),
                                                username=os.environ.get('USER'), password=os.environ.get('PSW'))
    records = await dns_manager.dhcp_records()
    print(records)
    print(await dns_manager.dhcp_record_add('c0:c9:e3:03:00:00', 'server.local', '10.1.0.11'))
    print(records)

    await dns_manager.close()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
