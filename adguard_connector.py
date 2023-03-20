from __future__ import annotations

import asyncio
import json
import socket

from typing import Any, Mapping, Dict

import aiohttp
import async_timeout
from yarl import URL


class AdGuardHomeError(Exception):
    """Generic AdGuard Home exception."""


class AdGuardHomeConnectionError(AdGuardHomeError):
    """AdGuard Home connection exception."""


class AdGuardHome:
    """Main class for handling connections with AdGuard Home."""

    def __init__(self,
                 host: str,
                 *,
                 base_path: str = "/control",
                 password: str | None = None,
                 port: int = 3000,
                 request_timeout: int = 10,
                 session: aiohttp.client.ClientSession | None = None,
                 tls: bool = False,
                 user_agent: str = "Python-API",
                 username: str | None = None,
                 verify_ssl: bool = True,
                 ) -> None:
        """Initialize connection with AdGuard Home.

        Class constructor for setting up an AdGuard Home object to
        communicate with an AdGuard Home instance.

        Args:
            host: Hostname or IP address of the AdGuard Home instance.
            base_path: Base path of the API, usually `/control`, which is the default.
            password: Password for HTTP auth, if enabled.
            port: Port on which the API runs, usually 3000.
            request_timeout: Max timeout to wait for a response from the API.
            session: Optional, shared, aiohttp client session.
            tls: True, when TLS/SSL should be used.
            user_agent: Defaults to PythonAdGuardHome/<version>.
            username: Username for HTTP auth, if enabled.
            verify_ssl: Can be set to false, when TLS with self-signed cert is used.
        """

        self._session = session
        self._close_session = False

        self.base_path = base_path
        self.host = host
        self.password = password
        self.port = port
        self.request_timeout = request_timeout
        self.tls = tls
        self.username = username
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent

        if self.base_path[-1] != "/":
            self.base_path += "/"

    # pylint: disable=too-many-arguments, too-many-locals
    async def request(self, uri: str, method: str = "GET", data: Any | None = None, json_data: dict | None = None,
                      params: Mapping[str, str] | None = None, ) -> dict[str, dict | str | list]:
        """Handle a request to the AdGuard Home instance.

        Make a request against the AdGuard Home API and handles the response.

        Args:
            uri: The request URI on the AdGuard Home API to call.
            method: HTTP method to use for the request; e.g., GET, POST.
            data: RAW HTTP request data to send with the request.
            json_data: Dictionary of data to send as JSON with the request.
            params: Mapping of request parameters to send with the request.

        Returns:
            The response from the API. In case the response is a JSON response,
            the method will return a decoded JSON response as a Python
            dictionary. In other cases, it will return the RAW text response.

        Raises:
            AdGuardHomeConnectionError: An error occurred while communicating
                with the AdGuard Home instance (connection issues).
            AdGuardHomeError: An error occurred while processing the
                response from the AdGuard Home instance (invalid data).
        """
        scheme = "https" if self.tls else "http"
        url = URL.build(
            scheme=scheme, host=self.host, port=self.port, path=self.base_path
        ).join(URL(uri))

        auth = None
        if self.username and self.password:
            auth = aiohttp.BasicAuth(self.username, self.password)

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/json, text/plain, */*",
        }

        if self._session is None:
            self._session = aiohttp.ClientSession()
            self._close_session = True

        skip_auto_headers = None
        if data is None and json_data is None:
            skip_auto_headers = {"Content-Type"}

        try:
            async with async_timeout.timeout(self.request_timeout):
                response = await self._session.request(method,
                                                       url,
                                                       auth=auth,
                                                       data=data,
                                                       json=json_data,
                                                       params=params,
                                                       headers=headers,
                                                       ssl=self.verify_ssl,
                                                       skip_auto_headers=skip_auto_headers,
                                                       )
        except asyncio.TimeoutError as exception:
            raise AdGuardHomeConnectionError(
                "Timeout occurred while connecting to AdGuard Home instance.") from exception
        except (aiohttp.ClientError, socket.gaierror) as exception:
            raise AdGuardHomeConnectionError("Error occurred while communicating with AdGuard Home.") from exception

        content_type = response.headers.get("Content-Type", "")

        if "application/json" in content_type:
            resp = await response.json()
            return {'status': response.status, "message": resp}

        text = await response.text()
        return {'status': response.status, "message": text}

    async def dns_records(self) -> list[dict]:
        """
        :return: DNS records [{'domain': 'adguard.local', 'answer': '10.1.0.20'}, ]
        """
        try:
            records = await self.request("rewrite/list")
            return records['message']
        except AdGuardHomeError as exception:
            raise AdGuardHomeError("Cannot get dns records") from exception

    async def dns_exists(self, fqdn: str, ip=None) -> bool:
        """
        :param fqdn: Fully Qualified Domain Name
        :param ip: IP address
        :return: True or False
        """
        try:
            records = await self.dns_records()
            for each in records:
                if each['domain'] == fqdn:
                    return True
            if ip:
                for each in records:
                    if each['answer'] == ip:
                        return True
            return False
        except AdGuardHomeError as exception:
            raise AdGuardHomeError("Cannot find record") from exception

    async def dns_add(self, fqdn, ip) -> None:
        """
        :param fqdn: Fully Qualified Domain Name
        :param ip: IP address
        :return:
        """
        try:
            await self.request("rewrite/add", method='POST', json_data={'domain': fqdn, 'answer': ip})
        except AdGuardHomeError as exception:
            raise AdGuardHomeError("Cannot add dns record") from exception

    async def dns_delete(self, fqdn, ip) -> None:
        """
        :param fqdn: Fully Qualified Domain Name
        :param ip: IP address
        :return: None
        """
        try:
            await self.request("rewrite/delete", method='POST', json_data={'domain': fqdn, 'answer': ip})
        except AdGuardHomeError as exception:
            raise AdGuardHomeError("Cannot delete dns record") from exception

    async def dhcp_records(self) -> list[dict]:
        """
        :return: [{'mac': '', 'hostname': 'adguard.local', 'ip': '10.1.0.20'}, ]
        """
        try:
            records = await self.request("dhcp/status")
            records = records['message']
            return records['static_leases']
        except AdGuardHomeError as exception:
            raise AdGuardHomeError("Cannot get DHCP records") from exception

    async def dhcp_record_exists(self, mac: str | None = None, hostname: str | None = None,
                                 ip: str | None = None) -> bool:
        try:
            records = await self.dhcp_records()
            for each in records:
                if mac == each['mac']:
                    return True
            if hostname:
                for each in records:
                    if hostname == each['hostname']:
                        return True
            if ip:
                for each in records:
                    if ip == each['ip']:
                        return True
            return False

        except AdGuardHomeError as exception:
            raise AdGuardHomeError("Cannot find DHCP record") from exception

    async def dhcp_record_add(self, mac: str, hostname: str, ip: str) -> bool:
        """
        :param mac: MAC address
        :param hostname: Hostname
        :param ip: IP address
        :return: None
        """
        try:
            resp = await self.request("dhcp/add_static_lease", method='POST', json_data={
                "mac": mac,
                "ip": ip,
                "hostname": hostname
            })

            return True if int(resp['status']) // 100 in [4, 5] else False

        except AdGuardHomeError as exception:
            raise AdGuardHomeError("Cannot add static lease") from exception

    async def version(self) -> str:
        """Return the current version of the AdGuard Home instance.

        Returns:
            The version number of the connected AdGuard Home instance.
        """
        response = await self.request("status")
        return response["version"]

    async def close(self) -> None:
        """Close open client session."""
        if self._session and self._close_session:
            await self._session.close()

    async def __aenter__(self) -> AdGuardHome:
        """Async enter.

        Returns:
            The AdGuard Home object.
        """
        return self

    async def __aexit__(self, *_exc_info) -> None:
        """Async exit.

        Args:
            _exc_info: Exec type.
        """
        await self.close()
