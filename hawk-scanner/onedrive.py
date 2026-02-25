"""
OneDrive connector for hawk_scanner.

Scans files in Microsoft OneDrive via the Microsoft Graph API.
Supports both application (client_credentials) and delegated (refresh_token) auth flows.

Config format in connection.yml:
  sources:
    onedrive:
      my_onedrive:
        client_id: "azure-app-client-id"
        client_secret: "azure-app-secret"
        tenant_id: "common"
        refresh_token: "user-refresh-token"   # omit for client_credentials flow
        folder_path: ""                       # empty = root
        exclude_patterns: []
        cache: false
"""

import os
import requests
from hawk_scanner.internals import system


GRAPH_BASE = "https://graph.microsoft.com/v1.0"
TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"


def get_access_token(args, client_id, client_secret, tenant_id, refresh_token=""):
    """Obtain an OAuth2 access token from Microsoft identity platform."""
    url = TOKEN_URL.format(tenant=tenant_id)

    if refresh_token:
        # Delegated flow using refresh token
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
            "scope": "https://graph.microsoft.com/Files.Read.All offline_access",
        }
    else:
        # Application (client_credentials) flow
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        }

    resp = requests.post(url, data=data, timeout=30)
    resp.raise_for_status()
    token = resp.json().get("access_token")
    if not token:
        raise RuntimeError(f"No access_token in response: {resp.json()}")
    system.print_debug(args, "Obtained Microsoft Graph access token")
    return token


def _graph_get(token, url, params=None):
    """Helper for authenticated GET requests to Microsoft Graph."""
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def list_files_recursive(args, token, folder_path=""):
    """
    List all files recursively from the given folder path.
    Returns a list of dicts with keys: id, name, path, size, download_url.
    """
    files = []

    if folder_path:
        # Specific folder
        url = f"{GRAPH_BASE}/me/drive/root:/{folder_path}:/children"
    else:
        # Root
        url = f"{GRAPH_BASE}/me/drive/root/children"

    while url:
        data = _graph_get(token, url)
        for item in data.get("value", []):
            if "folder" in item:
                # Recurse into subfolder
                child_path = item.get("parentReference", {}).get("path", "")
                # parentReference.path looks like /drive/root:/FolderA
                # Build the relative path for the child folder
                if child_path and "root:" in child_path:
                    relative_parent = child_path.split("root:")[-1].lstrip("/")
                    sub_path = f"{relative_parent}/{item['name']}" if relative_parent else item["name"]
                else:
                    sub_path = f"{folder_path}/{item['name']}" if folder_path else item["name"]

                files.extend(list_files_recursive(args, token, sub_path))
            elif "file" in item:
                parent_path = item.get("parentReference", {}).get("path", "")
                if parent_path and "root:" in parent_path:
                    relative_path = parent_path.split("root:")[-1].lstrip("/")
                else:
                    relative_path = folder_path

                files.append({
                    "id": item["id"],
                    "name": item["name"],
                    "path": f"{relative_path}/{item['name']}" if relative_path else item["name"],
                    "size": item.get("size", 0),
                    "download_url": item.get("@microsoft.graph.downloadUrl", ""),
                })

        # Handle pagination
        url = data.get("@odata.nextLink")

    return files


def download_file(args, token, file_info, cache_dir, cache_enabled):
    """
    Download a file from OneDrive to a local temp path.
    Returns the local file path.
    """
    file_id = file_info["id"]
    file_name = file_info["name"]
    local_path = os.path.join(cache_dir, file_id, file_name)

    if cache_enabled and os.path.exists(local_path):
        system.print_debug(args, f"File already in cache: {file_name}")
        return local_path

    os.makedirs(os.path.dirname(local_path), exist_ok=True)

    # Use the pre-authenticated download URL if available
    download_url = file_info.get("download_url")
    if not download_url:
        # Fall back to Graph API download endpoint (returns 302 redirect)
        download_url = f"{GRAPH_BASE}/me/drive/items/{file_id}/content"

    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(download_url, headers=headers, stream=True, timeout=120)
    resp.raise_for_status()

    with open(local_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)

    system.print_debug(args, f"Downloaded: {file_name} -> {local_path}")
    return local_path


def execute(args):
    """Main entry point called by hawk_scanner."""
    results = []
    connections = system.get_connection(args)
    is_cache_enabled = False

    if not connections or "sources" not in connections:
        system.print_error(args, "No 'sources' section found in connection.yml")
        return results

    onedrive_config = connections["sources"].get("onedrive", {})

    if not onedrive_config:
        system.print_error(args, "No OneDrive connection details found in connection file")
        return results

    cache_dir = "data/onedrive"

    for key, config in onedrive_config.items():
        system.print_info(args, f"Checking OneDrive profile: '{key}'")

        client_id = config.get("client_id", "")
        client_secret = config.get("client_secret", "")
        tenant_id = config.get("tenant_id", "common")
        refresh_token = config.get("refresh_token", "")
        folder_path = config.get("folder_path", "")
        exclude_patterns = config.get("exclude_patterns", [])
        is_cache_enabled = config.get("cache", False)

        if not client_id or not client_secret:
            system.print_error(args, f"Incomplete OneDrive config for profile '{key}': client_id and client_secret required")
            continue

        try:
            token = get_access_token(args, client_id, client_secret, tenant_id, refresh_token)
        except Exception as e:
            system.print_error(args, f"Failed to authenticate for profile '{key}': {e}")
            continue

        try:
            files = list_files_recursive(args, token, folder_path)
        except Exception as e:
            system.print_error(args, f"Failed to list files for profile '{key}': {e}")
            continue

        system.print_info(args, f"Found {len(files)} files in OneDrive profile '{key}'")

        for file_info in files:
            if system.should_exclude_file(args, file_info["name"], exclude_patterns):
                continue

            try:
                local_path = download_file(args, token, file_info, cache_dir, is_cache_enabled)
            except Exception as e:
                system.print_error(args, f"Failed to download {file_info['name']}: {e}")
                continue

            matches = system.read_match_strings(args, local_path, "onedrive")
            if matches:
                for match in matches:
                    results.append({
                        "file_id": file_info["id"],
                        "file_name": file_info["name"],
                        "file_path": file_info["path"],
                        "pattern_name": match["pattern_name"],
                        "matches": match["matches"],
                        "sample_text": match["sample_text"],
                        "profile": key,
                        "data_source": "onedrive",
                    })

    if not is_cache_enabled:
        os.system("rm -rf data/onedrive")

    return results
