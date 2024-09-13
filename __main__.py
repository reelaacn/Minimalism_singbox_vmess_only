import base64
import json
import socket
from pathlib import Path
from typing import Dict, List
from urllib.parse import unquote

CURRENT_PATH = Path(__file__).parent
node_count = 0

def decode_vless(node: str) -> Dict:
    global node_count
    node_count += 1
    node = node.replace("vless://", "")
    uuid = node.split("@")[0]
    node = node.replace(f"{uuid}@", "")
    address = node.split(":")[0]
    node = node.replace(f"{address}:", "")
    port = node.split("?")[0]
    node = node.replace(f"{port}?", "")
    remarks = node.split("#")[-1]
    node = node.replace(f"#{remarks}", "")
    remarks = unquote(remarks).strip()
    param = node.split("&")
    param_dict = {}
    for item in param:
        key, value = item.split("=")
        param_dict[key] = value
    flow = param_dict.get("flow")
    security = param_dict.get("security")
    sni = param_dict.get("sni")
    fingerprint = param_dict.get("fp")
    type_ = param_dict.get("type")
    path = param_dict.get("path")
    if path:
        path = unquote(path)
    host = param_dict.get("host")
    result = {
        "type": "vless",
        "tag": f"{remarks}☯{node_count}",
        "server": address,
        "server_port": int(port),
        "uuid": uuid,
        "packet_encoding": "xudp",
        "tls": {
            "enabled": True,
            "server_name": sni,
            "insecure": False,
            "utls": {"enabled": True, "fingerprint": fingerprint},
        },
    }
    if security == "reality":
        public_key = param_dict.get("pbk")
        short_id = param_dict.get("sid")
        result["tls"]["reality"] = {
            "enabled": True,
            "public_key": public_key,
            "short_id": short_id,
        }
        result["flow"] = flow
    elif security == "tls":
        if type_ == "ws":
            result["transport"] = {
                "type": type_,
                "path": path,
                "headers": {"Host": host},
            }
        elif type_ == "tcp":
            result["flow"] = flow
    return result
def decode_vmess(node: str) -> Dict:
    global node_count
    node_count += 1
    node = node.replace("vmess://", "")
    node = base64.b64decode(node).decode()
    node: Dict = json.loads(node)
    remarks = node["ps"]
    server = node["add"]
    server_port = int(node["port"])
    uuid = node["id"]
    security = node["scy"]
    alter_id = int(node["aid"])
    type_ = node.get("type", "tcp")
    path = node.get("path", "")
    host = node.get("host", "")
    tls = node.get("tls", "none")
    result = {
        "type": "vmess",
        "tag": f"{remarks}☯{node_count}",
        "server": server,
        "server_port": server_port,
        "uuid": uuid,
        "security": security,
        "authenticated_length": True,
        "packet_encoding": "xudp",
        "transport": {
        "type": "ws",
        "path": path,
        "headers": {
          "Host": host
        },
        "early_data_header_name": "Sec-WebSocket-Protocol"
      }
    }
    if type_ == "ws":
        result["transport"] = {
            "type": type_,
            "path": path,
            "headers": {"Host": host},
        }
    elif type_ == "tcp":
        result["packet_encoding"] = "xudp"

    if tls == "tls":
        result["tls"] = {
            "enabled": True,
            "server_name": host,
            "insecure": False,
        }
    return result
def decode_ss(node: str) -> Dict:
    global node_count
    node_count += 1
    node = node.replace("ss://", "")
    remarks = node.split("#")[-1]
    node = node.replace(f"#{remarks}", "")
    remarks = unquote(remarks).strip()
    port = node.split(":")[-1]
    node = node.replace(f":{port}", "")
    address = node.split("@")[-1]
    node = node.replace(f"@{address}", "")
    node = base64.b64decode(node).decode()
    method, password = node.split(":")
    return {
        "type": "shadowsocks",
        "tag": f"{remarks}☯{node_count}",
        "server": address,
        "server_port": int(port),
        "method": method,
        "password": password,
    }
def decode_trojan(node: str) -> Dict:
    global node_count
    node_count += 1
    node = node.replace("trojan://", "")
    password = node.split("@")[0]
    node = node.replace(f"{password}@", "")
    address = node.split(":")[0]
    node = node.replace(f"{address}:", "")
    port = node.split("?")[0]
    node = node.replace(f"{port}?", "")
    remarks = node.split("#")[-1]
    node = node.replace(f"#{remarks}", "")
    remarks = unquote(remarks).strip()
    param = node.split("&")
    param_dict = {}
    for item in param:
        key, value = item.split("=")
        param_dict[key] = value
    sni = param_dict.get("sni")
    return {
        "type": "trojan",
        "tag": f"{remarks}☯{node_count}",
        "server": address,
        "server_port": int(port),
        "password": password,
        "tls": {
            "enabled": True,
            "server_name": sni,
            "insecure": False,
        },
    }
def decode_hysteria2(node: str) -> Dict:
    global node_count
    node_count += 1
    node = node.replace("hysteria2://", "")
    password = node.split("@")[0]
    node = node.replace(f"{password}@", "")
    remarks = unquote(node.split("#")[-1]).strip()
    node = node.replace(f"#{remarks}", "")
    host_port, para_dict = node.split("?")
    server, port = host_port.split(":")
    param_dict = {}
    for item in para_dict.split("&"):
        key, value = item.split("=")
        param_dict[key] = value
    sni = param_dict.get("sni")
    insecure = param_dict.get("insecure")
    return {
        "type": "hysteria2",
        "tag": f"{remarks}☯{node_count}",
        "server": server,
        "server_port": int(port),
        "password": password,
        "tls": {
            "enabled": True,
            "server_name": sni,
            "insecure": bool(insecure),
        },
    }
def read_node() -> List[Dict]:
    node_info: List[Dict] = []
    with open(CURRENT_PATH / "nodes.txt", "r", encoding="utf-8") as f:
        for item in f:
            if item.startswith("vless://"):
                node_info.append(decode_vless(item))
            elif item.startswith("vmess://"):
                node_info.append(decode_vmess(item))
            elif item.startswith("ss://"):
                node_info.append(decode_ss(item))
            elif item.startswith("trojan://"):
                node_info.append(decode_trojan(item))
            elif item.startswith("hysteria2://"):
                node_info.append(decode_hysteria2(item))
    return node_info
def set_node_name_list(node_info):
    node_name_list = []
    for item in node_info:
        if 'tag' in item and item['tag']:
            node_name_list.append(item['tag'])
        else:
            print(f"Warning: 'tag' key not found or item is empty: {item}")
    return node_name_list
if __name__ == "__main__":
    node_info = read_node()
    node_name_list = set_node_name_list(node_info)
    try:
        with open(CURRENT_PATH / "config.json", "r", encoding="utf-8") as f:
            config_content = f.read()
    except FileNotFoundError:
        print("config.json 文件未找到")
        config_content = ""
    node_name_list_str = json.dumps(node_name_list, ensure_ascii=False, indent=4)
    node_info_str = ",\n".join(json.dumps(item, ensure_ascii=False, indent=4) for item in node_info)
    config_content = config_content.replace('"outbounds": node_name_list', f'"outbounds": {node_name_list_str}')
    config_content = config_content.replace('node_info', node_info_str)

    with open(CURRENT_PATH / "tun.json", "w", encoding="utf-8") as f:
        f.write(config_content)
    print(
        f">>>>>>>>> 总共生成{len(node_info)}个节点，当前目录已新增配置文件./tun.json。>>>本次配置为tun模式<<<"
    )