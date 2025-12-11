

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from 配 import generate_clash_config
import requests
import json
import binascii
import re
import time
import random
import sys
import datetime
import hashlib
import string
import base64
import os
def debug_info():
    """输出调试信息"""
    info = {
        "python_version": sys.version,
        "current_directory": os.getcwd(),
        "utc_time": str(datetime.datetime.utcnow()),
        "local_time": str(datetime.datetime.now()),
        "timezone": str(datetime.datetime.now().astimezone().tzinfo),
        "environment_variables": {k: v for k, v in os.environ.items() if "PYTHON" in k or "PATH" in k}
    }
    
    print("=== 调试信息 ===")
    print(json.dumps(info, indent=2, ensure_ascii=False))
    print("================")
    
# 安装命令：pip install pyaes pyyaml
try:
    import pyaes
    PY_CRYPTO_AVAILABLE = True
except ImportError:
    print("错误：请先安装 pyaes 库，命令：pip install pyaes")
    PY_CRYPTO_AVAILABLE = False
    pyaes = None

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    print("警告：未安装 pyyaml 库，Clash配置文件将无法生成")
    print("安装命令：pip install pyyaml")
    YAML_AVAILABLE = False

# 核心密钥
AES_KEY = "UDRnpNG4zVafoPDyKirGyqnq0gP4wlnS"

# ========== SSR链接生成函数 ==========


def node_to_ssr_link(node):
    """将单个节点转换为完整的SSR链接"""
    try:
        # 提取必需字段
        host = node.get('host', '').strip()
        port = str(node.get('remotePort', '')).strip()
        protocol = node.get('protocol', 'auth_chain_a').strip()
        method = node.get('method', 'chacha20').strip()
        obfs = node.get('obfs', 'tls1.2_ticket_auth').strip()
        password = node.get('password', '').strip()

        if not all([host, port, password]):
            return None

        # 密码Base64编码
        password_b64 = base64.b64encode(password.encode()).decode()

        # 构建基础配置
        base_config = f"{host}:{port}:{protocol}:{method}:{obfs}:{password_b64}"

        # 构建参数部分
        params = []
        params.append(f"obfsparam=")

        protocol_param = node.get('protocol_param', '').strip()
        if not protocol_param:
            protocol_param = "75022808:M0ngIu"

        first_encode = base64.b64encode(protocol_param.encode()).decode()
        second_encode = base64.b64encode(
            first_encode.encode()).decode().rstrip('=')
        params.append(f"protoparam={second_encode}")

        remarks = node.get('name', '').strip()
        if remarks:
            remarks_b64 = base64.b64encode(
                remarks.encode('utf-8')).decode().rstrip('=')
            params.append(f"remarks={remarks_b64}")
        else:
            params.append(f"remarks=")

        group = node.get('url_group', '无描述').strip()
        if group:
            group_b64 = base64.b64encode(group.encode('utf-8')).decode()
            params.append(f"group={group_b64}")
        else:
            params.append(f"group=")

        full_config = f"{base_config}/?{'&'.join(params)}"
        ssr_link = f"ssr://{base64.b64encode(full_config.encode()).decode()}"

        return ssr_link

    except Exception as e:
        print(f"转换节点失败: {e}")
        return None


# ========== 文件保存路径配置 ==========
def get_save_directory():
    """获取保存目录（优先使用Download文件夹）"""
    possible_paths = [
        "/storage/emulated/0/Download",
        "/sdcard/Download",
        "/storage/self/primary/Download",
    ]

    for path in possible_paths:
        if os.path.exists(path):
            return path

    current_dir = os.getcwd()
    print(f"未找到Download文件夹，将使用当前目录: {current_dir}")
    return current_dir


def save_all_files(ssr_links, nodes_data, token):
    """保存文件到GitHub Pages目录"""
    try:
        # 创建docs目录用于GitHub Pages
        docs_dir = "docs"
        if not os.path.exists(docs_dir):
            os.makedirs(docs_dir)

        # 保存Clash配置文件
        clash_file = os.path.join(docs_dir, "clash.yaml")
        print(f"\n📁 保存到: {clash_file}")

        clash_config_content = generate_clash_config(nodes_data, token)
        if clash_config_content:
            with open(clash_file, 'w', encoding='utf-8') as f:
                f.write(clash_config_content)
            print(f"✅ clash.yaml - 已保存到docs目录")
        else:
            print(f"❌ 未能生成Clash配置文件")
            return None, None

        # 生成SSR订阅链接
        ssr_links = generate_ssr_links_from_nodes(nodes_data)
        if ssr_links:
            ssr_file = os.path.join(docs_dir, "subscription.txt")
            with open(ssr_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(ssr_links))
            print(f"✅ subscription.txt - 已保存到docs目录")

        # 生成订阅信息
        info_file = os.path.join(docs_dir, "info.json")
        info = {
            "update_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_nodes": len(ssr_links),
            "clash_url": "https://[GITHUB_USERNAME].github.io/[REPO_NAME]/clash.yaml",
            "ssr_url": "https://[GITHUB_USERNAME].github.io/[REPO_NAME]/subscription.txt"
        }
        with open(info_file, 'w', encoding='utf-8') as f:
            json.dump(info, f, ensure_ascii=False, indent=2)
        print(f"✅ info.json - 已保存到docs目录")

        return clash_file, docs_dir

    except Exception as e:
        print(f"保存文件时出错: {e}")
        import traceback
        traceback.print_exc()

    return None, None


def generate_ssr_links_from_nodes(nodes_data):
    """从节点数据生成SSR链接列表"""
    ssr_links = []

    if 'goserverlist' not in nodes_data:
        print("错误：节点数据中没有找到goserverlist")
        return ssr_links

    print(f"\n🔧 正在生成SSR链接...")
    for i, node in enumerate(nodes_data['goserverlist']):

        # 检查是否包含vip（不区分大小写）

        ssr_link = node_to_ssr_link(node)
        if ssr_link:
            ssr_links.append(ssr_link)
            print(f"  ✓ 生成成功")
        else:
            print(f"  ✗ 生成失败")

    return ssr_links

# ========== 加密/解密核心函数 ==========


def pkcs7_unpad(data):
    """去除PKCS7填充"""
    if not data:
        return data
    padding_len = data[-1]
    if padding_len < 1 or padding_len > len(data):
        return data
    if data[-padding_len:] == bytes([padding_len]) * padding_len:
        return data[:-padding_len]
    return data


def aes_ecb_decrypt(encrypted_hex, key_str):
    """AES-ECB解密"""
    if not PY_CRYPTO_AVAILABLE:
        return None

    hex_clean = re.sub(r'[^0-9a-fA-F]', '', encrypted_hex)
    if not hex_clean:
        return None

    try:
        encrypted_bytes = binascii.unhexlify(hex_clean)
    except:
        return None

    key = key_str.encode('utf-8')
    try:
        aes = pyaes.AESModeOfOperationECB(key)
    except:
        return None

    decrypted_bytes = bytearray()
    for i in range(0, len(encrypted_bytes), 16):
        block = encrypted_bytes[i:i+16]
        if len(block) < 16:
            block = block.ljust(16, b'\x00')
        decrypted_block = aes.decrypt(block)
        decrypted_bytes.extend(decrypted_block)

    decrypted_bytes = pkcs7_unpad(bytes(decrypted_bytes))
    try:
        return decrypted_bytes.decode('utf-8')
    except:
        return None


def aes_ecb_encrypt(plaintext, key_str):
    """AES-ECB加密"""
    if not PY_CRYPTO_AVAILABLE:
        return None

    key = key_str.encode('utf-8')
    block_size = 16
    padding_len = block_size - (len(plaintext) % block_size)
    plaintext_bytes = plaintext.encode(
        'utf-8') + bytes([padding_len] * padding_len)

    try:
        aes = pyaes.AESModeOfOperationECB(key)
    except:
        return None

    encrypted_bytes = bytearray()
    for i in range(0, len(plaintext_bytes), 16):
        block = plaintext_bytes[i:i+16]
        encrypted_block = aes.encrypt(block)
        encrypted_bytes.extend(encrypted_block)

    return binascii.hexlify(bytes(encrypted_bytes)).decode('utf-8').upper()

# ========== 模拟新设备信息生成函数 ==========


def generate_random_imei():
    """生成随机IMEI（15位数字）"""
    imei_base = ''.join([str(random.randint(0, 9)) for _ in range(14)])
    total = 0
    for i, digit in enumerate(imei_base):
        n = int(digit)
        if (i + 1) % 2 == 0:
            n *= 2
            total += n - 9 if n > 9 else n
        else:
            total += n
    check_digit = (10 - (total % 10)) % 10
    return imei_base + str(check_digit)


def generate_random_hex(length):
    """生成指定长度的随机十六进制字符串"""
    return ''.join(random.choice('0123456789abcdef') for _ in range(length))


def generate_device_info():
    """生成模拟的新设备请求数据"""
    random_m = generate_random_hex(32).upper()

    device_info = {
        "imei": generate_random_imei(),
        "platform": "android",
        "version_number": 30,
        "models": generate_random_hex(20).upper(),
        "sdk": "33",
        "m": random_m,
        "c": random.randint(80, 99)
    }
    return device_info

# ========== 主流程函数 ==========


def get_new_token():
    """第一步：获取新Token"""
    print("🔧 步骤1: 生成模拟新设备信息...")
    device_info = generate_device_info()

    request_json = json.dumps(device_info, separators=(',', ':'))
    encrypted_value = aes_ecb_encrypt(request_json, AES_KEY)
    if not encrypted_value:
        print("加密失败！")
        return None

    current_time = time.strftime("%Y年%m月%d日%H:%M:%S", time.localtime()).replace(
        "年", "%E5%B9%B4").replace("月", "%E6%9C%88").replace("日", "%E6%97%A5")
    post_data = f"t={current_time}&value={encrypted_value}"

    url = "https://edgeapi.iosioapi.com/node/getInformation_ex"
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 13; 2312DRAABC Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/142.0.7444.102 Mobile Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "edgeapi.iosioapi.com",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }

    print("📡 步骤2: 发送获取Token的请求...")
    try:
        res = requests.post(url, headers=headers, data=post_data, timeout=15)
        if res.status_code != 200:
            print(f"请求失败，状态码: {res.status_code}")
            return None

        response_json = res.json()
        if 'data' not in response_json:
            return None

        encrypted_response = response_json['data']
        decrypted_response = aes_ecb_decrypt(encrypted_response, AES_KEY)
        if not decrypted_response:
            print("解密响应失败！")
            return None

        print("🔑 步骤3: 解析Token...")
        try:
            token_data = json.loads(decrypted_response)
            if 'rUser' in token_data and 'token' in token_data['rUser']:
                new_token = token_data['rUser']['token']
                print(f"✅ 成功获取新Token: {new_token}")
                return new_token
            else:
                return None
        except json.JSONDecodeError:
            return None

    except Exception as e:
        print(f"请求异常: {e}")
        return None


def get_nodes_with_token(token):
    """第二步：使用Token获取节点列表"""
    if not token:
        return [], None

    print(f"\n🌐 步骤4: 使用Token获取节点列表...")

    request_data = {"token": token, "platform": "android"}
    request_json = json.dumps(request_data, separators=(',', ':'))
    encrypted_value = aes_ecb_encrypt(request_json, AES_KEY)

    if not encrypted_value:
        print("加密请求数据失败！")
        return [], None

    url = "https://edgeapi.iosioapi.com/node/get_nodes"
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 13; 2312DRAABC Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/142.0.7444.102 Mobile Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "edgeapi.iosioapi.com"
    }
    post_data = f"value={encrypted_value}"

    try:
        res = requests.post(url, headers=headers, data=post_data, timeout=15)
        if res.status_code != 200:
            return [], None

        response_json = res.json()
        if 'data' not in response_json:
            return [], None

        encrypted_nodes = response_json['data']
        decrypted_nodes = aes_ecb_decrypt(encrypted_nodes, AES_KEY)
        if not decrypted_nodes:
            return [], None

        try:
            nodes_data = json.loads(decrypted_nodes)
            return nodes_data, None

        except json.JSONDecodeError:
            return [], None

    except Exception as e:
        print(f"获取节点异常: {e}")
        return [], None


def main():
    if not PY_CRYPTO_AVAILABLE:
        return

    print("=" * 60)
    print("🚀 SSR节点获取工具 (flclash专用)")
    print("=" * 60)

    # 第一步：获取新Token
    new_token = get_new_token()
    if not new_token:
        print("❌ 获取Token失败")
        return

    # 第二步：获取节点列表
    nodes_data, _ = get_nodes_with_token(new_token)
    if not nodes_data or 'goserverlist' not in nodes_data:
        print("❌ 未能获取到节点数据")
        return

    # 🔥 在这里一次性过滤VIP节点
    print("\n🔍 过滤VIP节点...")
    original_nodes = nodes_data['goserverlist'].copy()
    nodes_data['goserverlist'] = [
        node for node in original_nodes
        if 'vip' not in node.get('name', '').lower()
    ]

    total_nodes = len(original_nodes)
    filtered_nodes = len(nodes_data['goserverlist'])
    vip_nodes = total_nodes - filtered_nodes

    print(f"📊 过滤结果: 原始{total_nodes}个, VIP{vip_nodes}个, 可用{filtered_nodes}个")

    if filtered_nodes == 0:
        print("❌ 没有可用的普通节点")
        return

    # 第三步：保存Clash配置文件
    # 不需要ssr_links了
    clash_file, save_dir = save_all_files([], nodes_data, new_token)

    if not save_dir:
        print("❌ 配置文件保存失败")
        return

    print(f"\n✅ 完成！配置文件: {clash_file}")
    print("📱 flclash中: 导入配置 → 选择此文件")


if __name__ == "__main__":
    # 运行前请确保已安装: pip install requests pyaes pyyaml
    debug_info()

    main()
