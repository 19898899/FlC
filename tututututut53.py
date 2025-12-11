#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import binascii
import re
import time
import sys
import datetime
import random
import hashlib
import string
import base64
import os

# 导入外部函数
from 配 import generate_clash_config

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

# 调试选项
DEBUG_MODE = False
FIXED_DEVICE_INFO = {
    "imei": "861234567890123",
    "platform": "android",
    "version_number": 30,
    "models": "TEST_MODEL_1234567890",
    "sdk": "33",
    "m": "FIXED_M_12345678901234567890123456789012",
    "c": 85
}

# ========== 调试信息函数 ==========
def detect_environment():
    """检测当前运行环境"""
    is_github_actions = 'GITHUB_ACTIONS' in os.environ
    is_travis = 'TRAVIS' in os.environ
    is_azure = 'AZURE_WEBJOBS_SITE_NAME' in os.environ
    is_jenkins = 'JENKINS_URL' in os.environ
    
    env_name = '本地环境'
    if is_github_actions:
        env_name = 'GitHub Actions'
    elif is_travis:
        env_name = 'Travis CI'
    elif is_azure:
        env_name = 'Azure Pipelines'
    elif is_jenkins:
        env_name = 'Jenkins'
    
    return env_name

def debug_info():
    """输出详细调试信息"""
    # 检测运行环境
    env_name = detect_environment()
    
    # 基本信息
    info = {
        "环境名称": env_name,
        "Python版本": sys.version,
        "当前目录": os.getcwd(),
        "UTC时间": str(datetime.datetime.utcnow()),
        "本地时间": str(datetime.datetime.now()),
        "时区": str(datetime.datetime.now().astimezone().tzinfo),
        "调试模式": DEBUG_MODE,
        "FIXED_DEVICE_INFO": FIXED_DEVICE_INFO if DEBUG_MODE else "未启用"
    }
    
    # 网络信息
    try:
        import socket
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        info["主机名"] = hostname
        info["本地IP"] = local_ip
    except Exception as e:
        info["网络信息"] = f"获取失败: {e}"
    
    # 环境变量（相关的）
    env_vars = {}
    relevant_vars = [
        'GITHUB_ACTIONS', 'GITHUB_REPOSITORY', 'GITHUB_REF', 'GITHUB_SHA',
        'TRAVIS', 'AZURE_WEBJOBS_SITE_NAME', 'JENKINS_URL',
        'TZ', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY'
    ]
    for var in relevant_vars:
        if var in os.environ:
            env_vars[var] = os.environ[var]
    info["相关环境变量"] = env_vars
    
    print("=" * 70)
    print(f"🚀 当前运行环境: {env_name}")
    print("=" * 70)
    for key, value in info.items():
        if isinstance(value, dict):
            print(f"{key}:")
            for k, v in value.items():
                print(f"  {k}: {v}")
        else:
            print(f"{key}: {value}")
    print("=" * 70)

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
        second_encode = base64.b64encode(first_encode.encode()).decode().rstrip('=')
        params.append(f"protoparam={second_encode}")

        remarks = node.get('name', '').strip()
        if remarks:
            remarks_b64 = base64.b64encode(remarks.encode('utf-8')).decode().rstrip('=')
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
            "clash_url": "https://19898899.github.io/FlC/clash.yaml",
            "ssr_url": "https://19898899.github.io/FlC/subscription.txt"
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
        ssr_link = node_to_ssr_link(node)
        if ssr_link:
            ssr_links.append(ssr_link)
            if i < 3:  # 只打印前3个链接
                print(f"  ✓ 生成成功: {node.get('name', '未知')}")
        else:
            print(f"  ✗ 生成失败: {node.get('name', '未知')}")

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
    plaintext_bytes = plaintext.encode('utf-8') + bytes([padding_len] * padding_len)

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
    if DEBUG_MODE:
        return FIXED_DEVICE_INFO["imei"]
    
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
    if DEBUG_MODE:
        return f"FIXED_HEX_{length}"
    return ''.join(random.choice('0123456789abcdef') for _ in range(length))

def generate_device_info():
    """生成模拟的新设备请求数据"""
    if DEBUG_MODE:
        print("🔧 使用固定设备信息（调试模式）")
        return FIXED_DEVICE_INFO
    
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
    print(f"设备信息: IMEI={device_info['imei'][:10]}..., Platform={device_info['platform']}")

    request_json = json.dumps(device_info, separators=(',', ':'))
    encrypted_value = aes_ecb_encrypt(request_json, AES_KEY)
    if not encrypted_value:
        print("加密失败！")
        return None

    # 使用标准的URL编码
    current_time = time.strftime("%Y年%m月%d日%H:%M:%S", time.localtime())
    # 构建表单数据，使用urllib.parse.urlencode自动处理编码
    post_data = {
        "t": current_time,
        "value": encrypted_value
    }
    # 转换为URL编码的字符串
    import urllib.parse
    post_data = urllib.parse.urlencode(post_data)

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
                print(f"✅ 成功获取新Token: {new_token[:10]}...")
                return new_token
            else:
                return None
        except json.JSONDecodeError:
            return None

    except Exception as e:
        print(f"请求异常: {e}")
        import traceback
        traceback.print_exc()
        return None

def get_nodes_with_token(token):
    """第二步：使用Token获取节点列表"""
    if not token:
        return [], None

    print(f"\n🌐 步骤4: 使用Token获取节点列表...")
    print(f"使用的Token: {token[:20]}...")

    request_data = {"token": token, "platform": "android"}
    request_json = json.dumps(request_data, separators=(',', ':'))
    print(f"节点请求数据: {request_json}")
    encrypted_value = aes_ecb_encrypt(request_json, AES_KEY)
    if not encrypted_value:
        print("加密请求数据失败！")
        return [], None
    print(f"加密后的节点请求: {encrypted_value[:50]}...")

    url = "https://edgeapi.iosioapi.com/node/get_nodes"
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 13; 2312DRAABC Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/142.0.7444.102 Mobile Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "edgeapi.iosioapi.com",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }
    print(f"节点请求URL: {url}")
    print(f"节点请求头: User-Agent={headers['User-Agent'][:50]}...")
    
    # 使用标准的URL编码
    import urllib.parse
    post_data = {
        "value": encrypted_value
    }
    post_data_encoded = urllib.parse.urlencode(post_data)
    print(f"节点POST数据: {post_data_encoded[:100]}...")

    try:
        print("发送节点请求...")
        res = requests.post(url, headers=headers, data=post_data_encoded, timeout=15)
        print(f"节点响应状态码: {res.status_code}")
        print(f"节点响应头: {dict(res.headers)}")
        print(f"节点响应内容长度: {len(res.content)} 字节")
        
        if res.status_code != 200:
            print(f"获取节点失败，状态码: {res.status_code}")
            print(f"节点响应内容: {res.text[:200]}...")
            return [], None

        try:
            response_json = res.json()
            print(f"节点响应JSON: {json.dumps(response_json, ensure_ascii=False)[:200]}...")
        except json.JSONDecodeError:
            print(f"节点响应不是JSON格式: {res.text[:200]}...")
            return [], None

        if 'data' not in response_json:
            print(f"节点响应中没有data字段: {list(response_json.keys())}")
            print(f"节点响应完整内容: {json.dumps(response_json, ensure_ascii=False)}")
            return [], None

        encrypted_nodes = response_json['data']
        print(f"加密节点数据: {encrypted_nodes[:50]}...")
        decrypted_nodes = aes_ecb_decrypt(encrypted_nodes, AES_KEY)
        if not decrypted_nodes:
            print("解密节点数据失败！")
            return [], None
        print(f"解密后节点数据长度: {len(decrypted_nodes)} 字符")
        print(f"解密后节点数据前200字符: {decrypted_nodes[:200]}...")

        try:
            nodes_data = json.loads(decrypted_nodes)
            print(f"解析后的节点数据结构: {list(nodes_data.keys())}")
            if 'goserverlist' in nodes_data:
                print(f"获取到的节点数量: {len(nodes_data['goserverlist'])}")
                # 打印前3个节点的信息
                print("前3个节点信息:")
                for i, node in enumerate(nodes_data['goserverlist'][:3]):
                    print(f"  节点{i+1}: {node.get('name', '未知')} - {node.get('host', '未知')}:{node.get('remotePort', '未知')}")
            return nodes_data, None

        except json.JSONDecodeError as e:
            print(f"解析节点数据失败: {e}")
            print(f"解密后数据: {decrypted_nodes}")
            return [], None

    except Exception as e:
        print(f"获取节点异常: {e}")
        import traceback
        traceback.print_exc()
        return [], None

def main():
    if not PY_CRYPTO_AVAILABLE:
        return

    debug_info()
    print("=" * 60)
    print("🚀 SSR节点获取工具 (flclash专用)")
    print(f"当前时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # 第一步：获取新Token
    new_token = get_new_token()
    if not new_token:
        print("❌ 获取Token失败")
        return
    print(f"✅ Token: {new_token[:10]}...")

    # 第二步：获取节点列表
    print("\n🌐 正在获取节点列表...")
    nodes_data, _ = get_nodes_with_token(new_token)
    if not nodes_data:
        print("❌ 未能获取到节点数据")
        return
    if 'goserverlist' not in nodes_data:
        print(f"❌ 节点数据结构错误: {list(nodes_data.keys())}")
        return
    print(f"✅ 成功获取节点数据，包含{len(nodes_data['goserverlist'])}个节点")
    
    # 打印节点信息，方便调试
    print("\n🔍 节点信息（前3个）：")
    for i, node in enumerate(nodes_data['goserverlist'][:3]):
        print(f"节点{i+1}: {node.get('name', '未知')} - {node.get('host', '未知')}:{node.get('remotePort', '未知')}")

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

    # 第三步：保存配置文件
    print("\n💾 正在保存配置文件...")
    clash_file, save_dir = save_all_files([], nodes_data, new_token)

    if not save_dir:
        print("❌ 配置文件保存失败")
        return

    # 验证文件是否存在且有内容
    if os.path.exists(clash_file):
        file_size = os.path.getsize(clash_file)
        print(f"✅ 配置文件保存成功: {clash_file}")
        print(f"📏 文件大小: {file_size} 字节")
    
    # 检查docs目录内容
    if os.path.exists("docs"):
        docs_files = os.listdir("docs")
        print(f"📁 docs目录包含文件: {docs_files}")

    print(f"\n✅ 完成！配置文件已保存到: {clash_file}")
    print(f"🔗 Clash订阅链接: https://19898899.github.io/FlC/clash.yaml")
    print(f"🔗 SSR订阅链接: https://19898899.github.io/FlC/subscription.txt")
    print("📱 flclash中: 导入配置 → 选择此文件")

if __name__ == "__main__":
    # 运行前请确保已安装: pip install requests pyaes pyyaml
    main()
