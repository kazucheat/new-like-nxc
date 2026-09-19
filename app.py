from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
import time
import re
from collections import defaultdict
from datetime import datetime
import random
import os
import urllib.parse

import jwt
from datetime import timedelta

TOKEN_CACHE = {}

app = Flask(__name__)

KEY_LIMIT = 999
tracker = defaultdict(lambda: [0, time.time()])
liked_cache = defaultdict(set)

# ─────────────────────────────────────────────────────────────
# GARENA OFFICIAL ENDPOINTS (no third-party)
# ─────────────────────────────────────────────────────────────
GARENA_CLIENT_ID     = "100067"
GARENA_CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"

# OAuth endpoints — try in order until one succeeds
OAUTH_ENDPOINTS = [
    "https://ffmconnect.live.gop.garenanow.com/api/v2/oauth/guest/token:grant",
    "https://100067.connect.garena.com/oauth/guest/token/grant",
]

# MajorLogin hosts — primary + fallback
MAJOR_LOGIN_HOSTS = [
    "https://loginbp.ppmainecoonghj.com",
    "https://loginbp.ggblueshark.com",
]

_JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")


# ── protobuf wire helpers ────────────────────────────────────
def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _tag(field: int, wire: int) -> bytes:
    return _varint((field << 3) | wire)


def _pb_varint(field: int, value: int) -> bytes:
    return _tag(field, 0) + _varint(value)


def _pb_string(field: int, value) -> bytes:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return _tag(field, 2) + _varint(len(data)) + data


def _build_major_login_body(open_id: str, access_token: str) -> bytes:
    # MajorLoginReq: event_time=1, open_id=2, login_platform=3(=guest), access_token=4
    return (
        _pb_varint(1, int(time.time()))
        + _pb_string(2, open_id)
        + _pb_varint(3, 3)
        + _pb_string(4, access_token)
    )


# ── STEP 1: OAuth password grant (tries each endpoint) ──────
async def get_garena_access_token(uid, password, session):
    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P4(G0000 ;Android 9; en; US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    data = {
        "client_id": GARENA_CLIENT_ID,
        "client_secret": GARENA_CLIENT_SECRET,
        "grant_type": "password",
        "username": uid,
        "password": password,
    }

    for url in OAUTH_ENDPOINTS:
        try:
            async with session.post(url, data=data, headers=headers, timeout=15) as r:
                raw = await r.text()
                print(f"[OAUTH] {url} → {r.status}")
                if r.status != 200:
                    print(f"[OAUTH] body: {raw[:200]}")
                    continue
                try:
                    j = json.loads(raw)
                except Exception:
                    print(f"[OAUTH] non-JSON: {raw[:200]}")
                    continue
                if isinstance(j, dict) and "data" in j and isinstance(j["data"], dict):
                    j = j["data"]
                at = j.get("access_token")
                oid = j.get("open_id") or j.get("openid")
                if at and oid:
                    print(f"[OAUTH] ok via {url}")
                    return at, str(oid)
                print(f"[OAUTH] missing fields: {raw[:200]}")
        except Exception as e:
            print(f"[OAUTH] {url} exception: {e}")
            continue

    return None, None


# ── STEP 2: MajorLogin → JWT (tries each host) ───────────────
async def major_login(access_token, open_id, session):
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/octet-stream",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB55",
    }
    body = _build_major_login_body(open_id, access_token)

    for host in MAJOR_LOGIN_HOSTS:
        url = f"{host}/MajorLogin"
        try:
            async with session.post(url, data=body, headers=headers, timeout=15) as r:
                raw = await r.read()
                print(f"[MAJORLOGIN] {host} status={r.status} len={len(raw)}")
                if r.status != 200:
                    continue
                m = _JWT_RE.search(raw)
                if m:
                    print(f"[MAJORLOGIN] JWT found via {host}")
                    return m.group(0).decode("utf-8")
                try:
                    j = json.loads(raw)
                    if isinstance(j, dict):
                        for k in ("token", "jwt", "jwt_token", "access_token"):
                            v = j.get(k)
                            if isinstance(v, str) and v.startswith("eyJ"):
                                print(f"[MAJORLOGIN] JWT found in JSON via {host}")
                                return v
                except Exception:
                    pass
                print(f"[MAJORLOGIN] no JWT from {host} :: head={raw[:120]}")
        except Exception as e:
            print(f"[MAJORLOGIN] {host} exception: {e}")
            continue
    return None


# ── Public entry ─────────────────────────────────────────────
async def generate_jwt_token(uid, password):
    try:
        async with aiohttp.ClientSession() as session:
            at, oid = await get_garena_access_token(uid, password, session)
            if not at:
                return None
            return await major_login(at, oid, session)
    except Exception as e:
        print(f"[TokenGen] {uid}: {e}")
        return None


async def get_valid_token(uid, password):
    if uid in TOKEN_CACHE:
        cached = TOKEN_CACHE[uid]
        remaining = (cached["expires_at"] - datetime.utcnow()).total_seconds()
        if remaining > 1800:
            return cached["token"]

    token = await generate_jwt_token(uid, password)
    if not token:
        return None

    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        exp = payload.get("exp")
        TOKEN_CACHE[uid] = {
            "token": token,
            "expires_at": datetime.utcfromtimestamp(exp)
        }
    except:
        TOKEN_CACHE[uid] = {
            "token": token,
            "expires_at": datetime.utcnow() + timedelta(hours=24)
        }
    return token


# ── helpers ──────────────────────────────────────────────────
def get_today_midnight_timestamp():
    now = datetime.now()
    midnight = datetime(now.year, now.month, now.day)
    return midnight.timestamp()


def load_accounts(server_name):
    try:
        if server_name == "IND":
            filename = "account_ind.txt"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            filename = "account_br.txt"
        else:
            filename = "account_bd.txt"

        if not os.path.exists(filename):
            print(f"⚠️ {filename} not found, trying account_ind.txt")
            filename = "account_ind.txt"
            if not os.path.exists(filename):
                print("❌ No account file found")
                return []

        accounts = []
        print(f"📂 Loading from: {filename} for server {server_name}")

        with open(filename, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if ':' in line:
                    parts = line.split(':', 1)
                    uid, pw = parts[0].strip(), parts[1].strip()
                    if uid and pw:
                        accounts.append({"uid": uid, "password": pw})

        print(f"✅ Total {len(accounts)} accounts loaded for {server_name}")
        return accounts
    except Exception as e:
        print(f"❌ load_accounts: {e}")
        return []


def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext, AES.block_size)
    return binascii.hexlify(cipher.encrypt(padded)).decode('utf-8')


def create_protobuf_message(user_id, region):
    m = like_pb2.like()
    m.uid = int(user_id)
    m.region = region
    return m.SerializeToString()


async def send_like(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB55"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers, timeout=5) as r:
                return r.status
    except:
        return 500


async def process_account(target_uid, encrypted_uid, account, url, semaphore, server_name):
    async with semaphore:
        token = await get_valid_token(account['uid'], account['password'])
        if not token:
            return 500, account['uid']
        status = await send_like(encrypted_uid, token, url)
        if status == 200:
            liked_cache[target_uid].add(account['uid'])
        return status, account['uid']


async def send_all_likes(target_uid, server_name, url):
    protobuf_message = create_protobuf_message(target_uid, server_name)
    encrypted_uid = encrypt_message(protobuf_message)

    accounts = load_accounts(server_name)
    if not accounts:
        return {'success': 0, 'failed': 0, 'total': 0, 'already_liked': 0}

    already_liked = liked_cache.get(target_uid, set())
    fresh = [a for a in accounts if a['uid'] not in already_liked]
    print(f"📊 total={len(accounts)} fresh={len(fresh)} already={len(already_liked)}")

    if not fresh:
        return {'success': 0, 'failed': 0, 'total': len(accounts),
                'already_liked': len(already_liked), 'fresh_used': 0}

    random.shuffle(fresh)
    sem = asyncio.Semaphore(25)
    tasks = [process_account(target_uid, encrypted_uid, a, url, sem, server_name)
             for a in fresh[:2000]]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    ok = sum(1 for r in results if isinstance(r, tuple) and r[0] == 200)
    bad = sum(1 for r in results if isinstance(r, tuple) and r[0] != 200)

    return {'success': ok, 'failed': bad, 'total': len(accounts),
            'already_liked': len(already_liked), 'fresh_used': len(fresh[:2000])}


def enc(uid):
    m = uid_generator_pb2.uid_generator()
    m.krishna_ = int(uid)
    m.teamXdarks = 1
    return encrypt_message(m.SerializeToString())


def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except:
        return None


def get_player_info(encrypted_uid, server_name, token):
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ppmainecoonghj.com/GetPlayerPersonalShow"

    edata = bytes.fromhex(encrypted_uid)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB55"
    }
    try:
        r = requests.post(url, data=edata, headers=headers, verify=False, timeout=10)
        return decode_protobuf(r.content)
    except:
        return None


# ── routes ───────────────────────────────────────────────────
@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    key = request.args.get("key")
    client_ip = request.remote_addr

    if key != "NXC":
        return jsonify({"error": "Invalid or missing API key 🔑"}), 403
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    valid_servers = ["IND", "BR", "US", "SAC", "NA", "BD", "RU"]
    if server_name not in valid_servers:
        return jsonify({"error": f"Invalid server. Use: {valid_servers}"}), 400

    accounts = load_accounts(server_name) or load_accounts("IND")
    if not accounts:
        return jsonify({"error": f"No accounts for {server_name}"}), 500

    today_midnight = get_today_midnight_timestamp()
    count, last_reset = tracker[client_ip]
    if last_reset < today_midnight:
        tracker[client_ip] = [0, time.time()]
        count = 0
    if count >= KEY_LIMIT:
        return jsonify({"error": "Daily limit reached", "remains": f"(0/{KEY_LIMIT})"}), 429

    check_token = None
    for acc in accounts[:5]:
        check_token = asyncio.run(get_valid_token(acc['uid'], acc['password']))
        if check_token:
            print(f"✅ check token via {acc['uid']}")
            break
    if not check_token:
        return jsonify({"error": "Token generation failed"}), 500

    encrypted_uid = enc(uid)
    before = get_player_info(encrypted_uid, server_name, check_token)
    if before is None:
        return jsonify({"error": "Invalid UID or server", "status": 0}), 200

    try:
        before_data = json.loads(MessageToJson(before))
        before_like = int(before_data['AccountInfo'].get('Likes', 0))
    except:
        return jsonify({"error": "Data parsing failed", "status": 0}), 200

    if server_name == "IND":
        like_url = "https://client.ind.freefiremobile.com/LikeProfile"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        like_url = "https://client.us.freefiremobile.com/LikeProfile"
    else:
        like_url = "https://clientbp.ppmainecoonghj.com/LikeProfile"

    asyncio.run(send_all_likes(uid, server_name, like_url))

    after = get_player_info(encrypted_uid, server_name, check_token)
    if after is None:
        return jsonify({"error": "Verify failed", "status": 0}), 200

    try:
        after_data = json.loads(MessageToJson(after))
        after_like = int(after_data['AccountInfo']['Likes'])
        player_id = int(after_data['AccountInfo']['UID'])
        player_name = str(after_data['AccountInfo']['PlayerNickname'])
        like_given = after_like - before_like
        status = 1 if like_given != 0 else 2
        if like_given > 0:
            tracker[client_ip][0] += 1
            count += 1
        remains = KEY_LIMIT - count
        return jsonify({
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "PlayerNickname": player_name,
            "UID": player_id,
            "status": status,
            "remains": f"({remains}/{KEY_LIMIT})",
        })
    except Exception as e:
        return jsonify({"error": str(e), "status": 0}), 500


@app.route('/reset-cache', methods=['GET'])
def reset_cache():
    if request.args.get("key") != "JMLB":
        return jsonify({"error": "Invalid key"}), 403
    liked_cache.clear()
    return jsonify({"message": "Cache cleared", "credit": "@kuchupuchu04"})


if __name__ == '__main__':
    print("🚀 Official Garena Token API — Smart Like System")
    print("📁 Account files: account_ind.txt, account_br.txt, account_bd.txt")
    app.run(host='0.0.0.0', port=5003, debug=True, use_reloader=False)
