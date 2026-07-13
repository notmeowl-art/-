"""
SleepyXgift — Flask port of the Free Fire gift sender.
Hand-rolled protobuf + AES-CBC (PKCS7) so this runs anywhere Python runs.
Host on Render / Replit / Railway / PythonAnywhere / Fly.io — zero config.
"""
from flask import Flask, render_template, request, jsonify, Response
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64, json, time, struct, threading, os
import urllib.request, urllib.error

app = Flask(__name__, static_folder="static", template_folder="templates")

# ---------- Garena constants (do NOT change) ----------
KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
IV  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
USER_AGENT = "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)"
RELEASE_VERSION = "OB54"

PREFIX_MAP = {
    "902":"Avatar","214":"Facepaint","101":"Female Skills","102":"Male Skills",
    "103":"Microchip","905":"Parachute","710":"Bundle","720":"Bundle2",
    "203":"Top","204":"Bottom","205":"Shoes","211":"Head","901":"Banner",
    "131":"Pet2","130":"Pets/Emotes","903":"Loot Box","904":"Backpack",
    "906":"Skyboard","907":"Others","908":"Vehicles","909":"Emote",
    "911":"SkyWings","922":"Skill Skin",
}

def server_url(region: str) -> str:
    if region == "IND": return "https://client.ind.freefiremobile.com"
    if region in ("BR","US","SAC","NA"): return "https://client.us.freefiremobile.com"
    return "https://clientbp.ggpolarbear.com"

# ---------- JWT ----------
def decode_jwt(token: str):
    try:
        parts = token.split(".")
        if len(parts) < 2: return None, None
        p = parts[1].replace("-","+").replace("_","/")
        p += "=" * ((4 - len(p) % 4) % 4)
        data = json.loads(base64.b64decode(p))
        return data.get("lock_region"), data.get("external_id")
    except Exception:
        return None, None

# ---------- protobuf wire format (varint + length-delimited) ----------
def _enc_varint(n: int, out: bytearray):
    if n < 0: n = (1 << 64) + n
    while n >= 0x80:
        out.append((n & 0x7f) | 0x80); n >>= 7
    out.append(n & 0x7f)

def _enc_tag(field, wire, out): _enc_varint((field << 3) | wire, out)

def enc_varint_field(field, value, out):
    _enc_tag(field, 0, out); _enc_varint(int(value), out)

def enc_string_field(field, value, out):
    b = value.encode("utf-8")
    _enc_tag(field, 2, out); _enc_varint(len(b), out); out.extend(b)

def enc_bool_field(field, value, out):
    enc_varint_field(field, 1 if value else 0, out)

def iter_fields(buf: bytes):
    i, n = 0, len(buf)
    while i < n:
        shift, val = 0, 0
        while True:
            b = buf[i]; i += 1
            val |= (b & 0x7f) << shift
            if (b & 0x80) == 0: break
            shift += 7
        tag, wire = val >> 3, val & 7
        if wire == 0:
            shift, v = 0, 0
            while True:
                b = buf[i]; i += 1
                v |= (b & 0x7f) << shift
                if (b & 0x80) == 0: break
                shift += 7
            yield tag, wire, v, None
        elif wire == 2:
            shift, l = 0, 0
            while True:
                b = buf[i]; i += 1
                l |= (b & 0x7f) << shift
                if (b & 0x80) == 0: break
                shift += 7
            yield tag, wire, None, buf[i:i+l]; i += l
        elif wire == 1: i += 8
        elif wire == 5: i += 4
        else: raise ValueError(f"wire {wire}")

def as_int64(v: int) -> int:
    return v - (1 << 64) if v >= (1 << 63) else v

# ---------- encoders ----------
def encode_get_wallet_req(login_token: str) -> bytes:
    out = bytearray()
    enc_string_field(1, login_token, out)
    enc_bool_field(2, False, out)
    return bytes(out)

def encode_get_store_req() -> bytes:
    out = bytearray(); enc_varint_field(1, 1, out); return bytes(out)

def encode_send_gift_req(receiver_uid, commodity_id, message, currency_type, unit_price) -> bytes:
    out = bytearray()
    enc_varint_field(1, receiver_uid, out)
    enc_varint_field(2, 1, out)
    enc_varint_field(3, commodity_id, out)
    enc_string_field(4, message, out)
    enc_varint_field(5, currency_type, out)
    enc_varint_field(7, 1, out)
    enc_varint_field(11, unit_price, out)
    return bytes(out)

# ---------- decoders ----------
def decode_wallet(buf: bytes):
    coins, gems, last = 0, 0, 0
    for tag, wire, v, _ in iter_fields(buf):
        if wire != 0: continue
        if tag == 1: coins = v
        elif tag == 2: gems = as_int64(v)
        elif tag == 5: last = as_int64(v)
    ts = int(last)
    last_str = time.strftime("%d %b %Y, %I:%M %p", time.localtime(ts)) if ts > 0 else "Never"
    return {"gold": coins, "diamond": gems, "last_topup": last_str}

def decode_wallet_res(buf: bytes):
    for tag, wire, _, b in iter_fields(buf):
        if tag == 2 and wire == 2: return decode_wallet(b)
    return {"gold": 0, "diamond": 0, "last_topup": "Never"}

def decode_gift_item(buf: bytes):
    commodity_id=sort_id=item_id=coins=gems=0; expire=0
    for tag, wire, v, _ in iter_fields(buf):
        if wire != 0: continue
        if   tag == 1: commodity_id = v
        elif tag == 2: sort_id = v
        elif tag == 3: item_id = v
        elif tag == 4: coins = v
        elif tag == 5: gems = v
        elif tag == 14: expire = as_int64(v)
    id_str = str(item_id)
    category = PREFIX_MAP.get(id_str[:3], f"Other ({id_str[:3]})")
    if gems > 0 and coins > 0:
        price_str, pure_price, currency = f"💎 {gems} / 🪙 {coins}", gems, "diamond"
    elif gems > 0:
        price_str, pure_price, currency = f"💎 {gems}", gems, "diamond"
    elif coins > 0:
        price_str, pure_price, currency = f"🪙 {coins}", coins, "gold"
    else:
        price_str, pure_price, currency = "Free", 0, "free"
    expire_date = time.strftime("%d %b %Y", time.localtime(expire)) if expire > 0 else "Permanent"
    return {"item_id": id_str, "commodity_id": commodity_id, "sort_id": sort_id,
            "category": category, "price_str": price_str, "pure_price": pure_price,
            "currency": currency, "expire_date": expire_date}

def decode_store_res(buf: bytes):
    items, sent_today = [], 0
    for tag, wire, v, b in iter_fields(buf):
        if tag == 2 and wire == 2: items.append(decode_gift_item(b))
        elif tag == 3 and wire == 0: sent_today = v
    return items, sent_today

# ---------- HTTP ----------
def aes_encrypt(plain: bytes) -> bytes:
    return AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(plain, 16))

def ff_post(region, path, jwt, body: bytes):
    req = urllib.request.Request(
        server_url(region) + path,
        data=aes_encrypt(body),
        method="POST",
        headers={
            "Authorization": f"Bearer {jwt}",
            "X-GA": "v1 1",
            "ReleaseVersion": RELEASE_VERSION,
            "Content-Type": "application/octet-stream",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()

def fetch_wallet(jwt, login_token, region):
    try:
        code, data = ff_post(region, "/GetWallet", jwt, encode_get_wallet_req(login_token))
        if code != 200: return {"gold":0,"diamond":0,"last_topup":"Error"}
        return decode_wallet_res(data)
    except Exception:
        return {"gold":0,"diamond":0,"last_topup":"Error"}

def fetch_store(jwt, region):
    code, data = ff_post(region, "/GetGiftStoreDetails", jwt, encode_get_store_req())
    if code != 200: raise RuntimeError(f"Garena error {code}")
    items, sent_today = decode_store_res(data)
    items.sort(key=lambda i: i["sort_id"], reverse=True)
    return items, sent_today

def send_gift_api(jwt, receiver_uid, commodity_id, unit_price, currency, message):
    region, _ = decode_jwt(jwt)
    if not region: return {"success": False, "message": "Invalid JWT"}
    try: uid = int(receiver_uid)
    except Exception: return {"success": False, "message": "Invalid UID"}
    body = encode_send_gift_req(uid, commodity_id, message or "Gift!",
                                2 if currency == "diamond" else 1, unit_price)
    try:
        code, data = ff_post(region, "/SendGift", jwt, body)
        if code == 200:
            return {"success": True, "message": f"Gift sent to {receiver_uid} successfully!"}
        try: err = data.decode("utf-8", "replace").strip() or f"Error {code}"
        except Exception: err = f"Error {code}"
        return {"success": False, "message": err}
    except Exception as e:
        return {"success": False, "message": str(e)}

# ---------- cache ----------
_cache, _lock = {}, threading.Lock()
CACHE_TTL = 5 * 60

# ---------- routes ----------
@app.route("/")
def index(): return render_template("index.html")

@app.route("/api/get-store", methods=["POST"])
def api_get_store():
    body = request.get_json(silent=True) or {}
    jwt = body.get("jwt", "")
    page = max(1, int(body.get("page", 1)))
    limit = max(1, min(100, int(body.get("limit", 24))))
    category = body.get("category", "All")
    refresh = bool(body.get("refresh", False))

    region, login_token = decode_jwt(jwt)
    if not region or not login_token:
        return jsonify({"success": False, "message": "Invalid JWT!"}), 400

    with _lock: entry = _cache.get(jwt)
    if refresh or not entry or time.time() - entry["ts"] > CACHE_TTL:
        try:
            items, sent_today = fetch_store(jwt, region)
        except Exception as e:
            return jsonify({"success": False, "message": str(e)}), 500
        wallet = fetch_wallet(jwt, login_token, region)
        cats = sorted({i["category"] for i in items})
        entry = {"items": items, "sent_today": sent_today, "wallet": wallet,
                 "cats": cats, "ts": time.time()}
        with _lock: _cache[jwt] = entry

    filtered = entry["items"] if category == "All" else [i for i in entry["items"] if i["category"] == category]
    start = (page - 1) * limit
    return jsonify({
        "success": True,
        "items": filtered[start:start+limit],
        "categories": entry["cats"],
        "wallet": entry["wallet"],
        "sent_today": entry["sent_today"],
        "has_more": start + limit < len(filtered),
        "total": len(filtered),
    })

@app.route("/api/send-gift", methods=["POST"])
def api_send_gift():
    body = request.get_json(silent=True) or {}
    if not body.get("jwt") or not body.get("receiver_uid") or not body.get("commodity_id"):
        return jsonify({"success": False, "message": "Missing fields"}), 400
    result = send_gift_api(
        body["jwt"], body["receiver_uid"], int(body["commodity_id"]),
        int(body.get("price", 0) or 0),
        "gold" if body.get("currency") == "gold" else "diamond",
        body.get("message", "Gift!"),
    )
    if result.get("success"):
        with _lock: _cache.pop(body["jwt"], None)
    return jsonify(result)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
