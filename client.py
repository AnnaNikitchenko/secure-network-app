"""Console client. TLS peer and SAN are verified by the platform SSL stack."""
from __future__ import annotations
import argparse, asyncio, getpass, hashlib, json, ssl, struct
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

MAX_MESSAGE = 1024 * 1024

async def send(writer, obj):
    raw=json.dumps(obj,ensure_ascii=False,separators=(",",":")).encode()
    if not 1 <= len(raw) <= MAX_MESSAGE: raise ValueError("Повідомлення має некоректний розмір")
    writer.write(struct.pack("!I",len(raw))+raw); await writer.drain()

async def receive(reader):
    n=struct.unpack("!I",await reader.readexactly(4))[0]
    if not 1 <= n <= MAX_MESSAGE: raise ValueError("Некоректна відповідь сервера")
    value=json.loads(await reader.readexactly(n))
    if not isinstance(value,dict): raise ValueError("Некоректний формат відповіді")
    return value

async def request(host,port,ca,server_name,payload,plaintext=False):
    ctx=None
    if not plaintext:
        ctx=ssl.create_default_context(ssl.Purpose.SERVER_AUTH,cafile=ca)
        ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        ctx.check_hostname=True; ctx.verify_mode=ssl.CERT_REQUIRED
    reader,writer=await asyncio.open_connection(host,port,ssl=ctx,server_hostname=server_name if ctx else None)
    try:
        await send(writer,payload); return await receive(reader)
    finally:
        writer.close(); await writer.wait_closed()

async def interactive(a):
    print("Команди: register, login, mfa, mfa-off, send, admin, logout, quit")
    token=None
    while True:
        cmd=input("secure-app> ").strip().lower()
        if cmd=="quit": break
        if cmd=="register":
            name=input("Логін: "); password=getpass.getpass("Пароль (12+ символів): ")
            result=await request(a.host,a.port,a.ca,a.server_name,{"op":"register","username":name,"password":password})
        elif cmd=="login":
            name=input("Логін: "); password=getpass.getpass("Пароль: ")
            result=await request(a.host,a.port,a.ca,a.server_name,{"op":"auth","username":name,"password":password})
            if result.get("mfa_required"):
                otp=getpass.getpass("Код MFA: ")
                result=await request(a.host,a.port,a.ca,a.server_name,{"op":"mfa_verify","otp":otp,"challenge":result.get("challenge")})
            if result.get("ok"): token=result.get("token"); print("Вхід виконано")
        elif cmd=="mfa" and token:
            result=await request(a.host,a.port,a.ca,a.server_name,{"op":"mfa_enroll","token":token})
            if result.get("ok"):
                print("Введіть секрет у застосунок-аутентифікатор:",result["secret"])
                print("Після налаштування введіть код для увімкнення MFA.")
                otp=getpass.getpass("OTP: ")
                result=await request(a.host,a.port,a.ca,a.server_name,{"op":"mfa_enable","token":token,"otp":otp})
        elif cmd=="mfa-off" and token:
            otp=getpass.getpass("Поточний OTP для підтвердження: ")
            result=await request(a.host,a.port,a.ca,a.server_name,{"op":"mfa_disable","token":token,"otp":otp})
        elif cmd=="send" and token:
            text=input("Текст: "); digest=hashlib.sha256(text.encode()).hexdigest()
            result=await request(a.host,a.port,a.ca,a.server_name,{"op":"data","token":token,"payload":text,"sha256":digest})
        elif cmd=="admin" and token:
            result=await request(a.host,a.port,a.ca,a.server_name,{"op":"admin_list_users","token":token})
        elif cmd=="logout" and token:
            result=await request(a.host,a.port,a.ca,a.server_name,{"op":"logout","token":token}); token=None
        else:
            print("Спочатку увійдіть або оберіть доступну команду."); continue
        print("Успіх" if result.get("ok") else "Помилка: "+str(result.get("error")))
        if result.get("users") is not None:
            for account in result["users"]:
                print(f"{account['username']} — {account['role']}, MFA: {'увімкнено' if account['mfa_enabled'] else 'вимкнено'}")
        if result.get("error")=="temporarily_locked": print("Спробуйте пізніше:",result.get("retry_after"),"с")

def main():
    p=argparse.ArgumentParser(description="Консольний клієнт Secure Network App")
    p.add_argument("--host",default=os.getenv("CLIENT_HOST","127.0.0.1")); p.add_argument("--port",type=int,default=int(os.getenv("CLIENT_PORT","8443")))
    p.add_argument("--server-name",default=os.getenv("TLS_SERVER_NAME","localhost")); p.add_argument("--ca",default=os.getenv("TLS_CA","data/ca.crt"))
    p.add_argument("--demo-plaintext",action="store_true",help="Тільки тестові PING/ECHO без секретів")
    p.add_argument("--ping",action="store_true"); p.add_argument("--echo")
    a=p.parse_args()
    if a.demo_plaintext:
        op={"op":"ping"} if a.ping else {"op":"echo","text":a.echo or "demo"}
        print(asyncio.run(request(a.host,a.port,a.ca,a.server_name,op,True))); return
    asyncio.run(interactive(a))
if __name__=="__main__": main()
