import asyncio, hashlib, json, jwt, ssl, struct, time, threading, warnings
from pathlib import Path
import bcrypt
import pytest
import server
from add_user import create_user
from analyze_logs import analyze
from generate_cert import generate

@pytest.fixture
def app(tmp_path,monkeypatch):
    cert,key=generate(tmp_path/"tls")
    monkeypatch.setattr(server,"DB_FILE",tmp_path/"users.sqlite3")
    monkeypatch.setattr(server,"LOG_FILE",tmp_path/"events.jsonl")
    monkeypatch.setattr(server,"JWT_SECRET","t"*48)
    monkeypatch.setattr(server,"JWT_TTL",900)
    monkeypatch.setattr(server,"LOCK_ATTEMPTS",3)
    monkeypatch.setattr(server,"LOCK_SECONDS",1)
    server._failures.clear(); server._mfa_challenges.clear()
    create_user("alice","correct horse battery staple")
    create_user("admin","correct horse battery staple","ADMIN")
    return cert,key,tmp_path/"tls"/"ca.crt"

async def exchange(endpoint,ca,message,servername="localhost"):
    ctx=ssl.create_default_context(cafile=str(ca)); ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    reader,writer=await asyncio.open_connection("127.0.0.1",endpoint,ssl=ctx,server_hostname=servername)
    raw=json.dumps(message).encode(); writer.write(struct.pack("!I",len(raw))+raw); await writer.drain()
    size=struct.unpack("!I",await reader.readexactly(4))[0]; result=json.loads(await reader.readexactly(size))
    writer.close(); await writer.wait_closed(); return result

@pytest.fixture
def running(app):
    cert,key,ca=app
    loop=asyncio.new_event_loop(); state={}; ready=threading.Event()
    def worker():
        asyncio.set_event_loop(loop)
        async def start():
            state["srv"]=await asyncio.start_server(server.handle,"127.0.0.1",0,ssl=server.make_server_context(str(cert),str(key)))
            state["port"]=state["srv"].sockets[0].getsockname()[1]
            ready.set()
        loop.run_until_complete(start()); loop.run_forever()
    thread=threading.Thread(target=worker,daemon=True); thread.start(); assert ready.wait(5)
    yield state["port"],cert,ca
    async def stop(): state["srv"].close(); await state["srv"].wait_closed()
    asyncio.run_coroutine_threadsafe(stop(),loop).result(5)
    loop.call_soon_threadsafe(loop.stop); thread.join(5); loop.close()

def test_tls_and_certificate_rejection(running):
    endpoint,cert,ca=running
    assert asyncio.run(exchange(endpoint,ca,{"op":"auth","username":"alice","password":"correct horse battery staple"}))["ok"]
    async def bad(ca_path,name):
        ctx=ssl.create_default_context(cafile=str(ca_path) if ca_path else None)
        return await asyncio.open_connection("127.0.0.1",endpoint,ssl=ctx,server_hostname=name)
    with pytest.raises(ssl.SSLError): asyncio.run(bad(None,"localhost"))
    with pytest.raises(ssl.SSLError): asyncio.run(bad(ca,"wrong.example"))

def test_password_jwt_data_authorization_and_revocation(running):
    endpoint,cert,ca=running
    user=asyncio.run(exchange(endpoint,ca,{"op":"auth","username":"alice","password":"correct horse battery staple"}))
    assert user["ok"] and user["role"]=="USER"
    admin_denied=asyncio.run(exchange(endpoint,ca,{"op":"admin_status","token":user["token"]}))
    assert admin_denied["error"]=="forbidden"
    admin=asyncio.run(exchange(endpoint,ca,{"op":"auth","username":"admin","password":"correct horse battery staple"}))
    listing=asyncio.run(exchange(endpoint,ca,{"op":"admin_list_users","token":admin["token"]}))
    assert listing["ok"] and len(listing["users"])==2
    assert "password_hash" not in listing["users"][0]
    payload="тестовий вміст"; digest=hashlib.sha256(payload.encode()).hexdigest()
    assert asyncio.run(exchange(endpoint,ca,{"op":"data","token":user["token"],"payload":payload,"sha256":digest}))["ok"]
    assert asyncio.run(exchange(endpoint,ca,{"op":"data","token":user["token"],"payload":payload,"sha256":"0"*64}))["error"]=="integrity_check_failed"
    assert asyncio.run(exchange(endpoint,ca,{"op":"logout","token":user["token"]}))["ok"]
    assert asyncio.run(exchange(endpoint,ca,{"op":"data","token":user["token"],"payload":"x","sha256":hashlib.sha256(b"x").hexdigest()}))["error"]=="invalid_token"
    forged=jwt.encode({"sub":"admin","role":"ADMIN","exp":int(time.time())+20,"jti":"forged"},"wrong-secret-"*4,algorithm="HS256")
    assert asyncio.run(exchange(endpoint,ca,{"op":"admin_status","token":forged}))["error"]=="invalid_token"

def test_wrong_password_and_lock_expiry(running):
    endpoint,cert,ca=running
    for _ in range(2): assert asyncio.run(exchange(endpoint,ca,{"op":"auth","username":"alice","password":"wrong"}))["error"]=="invalid_credentials"
    assert asyncio.run(exchange(endpoint,ca,{"op":"auth","username":"alice","password":"wrong"}))["attempts_left"]==0
    assert asyncio.run(exchange(endpoint,ca,{"op":"auth","username":"alice","password":"correct horse battery staple"}))["error"]=="temporarily_locked"
    time.sleep(1.05)
    assert asyncio.run(exchange(endpoint,ca,{"op":"auth","username":"alice","password":"correct horse battery staple"}))["ok"]

def test_expired_token_and_missing_token(running):
    endpoint,cert,ca=running
    expired=jwt.encode({"sub":"alice","role":"USER","iat":1,"exp":2,"jti":"old"},server.JWT_SECRET,algorithm="HS256")
    assert asyncio.run(exchange(endpoint,ca,{"op":"data"}))["error"]=="authentication_required"
    assert asyncio.run(exchange(endpoint,ca,{"op":"data","token":expired}))["error"]=="invalid_token"

def test_mfa_enrollment_challenge_and_replay(running):
    import pyotp
    endpoint,cert,ca=running
    token=asyncio.run(exchange(endpoint,ca,{"op":"auth","username":"alice","password":"correct horse battery staple"}))["token"]
    enrollment=asyncio.run(exchange(endpoint,ca,{"op":"mfa_enroll","token":token}))
    assert enrollment["ok"] and enrollment["otpauth_uri"].startswith("otpauth://totp/")
    otp=pyotp.TOTP(enrollment["secret"]).now()
    assert asyncio.run(exchange(endpoint,ca,{"op":"mfa_enable","token":token,"otp":otp}))["ok"]
    challenge=asyncio.run(exchange(endpoint,ca,{"op":"auth","username":"alice","password":"correct horse battery staple"}))
    assert challenge["mfa_required"] and "token" not in challenge
    wrong="000000" if otp!="000000" else "000001"
    assert asyncio.run(exchange(endpoint,ca,{"op":"mfa_verify","challenge":challenge["challenge"],"otp":wrong}))["error"]=="invalid_otp"
    challenge=asyncio.run(exchange(endpoint,ca,{"op":"auth","username":"alice","password":"correct horse battery staple"}))
    with server._db() as db: db.execute("UPDATE users SET last_otp_counter=-1 WHERE username='alice'")
    logged_in=asyncio.run(exchange(endpoint,ca,{"op":"mfa_verify","challenge":challenge["challenge"],"otp":otp}))
    assert logged_in["ok"] and "token" in logged_in
    assert asyncio.run(exchange(endpoint,ca,{"op":"mfa_disable","token":logged_in["token"],"otp":otp}))["error"]=="invalid_otp"
    with server._db() as db: db.execute("UPDATE users SET last_otp_counter=-1 WHERE username='alice'")
    assert asyncio.run(exchange(endpoint,ca,{"op":"mfa_disable","token":logged_in["token"],"otp":otp}))["ok"]

def test_plaintext_ping_echo_demo_only(tmp_path,monkeypatch):
    monkeypatch.setattr(server,"DB_FILE",tmp_path/"db.sqlite3"); monkeypatch.setattr(server,"LOG_FILE",tmp_path/"log.jsonl")
    async def scenario():
        srv=await asyncio.start_server(server.handle,"127.0.0.1",0); port=srv.sockets[0].getsockname()[1]
        async def one(msg):
            r,w=await asyncio.open_connection("127.0.0.1",port); b=json.dumps(msg).encode(); w.write(struct.pack("!I",len(b))+b); await w.drain()
            n=struct.unpack("!I",await r.readexactly(4))[0]; out=json.loads(await r.readexactly(n)); w.close(); await w.wait_closed(); return out
        assert (await one({"op":"ping"}))["reply"]=="PONG"
        assert (await one({"op":"echo","text":"demo"}))["reply"]=="demo"
        assert (await one({"op":"auth","username":"a","password":"secret"}))["error"]=="secure_transport_required"
        srv.close(); await srv.wait_closed()
    asyncio.run(scenario())

def test_jsonl_events_and_analysis(running):
    endpoint,cert,ca=running
    asyncio.run(exchange(endpoint,ca,{"op":"auth","username":"alice","password":"bad-password"}))
    asyncio.run(exchange(endpoint,ca,{"op":"auth","username":"alice","password":"correct horse battery staple"}))
    with server.LOG_FILE.open(encoding="utf-8") as f: raw=f.read()
    assert "bad-password" not in raw and "correct horse battery staple" not in raw
    counts,events=analyze(server.LOG_FILE,user="alice")
    assert counts["auth.failure"]>=1 and counts["auth.success"]>=1

def test_bcrypt_jwt_and_expiry(tmp_path,monkeypatch):
    monkeypatch.setattr(server,"DB_FILE",tmp_path/"users.sqlite3")
    monkeypatch.setattr(server,"JWT_SECRET","unit-test-secret-"*4)
    create_user("unit","unit test password 123")
    with server._db() as db:
        row=db.execute("SELECT password_hash FROM users WHERE username='unit'").fetchone()
    assert b"unit test password 123" not in row["password_hash"]
    assert bcrypt.checkpw(b"unit test password 123",row["password_hash"])
    token=server._mint_token("unit","USER")
    assert server._decode_token(token)["sub"]=="unit"
    expired=jwt.encode({"sub":"unit","role":"USER","iat":1,"exp":2,"jti":"expired"},server.JWT_SECRET,algorithm="HS256")
    assert server._decode_token(expired) is None

def test_test_jwt_key_has_no_insecure_length_warning(monkeypatch):
    monkeypatch.setattr(server,"JWT_SECRET","unit-test-secret-"*4)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        server._mint_token("unit","USER")
        jwt.encode({"sub":"test"},"wrong-secret-"*4,algorithm="HS256")
    insecure=[w for w in caught if "InsecureKeyLengthWarning" in w.category.__name__]
    assert len(server.JWT_SECRET.encode("utf-8"))>=32
    assert not insecure

def test_rate_limit_window_expiration(monkeypatch):
    monkeypatch.setattr(server,"LOCK_ATTEMPTS",3); monkeypatch.setattr(server,"LOCK_SECONDS",5)
    server._failures.clear(); key="test-ip:account"
    assert server.record_login_failure(key,now=10)==(False,2)
    assert server.record_login_failure(key,now=11)==(False,1)
    assert server.record_login_failure(key,now=12)==(True,0)
    assert server.login_lock_remaining(key,now=14)==3
    assert server.login_lock_remaining(key,now=17)==0
    assert server.record_login_failure(key,now=17)==(False,2)
    server._failures.clear()

def test_log_allowlist_and_filtered_analysis(tmp_path,monkeypatch):
    monkeypatch.setattr(server,"LOG_FILE",tmp_path/"events.jsonl")
    marker="should-never-appear"
    server.log_event("auth.failure",user="case-user",password=marker,token=marker,otp=marker)
    contents=server.LOG_FILE.read_text(encoding="utf-8")
    assert marker not in contents
    counts,events=analyze(server.LOG_FILE,user="case-user",event_type="auth.failure")
    assert counts["auth.failure"]==1 and len(events)==1
    counts,_=analyze(server.LOG_FILE,user="other")
    assert counts["auth.failure"]==0
