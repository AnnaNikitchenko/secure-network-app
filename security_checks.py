"""Check trusted TLS, untrusted CA and SAN mismatch on a local test server."""
import asyncio, ssl, tempfile
from pathlib import Path
from generate_cert import generate
import server

async def probe(host,port,context,name):
    reader,writer=await asyncio.open_connection(host,port,ssl=context,server_hostname=name)
    writer.close(); await writer.wait_closed()

def is_hostname_mismatch(verify_message: str) -> bool:
    """Recognize OpenSSL hostname-mismatch text independent of capitalization."""
    return "hostname mismatch" in verify_message.casefold()

async def main():
    with tempfile.TemporaryDirectory() as folder:
        server.DB_FILE=Path(folder)/"users.sqlite3"
        server.LOG_FILE=Path(folder)/"events.jsonl"
        cert,key=generate(Path(folder))
        context=server.make_server_context(str(cert),str(key))
        srv=await asyncio.start_server(server.handle,"127.0.0.1",0,ssl=context)
        host,port=srv.sockets[0].getsockname()[:2]
        try:
            trusted=ssl.create_default_context(cafile=str(Path(folder)/"ca.crt"))
            try: await probe(host,port,trusted,"localhost")
            except ssl.SSLCertVerificationError as exc:
                if "unable to get local issuer" in exc.verify_message:
                    raise SystemExit("TLS-перевірка перервана локальним TLS-посередником; перевірте на вузлі без перехоплення.") from exc
                raise
            print("OK: довірений CA і SAN прийняті")
            checks=[("недовірений CA",ssl.create_default_context(),"localhost"),
                    ("невідповідний SAN",trusted,"wrong.example")]
            failed=[]
            for label,ctx,name in checks:
                try: await probe(host,port,ctx,name); failed.append(label); print("ПОМИЛКА:",label,"прийнято")
                except ssl.SSLCertVerificationError as exc:
                    if label=="невідповідний SAN" and not is_hostname_mismatch(exc.verify_message):
                        failed.append(label); print("ПОМИЛКА:",label,"сертифікат відхилено з іншої причини:",exc.verify_message)
                    else: print("OK:",label,"відхилено")
            if failed: raise SystemExit("Не пройшли: "+", ".join(failed))
        finally:
            srv.close(); await srv.wait_closed()

if __name__=="__main__": asyncio.run(main())
