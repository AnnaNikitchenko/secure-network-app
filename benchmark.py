"""Compare local TCP and TLS echo throughput for identical payload sizes."""
import argparse, asyncio, csv, json, ssl, statistics, time
from pathlib import Path
from generate_cert import generate

async def echo(reader,writer):
    try:
        while True:
            block=await reader.read(65536)
            if not block: break
            writer.write(block); await writer.drain()
    except (ConnectionError,asyncio.CancelledError): pass
    finally:
        writer.close()
        try: await writer.wait_closed()
        except OSError: pass

async def sample(host,port,ctx,payload):
    started=time.perf_counter()
    reader,writer=await asyncio.open_connection(host,port,ssl=ctx,server_hostname="localhost" if ctx else None)
    writer.write(payload); await writer.drain(); received=0
    while received<len(payload): received+=len(await reader.read(min(65536,len(payload)-received)))
    elapsed=time.perf_counter()-started; writer.close(); await writer.wait_closed()
    if received != len(payload): raise RuntimeError("Лічильник байтів не збігся")
    return elapsed

async def run(output: Path, sizes, repeats):
    output.mkdir(parents=True,exist_ok=True); cert,key=generate(output/"tls")
    tls_server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls_server.minimum_version=ssl.TLSVersion.TLSv1_2; tls_server.load_cert_chain(cert,key)
    client=ssl.create_default_context(cafile=str(output/"tls"/"ca.crt")); client.minimum_version=ssl.TLSVersion.TLSv1_2
    raw_srv=await asyncio.start_server(echo,"127.0.0.1",0); tls_srv=await asyncio.start_server(echo,"127.0.0.1",0,ssl=tls_server)
    rows=[]; tls_error=None
    try:
        for size in sizes:
            payload=b"x"*size; timings={"TCP":[],"TLS":[]}
            for _ in range(repeats):
                timings["TCP"].append(await sample("127.0.0.1",raw_srv.sockets[0].getsockname()[1],None,payload))
                if not tls_error:
                    try: timings["TLS"].append(await sample("127.0.0.1",tls_srv.sockets[0].getsockname()[1],client,payload))
                    except ssl.SSLCertVerificationError as exc: tls_error=type(exc).__name__
            for mode,values in timings.items():
                if values:
                    avg=statistics.mean(values)
                    rows.append({"mode":mode,"bytes":size,"repeats":repeats,"mean_seconds":avg,
                                 "median_seconds":statistics.median(values),"mib_per_second":size/avg/1024/1024,
                                 "status":"measured","reason":""})
                else:
                    rows.append({"mode":mode,"bytes":size,"repeats":repeats,"mean_seconds":None,
                                 "median_seconds":None,"mib_per_second":None,"status":"blocked",
                                 "reason":tls_error or "TLS unavailable"})
    finally:
        raw_srv.close(); tls_srv.close(); await raw_srv.wait_closed(); await tls_srv.wait_closed()
    with (output/"benchmark.csv").open("w",newline="",encoding="utf-8") as f:
        writer=csv.DictWriter(f,fieldnames=rows[0].keys()); writer.writeheader(); writer.writerows(rows)
    (output/"benchmark.json").write_text(json.dumps(rows,indent=2),encoding="utf-8")
    grouped={size:{r["mode"]:r for r in rows if r["bytes"]==size} for size in sizes}
    lines=["# Локальне порівняння TCP та TLS", "",f"Повторів на розмір: {repeats}","",
           "| Байти | TCP MiB/s | TLS MiB/s | Різниця часу TLS |","|---:|---:|---:|---:|"]
    for size,pair in grouped.items():
        t=pair["TCP"]; s=pair["TLS"]
        if s["status"]=="measured":
            overhead=(s["mean_seconds"]/t["mean_seconds"]-1)*100
            lines.append(f"| {size} | {t['mib_per_second']:.3f} | {s['mib_per_second']:.3f} | {overhead:+.2f}% |")
        else: lines.append(f"| {size} | {t['mib_per_second']:.3f} | недоступно | недоступно |")
    if tls_error:
        lines += ["",f"TLS вимірювання заблоковано під час перевірки сертифіката ({tls_error}); перевірку довіри не вимикали. Таблиця містить фактичні TCP вимірювання, але порівняння впливу TLS не обчислюється до запуску на вузлі без TLS-перехоплення.",""]
    else:
        lines += ["", "Час вимірювання охоплює встановлення з'єднання та обмін однаковим обсягом байтів. Результати залежать від ОС, Python, OpenSSL і локального навантаження.",""]
    (output/"benchmark.md").write_text("\n".join(lines),encoding="utf-8")

def main():
    p=argparse.ArgumentParser(); p.add_argument("--output",default="benchmark-results"); p.add_argument("--sizes",default="1024,65536,1048576"); p.add_argument("--repeats",type=int,default=5); a=p.parse_args()
    sizes=[int(x) for x in a.sizes.split(",")]
    if a.repeats<1 or not sizes or any(n<1 for n in sizes): p.error("Розміри та --repeats мають бути додатними")
    asyncio.run(run(Path(a.output),sizes,a.repeats))
    print(f"Результати: {a.output}")
if __name__=="__main__": main()
