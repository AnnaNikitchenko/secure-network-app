"""Filter and summarize structured JSONL security events."""
import argparse, collections, json
from datetime import datetime, timezone
from pathlib import Path

def read_events(path: Path, user=None, event_type=None, start=None, end=None):
    for number,line in enumerate(path.read_text(encoding="utf-8").splitlines(),1) if path.exists() else ():
        if not line.strip(): continue
        try: item=json.loads(line)
        except json.JSONDecodeError as exc: raise ValueError(f"Некоректний JSON у рядку {number}") from exc
        stamp=datetime.fromisoformat(item["timestamp"].replace("Z","+00:00"))
        if user and item.get("user") != user: continue
        if event_type and item.get("event") != event_type: continue
        if start and stamp < start: continue
        if end and stamp > end: continue
        yield item

def analyze(path: Path, user=None, event_type=None, start=None, end=None):
    events=list(read_events(path,user,event_type,start,end)); counts=collections.Counter(x.get("event","unknown") for x in events)
    return counts, events

def report(path: Path, **filters):
    counts,events=analyze(path,**filters)
    return "# Звіт аналізу журналу\n\n"+"| Подія | Кількість |\n|---|---:|\n"+"".join(f"| {name} | {number} |\n" for name,number in sorted(counts.items()))+f"\nВідібрано записів: {len(events)}\n"

def parse_date(value):
    if not value:return None
    parsed=datetime.fromisoformat(value.replace("Z","+00:00"))
    return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc)

def main():
    p=argparse.ArgumentParser(); p.add_argument("log",nargs="?",default="logs/server.jsonl"); p.add_argument("--user"); p.add_argument("--event")
    p.add_argument("--from-time"); p.add_argument("--to-time"); p.add_argument("--output",default="logs/analysis.md"); a=p.parse_args()
    text=report(Path(a.log),user=a.user,event_type=a.event,start=parse_date(a.from_time),end=parse_date(a.to_time))
    output=Path(a.output); output.parent.mkdir(parents=True,exist_ok=True); output.write_text(text,encoding="utf-8"); print(text)
if __name__=="__main__":main()
