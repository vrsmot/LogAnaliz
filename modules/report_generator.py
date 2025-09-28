import csv
import json
from pathlib import Path
import logging

def save_report(results, out_file, fmt="csv"):
    p = Path(out_file)
    p.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "csv":
        with open(p, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["value", "type", "result", "date"])
            writer.writeheader()
            for row in results:
                writer.writerow({
                    "value": row["value"],
                    "type": row["type"],
                    "result": json.dumps(row["result"], ensure_ascii=False),
                    "date": row["date"]
                })
        logging.info("CSV отчёт создан")
    else:
        with open(p, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        logging.info("JSON отчёт создан")
