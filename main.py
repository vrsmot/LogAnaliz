import argparse
import logging
from datetime import datetime, timezone
from pathlib import Path
import os

from modules.log_parser import parse_log_file
from modules.virustotal import check_ip, check_hash
from modules.report_generator import save_report

# Вставьте сюда свой VirusTotal API-ключ перед использованием
VT_API_KEY = "api"  # <-- ПОЛЬЗОВАТЕЛЬ ДОЛЖЕН ВСТАВИТЬ СВОЙ КЛЮЧ

if not VT_API_KEY:
    raise ValueError("Пожалуйста, вставьте свой VirusTotal API-ключ в переменную VT_API_KEY")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def process_file(log_path: Path, output_folder: Path, report_format: str):
    logging.info(f"Анализируем лог: {log_path}")
    ips, hashes = parse_log_file(log_path)
    logging.info(f"Найдено {len(ips)} IP и {len(hashes)} хэшей")

    results = []
    for ip in ips:
        res = check_ip(ip, VT_API_KEY)
        results.append({"value": ip, "type": "IP", "result": res, "date": datetime.now(timezone.utc).isoformat()})
    for h in hashes:
        res = check_hash(h, VT_API_KEY)
        results.append({"value": h, "type": "HASH", "result": res, "date": datetime.now(timezone.utc).isoformat()})

    # Имя отчёта совпадает с именем лог-файла, только в другом расширении
    output_file = output_folder / f"{log_path.stem}.{report_format}"
    save_report(results, output_file, report_format)
    logging.info(f"Отчёт сохранён: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="LogAnaliz — утилита анализа логов и проверки индикаторов угроз")

    parser.add_argument("-l", "--log-folder", default="logs", help="Папка с лог-файлами (по умолчанию logs)")
    parser.add_argument("-o", "--output-folder", default="output", help="Папка для отчётов (по умолчанию output)")
    parser.add_argument("-f", "--format", choices=["csv", "json"], default="csv", help="Формат отчёта (по умолчанию csv)")
    args = parser.parse_args()

    log_folder = Path(args.log_folder)
    output_folder = Path(args.output_folder)
    output_folder.mkdir(parents=True, exist_ok=True)

    if not log_folder.exists():
        logging.error(f"Папка {log_folder} не найдена")
        return

    # Рассматриваем все файлы в папке
    for file_path in log_folder.iterdir():
        if file_path.is_file():
            process_file(file_path, output_folder, args.format)

if __name__ == "__main__":
    main()
