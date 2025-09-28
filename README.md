# LogAnaliz

Утилита для анализа логов и проверки IP и SHA256-хэшей через VirusTotal API.
> ⚠️ API-ключ встроен в `main.py`.

## Установка

```bash
# Создаём виртуальное окружение
python -m venv env

# Активация
source env/bin/activate # Linux/macOS
env\Scripts\activate # Windows


# Установка зависимостей
pip install -r requirements.txt
```

## Использование

1. Скопируйте лог-файл в папку `logs/`.
2. Запустите программу:

```bash
python main.py
```

Программа выполнит:
- Разбор логов
- Проверку IP и хэшей через VirusTotal
- Генерацию отчёта (CSV/HTML)

## Структура проекта

```
loganaliz/
├── main.py
├── log_parser.py
├── virustotal.py
└── report_generator.py
```

