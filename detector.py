from urllib.parse import urlparse
import re

# Весовой коэффициент для оценки риска
WEIGHTS = {
    'high': 5,
    'medium': 3,
    'low': 1
}

# Список брендов для проверки маскировки (эвристика 4)
TARGET_BRANDS = ['sber', 'tinkoff', 'gosuslugi', 'vtb', 'alpha', 'gosuslugi', 'qiwi', 'yandex']

def analyze_url(url_string: str) -> dict:
    """
    Анализирует URL на признаки фишинга.
    Возвращает словарь с оценкой риска, списком сработавших признаков и рекомендацией.
    """
    triggered_features = []
    total_score = 0

    # Проверка на корректность базового парсинга
    try:
        parsed = urlparse(url_string)
        if not parsed.scheme and not parsed.netloc:
            parsed = urlparse('http://' + url_string)
        
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        full_domain = netloc.split(':')[0] # убираем порт, если есть
    except Exception:
        return {
            "url": url_string,
            "risk_level": "HIGH",
            "features": [{"name": "Некорректный формат URL", "weight": "high", "desc": "URL не может быть корректно разобран парсером."}],
            "recommendation": "Ссылка повреждена или имеет недопустимый формат. Ни в коем случае не открывайте её."
        }

    # ЭВРИСТИКА 1: Отсутствие HTTPS (схема http)
    if scheme == 'http':
        w = 'medium'
        total_score += WEIGHTS[w]
        triggered_features.append({
            "name": "Отсутствие HTTPS",
            "weight": w,
            "desc": "Сайт использует незащищенный протокол HTTP вместо шифрованного HTTPS."
        })

    # ЭВРИСТИКА 2: Наличие IP-адреса вместо домена
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, full_domain):
        w = 'high'
        total_score += WEIGHTS[w]
        triggered_features.append({
            "name": "Использование IP-адреса вместо домена",
            "weight": w,
            "desc": "Вместо привычного доменного имени используется прямой IP-адрес, что типично для фишинга."
        })

    # ЭВРИСТИКА 3: Длина домена (> 45 символов)
    if len(full_domain) > 45:
        w = 'medium'
        total_score += WEIGHTS[w]
        triggered_features.append({
            "name": "Подозрительно длинный домен",
            "weight": w,
            "desc": f"Длина домена составляет {len(full_domain)} символов. Злоумышленники используют это для сокрытия реального адреса."
        })

    # ЭВРИСТИКА 4: Вхождение известного бренда в сомнительный контекст
    for brand in TARGET_BRANDS:
        if brand in full_domain:
            if not full_domain.endswith(f"{brand}.ru") and not full_domain.endswith(f"{brand}.com"):
                w = 'high'
                total_score += WEIGHTS[w]
                triggered_features.append({
                    "name": f"Упоминание бренда ({brand}) в стороннем домене",
                    "weight": w,
                    "desc": f"Домен содержит название известного бренда '{brand}', но не принадлежит ему официально (имитация)."
                })
                break

    # ЭВРИСТИКА 5: Необычные комбинации TLD
    suspicious_tld_patterns = [r'\.ru\.com$', r'\.online\.pro$', r'\.co\.cc$', r'\.biz\.ua$', r'\.xyz$']
    for pat in suspicious_tld_patterns:
        if re.search(pat, full_domain):
            w = 'high'
            total_score += WEIGHTS[w]
            triggered_features.append({
                "name": "Подозрительная комбинация доменных зон (TLD)",
                "weight": w,
                "desc": "Используются сомнительные составные или дешевые доменные зоны, часто применяемые мошенниками."
            })
            break

    # ЭВРИСТИКА 6: Много поддоменов (4 и более уровней)
    subdomain_parts = full_domain.split('.')
    if len(subdomain_parts) >= 4:
        w = 'medium'
        total_score += WEIGHTS[w]
        triggered_features.append({
            "name": "Избыточное количество поддоменов",
            "weight": w,
            "desc": f"Обнаружено многоуровневых поддоменов ({len(subdomain_parts)} уровней), что затрудняет визуальную проверку подлинности."
        })

    # ЭВРИСТИКА 7: Специальные символы или множественные дефисы в домене
    if '--' in full_domain or full_domain.count('-') > 3:
        w = 'medium'
        total_score += WEIGHTS[w]
        triggered_features.append({
            "name": "Специальные символы / множественные дефисы",
            "weight": w,
            "desc": "В доменном имени присутствуют сдвоенные или частые дефисы, характерные для маскировки сайтов."
        })

    # Итоговое определение уровня риска
    if total_score >= 7:
        risk_level = "HIGH"
        recommendation = "Высокий риск фишинга! Ни в коем случае не вводите здесь личные данные, логины, пароли или банковские реквизиты."
    elif total_score >= 3:
        risk_level = "MEDIUM"
        recommendation = "Средний уровень подозрительности. Рекомендуем воздержаться от перехода по ссылке и проверить адрес официального сайта вручную."
    else:
        risk_level = "LOW"
        recommendation = "Признаков фишинга не обнаружено или их уровень минимален. Тем не менее, всегда проверяйте подлинность ресурса."

    return {
        "url": url_string,
        "risk_level": risk_level,
        "score": total_score,
        "features": triggered_features,
        "recommendation": recommendation
    }

def print_report(result: dict):
    """Красивый вывод результата в консоль для не-ИТ сотрудника"""
    print("=" * 60)
    print(f"URL: {result['url']}")
    print(f"ОЦЕНКА РИСКА: [{result['risk_level']}] (Баллы опасности: {result.get('score', 0)})")
    print("-" * 60)
    if result['features']:
        print("Сработавшие признаки угрозы:")
        for idx, f in enumerate(result['features'], 1):
            print(f"  {idx}. [{f['weight'].upper()}] {f['name']}")
            print(f"     └─ {f['desc']}")
    else:
        print(" Подозрительных признаков не выявлено.")
    print("-" * 60)
    print(f"Рекомендация: {result['recommendation']}")
    print("=" * 60 + "\n")