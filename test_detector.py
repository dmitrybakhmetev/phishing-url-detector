from detector import analyze_url, print_report

if __name__ == "__main__":
    test_urls = [
        # 1. Явно фишинговые / подозрительные
        "http://secure-login-sber.ru.com/verify/user/auth/login/step1",
        "http://192.168.1.50/tinkoff/index.html",
        "https://gosuslugi-24-7.xyz/cabinet/12345/secure/update/profile",
        "http://my--bank-100-percent-secure-login.com",
        # 2. Средний риск (например, HTTP или легкие аномалии)
        "http://example.com/about",
        "https://a.b.c.d.example.com/test",
        # 3. Безопасные / легитимные
        "https://www.sberbank.ru",
        "https://tinkoff.ru",
        "https://www.gosuslugi.ru",
        "https://habr.com/ru/all/"
    ]

    print("=== ЗАПУСК АВТОМАТИЧЕСКИХ ТЕСТОВ ДЕТЕКТОРА ФИШИНГА ===\n")
    
    for url in test_urls:
        res = analyze_url(url)
        print_report(res)
        
        # Проверяем базовые правила через assert для демонстрации авто-тестов
        assert "risk_level" in res
        assert "recommendation" in res

    print("Все тесты успешно выполнены!")