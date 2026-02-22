# PKCE (Proof Key for Code Exchange) — Реализация RFC 7636

**Автор:** Abral  
**Организация:** Abral Core Syndicate  
**Спецификация:** [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)

---

## Введение

PKCE (Proof Key for Code Exchange, произносится как «pixy») — это расширение протокола OAuth 2.0, разработанное для защиты общедоступных клиентов от атак перехвата кода авторизации. Данная библиотека представляет собой надёжную и простую реализацию протокола PKCE для PHP-приложений.

Протокол PKCE был впервые определён в документе [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) и первоначально предназначался для мобильных приложений и других общедоступных клиентов, которые не могут безопасно хранить секрет клиента. Однако сейчас он рекомендуется для всех типов клиентов OAuth 2.0 как дополнительный уровень безопасности.

### Как работает PKCE

Механизм PKCE работает следующим образом: клиентское приложение генерирует случайную строку, называемую `code_verifier`, которая затем хешируется и отправляется на сервер авторизации как `code_challenge`. При обмене кода авторизации на токен доступа клиент должен доказать, что владеет оригинальным `code_verifier`. Это предотвращает возможность использования перехваченного кода злоумышленником, поскольку без оригинального `code_verifier` обмен невозможен.

## Основные возможности

- **Соответствие RFC 7636**: Полная реализация протокола PKCE
- **Криптографическая безопасность**: Использование ` генерации случайrandom_bytes()` дляных чисел
- **Поддержка метода S256**: SHA256 + кодирование Base64URL
- **Поддержка метода Plain**: Простой код вызова для обратной совместимости
- **Base64URL кодирование**: URL-безопасное кодирование и декодирование Base64
- **Верификация**: Встроенная функция проверки
- **Отсутствие зависимостей**: Чистый PHP, без внешних библиотек

## Установка

### Через Composer

```bash
composer require pkce/pkce
```

### Ручная установка

Просто подключите скрипт в вашем PHP-проекте:

```php
require_once 'pkce_rfc7636.php';
```

## Использование

### Базовое использование

```php
<?php
require_once 'pkce_rfc7636.php';

// Генерация параметров PKCE с использованием метода S256 (рекомендуется)
$pkce = PKCE::generatePkceParameters('S256');

echo $pkce['code_verifier'];        // Случайная строка (43-128 символов)
echo $pkce['code_challenge'];        // Base64URL(SHA256(code_verifier))
echo $pkce['code_challenge_method']; // "S256"
```

### Использование вспомогательной функции

```php
<?php
require_once 'pkce_rfc7636.php';

$pkce = generatePkce('S256');
```

### Генерация только Code Verifier

```php
<?php
require_once 'pkce_rfc7636.php';

$codeVerifier = PKCE::generateCodeVerifier(64); // Пользовательская длина
```

### Генерация Code Challenge

```php
<?php
require_once 'pkce_rfc7636.php';

$codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

$codeChallenge = PKCE::generateS256CodeChallenge($codeVerifier);
// Результат: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM

$plainChallenge = PKCE::generatePlainCodeChallenge($codeVerifier);
// Результат: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

### Верификация Code Challenge

```php
<?php
require_once 'pkce_rfc7636.php';

$codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
$codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

// Проверка с использованием метода S256
$isValid = PKCE::verifyCodeChallenge($codeVerifier, $codeChallenge, 'S256');

if ($isValid) {
    echo "Верификация успешна!";
}
```

### Кодирование/декодирование Base64URL

```php
<?php
require_once 'pkce_rfc7636.php';

$encoded = PKCE::base64UrlEncode("Привет, мир!");
$decoded = PKCE::base64UrlDecode($encoded);
```

## Пример запроса авторизации OAuth 2.0

```php
<?php
require_once 'pkce_rfc7636.php';

// Генерация параметров PKCE
$pkce = PKCE::generatePkceParameters('S256');

// Сохраните $pkce['code_verifier'] в сессии для последующей верификации

// Формирование URL авторизации
$authUrl = "https://authorization-server.com/authorize?" . http_build_query([
    'client_id' => 'your-client-id',
    'redirect_uri' => 'https://your-app.com/callback',
    'response_type' => 'code',
    'scope' => 'read write',
    'code_challenge' => $pkce['code_challenge'],
    'code_challenge_method' => $pkce['code_challenge_method'],
    'state' => bin2hex(random_bytes(16))
]);

// Перенаправление пользователя на сервер авторизации
header("Location: $authUrl");
exit;
```

## Пример обмена токенами

```php
<?php
require_once 'pkce_rfc7636.php';

// Получение code_verifier из сессии
$codeVerifier = $_SESSION['code_verifier'];

// Обмен кода авторизации на токен
$tokenResponse = httpRequest("https://authorization-server.com/token", [
    'grant_type' => 'authorization_code',
    'code' => $_GET['code'],
    'redirect_uri' => 'https://your-app.com/callback',
    'client_id' => 'your-client-id',
    'code_verifier' => $codeVerifier
]);
```

## Спецификация RFC 7636

Данная реализация соответствует [RFC 7636 — Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636).

### Ключевые параметры

- **code_verifier**: Криптографически случайная строка длиной от 43 до 128 символов
- **code_challenge**: BASE64URL(SHA256(code_verifier)) для метода S256
- **code_challenge_method**: either "plain" или "S256" (рекомендуется)

### Рекомендации по безопасности

1. **Всегда используйте метод S256** в продакшене (если сервер авторизации поддерживает его)
2. Храните `code_verifier` безопасно (например, в серверной сессии)
3. Генерируйте `code_verifier` с использованием криптографически безопасных случайных байтов
4. Никогда не передавайте `code_verifier` на сервер авторизации

## Требования

- PHP 7.1 или выше
- Расширение OpenSSL (для функций `random_bytes()` и `hash()`)

## Лицензия

MIT License — подробности в файле [LICENSE](LICENSE).

## Ссылки

- [RFC 7636 — Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [Auth0 — Authorization Code Flow with PKCE](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-pkce)

---

# PKCE (Proof Key for Code Exchange) — RFC 7636 Implementation

**Author:** Abral  
**Organization:** Abral Core Syndicate  
**Specification:** [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)

---

## Overview

PKCE (pronounced "pixy") is an extension to OAuth 2.0 authorization code flow that helps secure public clients against authorization code interception attacks. This library provides a simple and secure implementation of the PKCE protocol for PHP applications.

PKCE was originally defined in [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) for mobile apps and other public clients that cannot securely store a client secret. However, it is now recommended for all OAuth 2.0 client types as an additional security layer.

### How PKCE Works

PKCE works by having the client application generate a random string called `code_verifier`, which is then hashed and sent to the authorization server as `code_challenge`. When the client exchanges the authorization code for an access token, it must prove it possesses the original `code_verifier`. This prevents an attacker from using intercepted authorization code, as the exchange is impossible without the original `code_verifier`.

## Features

- **RFC 7636 Compliant**: Full implementation of the PKCE protocol
- **Cryptographically Secure**: Uses `random_bytes()` for secure random generation
- **S256 Method Support**: SHA256 + Base64URL encoding
- **Plain Method Support**: Plain code challenge (for backward compatibility)
- **Base64URL Encoding**: URL-safe Base64 encoding/decoding
- **Verification**: Built-in verification function
- **Zero Dependencies**: Pure PHP, no external libraries required

## Installation

### Via Composer

```bash
composer require pkce/pkce
```

### Manual Installation

Simply include the script in your PHP project:

```php
require_once 'pkce_rfc7636.php';
```

## Usage

### Basic Usage

```php
<?php
require_once 'pkce_rfc7636.php';

// Generate PKCE parameters with S256 method (recommended)
$pkce = PKCE::generatePkceParameters('S256');

echo $pkce['code_verifier'];        // Random string (43-128 chars)
echo $pkce['code_challenge'];        // Base64URL(SHA256(code_verifier))
echo $pkce['code_challenge_method']; // "S256"
```

### Using Helper Function

```php
<?php
require_once 'pkce_rfc7636.php';

$pkce = generatePkce('S256');
```

### Generating Code Verifier Only

```php
<?php
require_once 'pkce_rfc7636.php';

$codeVerifier = PKCE::generateCodeVerifier(64); // Custom length
```

### Generating Code Challenge

```php
<?php
require_once 'pkce_rfc7636.php';

$codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

$codeChallenge = PKCE::generateS256CodeChallenge($codeVerifier);
// Output: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM

$plainChallenge = PKCE::generatePlainCodeChallenge($codeVerifier);
// Output: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

### Verifying Code Challenge

```php
<?php
require_once 'pkce_rfc7636.php';

$codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
$codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

// Verify using S256 method
$isValid = PKCE::verifyCodeChallenge($codeVerifier, $codeChallenge, 'S256');

if ($isValid) {
    echo "Verification successful!";
}
```

### Base64URL Encoding/Decoding

```php
<?php
require_once 'pkce_rfc7636.php';

$encoded = PKCE::base64UrlEncode("Hello, World!");
$decoded = PKCE::base64UrlDecode($encoded);
```

## OAuth 2.0 Authorization Request Example

```php
<?php
require_once 'pkce_rfc7636.php';

// Generate PKCE parameters
$pkce = PKCE::generatePkceParameters('S256');

// Store $pkce['code_verifier'] in session for later verification

// Build authorization URL
$authUrl = "https://authorization-server.com/authorize?" . http_build_query([
    'client_id' => 'your-client-id',
    'redirect_uri' => 'https://your-app.com/callback',
    'response_type' => 'code',
    'scope' => 'read write',
    'code_challenge' => $pkce['code_challenge'],
    'code_challenge_method' => $pkce['code_challenge_method'],
    'state' => bin2hex(random_bytes(16))
]);

// Redirect user to authorization server
header("Location: $authUrl");
exit;
```

## Token Exchange Example

```php
<?php
require_once 'pkce_rfc7636.php';

// Retrieve code_verifier from session
$codeVerifier = $_SESSION['code_verifier'];

// Exchange authorization code for token
$tokenResponse = httpRequest("https://authorization-server.com/token", [
    'grant_type' => 'authorization_code',
    'code' => $_GET['code'],
    'redirect_uri' => 'https://your-app.com/callback',
    'client_id' => 'your-client-id',
    'code_verifier' => $codeVerifier
]);
```

## RFC 7636 Specification

This implementation follows [RFC 7636 - Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636).

### Key Parameters

- **code_verifier**: A cryptographically random string between 43-128 characters
- **code_challenge**: BASE64URL(SHA256(code_verifier)) for S256 method
- **code_challenge_method**: Either "plain" or "S256" (recommended)

### Security Notes

1. **Always use S256 method** in production (unless the authorization server doesn't support it)
2. Store `code_verifier` securely (e.g., server-side session)
3. Generate `code_verifier` using cryptographically secure random bytes
4. Never transmit `code_verifier` to the authorization server

## Requirements

- PHP 7.1 or higher
- OpenSSL extension (for `random_bytes()` and `hash()` functions)

## License

MIT License - see [LICENSE](LICENSE) file for details.

## References

- [RFC 7636 - Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [Auth0 - Authorization Code Flow with PKCE](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-pkce)
