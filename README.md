# 🛡️ MTProto Secure Proxy

[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black)](https://ubuntu.com/)
[![MTProto](https://img.shields.io/badge/MTProto-FakeTLS-0088CC?logo=telegram&logoColor=white)](https://core.telegram.org/mtproto)
[![GitHub release](https://img.shields.io/github/v/release/meissah26/mtproto-secure-proxy)](https://github.com/meissah26/mtproto-secure-proxy/releases)

> DPI-resistant MTProto proxy for Telegram with FakeTLS masquerading, masquerade website, and real-time monitoring dashboard.

[English](#english) | [Русский](#русский)

---

<a id="русский"></a>

## Русский

### Описание

DPI-устойчивый MTProto прокси для Telegram с технологией FakeTLS, маскировочным сайтом и панелью мониторинга в реальном времени.

Трафик прокси неотличим от обычного HTTPS-трафика к `www.microsoft.com` для систем глубокой инспекции пакетов (DPI/ТСПУ).

### Архитектура

```
Интернет → :443 → mtg v2 (FakeTLS, SNI = www.microsoft.com)
                    ├─ Telegram-клиент (с секретом) → MTProto → Telegram DC
                    └─ Браузер / DPI-зонд (без секрета) → cloak → Nginx → Маскировочный сайт
                    
                  :9090 → Панель мониторинга (доступ по секретной ссылке)
```

### Компоненты

| Сервис | Описание | Порт |
|--------|----------|------|
| **mtg v2** | MTProto прокси с FakeTLS-обфускацией | 443 (внешний) |
| **Nginx** | TLS-терминация + маскировочный сайт | 8444 (только внутри Docker) |
| **Monitoring** | Панель мониторинга + ротация секрета | 9090 (внешний) |

### Методы обхода DPI

| Метод | Описание |
|-------|----------|
| **FakeTLS (ee-prefix)** | Трафик неотличим от TLS 1.3 для DPI |
| **Domain fronting** | SNI показывает `www.microsoft.com` — заблокировать невозможно |
| **Порт 443** | Стандартный HTTPS, никогда не блокируется ISP |
| **Anti-replay cache** | Защита от replay-атак при активном зондировании |
| **Маскировочный сайт** | При прямом обращении без секрета отдаётся реальный сайт |
| **Kernel hardening** | TCP SYN cookies, RP filter, TCP fastopen |

### Панель мониторинга

Доступ по секретной ссылке: `http://<IP>:9090/dashboard/<SECRET>`

**Метрики:**

| Карточка | Что показывает |
|----------|---------------|
| Telegram Clients | Активные клиентские сессии (из Prometheus mtg) |
| Telegram Connections | Подключения к Telegram DC с разбивкой по DC |
| Users by Country | Уникальные пользователи по странам (через conntrack + GeoIP) |
| CPU & Load | Загрузка процессора, load average, uptime сервера |
| Memory | Использование оперативной памяти |
| Disk | Использование диска |
| Traffic | Трафик клиент↔Telegram и cloak-трафик |
| Security | Replay-атаки, cloak-перенаправления, отклонённые соединения |
| Rotate Secret | Ротация секрета в один клик (с подтверждением) |

### Установка

#### Требования

- Ubuntu 22.04+ / Debian 12+
- 1 vCPU, 1 GB RAM (рекомендуется 2 GB)
- Публичный IPv4
- Свободный порт 443

#### Быстрый старт

```bash
git clone https://github.com/meissah26/mtproto-secure-proxy.git /opt/mtproto-proxy
cd /opt/mtproto-proxy
chmod +x scripts/install.sh
sudo ./scripts/install.sh
```

#### Параметры

```bash
# Сменить домен для FakeTLS (по умолчанию: www.microsoft.com)
export CLOAK_DOMAIN=www.google.com

# Указать IP вручную (по умолчанию: автоопределение)
export SERVER_IP=1.2.3.4

sudo -E ./scripts/install.sh
```

### Управление

```bash
cd /opt/mtproto-proxy

# Статус
docker compose ps

# Логи mtg
docker compose logs -f mtg

# Перезапуск
docker compose restart

# Остановка
docker compose down
```

### Структура проекта

```
/opt/mtproto-proxy/
├── docker-compose.yml        # Оркестрация сервисов
├── mtg-config.toml           # Конфигурация mtg (генерируется install.sh)
├── .env                      # DASHBOARD_SECRET (генерируется install.sh)
├── nginx/
│   ├── nginx.conf            # Конфигурация Nginx для cloak
│   └── certs/                # TLS-сертификаты (генерируются install.sh)
├── monitoring/
│   ├── Dockerfile
│   ├── app.py                # Бэкенд дашборда (aiohttp + conntrack)
│   └── templates/
│       └── dashboard.html    # Фронтенд дашборда
├── landing-static/           # Статический маскировочный сайт
├── scripts/
│   └── install.sh            # Установщик
├── keys/                     # SSH-ключи (генерируются install.sh)
└── CONNECTION_INFO.txt       # Строки подключения (генерируется install.sh)
```

### Безопасность

- SSH: только ключевая аутентификация (пароль отключается)
- UFW: открыты только порты 22, 443, 9090
- Kernel hardening через sysctl
- Панель мониторинга: доступ только по секретной ссылке
- Порт 8444 (nginx cloak) не выставлен наружу
- Docker socket read-only в контейнере мониторинга
- Ротация секрета с двойным подтверждением (защита от случайного нажатия)

---

<a id="english"></a>

## English

### Overview

DPI-resistant MTProto proxy for Telegram with FakeTLS technology, masquerade website, and real-time monitoring dashboard.

Proxy traffic is indistinguishable from regular HTTPS traffic to `www.microsoft.com` for Deep Packet Inspection systems.

### Architecture

```
Internet → :443 → mtg v2 (FakeTLS, SNI = www.microsoft.com)
                    ├─ Telegram client (with secret) → MTProto → Telegram DC
                    └─ Browser / DPI probe (no secret) → cloak → Nginx → Masquerade site
                    
                  :9090 → Monitoring Dashboard (secret URL only)
```

### Components

| Service | Description | Port |
|---------|-------------|------|
| **mtg v2** | MTProto proxy with FakeTLS obfuscation | 443 (external) |
| **Nginx** | TLS termination + masquerade website | 8444 (Docker internal only) |
| **Monitoring** | Dashboard + secret rotation | 9090 (external) |

### DPI Bypass Techniques

| Technique | Description |
|-----------|-------------|
| **FakeTLS (ee-prefix)** | Traffic indistinguishable from TLS 1.3 |
| **Domain fronting** | SNI shows `www.microsoft.com` — cannot be blocked |
| **Port 443** | Standard HTTPS, never blocked by ISPs |
| **Anti-replay cache** | Protection against replay attacks during active probing |
| **Masquerade website** | Direct access without secret serves a real website |
| **Kernel hardening** | TCP SYN cookies, RP filter, TCP fastopen |

### Monitoring Dashboard

Access via secret URL: `http://<IP>:9090/dashboard/<SECRET>`

**Metrics:**

| Card | What it shows |
|------|--------------|
| Telegram Clients | Active client sessions (from mtg Prometheus) |
| Telegram Connections | Connections to Telegram DCs with DC breakdown |
| Users by Country | Unique users by country (via conntrack + GeoIP) |
| CPU & Load | CPU usage, load average, server uptime |
| Memory | RAM usage |
| Disk | Disk usage |
| Traffic | Client↔Telegram traffic and cloak traffic |
| Security | Replay attacks, cloak redirects, rejected connections |
| Rotate Secret | One-click secret rotation (with confirmation) |

### Installation

#### Requirements

- Ubuntu 22.04+ / Debian 12+
- 1 vCPU, 1 GB RAM (2 GB recommended)
- Public IPv4 address
- Port 443 available

#### Quick Start

```bash
git clone https://github.com/meissah26/mtproto-secure-proxy.git /opt/mtproto-proxy
cd /opt/mtproto-proxy
chmod +x scripts/install.sh
sudo ./scripts/install.sh
```

#### Configuration

```bash
# Change FakeTLS domain (default: www.microsoft.com)
export CLOAK_DOMAIN=www.google.com

# Override auto-detected IP
export SERVER_IP=1.2.3.4

sudo -E ./scripts/install.sh
```

### Management

```bash
cd /opt/mtproto-proxy

# Status
docker compose ps

# MTG logs
docker compose logs -f mtg

# Restart
docker compose restart

# Stop
docker compose down
```

### Project Structure

```
/opt/mtproto-proxy/
├── docker-compose.yml        # Service orchestration
├── mtg-config.toml           # mtg configuration (generated by install.sh)
├── .env                      # DASHBOARD_SECRET (generated by install.sh)
├── nginx/
│   ├── nginx.conf            # Nginx config for cloak
│   └── certs/                # TLS certificates (generated by install.sh)
├── monitoring/
│   ├── Dockerfile
│   ├── app.py                # Dashboard backend (aiohttp + conntrack)
│   └── templates/
│       └── dashboard.html    # Dashboard frontend
├── landing-static/           # Static masquerade website
├── scripts/
│   └── install.sh            # Installer
├── keys/                     # SSH keys (generated by install.sh)
└── CONNECTION_INFO.txt       # Connection strings (generated by install.sh)
```

### Security

- SSH: key-only authentication (password disabled)
- UFW firewall: only ports 22, 443, 9090 open
- Kernel hardening via sysctl
- Dashboard: secret URL access only
- Port 8444 (nginx cloak) not exposed externally
- Docker socket read-only in monitoring container
- Secret rotation with double confirmation (accidental click protection)

### License

MIT License
