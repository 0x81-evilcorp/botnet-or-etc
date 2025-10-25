# TCP Bypass Methods

коллекция различных tcp bypass методов для обхода разных типов защиты.

## методы bypass

### 1. synack_bypass
**назначение:** обходит SYN flood protection
**что делает:** отправляет SYN+ACK пакеты
**обходит:** 
- SYN flood protection
- connection rate limiting
- basic firewall rules

### 2. psh_bypass  
**назначение:** обходит rate limiting
**что делает:** отправляет PSH+ACK пакеты с принудительной отправкой данных
**обходит:**
- rate limiting systems
- bandwidth throttling
- traffic shaping

### 3. urg_bypass
**назначение:** обходит DPI системы
**что делает:** отправляет URG+ACK пакеты с срочными данными
**обходит:**
- deep packet inspection (DPI)
- content filtering
- application layer firewalls

### 4. fin_bypass
**назначение:** обходит connection tracking
**что делает:** отправляет FIN+ACK пакеты для закрытия соединений
**обходит:**
- connection state tracking
- session management
- connection pooling

### 5. rst_bypass
**назначение:** обходит stateful firewalls
**что делает:** отправляет RST+ACK пакеты для сброса соединений
**обходит:**
- stateful firewalls
- connection state tables
- session tracking

### 6. combo_bypass
**назначение:** максимальный обход всех защит
**что делает:** отправляет пакеты со всеми tcp флагами (SYN+ACK+PSH+URG)
**обходит:**
- все вышеперечисленные защиты
- комбинированные системы защиты
- advanced firewall rules

### 7. lowrate_bypass
**назначение:** обходит rs media
**что делает:** использует feint-based low-rate атаки
**обходит:**
- rs media protection
- rate limiting systems
- traffic analysis

### 8. ml_bypass
**назначение:** обходит системы машинного обучения
**что делает:** создает adversarial примеры для обмана ML
**обходит:**
- ML-based protection systems
- anomaly detection
- behavioral analysis

### 9. handshake_flood
**назначение:** исчерпание сервера полными tcp handshake
**что делает:** создает множество полных tcp соединений с данными
**обходит:**
- connection limits
- tcp backlog
- server resources

### 10. connection_exhaust
**назначение:** исчерпание connection pool сервера
**что делает:** создает и удерживает множество соединений
**обходит:**
- connection pool limits
- server connection capacity
- resource exhaustion

## компиляция

```bash
make
```

## использование

```bash
# syn+ack bypass
sudo ./synack_bypass -i 192.168.1.1 -p 80 -d 60

# psh bypass  
sudo ./psh_bypass -i 192.168.1.1 -p 80 -d 60

# urg bypass
sudo ./urg_bypass -i 192.168.1.1 -p 80 -d 60

# fin bypass
sudo ./fin_bypass -i 192.168.1.1 -p 80 -d 60

# rst bypass
sudo ./rst_bypass -i 192.168.1.1 -p 80 -d 60

# combo bypass
sudo ./combo_bypass -i 192.168.1.1 -p 80 -d 60

# lowrate bypass (rs media)
sudo ./lowrate_bypass -i 192.168.1.1 -p 80 -d 60

# ml bypass (ML systems)
sudo ./ml_bypass -i 192.168.1.1 -p 80 -d 60

# handshake flood (tcp connections)
sudo ./handshake_flood -i 192.168.1.1 -p 80 -d 60

# connection exhaustion (connection pool)
sudo ./connection_exhaust -i 192.168.1.1 -p 80 -d 60
```

## аргументы

- `-i` - ip адрес цели
- `-p` - порт цели
- `-d` - длительность в секундах

## требования

- root права (для raw sockets)
- linux система
- clang или gcc компилятор

## особенности

- все методы используют raw sockets
- рандомизируют source ip, ports, seq/ack номера
- включают tcp options (mss, sack, timestamp, window scale)
- обходят разные типы защиты

## предупреждение

используй только для тестирования собственных систем или с разрешения владельца!
