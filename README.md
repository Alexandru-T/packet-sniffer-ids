# Network Packet Sniffer & Mini-IDS

Sniffer de rețea și sistem ușor de detecție a intruziunilor (IDS) scris în C++ folosind `libpcap`.
Aplicația capturează și analizează trafic live, aplică reguli personalizate în stil Snort și detectează
atacuri uzuale de rețea (Port Scanning, SYN Flood, ARP Spoofing).

## Funcționalități

- **Parsare protocoale:** Ethernet, IPv4, TCP, UDP, ICMP, ARP.
- **Motor de reguli (Snort-style):** încărcare reguli dintr-un fișier extern (`rules/test.conf`) cu filtrare după protocol, IP sursă și port destinație.
- **Detecție atacuri:**
  - **Port Scanning** (detecție scanări SYN pe multiple porturi).
  - **SYN Flood** (detecție rată anormală de pachete SYN).
  - **ARP Spoofing** (monitorizare dinamică a tabelei IP–MAC).
- **Raportare:** afișare statistici de trafic la oprirea aplicației (`Ctrl+C`).

## Structura proiectului

```text
.
├── .github/workflows/ci.yml   # Pipeline CI (build -Wall -Werror, cppcheck)
├── docker/                    # Dockerfile-uri pentru mediul de test (victim & attacker)
├── include/                   # Headere C++ (structuri protocoale, declarații)
├── rules/                     # Fișiere de reguli IDS (ex: test.conf)
├── src/                       # Cod sursă C++
├── CHANGELOG.md
├── docker-compose.yml         # Orchestrare rețea virtuală izolată
└── Makefile

```

## Rulare rapidă cu Docker (Recomandat)

Mediul Docker pornește două containere izolate într-o rețea bridge dedicată (`172.20.0.0/24`):
- **`victim`** (`172.20.0.10`) — compilează și rulează sniffer-ul/IDS.
- **`attacker`** (`172.20.0.20`) — conține unelte de generare trafic și simulare atacuri (`nmap`, `hping3`, `dsniff`, `netcat`).

### 1. Pornirea mediului
```bash
docker compose up -d --build
```
*(Pe sistemele cu versiunea veche de Compose, folosește `docker-compose up -d --build`.)*

### 2. Pornirea sniffer-ului pe `victim`
```bash
docker exec -it victim bash
./sniffer -i eth0 -R rules/test.conf
```

### 3. Simularea atacurilor din `attacker`
Deschide un al doilea terminal și intră în containerul `attacker`:
```bash
docker exec -it attacker bash
```

Comenzi de test:
- **Testare reguli (ICMP / Telnet / FTP / DNS):**
  ```bash
  ping -c 3 172.20.0.10
  nc -zv -w 1 172.20.0.10 23
  nc -zv -w 1 172.20.0.10 21
  nc -zvu -w 1 172.20.0.10 53
  ```
- **Port Scan:**
  ```bash
  nmap -sS -p 1-100 172.20.0.10
  ```
- **SYN Flood:**
  ```bash
  hping3 -S -p 80 --fast -c 100 172.20.0.10
  ```
- **ARP Spoofing** *(pentru detecție imediată, rulează mai întâi `ping -c 1 172.20.0.10` de pe host ca `victim` să înregistreze MAC-ul legitim al gateway-ului `172.20.0.1`)*:
  ```bash
  arpspoof -i eth0 -t 172.20.0.10 172.20.0.1
  ```

### 4. Oprirea și curățarea mediului
```bash
docker compose down
```

## Compilare și rulare locală (Linux)

### Dependințe
```bash
sudo apt update && sudo apt install -y g++ make libpcap-dev cppcheck
```

### Build & Run
```bash
make

# Captură live de pe o interfață de rețea
sudo ./sniffer -i <interfata> -R rules/test.conf

# Analiză offline dintr-un fișier .pcap
./sniffer -f captura.pcap -R rules/test.conf
```

### Argumente CLI
| Flag | Descriere | Exemplu |
| :--- | :--- | :--- |
| `-i` | Interfața de rețea pe care se face captura | `-i eth0` |
| `-R` | Calea către fișierul de reguli IDS | `-R rules/test.conf` |
| `-f` | Fișier `.pcap` pentru analiză offline | `-f test.pcap` |

## Formatul fișierului de reguli

Fiecare linie din `rules/test.conf` respectă formatul `PROTOCOL SRC_IP DST_PORT MESAJ`:

```text
# FORMAT: PROTOCOL SRC_IP DST_PORT MESAJ
TCP any 23 Telnet connection detected
TCP any 21 FTP traffic detected
UDP any 53 DNS query detected
ICMP any any ICMP Ping detected
```

## CI & Calitatea codului

La fiecare Pull Request, pipeline-ul GitHub Actions (`.github/workflows/ci.yml`) verifică automat:
- Compilare fără warning-uri (`-Wall -Werror`).
- Analiză statică cu `cppcheck`.