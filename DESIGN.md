# Document de Design — Network Packet Sniffer & Mini-IDS

## 1. Arhitectura sistemului

Aplicația este construită pe o arhitectură modulară orientată pe flux de date (*packet-processing pipeline*), folosind biblioteca `libpcap` pentru captura pachetelor brute de la nivelul interfeței de rețea (mod live) sau din fișiere `.pcap` (mod offline).

```text
[Interfață rețea (-i) / Fișier .pcap (-f)]
                     │
                     ▼
        [Modul Captură (libpcap)]
                     │
                     ▼
          [Parser Protocoale] ──► Ethernet → IPv4 / ARP → TCP / UDP / ICMP
                     │
                     ├──► [Motor Reguli (rules/test.conf)] ──► Alerte Snort-style
                     ├──► [Detector Atacuri (IDS)]         ──► Port Scan / SYN Flood / ARP Spoofing
                     └──► [Statistici Trafic]              ──► Raport final (SIGINT / EOF)
```

### Componente principale
- **Captura de pachete (`libpcap`):** deschide sesiunea de captură prin `pcap_open_live()` (mod promiscuu) sau `pcap_open_offline()` și pasează fiecare cadru către funcția callback prin `pcap_loop()`.
- **Decapsulare și parsare protocoale (`include/headers.h`, `src/main.cpp`):** interpretează buffer-ul brut (`const u_char *packet`) strat cu strat, convertind câmpurile din *network byte order* (Big-Endian) în *host byte order* prin `ntohs()` / `ntohl()`.
- **Motorul de reguli (`load_rules` / `check_rules`):** încarcă semnături externe la pornire și evaluează fiecare pachet IPv4 (TCP, UDP, ICMP) împotriva listei de reguli.
- **Modulul de detecție a anomaliilor (IDS):** menține stări în memorie (tabele de mapare per IP sursă și tabela ARP) pentru a identifica comportamente malițioase în timp real.
- **Raportare și oprire controlată:** interceptează semnalul `SIGINT` (`Ctrl+C`) pentru a opri bucla `pcap_loop()` curat (`pcap_breakloop()`) și a afișa sumarul statisticilor de trafic.

---

## 2. Parsarea protocoalelor (Decapsulare)

Fiecare pachet capturat este decapsulat secvențial prin avansarea unui pointer peste headerele protocoalelor definite în `include/headers.h`:

| Strat OSI | Protocol | Lungime Header | Câmpuri inspectate |
| :--- | :--- | :--- | :--- |
| **Layer 2** | Ethernet | 14 octeți (fix) | `ether_type` (`0x0800` = IPv4, `0x0806` = ARP), adrese MAC sursă/destinație |
| **Layer 2/3** | ARP | 28 octeți (IPv4/Eth) | Operație (Request/Reply), IP sursă (`spa`), MAC sursă (`sha`) |
| **Layer 3** | IPv4 | `ihl * 4` (20–60 octeți) | IP sursă (`saddr`), IP destinație (`daddr`), `protocol` (`6`=TCP, `17`=UDP, `1`=ICMP) |
| **Layer 4** | TCP | `doff * 4` (min. 20 octeți) | Port sursă, port destinație, flag-uri de control (`SYN`, `ACK`) |
| **Layer 4** | UDP | 8 octeți (fix) | Port sursă, port destinație, lungime |
| **Layer 4** | ICMP | 8 octeți | Tip mesaj (ex: Echo Request / Reply) |

---

## 3. Logica de detecție IDS

Sistemul implementează detecție bazată pe **semnături** (reguli configurabile) și detecție bazată pe **anomalii comportamentale**:

### 3.1. Port Scanning (SYN Scan)
- **Mecanism:** Monitorizează pachetele TCP care au setat flag-ul `SYN` fără `ACK`.
- **Structură de date:** Pentru fiecare IP sursă, se reține mulțimea porturilor destinație distincte accesate într-o fereastră de timp.
- **Condiție de alertă:** Dacă un IP sursă trimite pachete `SYN` către un număr de porturi distincte care depășește pragul configurat în fereastra de timp curentă, se emite o alertă de tip *Port Scan*.

### 3.2. SYN Flood (DoS)
- **Mecanism:** Monitorizează rata de pachete TCP `SYN` (fără `ACK`) provenite de la același IP sursă.
- **Structură de date:** Contor per IP sursă asociat cu un timestamp de început al ferestrei de timp.
- **Condiție de alertă:** Depășirea pragului de pachete `SYN` pe intervalul de timp stabilit declanșează alerta de *SYN Flood*.

### 3.3. ARP Spoofing (MITM)
- **Mecanism:** Inspectează pachetele ARP (`ether_type == 0x0806`) și extrage perechea `(IP sursă, MAC sursă)`.
- **Structură de date:** Tabelă dinamică `arp_table` (`IP → MAC`).
- **Condiție de alertă:** La prima apariție a unui IP, adresa MAC este înregistrată ca legitimă. Dacă ulterior același IP este anunțat cu o adresă MAC diferită, se declanșează imediat alerta de *ARP Spoofing*.

---

## 4. Formatul fișierului de reguli

Regulile IDS sunt definite într-un fișier text extern (ex: `rules/test.conf`) transmis prin flag-ul `-R`.

### Sintaxă
```text
<PROTOCOL> <SRC_IP> <DST_PORT> <MESAJ_ALERTA>
```

- **`PROTOCOL`:** `TCP`, `UDP` sau `ICMP`.
- **`SRC_IP`:** adresă IPv4 specifică (ex: `172.20.0.20`) sau wildcard `any`.
- **`DST_PORT`:** număr de port (ex: `23`, `53`) sau wildcard `any` (obligatoriu `any` pentru `ICMP`).
- **`MESAJ_ALERTA`:** textul afișat la potrivirea regulii.
- Liniile goale și comentariile (care încep cu `#`) sunt ignorate.

### Exemplu
```text
# FORMAT: PROTOCOL SRC_IP DST_PORT MESAJ
TCP any 23 Telnet connection detected
TCP any 21 FTP traffic detected
UDP any 53 DNS query detected
ICMP any any ICMP Ping detected
```

---

## 5. Topologia mediului de testare (Docker)

Pentru a permite testarea sigură și reproductibilă a atacurilor de rețea fără a afecta rețeaua fizică a host-ului, proiectul folosește Docker Compose cu o rețea bridge izolată:

```text
                Rețea Docker Bridge: lab_net (172.20.0.0/24)
                            Gateway: 172.20.0.1
                                     │
                 ┌───────────────────┴───────────────────┐
                 │                                       │
       [Container: victim]                     [Container: attacker]
         IP: 172.20.0.10                         IP: 172.20.0.20
       Imagine: debian-slim                    Imagine: debian-slim
    Rulează: ./sniffer (IDS)             Unelte: nmap, hping3, dsniff, nc
```

### Decizii de infrastructură
- **Capabilități Linux (`NET_RAW`, `NET_ADMIN`):** atribuite ambelor containere pentru a permite capturarea pachetelor în mod promiscuu (`libpcap`) și generarea de pachete raw (`nmap -sS`, `hping3`, `arpspoof`), fără a rula containerele în mod `--privileged`.
- **Mod offline (`-f <fisier.pcap>`):** permite validarea logicii de parsare și a detecției IDS pe capturi preînregistrate, fără a necesita privilegii `root` sau acces la o interfață de rețea activă.