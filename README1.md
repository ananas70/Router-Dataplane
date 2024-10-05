
# Dataplane Router README

Acest README oferă o prezentare generală a implementării dataplane-ului routerului și descrie funcționalitatea din codul sursă.


## Structura Fișierelor

Sunt prezente mai multe fișiere de bază, printre care:
- `queue.h`: Fișierul header pentru o implementare generică a cozii (structură folosită pentru `arp_queue`, coada pachetelor ce așteaptă un ARP reply).
- `lib.h`
- `protocols.h`: Fișierul header care definește constantele și structurile protocolului. Am adăugat și alte macrodefiniții ( `ETHERTYPE_IPv4`  `ETHERTYPE_ARP ` `ICMP_PROTOCOL` `ICMP_DATA_SIZE`  `ETH_IP_ICMP_SIZE` )
- `router.c`: Fișierul principal care conține implementarea routerului.

## Prezentare generală

Routerul îndeplinește următoarele funcții principale:
1. Primește pachetele.
2. Procesează pachetele primite, inclusiv verificarea sumelor de control, TTL-ul și efectuarea căutărilor în tabela de rutare.
3. Transmite pachetele pe baza intrărilor din tabela de rutare.
4. Gestionează cererile ARP și menține o memorie cache ARP.
5. Răspunde la mesajele ICMP, inclusiv cererile de ecou și erori.

## Detalii Funcționale

### check_memory_allocation

Această funcție verifică dacă alocarea memoriei a fost reușită. Dacă alocarea memoriei eșuează (adică `buf` este `NULL`), se afișează un mesaj de eroare și se închide programul.

### search_MAC_in_ARP_table

Această funcție caută o adresă MAC corespunzătoare unei adrese IP date în tabela ARP. Dacă se găsește o potrivire, se returnează adresa MAC; în caz contrar, se returnează `NULL`.

### parse_waiting_ARP

Această funcție iterează în coada ARP a pachetelor ce așteaptă reply. Dacă se găsește o adresă MAC potrivită în memoria cache ARP, se transmite pachetul; în caz contrar, pachetul scos din coadă este readus în coadă și se așteaptă răspunsul ARP pentru el.

### enqueue_ARP_packet

Această funcție înscrie un pachet ARP în coada de așteptare pentru procesare ulterioară. Este apelată atunci când se trimite o cerere ARP și adresa MAC corespunzătoare nu este găsită în memoria cache ARP.

### respond_with_ARP_reply

Această funcție construiește și trimite un răspuns ARP în urma unei cereri ARP. Se actualizează memoria cache ARP cu adresa MAC a expeditorului.

### send_ARP_request

Această funcție trimite o cerere ARP pentru a rezolva adresa MAC corespunzătoare unei adrese IP date. Este apelată atunci când adresa MAC nu este găsită în memoria cache ARP.

### update_arp_table

Această funcție actualizează memoria cache ARP cu o nouă intrare (mapare IP-MAC) sau actualizează o intrare existentă cu o nouă adresă MAC.

### comparator

Această funcție este un comparator utilizat pentru sortarea intrărilor din tabela de rutare. Sortează intrările după prefix și mască în ordine descrescătoare.

### search_route

Această funcție caută o intrare corespunzătoare în tabela de rutare pe baza adresei IP destinație. Dacă se găsește o potrivire, se returnează intrarea și interfața corespunzătoare. Tabela de rutare este sortată anterior apelării funcției `search_route`.

### send_ICMP_reply

Această funcție construiește și trimite un răspuns ICMP în urma unei cereri ICMP de tip "Echo Request". Funcția primește pachetul vechi, îi creează o copie căreia îi modifică valorile anumitor câmpuri (Ethernet Header, TTL, checksum) și îi adaugă datele care se aflau deasupra antetului ICMP în pachetul original.

### send_ICMP_error

Această funcție construiește și trimite un mesaj ICMP de eroare ( expirarea TTL-ului, destinație inaccesibilă).

