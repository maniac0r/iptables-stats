# iptables-map

Mapa pravidiel firewallu z `iptables-save`: každý chain je box, čiary vedú z pravidla (skok -j/-g)
do chainu, ktorý volá. Boxy sa zbaľujú klikom na hlavičku.

## Spustenie

    iptables-save -c > rules/iptables.rules      # -c pridá počítadlá paketov
    docker compose up -d --build     # po zmene súborov v static/ stačí obnoviť stránku (je mountnuté)
    # http://localhost:8080

Súbor sa načíta pri otvorení stránky (tlačidlo ⟳ ho načíta znova, netreba reštart).
Môžeš tiež pretiahnuť súbor do okna, vložiť text (Ctrl+V) alebo použiť "Otvoriť súbor..." –
parsovanie beží v prehliadači.

## Farby

ACCEPT zelená, DROP červená, REJECT oranžová, SNAT/MASQUERADE fialová, DNAT/REDIRECT modrá,
MARK/CONNMARK ružová, RETURN sivá, LOG žltá, skok do chainu azúrová, ostatné tyrkysová.
Legenda hore je klikateľná (zvýrazní len daný typ pravidiel).

## Ovládanie

- klik na hlavičku chainu = zbaliť/rozbaliť; tlačidlá Zbaliť/Rozbaliť všetko
- klik na pravidlo = zalomí len toto pravidlo (celý text); klik znova ho vráti
- v hlavičke chainu: ⇔ roztiahne box na šírku (pravidlá na jeden riadok), ↵ zalomí všetky pravidlá v boxe
- hore: "široké boxy" (⇔ pre všetky), "zalamovať riadky" (↵ pre všetky)
- "skryť nezhodné": pri hľadaní/filtri podľa typu skryje nezhodné pravidlá aj chainy (zostane cesta k zhode)
- "čiary obchádzajú boxy": čiary vedú medzerami medzi stĺpcami, nie pod boxami
- hover nad boxom/pravidlom zvýrazní prepojené čiary
- Ctrl+koliesko = zoom, Fit = prispôsob šírke
- hľadanie (IP, port, comment) stlmí nezodpovedajúce pravidlá
- prerušovaná čiara = -g (goto), prerušovaný rámček = chain, ktorý nikto nevolá
- téma sa prepína podľa OS (svetlá/tmavá)
- "počítadlá": všetky / ≠ 0 (len použité pravidlá) / = 0 (nepoužité pravidlá); vyžaduje export cez iptables-save -c
- "⟳ auto" (1/5/10/30 s): pravidelne znova načíta súbor zo servera; ak sa zmenili len počítadlá, aktualizujú sa
  na mieste a pravidlá, kde pribudli pakety, krátko zablikajú (tooltip na čísle ukáže prírastok).
  Funguje len pre súbor zo servera, nie pre ručne otvorený/vložený text.
- ip6tables: stačí podstrčiť export z ip6tables-save
