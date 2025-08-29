# HOUSETECH Ops — FINAL v2

## Kaj je novega (CHANGELOG)

### 🆕 Nova verzija (2025-08)
- **Registracija prisotnosti**
  - Odstranjen obvezen izbor **projekta** → prihod/odhod/malica se beleži tudi brez projekta.
  - Gumbi **Odhod**, **Začetek malice**, **Konec malice**, **Ponovni prihod** niso več na voljo, če uporabnik trenutno ni prijavljen (samo začetni “Prihod”).
- **Dnevnik del**
  - Input polje za **Aktivnost** je podaljšano in povečano → primerno za daljše opise (npr. “Montaža stikal, vtičnic, vleka kablov, štemanje…”).
  - Pravice za urejanje in brisanje:
    - **Vsak uporabnik** lahko ureja/briše **svoje** dnevnike.
    - **Owner/CEO** lahko urejata/brišeta **vse** dnevnike.
- Ostalo
  - Čiščenje UI: odstranjena polja, ki niso več relevantna (npr. projekt v prisotnosti).
  - Popravki konsistence vlog (`Owner`, `CEO`, `vodja`, `zaposlen`, `študent`).

---

### 📦 Prejšnja verzija (2025-07)
- Prijava z Google (GIS) → backend preveri ID token in izda JWT z vlogami.
- **Owner/CEO**:
  - vidita zavihek **Admin** (upravljanje uporabnikov/projektov),
  - vidita levi seznam projektov v **Dnevnik del**,
  - vidita zavihek **Poročila**.
- Navadni uporabniki:
  - ne vidijo Admin, ne vidijo Poročila,
  - v Dnevnik del ne vidijo levega projektnega panela.
- **Dnevnik del** podpira **več materialov** na vnos (Dodaj material).
- “Prijava” gumb izgine po uspešni prijavi; pokaže se **Odjava**.

---

## 🚀 Zagon

1. Konfiguracija (`server/.env`):
   ```env
   PORT=8787
   GOOGLE_CLIENT_ID=REPLACE_WITH_YOUR_CLIENT_ID.apps.googleusercontent.com
   JWT_SECRET=change_me_to_long_random_string
