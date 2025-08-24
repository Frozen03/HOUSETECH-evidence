# HOUSETECH Ops — FINAL

## Kaj je v tej verziji
- Prijava z Google (GIS) → backend preveri ID token in izda JWT z vlogami.
- **Owner/CEO**:
  - vidita zavihek **Admin** (upravljanje uporabnikov/ projektov),
  - vidita levi seznam projektov v **Dnevnik del**,
  - vidita zavihek **Poročila**.
- Navadni uporabniki:
  - ne vidijo Admin, ne vidijo Poročila,
  - v Dnevnik del ne vidijo levega projektnega panela.
- **Dnevnik del** podpira **več materialov** na vnos (Dodaj material).
- “Prijava” gumb izgine po uspešni prijavi; pokaže se **Odjava**.

## Zagon
1) `server/.env`:
```
PORT=8787
GOOGLE_CLIENT_ID=REPLACE_WITH_YOUR_CLIENT_ID.apps.googleusercontent.com
JWT_SECRET=change_me_to_long_random_string
```
2) Backend:
```
cd server
npm i
npm start
```
3) Frontend: postrezi `web/index.html` (npr. `http-server` ali Live Server) na `http://localhost:5500/`.

## Opombe
- Vloge so seedane v `server/server.js` (ROLE_MAP) in tudi v `db/schema_roles.sql`.
- Shranjevanje ur in dnevnikov je lokalno (localStorage) – lahko nadgradimo na Postgres.
© 2025 HOUSETECH
