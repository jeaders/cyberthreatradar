# 🛡️ Cyber Threat Intelligence Dashboard

Una dashboard completa per la Cyber Threat Intelligence, costruita come applicazione web statica. Si aggiorna automaticamente ogni giorno tramite GitHub Actions, raccogliendo dati da fonti pubbliche e gratuite, senza necessità di backend o API a pagamento.

## 🌟 Caratteristiche

- **Zero Backend:** Completamente statica (HTML, CSS, JS).
- **Aggiornamento Automatico:** Utilizza GitHub Actions per eseguire uno script Python ogni giorno alle 07:00 UTC.
- **Fonti Dati Gratuite:**
  - NVD NIST API (Vulnerabilità critiche e alte).
  - CISA KEV (Known Exploited Vulnerabilities).
  - HackerNews (Top stories filtrate per parole chiave di sicurezza).
  - Reddit r/netsec (Top post del giorno).
- **Interfaccia Dark Theme:** Design moderno e responsive.
- **Filtri Avanzati:** Filtra per severità CVSS, vendor/tecnologia e sorgente.

## 🚀 Setup e Deploy su Netlify

### 1. Preparazione del Repository GitHub
1. Crea un nuovo repository su GitHub.
2. Carica tutti i file di questo progetto nel tuo nuovo repository.

### 2. Configurazione di GitHub Actions
Il workflow è già configurato nel file `.github/workflows/daily_update.yml`.
Per permettere alla Action di fare commit e push dei nuovi dati:
1. Vai su **Settings** del tuo repository GitHub.
2. Seleziona **Actions** > **General**.
3. Scorri fino a **Workflow permissions**.
4. Seleziona **Read and write permissions** e clicca su **Save**.

*Nota: Non sono necessari "Secrets" per le API attuali poiché tutte le fonti utilizzate sono pubbliche e non richiedono autenticazione.*

### 3. Deploy su Netlify
1. Crea un account gratuito su [Netlify](https://www.netlify.com/).
2. Clicca su **Add new site** > **Import an existing project**.
3. Seleziona **GitHub** e autorizza Netlify.
4. Scegli il repository che hai appena creato.
5. Nelle impostazioni di build:
   - **Base directory:** (lascia vuoto)
   - **Build command:** (lascia vuoto, è un sito statico)
   - **Publish directory:** (lascia vuoto o inserisci `/` se richiesto, poiché `index.html` è nella root)
6. Clicca su **Deploy site**.

Ora, ogni volta che GitHub Actions aggiornerà i file JSON nella cartella `data/`, Netlify rileverà il push e aggiornerà automaticamente il sito live!

## 🛠️ Sviluppo Locale

Per testare il progetto in locale:

1. Clona il repository.
2. Installa le dipendenze Python:
   ```bash
   pip install -r requirements.txt
   ```
3. Esegui lo script per recuperare i dati (o usa i dati mock):
   ```bash
   python scripts/fetch_data.py
   ```
   *(In alternativa, puoi eseguire `python scripts/mock_data.py` per generare dati di test rapidi).*
4. Apri il file `index.html` nel tuo browser.

## ➕ Come aggiungere nuove fonti dati

Se desideri aggiungere nuove fonti di intelligence in futuro:

1. Apri `scripts/fetch_data.py`.
2. Crea una nuova funzione `fetch_nuova_fonte_data()`.
3. Richiama la funzione all'interno di `main()` e aggiungi i risultati ai dizionari `threats_data` o `news_data`.
4. Apri `app.js` e aggiorna le funzioni `renderThreats()` o `renderNews()` per gestire e visualizzare i nuovi dati.
5. Fai commit e push delle modifiche.

## 📄 Licenza

Questo progetto è open-source e disponibile sotto licenza MIT.
