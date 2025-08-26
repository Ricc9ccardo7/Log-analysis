
**head note: Questo progetto nasce come compito universitario per la `University of the People`. Attualmente lo sto traducendo dall'inglese all'italiano ...la directory è ancora in fase di completamento.

# Correlazione Log — Analisi di Incidenti

##  Informazioni sul Progetto

In questo progetto lavoro con un insieme misto di log raccolti da diversi livelli di un ambiente simulato, tra cui:

- Log del web server 
- Log del proxy
- Log del firewall
- Log del server applicativo
- Log dei processi 
- Log di sicurezza e monitoraggio
- E altri artefatti a livello di sistema

Ogni caso inizia con un'alarm di attacco, simulando come un SIEM potrebbe avvisare un analista su un’attività sospetta.

Da lì, il mio compito è tracciare manualmente tutti i movimenti dell’attaccante, correlando:
- Eventi nei log grezzi
- Timestamps, PID, UID, contenuto dei comandi, IP sorgente
- Tutta la catena dell’attacco ... dall’accesso iniziale all’escalation, esfiltrazione e persistenza

---

##  Obiettivo 

Il focus principale è sulla `**correlazione dei log** `

Non mi limito a raccontare cosa è successo, ma spiego come l’ho scoperto.

Invece di usare un linguaggio formale da report professionale, ogni indagine è scritta in stile diario personale Spiego passo per passo:
- Cosa cercavo
- Perché ho controllato certi log
- Come ho verificato e collegato gli eventi
- Su cosa si basavano le mie decisioni

Lo scopo è mostrare il ragionamento dietro ogni passaggio, non solo il risultato finale.

---

##  Struttura dei File

- `cases/` — Analisi strutturate degli scenari 
- `logs/` — Contiene i log grezzi usati nei vari casi.
- `README.md` — Questo file.

