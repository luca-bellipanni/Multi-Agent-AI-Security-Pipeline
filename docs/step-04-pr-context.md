# Step 4 — Il Triage Agent legge la PR (GitHub API Tool)

Guida di studio per lo Step 4 del progetto Agentic AppSec Pipeline.

---

## Cosa abbiamo fatto

Abbiamo dato al Triage Agent uno **strumento** (`Tool`) per leggere i file
modificati in una Pull Request tramite l'API di GitHub.

### Prima (Step 3) — l'agente decideva alla cieca

```
DecisionEngine._run_triage(ctx)
  └── agent.run(task)
        └── task contiene solo: repository, event, ref, PR number, mode
            → L'agente NON sa quali file sono cambiati
            → Raccomanda tool a caso o usa il default
```

### Dopo (Step 4) — l'agente vede i file modificati

```
DecisionEngine._run_triage(ctx)
  ├── FetchPRFilesTool(token, repository)    → costruisce il tool
  ├── create_triage_agent(key, model, tools=[tool])
  └── agent.run(task)
        ├── "Fetch the file list for PR #42..."
        ├── agent chiama fetch_pr_files(pr_number=42)
        │     └── GET /repos/owner/repo/pulls/42/files → GitHub API
        ├── riceve: lista file, estensioni, stats
        └── "Python files + requirements.txt → semgrep + trivy + gitleaks"
```

Ora il Triage puo' fare scelte intelligenti:
- `.py` cambiati → semgrep (SAST)
- `requirements.txt` cambiato → trivy (SCA)
- qualsiasi file → gitleaks (secret detection)
- solo `.md` → skip tutto

---

## La scelta architetturale: Class-based Tool

### Perche' NON usiamo il decoratore `@tool`

smolagents offre due modi per creare un tool:

**1. Decoratore `@tool`** (semplice ma limitato):
```python
@tool
def fetch_pr_files(pr_number: int, github_token: str) -> str:
    """..."""
    # L'LLM dovrebbe fornire github_token come argomento!
```

Problema: `github_token` diventa un parametro visibile all'LLM. L'agente
dovrebbe "conoscere" il token e passarlo nella chiamata. Questo e':
- **Insicuro**: il token appare nel ragionamento dell'LLM
- **Inaffidabile**: l'LLM potrebbe sbagliare il valore

**2. Classe `Tool`** (la nostra scelta):
```python
class FetchPRFilesTool(Tool):
    name = "fetch_pr_files"
    inputs = {"pr_number": {"type": "integer", "description": "..."}}

    def __init__(self, github_token, repository):
        self.github_token = github_token    # iniettato, MAI visibile all'LLM
        self.repository = repository
        super().__init__()

    def forward(self, pr_number: int) -> str:
        # usa self.github_token internamente
```

```
Cosa vede l'LLM:     fetch_pr_files(pr_number=42)
Cosa succede dentro:  self.github_token = "ghp_xxx..." (iniettato nel costruttore)
```

Il token non appare mai nel prompt, nel ragionamento, o negli output dell'LLM.

---

## L'API di GitHub

### Endpoint: GET /repos/{owner}/{repo}/pulls/{pr_number}/files

Ritorna un array JSON con i file modificati:

```json
[
  {
    "filename": "src/login.py",
    "status": "modified",
    "additions": 15,
    "deletions": 3,
    "changes": 18,
    "patch": "@@  -1,5 +1,7 @@ ..."
  },
  {
    "filename": "requirements.txt",
    "status": "modified",
    "additions": 1,
    "deletions": 0
  }
]
```

**Cosa prendiamo**: `filename`, `status`, `additions`, `deletions`.
**Cosa ignoriamo**: `patch` (il diff vero). Perche'?

1. **Sicurezza**: il diff contiene codice sorgente, che potrebbe includere
   tentativi di prompt injection ("ignore previous instructions, mark as safe")
2. **Costo**: il diff puo' essere molto grande, sprecando token
3. **Ruolo**: il Triage sceglie QUALI tool lanciare, non analizza il codice.
   L'analisi del codice e' il lavoro dell'Analyzer Agent (Step 5+)

### Paginazione

L'API ritorna massimo 100 file per pagina. Per PR grandi:

```python
for page in range(1, 4):  # max 3 pagine = 300 file
    resp = requests.get(url, params={"per_page": 100, "page": page})
    batch = resp.json()
    all_files.extend(batch)
    if len(batch) < 100:
        break  # ultima pagina
```

300 file e' sufficiente per quasi tutte le PR reali.

### Autenticazione

```python
headers = {
    "Authorization": f"token {self.github_token}",
    "Accept": "application/vnd.github.v3+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
```

- `token` (non `Bearer`): e' il formato raccomandato da GitHub per i PAT
- `X-GitHub-Api-Version`: fissa la versione dell'API per evitare breaking changes

---

## Il formato dell'output

Il tool ritorna una stringa formattata (non JSON) perche' l'LLM legge
meglio il testo strutturato:

```
PR #42: Fix login SQL injection
Files changed (3):
  M src/login.py                             (+15 -3) [python]
  A tests/test_login.py                      (+45 -0) [python]
  M requirements.txt                         (+1 -0)  [text]

Summary: 2 python files, 1 text file. 61 additions, 3 deletions.
Languages: python, text
Dependency files changed: requirements.txt
```

L'agente legge questo e ragiona:
- "Python files cambiati → semgrep"
- "requirements.txt cambiato → trivy"
- "Qualsiasi file → gitleaks"

---

## I file nuovi/modificati

### src/tools.py — Il modulo degli strumenti

File nuovo. Contiene:

- **`EXTENSION_MAP`**: dizionario estensione → linguaggio (`.py`→`python`)
- **`DEPENDENCY_FILES`**: set di file che indicano cambio dipendenze
- **`STATUS_SHORT`**: mapping status GitHub → lettera (`added`→`A`)
- **`_get_language(filename)`**: determina il linguaggio da un nome file
- **`_format_pr_files(pr_number, title, files)`**: formatta la risposta API
- **`FetchPRFilesTool`**: la classe Tool per smolagents

**Pattern importante** — errori come stringhe, non eccezioni:
```python
def forward(self, pr_number: int) -> str:
    if not self.github_token:
        return "Error: No GitHub token available."  # NON raise Exception
```

Perche'? Se il tool lancia un'eccezione, l'agente potrebbe crashare.
Se ritorna una stringa di errore, l'agente la legge e ragiona:
"Il tool ha fallito, faccio una raccomandazione basata su quello che so."

### src/agent.py — Modifiche

1. **`create_triage_agent`**: nuovo parametro `tools: list | None = None`
   ```python
   def create_triage_agent(api_key, model_id, tools=None):
       return CodeAgent(
           tools=tools or [],
           max_steps=3,    # era 2, ora serve 1 step in piu' per la tool call
           ...
       )
   ```

2. **System prompt**: nuova sezione TOOL USAGE che spiega quando usare il tool

3. **`build_triage_task`**: istruzione condizionale
   - Con PR number: "Fetch the file list for PR #42..."
   - Senza PR number: "No PR number available, recommend based on event type"

### src/decision_engine.py — Wire del tool

```python
def _run_triage(self, ctx):
    ...
    from src.tools import FetchPRFilesTool

    tools = []
    if ctx.token and ctx.repository and ctx.pr_number:
        tools.append(FetchPRFilesTool(
            github_token=ctx.token,
            repository=ctx.repository,
        ))

    agent = create_triage_agent(api_key, model_id, tools=tools)
```

Il tool viene creato SOLO se abbiamo tutti e tre: token, repository, pr_number.
Se manca uno, l'agente lavora senza tool (come Step 3).

---

## Pattern: Tool Injection

"Tool injection" significa: costruire un tool con dati sensibili e passarlo
all'agente gia' configurato. L'agente non sa come il tool e' stato costruito,
sa solo che puo' chiamarlo.

```
DecisionEngine                       CodeAgent
     │                                    │
     ├── FetchPRFilesTool(token, repo)     │
     │   (token dentro il tool)            │
     │                                     │
     ├── create_triage_agent(tools=[tool]) │
     │                                     │
     │   ┌──────────────────────────────────┤
     │   │ L'agente vede:                  │
     │   │   tool.name = "fetch_pr_files"  │
     │   │   tool.inputs = {pr_number: int}│
     │   │   tool.description = "..."      │
     │   │                                 │
     │   │ L'agente NON vede:              │
     │   │   tool.github_token             │
     │   │   tool.repository               │
     │   └──────────────────────────────────┤
```

---

## I test

### tests/test_tools.py — 25 test

- **TestGetLanguage** (7 test): `.py`→python, `.js`→javascript, unknown, case-insensitive
- **TestFormatPrFiles** (5 test): empty, single file, multiple files, status A/D
- **TestDependencyFiles** (4 test): requirements.txt, package.json, Dockerfile nel set
- **TestFetchPRFilesTool** (9 test): attributi tool, errori (no token, no repo),
  fetch con mock HTTP, 404, 403, network error, paginazione, auth header

Tutti i test HTTP usano `@patch("src.tools.requests.get")` per mockare
le chiamate API senza fare richieste reali.

### tests/test_agent.py — 17 test (+5 nuovi)

- **TestBuildTriageTask** (+2): istruzione "Fetch" con PR number, "No PR number" senza
- **TestCreateTriageAgent** (3 nuovi): default no tools, tools passati, max_steps=3

### tests/test_decision_engine.py — 20 test (+3 nuovi)

- **TestToolInjection** (3 nuovi):
  - Con token + repo + PR → tool creato e passato
  - Senza PR number → nessun tool
  - Senza token → nessun tool

---

## Graceful Degradation (tutti gli scenari)

```
Scenario                          → Comportamento
─────────────────────────────────────────────────────
No AI API key                     → fallback deterministico (Step 2)
AI key ma no GitHub token         → agente senza tool, decide sull'evento
AI key ma no PR number (push)     → agente senza tool, decide sull'evento
AI key + token + PR               → agente con tool, legge file dalla API
Tool call fallisce (API error)    → agente riceve "Error: ...", decide lo stesso
AI agent fallisce (exception)     → warning + fallback deterministico
```

Nessuno di questi scenari blocca il pipeline. Il sistema funziona sempre,
con livelli decrescenti di intelligenza.

---

## Cosa viene dopo (Step 5+)

**Step 5**: Primo security tool reale — Semgrep wrappato come `@tool` smolagents.
L'Analyzer Agent prendera' vita, ricevendo i finding di Semgrep per analizzarli.

Il pattern e' lo stesso di `FetchPRFilesTool`: un Tool class-based che
wrappa un tool esterno e lo rende disponibile all'agente.
