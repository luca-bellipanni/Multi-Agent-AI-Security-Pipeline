# Step 1 — Come funziona una GitHub Action custom (Docker)

Guida di studio per lo Step 1 del progetto Agentic AppSec Pipeline.

---

## Il problema che risolviamo

La pipeline di sicurezza classica funziona cosi':

```
PR aperta
  → SAST scan (Semgrep, CodeQL, ...)
    → SCA scan (Trivy, Dependabot, ...)
      → Secret scan (Gitleaks, ...)
        → Analista rivede i finding
          → Security gate: pass/fail
```

Ogni tool gira sempre, su ogni PR, in sequenza. Risultato:
- **Tempo sprecato**: scan inutili su PR che toccano solo documentazione
- **Falsi positivi**: ogni tool genera rumore, l'analista deve filtrare tutto
- **Collo di bottiglia**: l'analista e' il gate umano su ogni PR

L'idea agentica: un AI "cervello" riceve la PR, guarda il diff, decide QUALI tool servono,
li esegue, analizza i risultati, e prende una decisione spiegata. Niente scan inutili,
niente analista su ogni PR.

Ma per arrivarci, prima dobbiamo capire come funziona una GitHub Action.

---

## Struttura del progetto (Step 1)

```
Appsec-Agentic-Pipeline/
├── action.yml          # 1. Il contratto: cosa entra, cosa esce
├── Dockerfile          # 2. Il container: ambiente di esecuzione
├── entrypoint.sh       # 3. Il ponte: shell → Python
├── src/
│   └── main.py         # 4. La logica: leggi input, decidi, scrivi output
└── README.md           # 5. La documentazione pubblica
```

Ogni file ha UN ruolo preciso. Vediamoli uno per uno.

---

## 1. action.yml — Il contratto

```yaml
name: 'Agentic AppSec Pipeline'
description: 'AI-driven application security analysis for pull requests'

inputs:
  github_token:
    description: 'GitHub token for API access'
    required: true
  mode:
    description: 'shadow (observe only) or enforce (can block the PR)'
    required: false
    default: 'shadow'

outputs:
  decision:
    description: 'Security verdict: allowed, manual_review, or blocked'
  continue_pipeline:
    description: 'true if the pipeline should continue, false if blocked'
  reason:
    description: 'Human-readable explanation of the decision'

runs:
  using: 'docker'
  image: 'Dockerfile'
  env:
    INPUT_GITHUB_TOKEN: ${{ inputs.github_token }}
    INPUT_MODE: ${{ inputs.mode }}
```

### Cosa fa

Questo file e' la **carta d'identita'** dell'action. GitHub lo legge per sapere:

- **Come si chiama** l'action (`name`)
- **Cosa accetta** in ingresso (`inputs`) — i parametri che il chiamante passa con `with:`
- **Cosa restituisce** (`outputs`) — i valori che lo step successivo legge con `${{ steps.appsec.outputs.xxx }}`
- **Come si esegue** (`runs`) — in questo caso, buildando un container Docker dal Dockerfile

### Concetti chiave

**Inputs e il prefisso INPUT_**

Quando un workflow passa `mode: shadow`, GitHub Actions crea una variabile d'ambiente
`INPUT_MODE=shadow` dentro il container. La convenzione e':
- nome input nel YAML: `mode`
- variabile d'ambiente nel container: `INPUT_MODE` (tutto maiuscolo, prefisso `INPUT_`)

Il blocco `env:` nel `runs` rende esplicito questo mapping. Non e' strettamente necessario
per Docker actions (GitHub lo fa automaticamente), ma lo scriviamo per chiarezza.

**Outputs e GITHUB_OUTPUT**

Gli output non sono "magici". Il nostro codice deve scrivere key=value in un file speciale
il cui path e' nella variabile `GITHUB_OUTPUT`. Esempio:

```
echo "decision=allowed" >> $GITHUB_OUTPUT
```

Dopo, il workflow chiamante puo' leggere il valore con `${{ steps.ID.outputs.decision }}`.

**Perche' Docker e non composite?**

Ci sono 3 tipi di action:
1. **JavaScript** — gira Node.js direttamente nel runner
2. **Composite** — una sequenza di step YAML (come un mini-workflow)
3. **Docker** — builda un container e ci esegue il codice dentro

Usiamo Docker perche' negli step futuri installeremo tool binari (Semgrep, Gitleaks, Trivy)
e SDK Python (per l'AI). Con Docker, l'ambiente e' riproducibile e isolato.
Con composite, dovresti installare tutto nel runner ogni volta.

---

## 2. Dockerfile — Il container

```dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY entrypoint.sh /app/entrypoint.sh
COPY src/ /app/src/

RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
```

### Cosa fa

Definisce l'ambiente dove il nostro codice gira. Quando l'action viene eseguita,
GitHub Actions:
1. Builda l'immagine Docker da questo file
2. Avvia un container dall'immagine
3. Monta il workspace del repo in `/github/workspace`
4. Inietta le variabili d'ambiente (INPUT_MODE, GITHUB_OUTPUT, ecc.)
5. Esegue l'ENTRYPOINT

### Riga per riga

**`FROM python:3.12-slim`**

Immagine base: Python 3.12 su Debian slim. "slim" significa senza compilatori e tool
di sviluppo — immagine piu' piccola (~150MB vs ~900MB per la versione completa).
Usiamo slim e non alpine perche' alpine usa musl libc che causa problemi con alcuni
pacchetti Python (es. wheels precompilati).

**`ENV PYTHONDONTWRITEBYTECODE=1`**

Dice a Python di non creare file `.pyc` (bytecode compilato). In un container
usa-e-getta non servono, risparmiano spazio e evitano confusione.

**`ENV PYTHONUNBUFFERED=1`**

Forza Python a stampare subito su stdout/stderr senza buffering. Senza questo flag,
i print() potrebbero non apparire nei log di GitHub Actions perche' il buffer non
viene flushato prima che il container si chiuda.

**`COPY entrypoint.sh /app/entrypoint.sh`** e **`COPY src/ /app/src/`**

Copia i nostri file dentro il container. L'ordine conta per il layer caching di Docker:
se cambi solo `src/`, Docker riusa il layer dell'entrypoint cachato.
(Negli step futuri, copieremo `requirements.txt` e faremo `pip install` PRIMA di copiare
il codice, cosi' le dipendenze vengono cachate.)

**`RUN chmod +x /app/entrypoint.sh`**

Rende lo script eseguibile. Senza questo, il container non puo' avviare l'entrypoint.

**`ENTRYPOINT ["/app/entrypoint.sh"]`**

Il comando che viene eseguito quando il container parte. Usiamo la forma exec
(array JSON), non la forma shell, perche' cosi' lo script riceve i segnali
direttamente (es. SIGTERM per shutdown pulito).

---

## 3. entrypoint.sh — Il ponte

```bash
#!/bin/bash
set -euo pipefail

# Mark workspace as safe for git operations inside the container
if [ -n "${GITHUB_WORKSPACE:-}" ]; then
    git config --global --add safe.directory "${GITHUB_WORKSPACE}"
fi

exec python /app/src/main.py
```

### Cosa fa

E' un wrapper sottilissimo tra Docker e Python. Perche' non chiamare Python direttamente
dall'ENTRYPOINT del Dockerfile? Due motivi:

1. **Setup pre-Python**: la riga `git config --global --add safe.directory` e'
   necessaria perche' il repo e' montato nel container come volume esterno.
   Git per sicurezza rifiuta di operare su directory owned da un utente diverso.
   Questo lo sblocca.

2. **Convenzione GitHub Actions**: la documentazione ufficiale raccomanda un shell
   entrypoint per Docker actions, perche' gestisce meglio l'espansione delle
   variabili e il passaggio degli argomenti.

### Riga per riga

**`set -euo pipefail`**

Tre flag di sicurezza bash:
- `-e`: esci immediatamente se un comando fallisce (exit code != 0)
- `-u`: errore se si usa una variabile non definita (previene bug silenziosi)
- `-o pipefail`: in una pipe `cmd1 | cmd2`, l'exit code e' quello del primo
  comando che fallisce (non solo dell'ultimo)

**`${GITHUB_WORKSPACE:-}`**

La sintassi `:-` e' un default bash: se `GITHUB_WORKSPACE` non e' definita,
usa stringa vuota invece di generare errore (che altrimenti `-u` causerebbe).

**`exec python /app/src/main.py`**

`exec` sostituisce il processo shell con Python. Senza exec, Python sarebbe un
processo figlio della shell — con exec, Python diventa il PID 1 del container
e riceve i segnali direttamente. Questo e' importante per shutdown pulito.

---

## 4. src/main.py — La logica

```python
import os
import sys


def get_mode() -> str:
    mode = os.environ.get("INPUT_MODE", "shadow")
    if mode not in ("shadow", "enforce"):
        print(f"::warning::Unknown mode '{mode}', defaulting to 'shadow'")
        mode = "shadow"
    return mode


def decide(mode: str) -> dict:
    if mode == "shadow":
        return {
            "decision": "allowed",
            "continue_pipeline": "true",
            "reason": "Shadow mode: observing only, pipeline continues.",
        }
    else:
        return {
            "decision": "manual_review",
            "continue_pipeline": "false",
            "reason": "Enforce mode: no security tools configured yet, requiring manual review.",
        }


def write_outputs(outputs: dict) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        print("--- Outputs (no GITHUB_OUTPUT file) ---")
        for key, value in outputs.items():
            print(f"  {key}={value}")
        return

    with open(output_path, "a") as f:
        for key, value in outputs.items():
            f.write(f"{key}={value}\n")
            print(f"  Output: {key}={value}")


def main() -> int:
    print("=== Agentic AppSec Pipeline ===")
    mode = get_mode()
    outputs = decide(mode)
    write_outputs(outputs)

    if mode == "enforce" and outputs["continue_pipeline"] == "false":
        print("::warning::Pipeline blocked by Agentic AppSec (enforce mode)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### Il flusso

```
main()
  │
  ├─ get_mode()         → legge INPUT_MODE dall'ambiente
  │
  ├─ decide(mode)       → produce un dict con decision/continue_pipeline/reason
  │
  ├─ write_outputs()    → scrive su GITHUB_OUTPUT (o stampa se locale)
  │
  └─ return exit code   → 0 = successo, 1 = pipeline bloccata
```

### Concetti chiave

**`os.environ.get("INPUT_MODE", "shadow")`**

Legge la variabile d'ambiente `INPUT_MODE`. Se non esiste, usa `"shadow"` come default.
Ricorda: GitHub Actions trasforma l'input `mode: shadow` dell'action.yml
nella variabile `INPUT_MODE=shadow`.

**`::warning::` — Workflow commands**

Le stringhe con formato `::warning::messaggio` sono comandi speciali di GitHub Actions.
Se il nostro codice stampa `::warning::qualcosa` su stdout, GitHub Actions lo intercetta
e mostra un warning giallo nella UI. Altri comandi utili:
- `::error::messaggio` — errore rosso
- `::notice::messaggio` — nota blu
- `::debug::messaggio` — visibile solo con debug logging attivo

**GITHUB_OUTPUT — come funziona**

GitHub Actions crea un file temporaneo e mette il suo path in `GITHUB_OUTPUT`.
Per settare un output, scrivi `key=value` nel file (una coppia per riga).
Usiamo `open(path, "a")` (append) perche' il file potrebbe gia' contenere
output di altri comandi.

Prima del 2022, gli output si settavano con `::set-output name=key::value`,
ma questo metodo e' deprecato perche' vulnerabile a injection.
Il file e' piu' sicuro.

**Exit code e il significato per la pipeline**

- `return 0` → lo step GitHub Actions risulta "success" (check verde)
- `return 1` → lo step risulta "failure" (check rosso)

In shadow mode, torniamo sempre 0 perche' stiamo solo osservando.
In enforce mode, torniamo 1 se la decisione blocca la pipeline.
Il workflow chiamante puo' usare `continue_pipeline` per decidere
se fermarsi o proseguire.

**`if __name__ == "__main__"`**

Questo pattern Python significa: "esegui main() solo se questo file viene
eseguito direttamente, non se viene importato come modulo".
`sys.exit(main())` passa il return value di main() come exit code del processo.

---

## Come si collegano i pezzi (flusso completo)

Quando qualcuno apre una PR su un repo che usa questa action:

```
1. GitHub vede il trigger `on: pull_request` nel workflow del chiamante
2. Legge l'action.yml del nostro repo → scopre che e' una Docker action
3. Builda l'immagine Docker dal Dockerfile
4. Avvia il container con:
   - Variabili d'ambiente: INPUT_MODE, INPUT_GITHUB_TOKEN, GITHUB_OUTPUT, ecc.
   - Volume montato: il repo checkout in /github/workspace
5. Il container esegue entrypoint.sh
6. entrypoint.sh configura git ed esegue main.py
7. main.py:
   a. Legge INPUT_MODE → "shadow"
   b. Produce decision=allowed, continue_pipeline=true
   c. Scrive nel file GITHUB_OUTPUT
   d. Esce con codice 0
8. GitHub Actions legge GITHUB_OUTPUT e rende i valori disponibili
   come ${{ steps.appsec.outputs.decision }}, ecc.
9. Lo step successivo del workflow puo' usare questi output
```

---

## Test locale

Puoi testare senza GitHub Actions settando le variabili d'ambiente a mano:

```bash
# Shadow mode (default)
INPUT_MODE=shadow python src/main.py
# → decision=allowed, exit 0

# Enforce mode
INPUT_MODE=enforce python src/main.py
# → decision=manual_review, exit 1

# Mode invalido (fallback a shadow)
INPUT_MODE=banana python src/main.py
# → warning + decision=allowed, exit 0
```

Senza `GITHUB_OUTPUT` settato, main.py stampa gli output su console
invece di scriverli su file. Questo e' il pattern "graceful degradation":
funziona sia su GitHub Actions che in locale, con comportamento adattato.

---

## Cosa viene dopo (Step 2)

Nello Step 2, il codice di main.py verra' scomposto in moduli:
- `models.py` — dataclass Decision, enum Verdict/Severity
- `github_context.py` — parsing dell'ambiente GH Actions
- `decision_engine.py` — la logica decisionale isolata

Questo ci prepara allo Step 3, dove il decision engine diventera'
il cervello AI del pipeline.
