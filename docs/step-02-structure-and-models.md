# Step 2 — Struttura modulare e modelli dati

Guida di studio per lo Step 2 del progetto Agentic AppSec Pipeline.

---

## Cosa abbiamo fatto

Abbiamo preso il codice monolitico di `main.py` (Step 1) e lo abbiamo scomposto in moduli
con responsabilita' chiare. Il comportamento esterno e' identico — stessi output, stessi
exit code. Ma il codice e' organizzato per crescere.

### Prima (Step 1) — tutto in main.py

```
main.py
  ├── get_mode()         → legge INPUT_MODE
  ├── decide()           → if/else che ritorna un dict
  └── write_outputs()    → scrive su GITHUB_OUTPUT
```

### Dopo (Step 2) — 4 moduli separati

```
src/
├── main.py              → orchestratore (chiama gli altri moduli)
├── models.py            → cosa sono i dati (Decision, Finding, ToolResult, enums)
├── github_context.py    → da dove vengono i dati (ambiente GH Actions)
└── decision_engine.py   → la logica (come si decide)
```

---

## Perche' separare? (Il principio)

La regola d'oro e': **ogni modulo ha UN motivo per cambiare**.

- `models.py` cambia se aggiungiamo campi alla Decision (es. findings, tool_results)
- `github_context.py` cambia se leggiamo nuove variabili d'ambiente
- `decision_engine.py` cambia se cambia la logica decisionale (da regole semplici a pipeline multi-agent)
- `main.py` cambia solo se cambia il flusso generale

Quando allo Step 3 integriamo smolagents, toccheremo solo `decision_engine.py`.
Il resto del codice non sa e non gli importa se la decisione viene da un if/else
o da un modello AI.

---

## I moduli nel dettaglio

### models.py — I modelli dati

```python
class Verdict(str, Enum):
    ALLOWED = "allowed"
    MANUAL_REVIEW = "manual_review"
    BLOCKED = "blocked"

class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    ...

@dataclass
class Decision:
    verdict: Verdict
    continue_pipeline: bool
    max_severity: Severity
    selected_tools: list[str]
    findings_count: int
    reason: str
    mode: str
    analysis_report: str
    safety_warnings: list[dict]
    timestamp: str
```

**Concetti chiave:**

**Enum (enumerazione)**
Un Enum definisce un insieme fisso di valori possibili. `Verdict.ALLOWED` e' l'unico
modo per dire "allowed" — non puoi scrivere `Verdict("allwoed")` per errore (typo),
Python ti darebbe un errore immediato.

`str, Enum` significa che l'enum e' anche una stringa. Puoi fare:
```python
Verdict.ALLOWED == "allowed"  # True
Verdict.ALLOWED.value         # "allowed"
```
Questo e' comodo per la serializzazione JSON.

**Dataclass**
Una dataclass e' una classe Python dove definisci solo i campi e Python genera
automaticamente `__init__`, `__repr__`, `__eq__`. Invece di scrivere:
```python
class Decision:
    def __init__(self, verdict, continue_pipeline, ...):
        self.verdict = verdict
        self.continue_pipeline = continue_pipeline
        ...
```
Scrivi:
```python
@dataclass
class Decision:
    verdict: Verdict
    continue_pipeline: bool
    ...
```
Meno codice, meno errori, piu' leggibile.

**`field(default_factory=lambda: ...)`**
Il campo `timestamp` ha un valore di default generato al momento della creazione.
`default_factory` e' necessario perche' il default deve essere calcolato ogni volta
(la data corrente), non una volta sola all'import del modulo.

**Metodi di serializzazione:**
- `to_dict()` → dizionario Python (per uso interno)
- `to_json()` → stringa JSON (per artifact)
- `to_outputs()` → dizionario stringa→stringa (per GITHUB_OUTPUT)

Il campo `version` in `to_dict()` serve per la forward compatibility:
se in futuro cambiamo la struttura del JSON, chi lo legge puo' controllare la versione.

---

### github_context.py — Parsing dell'ambiente

```python
@dataclass
class GitHubContext:
    token: str
    mode: str
    workspace: str
    repository: str
    event_name: str
    sha: str
    ref: str
    pr_number: Optional[int]
    is_pull_request: bool

    @classmethod
    def from_environment(cls) -> "GitHubContext":
        ...
```

**Concetti chiave:**

**`@classmethod` e il pattern factory**
`from_environment()` e' un "class method" — si chiama sulla classe, non su un'istanza:
```python
ctx = GitHubContext.from_environment()  # non GitHubContext().from_environment()
```
Questo pattern si chiama "factory method": e' un modo alternativo per creare un oggetto
quando la creazione richiede logica (leggere env vars, parsare JSON, validare).

**`Optional[int]`**
Significa "int oppure None". `pr_number` e' None quando l'evento non e' una pull request
(es. un push diretto su main).

**Perche' tutto in un dataclass?**
Invece di leggere `os.environ.get(...)` in 10 posti diversi nel codice, lo leggiamo
UNA volta e lo mettiamo in un oggetto pulito. Vantaggi:
1. **Testabilita'**: nei test crei `GitHubContext(mode="shadow", ...)` senza toccare env vars
2. **Leggibilita'**: `ctx.mode` e' piu' chiaro di `os.environ.get("INPUT_MODE", "shadow")`
3. **Un solo punto di validazione**: il mode viene validato una volta in `from_environment()`

---

### decision_engine.py — La logica decisionale

```python
class DecisionEngine:
    def decide(self, ctx: GitHubContext) -> Decision:
        triage = self._run_triage(ctx)
        tool_results, analysis = self._run_analyzer(ctx, triage)
        return self._apply_gate(ctx, triage, tool_results, analysis)
```

Questo e' il modulo piu' importante: orchestra triage, analyzer e gate deterministico.
Il contratto e': **prende un contesto, ritorna una decisione**. Come ci arriva
e' un dettaglio interno.

La firma `decide(ctx) -> Decision` resta stabile anche mentre la logica evolve.

---

### main.py — L'orchestratore

```python
def main() -> int:
    ctx = GitHubContext.from_environment()
    engine = DecisionEngine()
    decision = engine.decide(ctx)
    write_outputs(decision.to_outputs())
    return 0 if decision.continue_pipeline else 1
```

Nota come main.py ora e' cortissimo. Non sa COME si legge l'ambiente (lo fa
`GitHubContext`). Non sa COME si decide (lo fa `DecisionEngine`). Non sa COME
si formattano gli output (lo fa `Decision.to_outputs()`). Sa solo l'ORDINE
in cui chiamare le cose.

---

## I test

```
tests/
├── __init__.py
└── test_decision_engine.py
```

**La funzione helper `_make_context()`**
```python
def _make_context(**overrides) -> GitHubContext:
    defaults = dict(token="fake", mode="shadow", ...)
    defaults.update(overrides)
    return GitHubContext(**defaults)
```

Crea un `GitHubContext` con valori di default sensati. Nei test scrivi:
```python
_make_context(mode="enforce")  # tutto default tranne mode
```
Senza questa helper, ogni test dovrebbe specificare tutti i 9 campi.
`**overrides` e' Python per "prendi tutti gli argomenti keyword e mettili
in un dizionario". `**defaults` fa il contrario: "spacchetta il dizionario
come argomenti keyword".

**Struttura dei test (classi)**
```python
class TestShadowMode:
    def test_verdict_is_allowed(self): ...
    def test_pipeline_continues(self): ...

class TestEnforceMode:
    def test_verdict_is_manual_review(self): ...
```

Ogni classe raggruppa i test per scenario. pytest li scopre automaticamente
(qualsiasi classe che inizia con `Test`, qualsiasi metodo che inizia con `test_`).

**Perche' un test per asserzione?**
Ogni test verifica UNA cosa. Se `test_verdict_is_allowed` fallisce, sai subito
che il problema e' nel verdict, non nel continue_pipeline. Se mettessi tutto
in un unico test, dovresti debuggare per capire quale assert e' fallita.

---

## pyproject.toml

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["."]
```

`pythonpath = ["."]` dice a pytest: "aggiungi la root del progetto al Python path".
Senza questo, `from src.models import ...` non funzionerebbe nei test perche'
pytest non saprebbe dove trovare `src`.

---

## Il flusso dopo Step 2

```
entrypoint.sh
  └── python -m src.main
        ├── GitHubContext.from_environment()    → legge env vars
        ├── DecisionEngine().decide(ctx)        → applica regole
        │     └── Decision(verdict=..., ...)    → oggetto strutturato
        ├── decision.to_outputs()               → formatta per GH Actions
        ├── write_outputs()                     → scrive su GITHUB_OUTPUT
        └── exit 0 o 1                          → segnala a GH Actions
```

L'output per l'utente e' identico a Step 1. La differenza e' tutta interna:
il codice e' pronto per evolversi.

---

## Cosa viene dopo (dallo stato attuale)

La separazione in moduli continua a pagare:
- puoi aggiungere nuovi scanner in `tools.py`
- puoi evolvere policy nel gate senza toccare il runtime
- puoi migliorare reporting PR senza riscrivere i modelli base

Questo e' il valore della separazione: cambi un blocco, il resto regge.
