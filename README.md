
# Project Savitar

Savitar helps a security team answer one question: **"Something suspicious
showed up. What is connected to it, and what should we look at first?"**

It works on a map of your IT world: computers, user accounts, software flaws,
known attackers, past incidents, and warning signs (like a bad file or website).
Savitar finds how these things connect, gives each connection a score, and
shows you the most important ones first.

It only analyzes information. It does not attack, scan, or change anything.

> This project comes with a small made-up sample network so you can try it right
> away. It is a demo, not connected to any real systems.

---

## What you need

- Python 3.10 or newer
- An internet connection (for the one-time install)

Check your Python version with: `python --version`

---

## Setup (about 2 minutes)

Open a terminal in the project folder and run these one at a time.

**Mac / Linux**

    python -m venv .venv
    . .venv/bin/activate
    pip install -e '.[dev]'

**Windows**

    python -m venv .venv
    .venv\Scripts\activate
    pip install -e ".[dev]"

---

## Check that it works

    pytest -q

You should see a line ending in "passed". If you see "failed", see
Troubleshooting below.

---

## Start the app

    uvicorn savitar.api:app --port 8000

Leave that window open. In a second terminal, check it is alive:

    curl http://localhost:8000/healthz

You should get back `{"status":"ok", ...}`.

Tip: open http://localhost:8000/docs in your browser for a page where you can
try every feature by clicking, no commands needed.

To stop the app, press Ctrl+C in the first window.

---

## What it can do

| Feature | What it answers |
|---|---|
| `POST /v1/find_related` | "What is connected to this item, up to N steps away?" |
| `POST /v1/find_recurring_patterns` | "What relationships keep repeating?" (shows at most 20) |
| `POST /v1/rank_by_decision_relevance` | "Here is a list of items. Which matter most?" |
| `GET /v1/executive_summary` | "Give me the top patterns in plain terms for leadership." |
| `GET /healthz` | "Is the app running?" |

### Try it

Ask what is connected to a suspicious file in the sample data:

    curl -s -X POST http://localhost:8000/v1/find_related \
      -H 'content-type: application/json' \
      -d '{"entity_id":"ioc:sha256:deadbeef","hops":3}'

(On Windows PowerShell, the browser page at `/docs` is easier than curl.)

Each result includes:

- **what** it is and **how many steps** away it is
- a **score** from 0 to 1 (higher means look at it sooner)
- the **evidence** behind the connection: where it came from and when
- the **path** that links it back to what you asked about

---

## How the score works

Every score is three numbers multiplied together, each between 0 and 1:

    score = confidence × recency × impact

- **Confidence**: how sure we are. Closer connections and more independent
  sources of evidence raise it.
- **Recency**: how fresh the evidence is. Old information counts for less.
- **Impact**: how much it would hurt if this item were compromised.

The same input always gives the same ranking, so results can be checked and
repeated. Details are in `docs/scoring-model.md` if that folder is included.

---

## What is in the folder

    src/savitar/     the program itself
        graph.py       the sample network and how connections are stored
        scoring.py     the scoring math
        queries.py     find related items, find patterns, rank items
        patterns.py    finds relationships that repeat
        api.py         the web app
        cypher.py      five example queries for graph databases
    tests/           automatic checks that the program behaves correctly
    pyproject.toml   project settings and what to install

---

## Troubleshooting

**"python not found"**: try `python3` instead of `python`.

**"pip install" fails**: check your internet connection, and make sure you
activated the virtual environment (your terminal line should start with
`(.venv)`).

**"Address already in use"**: something else is using port 8000. Use another
port, for example `--port 8001`.

**A test fails**: copy the full output of `pytest -q` and share it with
whoever maintains the project. Please do not edit the files in `tests/`; they
define what correct behavior is, so fix the code in `src/savitar/` instead.

---

## Known limits

- It runs on built-in sample data only. Connecting it to real systems would
  need extra work.
- There is no login or rate limiting yet, so do not expose it to the internet.
- Scores are a way to decide what to look at first. They are not proof that
  something is or is not dangerous.
