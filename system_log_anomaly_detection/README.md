# Linux SOC Monitor — Linux System Log Anomaly Detection

A Streamlit SOC-style dashboard that turns **Linux system logs** (auth, SSH, sudo/su, kernel, services) into
ranked, explainable anomalies. Scope is deliberately limited to Linux logs; it detects *anomalous log activity
and repeated-failure indicators*, not every kind of attack.

## Run
```bash
pip install -r requirements.txt
streamlit run app.py          # register an account on first run, then log in
python -m pytest -q           # optional: pipeline tests (no Streamlit needed)
```
The bundled 25,549-event Linux syslog dataset loads automatically; upload your own on **Upload Linux Logs**.

## Password recovery email
The login page can send a time-limited password reset code to the email address registered to an account. Configure SMTP in the root `.env` file to enable delivery:
```env
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=your_smtp_username
SMTP_PASSWORD=your_smtp_password
SMTP_FROM_EMAIL=soc-monitor@example.com
SMTP_USE_TLS=true
```
`SMTP_USERNAME` and `SMTP_PASSWORD` may be omitted when the SMTP server does not require authentication. TLS is enabled by default; set `SMTP_USE_TLS=false` only when the SMTP server is configured for a trusted, non-TLS connection. Reset codes expire after 15 minutes and are invalidated after use or five incorrect attempts.

## ML models and analysis pipeline
```
Linux logs (CSV / syslog text)
  → log_parser          parse CSV or supported syslog text; report rejected rows
  → cleaning            normalise services, classify events, extract source/user fields,
                         create message templates and event IDs
  → feature engineering cyclic time, message length, template/service frequency, burst size,
                         token count and digit ratio
  → scaled feature set   scale numeric features and one-hot encode event classes
  → DBSCAN               find events outside dense groups (density outliers)
  → Isolation Forest     find unusual feature combinations (300 trees)
  → anomaly status       mark an event anomalous if either detector flags it
  → risk/severity        combine event type, service sensitivity, burst, rarity,
                         DBSCAN signal and Isolation Forest score
  → pattern analysis     Apriori itemsets/rules over time-windowed service/event activity
  → AnalysisResult       share results with the Streamlit pages
```

### Detector details and limits
- **DBSCAN** is an unsupervised density-based detector. It uses cyclic hour features, log-scaled message length, message-template frequency, service frequency and burst size, plus one-hot event classes. Numeric features are standardised. Files with fewer than 5,000 rows have DBSCAN parameters adjusted automatically.
- **Isolation Forest** is an unsupervised detector trained on the same scaled feature representation. Its 300-tree model produces an anomaly score; that score is a relative detector score, **not** a probability of an attack.
- The final anomaly label is the union of DBSCAN noise and Isolation Forest outliers. The authentication-burst flag is retained as explanatory/triage context; it is not a separate vote in the final anomaly label.
- A **risk score** is a transparent 0–1 triage heuristic combining event-class relevance, service sensitivity, repetition, message-template rarity, DBSCAN noise and the Isolation Forest score. Severity bands are LOW, MEDIUM, HIGH and CRITICAL. A high score or anomaly label is not confirmation of malicious activity.
- **Apriori** computes frequent itemsets and association rules for services, event classes and anomalous time windows. The analysis pipeline still computes these results, but the patterns/ML analytics pages are not part of the current UI navigation.
- If a CSV includes recognised ground-truth labels, they are used only for post-detection evaluation; they do not affect detector fitting or anomaly decisions. No labeled data means there are no ground-truth accuracy metrics.
- For scoring a new file, the fitted Isolation Forest is applied and DBSCAN is recomputed for that file. The pipeline and parameter defaults are in `services/ml_pipeline.py`.

## Layout
`app.py` entry · `views/` pages · `components/` charts, tables, UI blocks, sidebar · `services/` parser, ML pipeline, orchestration ·
`models/` data contracts · `database/` SQLite + bcrypt auth (unchanged) · `data/` demo dataset and original Colab outputs · `tests/`

## Current UI
- **Overview:** dataset/time-range KPIs, severity and activity charts, high-anomaly-volume alert, and a filtered recent-events table.
- **Anomalies:** anomaly and high-risk counts, filtering/sorting/pagination, and a quick event explanation with a link to Investigation.
- **Log Explorer:** search and filter all parsed events, select an event for investigation, and export filtered rows as CSV.
- **Investigation:** event context, SOC analyst summary, optional triage suggestions, related events/message patterns, recommended actions and session-only analyst disposition.
- **Upload Linux Logs:** accept CSV or syslog text, show parse report and preview, then run the analysis on the uploaded dataset.
- **Reports:** create a summary and optional AI incident review; export anomaly/all-event CSVs and session dispositions.
- **Settings:** configure the high-anomaly-volume alert threshold/window and view severity bands/account controls. Detection parameters are not exposed in this page.

The Streamlit page registry is in `app.py`, while sidebar labels and groups are in `utils/helpers.py` and `components/sidebar.py`. Pages display results from `models/analysis_result.py`; `services/analysis_service.py` caches analysis by input and parameters so navigation does not rerun the pipeline.

## AI analyst features
- **Investigation:** automatically generate and cache a concise summary for the selected event; event-specific triage suggestions remain on demand.
- **Reports:** generate and download an incident-review Markdown report.
- To enable Gemini, create an API key in [Google AI Studio](https://aistudio.google.com/apikey), then create or edit `.env` in the project root (the same folder as `app.py`) and add:
  ```env
  GEMINI_API_KEY=your_gemini_api_key
  ```
  Replace the example value with your key. Do not put the real key in this README, commit it, or share it. `.env` is ignored by Git. Restart Streamlit after changing the file so the application reloads the environment. `GEMINI_MODEL` can optionally select a Gemini model; the default is `gemini-2.5-flash`. `OPENAI_API_KEY` remains supported as a fallback when no Gemini key is set. Without either key, event summaries, triage, and reports show clearly labelled local guidance.
- When remote generation is enabled, prompts are sent to the configured provider (Gemini takes precedence when both keys are set). Event-summary and triage prompts include event metadata (including event ID, timestamp, service, class, severity and risk score), relevant detector evidence and recommendations. Raw log messages, hostnames, usernames and source addresses are withheld or redacted. Incident-review prompts use aggregate analysis findings.
- Model-generated content is advisory only. Verify it against the original logs; anomaly scores are not proof of malicious activity. API errors are shown instead of silently replaced with generated-looking output.
- Gemini retries temporary service-unavailable and rate-limit responses with short exponential backoff. If a `503` persists, wait briefly and try again; it indicates Gemini service availability, not necessarily an invalid API key.

## Known limitations
- Detects unusual Linux log activity, including repeated authentication failures; it does not analyse network, Windows or cloud logs.
- Risk weights and severity bands are expert-chosen heuristics; validate them against your own labeled incidents.
- Analyst dispositions are kept per browser session (exported via Reports), not persisted to the database.
- Syslog files must follow `Mon DD HH:MM:SS host service[pid]: message` (or ISO timestamps); other lines are counted as skipped.
