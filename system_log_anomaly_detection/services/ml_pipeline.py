"""
Linux log anomaly-detection pipeline (no UI code in here).

    parsed Linux logs
      -> clean / normalise (service names, event classes, source host, target user)
      -> feature engineering (time, length, template rarity, service rarity, burstiness)
      -> DBSCAN            unsupervised: events in no dense group of normal activity
      -> burst rule        explicit auth-failure-burst indicator (DBSCAN cannot flag
                           *frequent* behaviour, so brute force needs this)
      -> Isolation Forest unsupervised: isolates unusual feature combinations
      -> risk score        transparent weighted indicator (not a probability)
      -> Apriori           co-occurring service/event patterns per 5-minute window

Honesty note: there is no ground-truth attack label in typical Linux logs, so the
Decision Tree is trained on the DBSCAN+rule labels. Its metrics measure how well
the tree reproduces / generalises those labels on unseen rows, NOT real-world
attack-detection accuracy. The UI states this explicitly.
"""

from __future__ import annotations

import re
import time
from itertools import combinations
from typing import Dict, Optional

import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score, precision_score,
    recall_score, roc_auc_score, roc_curve,
)
from sklearn.neighbors import NearestNeighbors
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import StratifiedKFold, cross_val_predict, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier, export_text

from models.analysis_result import AnalysisResult, DatasetInfo

DEFAULT_PARAMS: Dict = {
    "eps": 0.5,
    "min_samples": 10,
    "burst_threshold": 20,       # AUTH_FAIL events per service per 5-min window
    "window": "5min",
    "tree_max_depth": 8,
    "test_size": 0.2,
    "random_state": 42,
    "detection_source": "live",  # live DBSCAN; reference only for legacy demo labels
    "if_contamination": "auto",
    "min_support": 0.05,         # Apriori, fraction of time windows
    "min_confidence": 0.7,
}

SMALL_FILE_ROWS = 5000
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEV_THRESHOLDS = {"CRITICAL": 0.80, "HIGH": 0.60, "MEDIUM": 0.40}

# how security-relevant each event class is on its own (0..1)
EVENT_WEIGHT = {
    "AUTH_FAIL": 1.00, "PRIVILEGE_EVENT": 0.70, "SERVICE_ERROR": 0.70, "WARNING": 0.50,
    "SERVICE_STOP": 0.30, "SESSION_OPEN": 0.25, "RESTART": 0.20, "SESSION_CLOSE": 0.10,
    "SERVICE_START": 0.15, "KERNEL_EVENT": 0.10, "INFO": 0.05,
}
EVENT_CLASSES = list(EVENT_WEIGHT)

# how sensitive a service is from an access-control point of view (0..1)
SERVICE_SENSITIVITY = {
    "sshd": 1.0, "su": 0.9, "sudo": 0.9, "login": 0.8, "telnetd": 0.8, "ftpd": 0.7,
    "xinetd": 0.6, "unix_chkpwd": 0.7, "sendmail": 0.4, "named": 0.4, "cron": 0.4,
    "crond": 0.4, "systemd": 0.3, "logrotate": 0.3, "snmpd": 0.4, "squid": 0.3,
}

RECOMMENDED_ACTIONS = {
    "AUTH_FAIL": [
        "Identify the source host and check whether it is expected (admin jump host, scanner) or external.",
        "Search the same source for a *successful* login shortly after the failures (possible compromise).",
        "Rate-limit or block the source (firewall / fail2ban / SSH `MaxAuthTries`), and disable password auth for root where possible.",
        "If the targeted account is real, force a credential rotation and review its recent sessions.",
    ],
    "PRIVILEGE_EVENT": [
        "Confirm the user is authorised to use su/sudo on this host and that the timing matches a change window.",
        "Review commands run in the session and any new entries in sudoers or user accounts.",
        "Escalate to incident response if the account owner cannot explain the activity.",
    ],
    "SERVICE_ERROR": [
        "Check the service's recent logs and status for repeated crashes or exited-abnormally messages.",
        "Correlate with deployments, disk/memory pressure or dependency failures around the same time.",
        "If the service is security-relevant (auth, logging), treat repeated failures as a possible tampering indicator.",
    ],
    "WARNING": ["Review the warning in context; escalate only if it repeats or coincides with other anomalies."],
    "SERVICE_STOP": [
        "Verify the stop/shutdown was planned. Unplanned stops of logging or security services deserve follow-up.",
    ],
    "DEFAULT": [
        "Review neighbouring events in the investigation timeline to understand context.",
        "Check whether the same message pattern appears across related events.",
        "Mark as benign if it matches known maintenance; otherwise escalate for analyst review.",
    ],
}

_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_RHOST = re.compile(r"rhost=([^\s]+)")
_FROM = re.compile(r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b")
_USER_EQ = re.compile(r"\buser=([^\s]+)")
_USER_FOR = re.compile(r"\b(?:for user|for invalid user|for)\s+([a-zA-Z0-9_.-]+)")
_ID_NORMALISE = [
    (re.compile(r"rhost=\S+"), "rhost=H"),
    (re.compile(r"user=\S+"), "user=U"),
    (re.compile(r"for user \S+"), "for user U"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "IP"),
    (re.compile(r"0x[0-9a-fA-F]+"), "HEX"),
    (re.compile(r"\d+"), "N"),
]


# ----------------------------------------------------------------------------
# 1. Cleaning / normalisation
# ----------------------------------------------------------------------------
def classify_events(df: pd.DataFrame) -> pd.Series:
    """Map each Linux log line to a security-oriented event class."""
    msg = df["message"].str.lower()
    svc = df["service"]
    raw = df["raw_event_type"].astype(str).str.upper() if "raw_event_type" in df else pd.Series("", index=df.index)

    auth_fail = msg.str.contains(
        r"authentication failure|failed password|failed login|invalid user|illegal user|"
        r"check pass; user unknown|failed none|login incorrect|auth.*fail", regex=True)
    privilege = svc.isin(["su", "sudo"]) | msg.str.contains(r"\bsudo\b|command=|session opened for user root", regex=True)
    conds = [
        auth_fail,
        privilege & ~msg.str.contains("session closed", regex=False),
        msg.str.contains("session opened", regex=False),
        msg.str.contains("session closed", regex=False),
        (svc == "kernel") & ~(raw == "ERROR"),
        (raw == "ERROR") | msg.str.contains(r"\berror\b|exited abnormally|fatal|segfault|\bdied\b|failed", regex=True),
        (raw == "WARNING") | msg.str.contains("warning", regex=False),
        (raw == "SERVICE_STOP") | msg.str.contains(r"shutdown succeeded|shutting down|\bstopped\b|terminated", regex=True),
        (raw == "SERVICE_START") | msg.str.contains(r"startup succeeded|\bstarted\b|\bstarting\b", regex=True),
        (raw == "RESTART") | msg.str.contains("restart", regex=False),
    ]
    choices = ["AUTH_FAIL", "PRIVILEGE_EVENT", "SESSION_OPEN", "SESSION_CLOSE", "KERNEL_EVENT",
               "SERVICE_ERROR", "WARNING", "SERVICE_STOP", "SERVICE_START", "RESTART"]
    return pd.Series(np.select(conds, choices, default="INFO"), index=df.index)


def _normalise_service(raw: pd.Series) -> pd.DataFrame:
    s = raw.astype(str).str.replace(r"\[\d+\]", "", regex=True).str.replace(r"\s[\d.]+$", "", regex=True)
    base = s.str.replace(r"\(.*\)$", "", regex=True).str.strip().replace("", "unknown")
    return pd.DataFrame({"service": base, "service_raw": s})


def _extract_src_user(msg: pd.Series):
    def first(rx_list, text):
        for rx in rx_list:
            m = rx.search(text)
            if m:
                return m.group(1)
        return ""
    src = msg.map(lambda t: first([_RHOST, _FROM], t)).replace("", np.nan)
    usr = msg.map(lambda t: first([_USER_EQ, _USER_FOR], t)).replace("", np.nan)
    return src, usr


def _template(msg: pd.Series) -> pd.Series:
    t = msg
    for rx, repl in _ID_NORMALISE:
        t = t.str.replace(rx, repl, regex=True)
    return t.str.slice(0, 80)


def clean(df: pd.DataFrame) -> pd.DataFrame:
    d = df.copy()
    # repeated identical lines are kept on purpose: repetition is itself a signal
    svc = _normalise_service(d["service"])
    d["service"], d["service_raw"] = svc["service"], svc["service_raw"]
    d["message"] = d["message"].str.strip()
    d["event_class"] = classify_events(d)
    d["src_host"], d["target_user"] = _extract_src_user(d["message"])
    d["hour"] = d["timestamp"].dt.hour
    d["message_length"] = d["message"].str.len()
    d["template"] = _template(d["message"])
    d = d.reset_index(drop=True)
    d["event_id"] = ["EVT-%06d" % (i + 1) for i in range(len(d))]
    return d


# ----------------------------------------------------------------------------
# 2. Feature engineering
# ----------------------------------------------------------------------------
def build_features(d: pd.DataFrame, window: str = "5min") -> pd.DataFrame:
    d = d.copy()
    d["tmpl_freq"] = d.groupby("template")["template"].transform("size")
    d["svc_freq"] = d.groupby("service")["service"].transform("size")
    bucket = d["timestamp"].dt.floor(window)
    d["burst"] = d.groupby(["service", "event_class", bucket])["event_class"].transform("size")
    d["token_count"] = d["message"].str.split().str.len().fillna(0)
    d["digit_ratio"] = d["message"].str.count(r"\d") / d["message_length"].clip(lower=1)
    return d


def _cluster_matrix(d: pd.DataFrame) -> pd.DataFrame:
    """Feature vector DBSCAN works on. Numeric columns are standardised; one-hots are not."""
    num = pd.DataFrame({
        "hour_sin": np.sin(2 * np.pi * d["hour"] / 24),
        "hour_cos": np.cos(2 * np.pi * d["hour"] / 24),
        "log_length": np.log1p(d["message_length"]),
        "log_template_freq": np.log1p(d["tmpl_freq"]),
        "log_service_freq": np.log1p(d["svc_freq"]),
        "log_burst": np.log1p(d["burst"]),
    })
    num = pd.DataFrame(StandardScaler().fit_transform(num), columns=num.columns, index=d.index)
    onehot = pd.get_dummies(d["event_class"]).reindex(columns=EVENT_CLASSES, fill_value=0).astype(float)
    onehot.columns = ["evt_" + c for c in onehot.columns]
    return pd.concat([num, onehot], axis=1)


def _tree_matrix(d: pd.DataFrame, top_services: Optional[list] = None):
    X = pd.DataFrame({
        "hour": d["hour"], "message_length": d["message_length"], "token_count": d["token_count"],
        "digit_ratio": d["digit_ratio"], "log_template_freq": np.log1p(d["tmpl_freq"]),
        "log_service_freq": np.log1p(d["svc_freq"]), "log_burst": np.log1p(d["burst"]),
    })
    for c in EVENT_CLASSES:
        X["evt_" + c] = (d["event_class"] == c).astype(int)
    if top_services is None:
        top_services = d["service"].value_counts().head(12).index.tolist()
    for s in top_services:
        X["svc_" + s] = (d["service"] == s).astype(int)
    return X, top_services


# ----------------------------------------------------------------------------
# 3. Detection
# ----------------------------------------------------------------------------
def _risk(d: pd.DataFrame) -> pd.Series:
    """Transparent triage score; ML anomaly score is one signal, not a probability."""
    base = d["event_class"].map(EVENT_WEIGHT).fillna(0.05)
    sens = d["service"].map(SERVICE_SENSITIVITY).fillna(0.2)
    burst_n = (np.log1p(d["burst"] - 1) / np.log1p(50)).clip(0, 1)
    rarity = 1 - np.log1p(d["tmpl_freq"]) / np.log1p(max(d["tmpl_freq"].max(), 1))
    risk = (0.30 * base + 0.15 * sens + 0.15 * burst_n + 0.10 * rarity
            + 0.15 * d["dbscan_noise"].astype(float) + 0.15 * d["model_prob"])
    return risk.clip(0, 1).round(3)


def _severity(risk: pd.Series) -> pd.Series:
    return pd.Series(np.select(
        [risk >= SEV_THRESHOLDS["CRITICAL"], risk >= SEV_THRESHOLDS["HIGH"], risk >= SEV_THRESHOLDS["MEDIUM"]],
        ["CRITICAL", "HIGH", "MEDIUM"], default="LOW"), index=risk.index)


def _metrics(y_true, y_pred, y_prob) -> Dict:
    out = {
        "n": int(len(y_true)), "positives": int(np.sum(y_true)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
    }
    if len(set(y_true)) == 2:
        out["roc_auc"] = float(roc_auc_score(y_true, y_prob))
        fpr, tpr, _ = roc_curve(y_true, y_prob)
        out["roc"] = {"fpr": fpr.tolist(), "tpr": tpr.tolist()}
    else:
        out["roc_auc"] = None
    return out


def _evaluate_tree(X, y, d_time_order, p):
    rs, depth = p["random_state"], p["tree_max_depth"]
    mk = lambda: DecisionTreeClassifier(max_depth=depth, min_samples_leaf=5, class_weight="balanced", random_state=rs)
    res: Dict = {}
    can_stratify = y.value_counts().min() >= 2 and y.nunique() == 2
    if not can_stratify:
        return {"error": "Not enough anomalous / normal events to evaluate a classifier (need both classes)."}

    # (a) stratified random hold-out — the headline "unseen test data" figure
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=p["test_size"], random_state=rs, stratify=y)
    m = mk().fit(Xtr, ytr)
    res["holdout"] = _metrics(yte.values, m.predict(Xte), m.predict_proba(Xte)[:, 1])
    res["holdout"].update(train_n=int(len(Xtr)), test_n=int(len(Xte)))

    # (b) temporal hold-out — train on the earliest 80%, test on the latest 20% (harder, more realistic)
    order = np.argsort(d_time_order.values, kind="stable")
    cut = int(len(order) * (1 - p["test_size"]))
    tr_idx, te_idx = order[:cut], order[cut:]
    if y.iloc[tr_idx].nunique() == 2 and y.iloc[te_idx].nunique() == 2:
        mt = mk().fit(X.iloc[tr_idx], y.iloc[tr_idx])
        res["temporal"] = _metrics(y.iloc[te_idx].values, mt.predict(X.iloc[te_idx]), mt.predict_proba(X.iloc[te_idx])[:, 1])
        res["temporal"].update(train_n=int(len(tr_idx)), test_n=int(len(te_idx)))

    # (c) 5-fold stratified CV (mean +/- std of F1 / accuracy)
    k = int(min(5, y.value_counts().min()))
    if k >= 2:
        skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=rs)
        accs, f1s = [], []
        for a, b in skf.split(X, y):
            mm = mk().fit(X.iloc[a], y.iloc[a])
            pr = mm.predict(X.iloc[b])
            accs.append(accuracy_score(y.iloc[b], pr)); f1s.append(f1_score(y.iloc[b], pr, zero_division=0))
        res["cv"] = {"folds": k, "accuracy_mean": float(np.mean(accs)), "accuracy_std": float(np.std(accs)),
                     "f1_mean": float(np.mean(f1s)), "f1_std": float(np.std(f1s))}
    return res


# ----------------------------------------------------------------------------
# 4. Apriori on time-window transactions
# ----------------------------------------------------------------------------
def apriori_patterns(d: pd.DataFrame, window: str, min_support: float, min_confidence: float, max_len: int = 3):
    """Transactions = 5-minute windows; items = service, event class and an ANOMALY flag."""
    w = d["timestamp"].dt.floor(window)
    items = {}
    for col, prefix in (("service", "svc="), ("event_class", "evt=")):
        ind = pd.crosstab(w, d[col]) > 0
        for c in ind.columns:
            items[prefix + str(c)] = ind[c]
    anom = (d["status"] == "ANOMALY").groupby(w).any()
    items["ANOMALY_IN_WINDOW"] = anom
    B = pd.DataFrame(items).fillna(False).astype(bool)
    n = len(B)
    if n < 5:
        return pd.DataFrame(), pd.DataFrame(), n
    arr = {c: B[c].values for c in B.columns}
    support = {(c,): arr[c].mean() for c in arr}
    freq = {k: v for k, v in support.items() if v >= min_support}
    all_freq = dict(freq)
    current = list(freq)
    for size in range(2, max_len + 1):
        cand = set()
        for a, b in combinations(current, 2):
            u = tuple(sorted(set(a) | set(b)))
            if len(u) == size:
                cand.add(u)
        nxt = {}
        for c in cand:
            s = np.logical_and.reduce([arr[i] for i in c]).mean()
            if s >= min_support:
                nxt[c] = s
        all_freq.update(nxt)
        current = list(nxt)
        if not current:
            break
    iset = pd.DataFrame([{"itemset": " + ".join(k), "size": len(k), "support": v,
                          "windows": int(round(v * n))} for k, v in all_freq.items()])
    rules = []
    for k, s in all_freq.items():
        if len(k) < 2:
            continue
        for r in range(1, len(k)):
            for ante in combinations(k, r):
                cons = tuple(i for i in k if i not in ante)
                conf = s / all_freq[tuple(sorted(ante))]
                lift = conf / all_freq[tuple(sorted(cons))]
                if conf >= min_confidence and lift > 1.0:
                    rules.append({"if": " + ".join(ante), "then": " + ".join(cons), "support": s,
                                  "confidence": conf, "lift": lift, "windows": int(round(s * n))})
    rules = pd.DataFrame(rules)
    if len(iset):
        iset = iset.sort_values(["size", "support"], ascending=[False, False]).reset_index(drop=True)
    if len(rules):
        rules = rules.sort_values(["lift", "confidence"], ascending=False).reset_index(drop=True)
    return iset, rules, n


# ----------------------------------------------------------------------------
# 5. Orchestration
# ----------------------------------------------------------------------------
def run_pipeline(df: pd.DataFrame, info: DatasetInfo, params: Optional[Dict] = None) -> AnalysisResult:
    """Run a fully unsupervised anomaly pipeline.

    DBSCAN detects density-based outliers and Isolation Forest detects points
    that are easy to isolate in the engineered feature space. No ground-truth
    label is used to create the anomaly decision. If an input file contains a
    label/actual_label column, it is used only AFTER detection for evaluation.
    """
    p = {**DEFAULT_PARAMS, **(params or {})}
    t0 = time.time()
    stages: Dict = {"input_rows": int(len(df))}

    d = clean(df)
    d = build_features(d, p["window"])
    stages["cleaned_rows"] = int(len(d))
    stages["services"] = int(d["service"].nunique())
    stages["event_classes"] = int(d["event_class"].nunique())

    # --- DBSCAN: unsupervised density detector ----------------------------
    Xc = _cluster_matrix(d)
    used_reference = False
    p["eps_used"], p["min_samples_used"] = p["eps"], p["min_samples"]
    if p["detection_source"] == "reference" and "dbscan_cluster" in d.columns and d["dbscan_cluster"].notna().all():
        d["dbscan_cluster"] = d["dbscan_cluster"].astype(int)
        used_reference = True
    else:
        eps, ms = p["eps"], p["min_samples"]
        if len(d) < SMALL_FILE_ROWS:
            ms = max(4, min(ms, max(4, len(d) // 100)))
            kd = NearestNeighbors(n_neighbors=min(ms, len(d))).fit(Xc.values).kneighbors(Xc.values)[0][:, -1]
            eps = max(float(np.percentile(kd, 95)), 0.1)
            stages["auto_params"] = True
        p["eps_used"], p["min_samples_used"] = round(eps, 3), ms
        d["dbscan_cluster"] = DBSCAN(eps=eps, min_samples=ms, n_jobs=-1).fit_predict(Xc.values)

    d["dbscan_noise"] = d["dbscan_cluster"] == -1
    stages["dbscan_clusters"] = int(d.loc[~d["dbscan_noise"], "dbscan_cluster"].nunique())
    stages["dbscan_noise"] = int(d["dbscan_noise"].sum())
    stages["detection_source"] = "reference" if used_reference else "live"

    # --- Isolation Forest: unsupervised anomaly detector ------------------
    # It does not use actual_label/label or any hand-written security label.
    contamination = p.get("if_contamination", "auto")
    if_model = IsolationForest(
        n_estimators=300,
        contamination=contamination,
        random_state=p["random_state"],
        n_jobs=-1,
    )
    if_model.fit(Xc.values)
    if_pred = if_model.predict(Xc.values)
    raw_score = -if_model.decision_function(Xc.values)  # larger = more anomalous
    lo, hi = float(raw_score.min()), float(raw_score.max())
    if hi > lo:
        anomaly_score = (raw_score - lo) / (hi - lo)
    else:
        anomaly_score = np.zeros(len(raw_score))

    d["iforest_noise"] = if_pred == -1
    d["model_prob"] = np.round(anomaly_score, 3)  # anomaly score, NOT probability
    d["model_pred"] = d["iforest_noise"].astype(int)
    # Informational only; NOT used to create the anomaly label.
    d["auth_burst"] = (d["event_class"] == "AUTH_FAIL") & (d["burst"] >= p["burst_threshold"])

    # Final unsupervised decision: either independent detector can flag an event.
    # No label is involved. A high burst is already represented in the features.
    d["is_anomaly"] = (d["dbscan_noise"] | d["iforest_noise"]).astype(int)
    d["status"] = np.where(d["is_anomaly"] == 1, "ANOMALY", "NORMAL")
    d["detection_method"] = np.select(
        [
            d["dbscan_noise"] & d["iforest_noise"],
            d["dbscan_noise"],
            d["iforest_noise"],
        ],
        [
            "DBSCAN + Isolation Forest",
            "DBSCAN",
            "Isolation Forest",
        ],
        default="—",
    )
    stages["isolation_forest_anomalies"] = int(d["iforest_noise"].sum())
    stages["ensemble_anomalies"] = int(d["is_anomaly"].sum())
    stages["detection_mode"] = "unsupervised"

    # Optional external evaluation ONLY when the uploaded file contains labels.
    # Labels never participate in fitting or anomaly decisions.
    metrics: Dict = {"method": "unsupervised ensemble", "ground_truth": None}
    if "label" in d.columns:
        lab = d["label"].astype(str).str.lower().map(
            {"1": 1, "true": 1, "anomaly": 1, "anomalous": 1, "abnormal": 1,
             "0": 0, "false": 0, "normal": 0}
        )
        valid = lab.notna()
        if valid.sum() >= 2 and lab[valid].nunique() == 2:
            yt, yp = lab[valid].astype(int), d.loc[valid, "is_anomaly"].astype(int)
            metrics["ground_truth"] = {
                "n": int(valid.sum()),
                "positives": int(yt.sum()),
                "accuracy": float(accuracy_score(yt, yp)),
                "precision": float(precision_score(yt, yp, zero_division=0)),
                "recall": float(recall_score(yt, yp, zero_division=0)),
                "f1": float(f1_score(yt, yp, zero_division=0)),
                "confusion": confusion_matrix(yt, yp, labels=[0, 1]).tolist(),
            }

    # Feature importance is descriptive: mean absolute standardized feature
    # magnitude among ensemble anomalies, NOT supervised feature importance.
    if d["is_anomaly"].sum() > 0:
        z = pd.DataFrame(StandardScaler().fit_transform(Xc), columns=Xc.columns, index=d.index)
        importance = (
            pd.DataFrame({
                "feature": Xc.columns,
                "importance": z.loc[d["is_anomaly"].eq(1)].abs().mean().values
            })
            .sort_values("importance", ascending=False)
            .reset_index(drop=True)
        )
    else:
        importance = pd.DataFrame(columns=["feature", "importance"])
    stages["model_features"] = int(Xc.shape[1])

    # --- risk / severity ---------------------------------------------------
    d["risk_score"] = _risk(d)
    d["severity"] = _severity(d["risk_score"])
    d.loc[(d["status"] == "NORMAL") & d["severity"].isin(["HIGH", "CRITICAL"]), "severity"] = "MEDIUM"
    d["reason"] = _short_reason(d, p)

    # --- clusters & projection --------------------------------------------
    cl = (d.groupby("dbscan_cluster")
          .agg(size=("event_id", "size"),
               top_service=("service", lambda s: s.value_counts().index[0]),
               top_event=("event_class", lambda s: s.value_counts().index[0]),
               avg_length=("message_length", "mean"))
          .reset_index().sort_values("size", ascending=False))
    cl["cluster"] = np.where(cl["dbscan_cluster"] == -1, "Noise (anomalous)", "Cluster " + cl["dbscan_cluster"].astype(str))
    cl["share_pct"] = (cl["size"] / len(d) * 100).round(2)
    proj = _projection(d, Xc, p["random_state"])

    # --- Apriori ----------------------------------------------------------
    itemsets, rules, n_windows = apriori_patterns(d, p["window"], p["min_support"], p["min_confidence"])
    stages.update(apriori_windows=int(n_windows), itemsets=int(len(itemsets)), rules=int(len(rules)))
    stages["seconds"] = round(time.time() - t0, 1)

    keep = ["event_id", "timestamp", "hostname", "service", "service_raw", "event_class", "message", "status",
            "detection_method", "severity", "risk_score", "dbscan_cluster", "model_prob", "model_pred",
            "burst", "tmpl_freq", "svc_freq", "src_host", "target_user", "hour", "message_length",
            "reason", "template", "dbscan_noise", "iforest_noise", "auth_burst"]
    if "label" in d.columns:
        keep.append("label")
    events = d[keep].copy()
    events["timestamp"] = pd.to_datetime(events["timestamp"])
    info = DatasetInfo(**{**info.__dict__, "num_records": len(events)})
    return AnalysisResult(events=events, itemsets=itemsets, rules=rules, clusters=cl, projection=proj,
                          importance=importance, metrics=metrics, params=p, pipeline=stages,
                          model=if_model, feature_names=list(Xc.columns),
                          tree_text="", dataset_info=info)


def _short_reason(d: pd.DataFrame, p: Dict) -> pd.Series:
    r = pd.Series("", index=d.index)
    both = d["iforest_noise"] & d["dbscan_noise"]
    r[d["iforest_noise"]] = "Isolation Forest identified an unusual feature combination"
    r[both] = "DBSCAN and Isolation Forest both identified unusual behaviour"
    only_noise = d["dbscan_noise"] & ~d["iforest_noise"]
    rare = only_noise & (d["tmpl_freq"] <= 3)
    r[only_noise] = "Unusual feature pattern (DBSCAN noise)"
    only_if = d["iforest_noise"] & ~d["dbscan_noise"]
    r[only_if] = "Isolation Forest anomaly score exceeded its unsupervised threshold"
    r[rare] = "Rare message pattern (seen " + d.loc[rare, "tmpl_freq"].astype(str) + "x)"
    return r


def _projection(d: pd.DataFrame, Xc: pd.DataFrame, rs: int, max_points: int = 4000) -> pd.DataFrame:
    noise_idx = d.index[d["dbscan_noise"]]
    other_idx = d.index[~d["dbscan_noise"]]
    rng = np.random.RandomState(rs)
    n_noise = min(len(noise_idx), max_points // 3)
    take = np.concatenate([
        rng.choice(noise_idx, n_noise, replace=False) if n_noise else np.array([], dtype=int),
        rng.choice(other_idx, min(len(other_idx), max_points - n_noise), replace=False) if len(other_idx) else np.array([], dtype=int)])
    if len(take) < 3:
        return pd.DataFrame()
    pca = PCA(n_components=2, random_state=rs).fit(Xc.values)
    xy = pca.transform(Xc.loc[take].values)
    return pd.DataFrame({
        "x": xy[:, 0], "y": xy[:, 1], "is_noise": d.loc[take, "dbscan_noise"].values,
        "cluster": np.where(d.loc[take, "dbscan_noise"], "Noise (anomalous)", "Cluster " + d.loc[take, "dbscan_cluster"].astype(str)),
        "service": d.loc[take, "service"].values, "event_class": d.loc[take, "event_class"].values,
        "explained": float(pca.explained_variance_ratio_.sum()),
    })


# ----------------------------------------------------------------------------
# 6. Explanations (used by the Investigation page)
# ----------------------------------------------------------------------------
def explain_event(res: AnalysisResult, event_id: str) -> Dict:
    e = res.events
    row = e.loc[e["event_id"] == event_id].iloc[0]
    n = len(e)
    p = res.params
    ev = []

    if row["dbscan_noise"]:
        ev.append(f"**DBSCAN:** this event is in the noise group (label −1). In the standardised feature space "
                  f"(event class, hour, message length, message-pattern rarity, service rarity, burst size) it has fewer than "
                  f"{p.get('min_samples_used', p['min_samples'])} neighbours within eps={p.get('eps_used', p['eps'])}, so it does not belong to any dense group of normal Linux activity.")
    else:
        size = int((e["dbscan_cluster"] == row["dbscan_cluster"]).sum())
        ev.append(f"**DBSCAN:** belongs to Cluster {row['dbscan_cluster']} ({size:,} events), so by density alone it looks like routine activity.")

    pct = row["tmpl_freq"] / n * 100
    rarity_txt = "very rare" if row["tmpl_freq"] <= 3 else ("uncommon" if pct < 1 else "common")
    ev.append(f"**Message pattern:** this wording appears {int(row['tmpl_freq']):,} time(s) ({pct:.2f}% of events) — {rarity_txt}.")

    if row["burst"] > 1:
        ev.append(f"**Repetition:** {int(row['burst'])} `{row['event_class']}` events from `{row['service']}` occurred in the same "
                  f"{p['window']} window.")
    if row["auth_burst"]:
        ev.append(f"**Burst rule:** at least {p['burst_threshold']} authentication failures from one service inside a {p['window']} window "
                  f"(repeated-login-failure indicator).")
    if isinstance(row["src_host"], str) and row["src_host"]:
        same = e[(e["src_host"] == row["src_host"]) & (e["event_class"] == "AUTH_FAIL")]
        users = same["target_user"].dropna().nunique()
        ev.append(f"**Source host `{row['src_host']}`** is linked to {len(same):,} authentication-failure event(s)"
                  + (f" across {users} target account(s)" if users else "") + ".")
    if isinstance(row["target_user"], str) and row["target_user"]:
        tu = e[(e["target_user"] == row["target_user"]) & (e["event_class"] == "AUTH_FAIL")]
        if len(tu) > 1:
            ev.append(f"**Target account `{row['target_user']}`** appears in {len(tu):,} failed-authentication events.")
    hour_share = (e["hour"] == row["hour"]).mean() * 100
    if hour_share < 3:
        ev.append(f"**Timing:** only {hour_share:.1f}% of events occur in hour {int(row['hour']):02d}:00.")

    if res.model is not None:
        agree = "agrees" if row["model_pred"] == (1 if row["status"] == "ANOMALY" else 0) else "disagrees"
        ev.append(f"**Isolation Forest:** unsupervised anomaly score = {row['model_prob']:.2f}; the model {agree} with the ensemble detector label.")

    sens = SERVICE_SENSITIVITY.get(row["service"])
    if sens and sens >= 0.7:
        ev.append(f"**Service sensitivity:** `{row['service']}` is an access-control related service, which raises the risk score.")

    actions = RECOMMENDED_ACTIONS.get(row["event_class"], RECOMMENDED_ACTIONS["DEFAULT"])
    if row["status"] == "ANOMALY" and row["event_class"] in ("INFO", "KERNEL_EVENT", "SERVICE_START", "SESSION_CLOSE", "SESSION_OPEN", "RESTART"):
        actions = RECOMMENDED_ACTIONS["DEFAULT"]

    if row["auth_burst"]:
        headline = "Repeated authentication failures were detected in a short time window — a typical brute-force or password-guessing indicator."
    elif row["dbscan_noise"] and row["iforest_noise"]:
        headline = "DBSCAN and Isolation Forest both flagged this event as unusual compared with common activity."
    elif row["dbscan_noise"] and row["tmpl_freq"] <= 3:
        headline = "This event has a rare message pattern and sits outside every dense group of normal Linux activity."
    elif row["dbscan_noise"]:
        headline = "This event's feature pattern is significantly different from normal Linux activity and belongs to the DBSCAN noise group."
    elif row["iforest_noise"]:
        headline = "Isolation Forest flagged an unusual combination of event features."
    else:
        headline = "This event was not flagged as anomalous; the evidence below shows how it was scored."
    return {"row": row, "headline": headline, "evidence": ev, "actions": actions}


def event_context(res: AnalysisResult, event_id: str, before: int = 8, after: int = 8) -> pd.DataFrame:
    e = res.events
    idx = e.index[e["event_id"] == event_id][0]
    return e.iloc[max(0, idx - before): idx + after + 1]


# ----------------------------------------------------------------------------
# 7. Scoring an unseen file with the trained tree
# ----------------------------------------------------------------------------
def score_unseen(res: AnalysisResult, df: pd.DataFrame) -> pd.DataFrame:
    """Score a new file using the fitted unsupervised Isolation Forest.

    DBSCAN is recomputed on the new file because it is a density model over the
    active dataset; the trained Isolation Forest provides the portable model score.
    """
    if res.model is None:
        raise ValueError("No trained unsupervised model is available.")
    d = build_features(clean(df), res.params["window"])
    Xc = _cluster_matrix(d)
    # Align to the training feature schema.
    Xc = Xc.reindex(columns=res.feature_names, fill_value=0)

    if_pred = res.model.predict(Xc.values)
    raw = -res.model.decision_function(Xc.values)
    lo, hi = float(raw.min()), float(raw.max())
    score = (raw - lo) / (hi - lo) if hi > lo else np.zeros(len(raw))

    # Recompute DBSCAN for this uploaded dataset.
    eps = res.params.get("eps_used", res.params["eps"])
    ms = res.params.get("min_samples_used", res.params["min_samples"])
    clusters = DBSCAN(eps=eps, min_samples=ms, n_jobs=-1).fit_predict(Xc.values)
    db_noise = clusters == -1

    out = d[["event_id", "timestamp", "service", "event_class", "message"]].copy()
    out["dbscan_noise"] = db_noise.astype(int)
    out["model_prob"] = np.round(score, 3)
    out["model_pred"] = ((if_pred == -1) | db_noise).astype(int)
    out["detection_method"] = np.select(
        [(if_pred == -1) & db_noise, db_noise, if_pred == -1],
        ["DBSCAN + Isolation Forest", "DBSCAN", "Isolation Forest"],
        default="Normal",
    )
    if "label" in d.columns:
        lab = d["label"].astype(str).str.lower().map(
            {"1": 1, "true": 1, "anomaly": 1, "anomalous": 1, "abnormal": 1,
             "0": 0, "false": 0, "normal": 0})
        out["label"] = lab
    return out


def risk_breakdown(res: AnalysisResult, event_id: str) -> pd.DataFrame:
    """Weighted contributions that add up to the event's risk score."""
    e = res.events
    row = e.loc[e["event_id"] == event_id].iloc[0]
    base = EVENT_WEIGHT.get(row["event_class"], 0.05)
    sens = SERVICE_SENSITIVITY.get(row["service"], 0.2)
    burst_n = float(np.clip(np.log1p(row["burst"] - 1) / np.log1p(50), 0, 1))
    rarity = 1 - np.log1p(row["tmpl_freq"]) / np.log1p(e["tmpl_freq"].max())
    parts = [
        (f"Event type ({row['event_class']})", 0.35 * base, 0.35),
        (f"Service sensitivity ({row['service']})", 0.15 * sens, 0.15),
        ("Repetition / burst size", 0.15 * burst_n, 0.15),
        ("Message-pattern rarity", 0.10 * rarity, 0.10),
        ("DBSCAN noise membership", 0.15 * float(row["dbscan_noise"]), 0.15),
        ("Isolation Forest anomaly score", 0.15 * float(row["model_prob"]), 0.15),
    ]
    return pd.DataFrame(parts, columns=["component", "contribution", "max_weight"])
