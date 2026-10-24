"""Score logs with artifacts/message_detector.joblib.

Usage (from the project root):
    uv run detect-anomaly                        # score data/security_logs.csv
    uv run detect-anomaly --csv other_stream.csv # any CSV with severity + message columns
    uv run detect-anomaly --samples              # a few lines taken from security_logs.csv
    uv run detect-anomaly "WARNING Failed password for bob from 203.0.113.7 port 22 ssh2"
    uv run detect-anomaly --file my_logs.txt     # one "SEVERITY message" per line
"""
import argparse
import re
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = ROOT / "artifacts" / "message_detector.joblib"
DEFAULT_CSV = ROOT / "data" / "security_logs.csv"
DEFAULT_OUT = ROOT / "artifacts" / "security_logs_scored.csv"
SEV_MAP = {"INFO": 0, "WARNING": 1, "ERROR": 2, "CRITICAL": 3}
SEV_RE = re.compile(r"^(INFO|WARNING|ERROR|CRITICAL)\s+")
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
USER_PREFIX_RE = re.compile(r"^(Accepted login for|Session closed for|Failed password for|sudo session opened for|VPN login for) (\S+)")
ALL_COLS = ["sev_ord", "rarity", "log_size_mb", "n_ext_ip"] + [f"text_svd_{i}" for i in range(6)]

# Real lines from data/security_logs.csv: routine traffic first, then the attack patterns found in it.
SAMPLE_LOGS = [
    'INFO "GET /api/users HTTP/1.1" 200',
    "INFO DNS query for github.com",
    "INFO Accepted login for bob from 10.0.1.11",
    "INFO Opened \\\\files-01\\shared\\finance\\doc264.docx",
    "INFO Outbound transfer of 29 KB",
    'WARNING "GET /api/orders HTTP/1.1" 404',
    "WARNING Failed password for laura from 10.0.1.21 port 47439 ssh2",
    "WARNING DROP TCP 185.114.141.41 -> 10.0.30.6:6132",
    "WARNING Failed password for root from 194.45.85.31 port 63228 ssh2",
    "ERROR Large outbound transfer of 2052 MB to 141.194.251.175",
    "ERROR Port scan detected from 185.114.141.41",
    "ERROR VPN login for ivan from SG two minutes after US",
    "ERROR root logged in from 194.197.155.217 outside business hours",
    "CRITICAL Accepted password for root from 194.45.85.31 after repeated failures",
    "CRITICAL sudo session opened for root",
    "ERROR Database dump of customers table",
]


# The helpers below must match the notebook: the pickled model refers to these names.
def to_template(msg: str) -> str:
    t = IP_RE.sub("<IP>", msg)
    t = USER_PREFIX_RE.sub(r"\1 <USER>", t)
    t = re.sub(r"^\w+ (logged in from)", r"<USER> \1", t)
    t = re.sub(r"\b(from|after) [A-Z]{2}\b", r"\1 <CC>", t)
    t = re.sub(r"files-\d+", "files-<N>", t)
    t = re.sub(r"doc\d+\.docx", "doc<N>.docx", t)
    t = re.sub(r"HTTP/\d\.\d", "HTTP/<V>", t)
    t = re.sub(r"\bport \d+", "port <PORT>", t)
    t = re.sub(r"(\bof )\d+( [MK]B)", r"\1<N>\2", t)
    t = re.sub(r"(<IP>):\d+$", r"\1:<PORT>", t)
    return t


def parse_message(msg: str):
    ips = IP_RE.findall(msg)
    size = re.search(r"of (\d+) ([MK])B", msg)
    size_mb = int(size.group(1)) * (1.0 if size.group(2) == "M" else 1 / 1024) if size else 0.0
    n_ext = sum(not ip.startswith(("10.", "192.168.")) for ip in ips)
    user = USER_PREFIX_RE.match(msg)
    entity = ips[0] if ips else (user.group(2) if user else "")
    return size_mb, n_ext, entity


def strip_severity(line: pd.Series) -> pd.Series:
    return line.str.replace(SEV_RE, "", regex=True)


class MsgFeatures:
    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        msg = strip_severity(df.line)
        tpl = msg.map(to_template)
        parsed = np.array([parse_message(m)[:2] for m in msg]).reshape(-1, 2)
        F = pd.DataFrame(index=df.index)
        F["sev_ord"] = df.type.map(SEV_MAP).fillna(0).values
        F["rarity"] = -np.log((tpl.map(self.tpl_counts_).fillna(0).values + 1) / (self.n_ref_ + 1))
        F["log_size_mb"], F["n_ext_ip"] = np.log1p(parsed[:, 0]), parsed[:, 1]
        svd = self.svd_.transform(self.tfidf_.transform(tpl))
        for i in range(svd.shape[1]):
            F[f"text_svd_{i}"] = svd[:, i]
        return F


class MessageDetector:
    def score(self, df):
        return self.model.predict_proba(self.features.transform(df)[ALL_COLS].values)[:, 1]

    def predict(self, df):
        return (self.score(df) >= self.threshold).astype(int)


def load_detector(path: Path = MODEL_PATH):
    """joblib.load, with the notebook's `__main__` class names temporarily resolving to this module."""
    main = sys.modules["__main__"]
    names = {"MsgFeatures": MsgFeatures, "MessageDetector": MessageDetector}
    missing = object()
    saved = {n: getattr(main, n, missing) for n in names}
    try:
        for n, cls in names.items():
            setattr(main, n, cls)
        return joblib.load(path)
    finally:
        for n, old in saved.items():
            if old is missing:
                delattr(main, n)
            else:
                setattr(main, n, old)


def to_frame(lines):
    rows = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if not SEV_RE.match(line):
            print(f"note: no severity prefix, treating as INFO: {line}")
            line = f"INFO {line}"
        rows.append({"type": line.split(None, 1)[0], "line": line})
    return pd.DataFrame(rows)


def load_csv(path):
    df = pd.read_csv(path)
    missing = {"severity", "message"} - set(df.columns)
    if missing:
        raise SystemExit(f"{path} needs columns {sorted(missing)} (found {list(df.columns)})")
    df["type"] = df.severity.str.upper()
    df["line"] = df.type + " " + df.message.astype(str)
    return df


def proxy_labels(df):
    """Rule-based labels from columns the model never sees; a sanity check, not ground truth."""
    ext_src = ~df.source_ip.str.startswith("10.")
    lab = np.full(len(df), "normal", dtype=object)
    lab[((df.event_type == "file_transfer") & (df.bytes_out >= 100e6)).values] = "exfiltration"
    lab[(df.event_type == "port_scan").values] = "port_scan"
    lab[((df.event_type == "login_failed") & ext_src).values] = "ssh_brute_force"
    lab[((df.event_type == "login_success") & (df.severity == "ERROR")).values] = "suspicious_login"
    lab[(df.event_type == "privilege_escalation").values] = "privilege_escalation"
    lab[((df.event_type == "file_access") & (df.severity == "ERROR")).values] = "data_dump"
    return pd.Series(lab, index=df.index)


def report_csv(df, prob, alert, detector, out_path, top):
    tpl = strip_severity(df.line).map(to_template)
    unseen = (~tpl.isin(detector.features.tpl_counts_)).mean()
    print(f"rows scored: {len(df):,} | alerts: {alert.sum():,} ({alert.mean():.2%}) | threshold: {detector.threshold:.3f}")
    print(f"rows with a message template never seen in training: {unseen:.2%}")
    if unseen > 0.2:
        print("warning: many unseen templates, the fixed threshold may not transfer to this stream")

    flagged = df.assign(prob=prob, tpl=tpl)[alert == 1]
    print("\nalerts by template:")
    print(flagged.groupby(["tpl", "severity"]).size().sort_values(ascending=False).head(10).to_string())

    cols = [c for c in ["timestamp", "host", "severity", "message"] if c in df.columns]
    print(f"\ntop {top} alerts by probability:")
    print(flagged.sort_values("prob", ascending=False).head(top)[cols + ["prob"]].round(3).to_string(index=False))

    if {"event_type", "source_ip", "bytes_out"} <= set(df.columns):
        attack = proxy_labels(df)
        y = (attack != "normal").astype(int).values
        tp, fp = int(((alert == 1) & (y == 1)).sum()), int(((alert == 1) & (y == 0)).sum())
        fn, tn = int(((alert == 0) & (y == 1)).sum()), int(((alert == 0) & (y == 0)).sum())
        prec, rec = tp / max(tp + fp, 1), tp / max(tp + fn, 1)
        f1 = 2 * prec * rec / max(prec + rec, 1e-12)
        print(f"\nagainst proxy labels (event_type/source_ip/bytes_out rules, not ground truth): {y.sum()} anomalies")
        print(f"confusion matrix  TP={tp} FP={fp} FN={fn} TN={tn}")
        print(f"precision={prec:.3f} recall={rec:.3f} F1={f1:.3f}")
        print("recall per attack type:")
        print(pd.Series(alert, index=df.index)[y == 1].groupby(attack[y == 1]).mean().round(3).to_string())

    out = df.drop(columns=["type", "line"]).assign(anomaly_prob=prob.round(4), anomaly=alert)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(out_path, index=False)
    print(f"\nsaved: {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Detect anomalous log lines.")
    parser.add_argument("logs", nargs="*", help='log lines, e.g. "ERROR Port scan detected from 1.2.3.4"')
    parser.add_argument("--file", help="text file with one log line per line")
    parser.add_argument("--csv", help=f"CSV log stream with severity and message columns (default: {DEFAULT_CSV.name})")
    parser.add_argument("--samples", action="store_true", help="score the built-in sample lines taken from security_logs.csv")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="where to save the scored CSV (CSV mode)")
    parser.add_argument("--top", type=int, default=15, help="how many top alerts to print (CSV mode)")
    args = parser.parse_args()

    line_mode = bool(args.logs or args.file or args.samples)
    if args.csv or not line_mode:
        detector = load_detector()
        df = load_csv(args.csv or DEFAULT_CSV)
        prob = detector.score(df)
        report_csv(df, prob, (prob >= detector.threshold).astype(int), detector, Path(args.out), args.top)
        return

    lines = list(args.logs)
    if args.file:
        lines += Path(args.file).read_text(encoding="utf-8").splitlines()
    if args.samples:
        lines += SAMPLE_LOGS

    df = to_frame(lines)
    detector = load_detector()
    feats = detector.features.transform(df)
    prob = detector.score(df)

    print(f"{'verdict':8} {'prob':>5}  {'ext_ip':>6} {'rarity':>6}  log")
    for line, p, ext, rar in zip(df.line, prob, feats.n_ext_ip, feats.rarity):
        verdict = "ANOMALY" if p >= detector.threshold else "normal"
        print(f"{verdict:8} {p:5.3f}  {int(ext):6d} {rar:6.2f}  {line}")
    print(f"\nthreshold = {detector.threshold:.3f} | anomalies: {(prob >= detector.threshold).sum()} of {len(df)}")


if __name__ == "__main__":
    main()
