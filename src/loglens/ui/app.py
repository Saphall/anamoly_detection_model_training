"""LogLens: single-page security log analysis app built on the saved message detector.

Run: uv run app  (or: streamlit run streamlit_app.py)
"""
import base64
import html
from pathlib import Path

import altair as alt
import numpy as np
import pandas as pd
import streamlit as st

from loglens import detect_anomaly as da

ASSETS = Path(__file__).parent / "assets"
SEV_ORDER = list(da.SEV_MAP)
MAX_LIVE_LINES = 200
LIVE_EXAMPLES = [
    "INFO Accepted login for bob from 10.0.1.11",
    "WARNING Failed password for laura from 10.0.1.21 port 47439 ssh2",
    "WARNING Failed password for root from 194.45.85.31 port 63228 ssh2",
    "ERROR Large outbound transfer of 2052 MB to 141.194.251.175",
    "ERROR Port scan detected from 185.114.141.41",
    "CRITICAL sudo session opened for root",
]

PALETTES = {
    "dark": dict(
        bg="#060a14", bg2="#0b1226", text="#e8eefb", muted="#8fa0bd", glass="rgba(255,255,255,.055)",
        border="rgba(255,255,255,.13)", shadow="0 10px 40px rgba(0,0,0,.45)", input="rgba(255,255,255,.07)",
        accent="#22d3ee", accent2="#818cf8", danger="#fb4d6d", ok="#34d399", warn="#fbbf24",
        grid="rgba(148,163,184,.09)", blob1="rgba(34,211,238,.20)", blob2="rgba(99,102,241,.26)",
        blob3="rgba(244,63,94,.13)", bar_soft="#4a6fa8", chart_grid="rgba(148,163,184,.16)",
    ),
    "light": dict(
        bg="#eaf0fb", bg2="#dde7f7", text="#0f1b2d", muted="#56677f", glass="rgba(255,255,255,.58)",
        border="rgba(15,27,45,.10)", shadow="0 10px 40px rgba(40,60,110,.14)", input="rgba(255,255,255,.75)",
        accent="#0891b2", accent2="#4f46e5", danger="#e11d48", ok="#059669", warn="#d97706",
        grid="rgba(30,58,110,.07)", blob1="rgba(8,145,178,.20)", blob2="rgba(99,102,241,.20)",
        blob3="rgba(244,63,94,.12)", bar_soft="#7b97c4", chart_grid="rgba(30,58,110,.14)",
    ),
}

st.set_page_config(
    page_title="LogLens | Security log threat detection",
    page_icon=str(ASSETS / "favicon.png"),
    layout="wide",
    initial_sidebar_state="collapsed",
)

light = st.session_state.get("light", False)
P = PALETTES["light" if light else "dark"]


def h(markup: str) -> str:
    """Collapse indentation and blank lines so Markdown never treats the HTML as a code block."""
    return "".join(line.strip() for line in markup.splitlines())


def esc(value) -> str:
    return html.escape(str(value)).replace("$", "&#36;")


def theme_css(p: dict) -> str:
    return h("<style>") + f"""
:root {{ --text:{p['text']}; --muted:{p['muted']}; --glass:{p['glass']}; --border:{p['border']}; --accent:{p['accent']};
        --accent2:{p['accent2']}; --danger:{p['danger']}; --ok:{p['ok']}; --warn:{p['warn']}; --input:{p['input']}; }}
[data-testid="stSidebar"], [data-testid="stSidebarCollapsedControl"], [data-testid="stToolbar"],
[data-testid="stDecoration"], #MainMenu, footer {{ display:none !important; }}
[data-testid="stHeader"] {{ background:transparent; height:0; }}
.stApp {{ color:var(--text); background:
    radial-gradient(900px 520px at 8% -6%, {p['blob1']}, transparent 62%),
    radial-gradient(820px 560px at 96% 4%, {p['blob2']}, transparent 62%),
    radial-gradient(760px 620px at 50% 108%, {p['blob3']}, transparent 62%),
    linear-gradient(180deg, {p['bg']}, {p['bg2']}); background-attachment:fixed; }}
.stApp::before {{ content:""; position:fixed; inset:0; pointer-events:none; z-index:0;
    background-image:linear-gradient({p['grid']} 1px, transparent 1px), linear-gradient(90deg, {p['grid']} 1px, transparent 1px);
    background-size:44px 44px; -webkit-mask-image:radial-gradient(ellipse at 50% 0%, #000 0%, transparent 78%);
    mask-image:radial-gradient(ellipse at 50% 0%, #000 0%, transparent 78%); }}
[data-testid="stAppViewContainer"] {{ position:relative; z-index:1; }}
.block-container {{ max-width:1180px; padding-top:1.6rem; padding-bottom:3rem; }}
.stApp, .stApp [data-testid="stMarkdownContainer"] p, .stApp [data-testid="stWidgetLabel"] *,
.stApp [data-testid="stFileUploaderDropzone"] *, .stApp [data-testid="stAlert"] * {{ color:var(--text); }}
[data-testid="stWidgetLabel"] p {{ font-size:.82rem; font-weight:600; letter-spacing:.02em; }}

/* glass surfaces */
[class*="st-key-glass"] {{ background:var(--glass); border:1px solid var(--border); border-radius:20px; padding:1.1rem 1.3rem;
    -webkit-backdrop-filter:blur(18px) saturate(150%); backdrop-filter:blur(18px) saturate(150%);
    box-shadow:{p['shadow']}, inset 0 1px 0 rgba(255,255,255,.10); }}
.kpi {{ min-height:122px; background:var(--glass); border:1px solid var(--border); border-radius:18px; padding:1rem 1.15rem; height:100%;
    -webkit-backdrop-filter:blur(18px); backdrop-filter:blur(18px); box-shadow:{p['shadow']}; }}
.kpi .label {{ color:var(--muted); font-size:.7rem; text-transform:uppercase; letter-spacing:.1em; font-weight:600; }}
.kpi .value {{ font-size:1.85rem; font-weight:750; font-family:ui-monospace,Menlo,Consolas,monospace; line-height:1.25; }}
.kpi .note {{ color:var(--muted); font-size:.74rem; line-height:1.35; }}
.kpi.danger .value {{ color:var(--danger); }} .kpi.accent .value {{ color:var(--accent); }}

/* header */
.brand {{ display:flex; align-items:center; gap:1rem; }}
.brand img {{ width:62px; height:62px; filter:drop-shadow(0 6px 16px rgba(34,211,238,.35)); }}
.brand .name {{ font-size:2.1rem; font-weight:800; letter-spacing:-.03em; line-height:1.05;
    background:linear-gradient(90deg, var(--accent), var(--accent2)); -webkit-background-clip:text; background-clip:text; color:transparent; }}
.brand .tagline {{ color:var(--muted); font-size:.9rem; margin-top:.2rem; }}
.pill {{ display:inline-flex; align-items:center; gap:.4rem; font-size:.72rem; padding:.18rem .65rem; border-radius:99px;
    border:1px solid var(--border); background:var(--glass); color:var(--muted); margin-right:.4rem; font-weight:600; }}
.pill .dot {{ width:7px; height:7px; border-radius:50%; background:var(--ok); box-shadow:0 0 8px var(--ok); animation:pulse 2s infinite; }}
@keyframes pulse {{ 50% {{ opacity:.35; }} }}

/* sections and chart headers */
.sec {{ margin:2.2rem 0 .9rem; }}
.sec .eyebrow {{ color:var(--accent); font-size:.72rem; font-weight:700; letter-spacing:.16em; text-transform:uppercase; }}
.sec .title {{ font-size:1.5rem; font-weight:750; letter-spacing:-.02em; margin:.1rem 0; }}
.sec .desc {{ color:var(--muted); font-size:.9rem; max-width:760px; line-height:1.5; }}
.ch-title {{ font-weight:700; font-size:1rem; }}
.ch-desc {{ color:var(--muted); font-size:.8rem; line-height:1.45; margin:.15rem 0 .5rem; }}

/* live check results */
.banner {{ border-radius:14px; padding:.8rem 1.1rem; font-weight:650; margin:.6rem 0 .8rem; border:1px solid var(--border); }}
.banner.bad {{ background:color-mix(in srgb, var(--danger) 16%, transparent); border-color:var(--danger); }}
.banner.ok {{ background:color-mix(in srgb, var(--ok) 15%, transparent); border-color:var(--ok); }}
.res {{ border:1px solid var(--border); border-left:4px solid var(--ok); border-radius:14px; padding:.75rem 1rem; margin-bottom:.65rem;
    background:var(--glass); }}
.res.bad {{ border-left-color:var(--danger); box-shadow:0 0 22px color-mix(in srgb, var(--danger) 16%, transparent); }}
.res-top {{ display:flex; align-items:center; gap:.5rem; flex-wrap:wrap; margin-bottom:.45rem; }}
.badge {{ font-size:.68rem; font-weight:800; letter-spacing:.08em; padding:.15rem .55rem; border-radius:7px; color:#fff; }}
.badge.bad {{ background:var(--danger); }} .badge.ok {{ background:var(--ok); }}
.badge.sev {{ background:transparent; border:1px solid var(--border); color:var(--muted); }}
.score {{ margin-left:auto; font-family:ui-monospace,Menlo,Consolas,monospace; font-weight:750; font-size:1.05rem; }}
.meter {{ position:relative; height:8px; border-radius:6px; background:color-mix(in srgb, var(--muted) 22%, transparent); margin:.2rem 0 1.15rem; }}
.meter .fill {{ height:100%; border-radius:6px; background:linear-gradient(90deg, var(--ok), var(--warn), var(--danger)); }}
.meter .tick {{ position:absolute; top:-4px; width:2px; height:16px; background:var(--text); opacity:.75; }}
.meter .tick span {{ position:absolute; top:17px; left:-30px; width:62px; text-align:center; font-size:.62rem; color:var(--muted); }}
.logline {{ font-family:ui-monospace,Menlo,Consolas,monospace; font-size:.84rem; word-break:break-all; margin:.1rem 0 .5rem; }}
.tags {{ display:flex; flex-wrap:wrap; gap:.35rem; }}
.tag {{ font-size:.7rem; padding:.12rem .55rem; border-radius:99px; border:1px solid var(--border); color:var(--muted); }}
.tag.hot {{ color:var(--danger); border-color:var(--danger); }}

/* alerts table */
.tbl-wrap {{ overflow-x:auto; border-radius:14px; border:1px solid var(--border); }}
table.alerts {{ width:100%; border-collapse:collapse; font-size:.82rem; }}
table.alerts th {{ text-align:left; color:var(--muted); font-size:.68rem; text-transform:uppercase; letter-spacing:.09em; padding:.6rem .8rem;
    border-bottom:1px solid var(--border); background:color-mix(in srgb, var(--muted) 8%, transparent); white-space:nowrap; }}
table.alerts td {{ white-space:nowrap; padding:.5rem .8rem; border-bottom:1px solid color-mix(in srgb, var(--border) 60%, transparent); vertical-align:middle; }}
table.alerts td.msg {{ white-space:normal; font-family:ui-monospace,Menlo,Consolas,monospace; font-size:.78rem; min-width:260px; }}
table.alerts tr:last-child td {{ border-bottom:none; }}
.mini {{ display:flex; align-items:center; gap:.5rem; min-width:120px; }}
.mini .b {{ flex:1; height:6px; border-radius:4px; background:color-mix(in srgb, var(--muted) 22%, transparent); }}
.mini .b i {{ display:block; height:100%; border-radius:4px; background:var(--danger); }}
.foot {{ color:var(--muted); font-size:.75rem; text-align:center; margin-top:2.2rem; }}

/* widgets */
[data-baseweb="textarea"] {{ background:var(--input) !important; border:1px solid var(--border) !important; border-radius:14px !important; }}
[data-testid="stTextArea"] div:not([data-baseweb="textarea"]), [data-baseweb="base-input"] {{ background:transparent !important; }}
[data-testid="stTooltipIcon"] svg {{ color:var(--muted) !important; }}
[data-baseweb="textarea"] textarea {{ background:transparent !important; color:var(--text) !important;
    font-family:ui-monospace,Menlo,Consolas,monospace; font-size:.85rem; }}
[data-baseweb="textarea"]:focus-within {{ border-color:var(--accent) !important; box-shadow:0 0 0 3px color-mix(in srgb, var(--accent) 22%, transparent); }}
[data-testid="stBaseButton-secondary"], button[data-variant="pills"], button[data-variant="segmented_control"] {{
    background:var(--input); color:var(--text); border:1px solid var(--border); border-radius:12px; }}
[data-testid="stBaseButton-secondary"] *, button[data-variant="pills"] *, button[data-variant="segmented_control"] * {{ color:var(--text) !important; }}
[data-testid="stBaseButton-primary"] {{ background:linear-gradient(135deg, {p['accent']}, {p['accent2']}); border:none; border-radius:12px; }}
[data-testid="stBaseButton-primary"] * {{ color:#fff !important; font-weight:650; }}
button[data-variant="pills"][aria-pressed="true"], button[data-variant="segmented_control"][aria-checked="true"],
button[data-variant="segmented_control"][aria-pressed="true"] {{
    background:color-mix(in srgb, var(--accent) 26%, transparent); border:1px solid var(--accent); }}
[data-testid="stFileUploaderDropzone"] {{ background:var(--input); border:1px dashed var(--border); border-radius:14px; }}
[data-testid="stSliderThumbValue"] {{ color:var(--accent) !important; font-weight:700; }}
[data-testid="stSliderTickBarMin"], [data-testid="stSliderTickBarMax"] {{ color:var(--muted) !important; }}
[data-testid="stDownloadButton"] button {{ background:var(--input); border:1px solid var(--border); border-radius:12px; }}
[data-testid="stDownloadButton"] button * {{ color:var(--text) !important; }}
[data-testid="stAlert"] {{ background:var(--glass); border:1px solid var(--border); border-radius:14px; }}
</style>"""


@st.cache_resource(show_spinner="Loading model...")
def load_detector():
    return da.load_detector()


@st.cache_data(show_spinner="Scoring events...")
def score_frame(df: pd.DataFrame) -> pd.DataFrame:
    detector = load_detector()
    df = df.copy()
    df["type"] = df.severity.astype(str).str.upper()
    df["line"] = df.type + " " + df.message.astype(str)
    df["prob"] = detector.score(df)
    df["template"] = da.strip_severity(df.line).map(da.to_template)
    df["seen"] = df.template.isin(detector.features.tpl_counts_)
    if "timestamp" in df.columns:
        df["ts"] = pd.to_datetime(df.timestamp, errors="coerce")
    return df.drop(columns=["type", "line"])


def parse_live_lines(text: str) -> pd.DataFrame:
    rows = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            continue
        first, _, rest = s.partition(" ")
        sev = first.strip("[]:").upper()
        has_sev = sev in da.SEV_MAP and rest.strip() != ""
        line = f"{sev} {rest.strip()}" if has_sev else f"INFO {s}"
        rows.append({"type": line.split(None, 1)[0], "line": line, "assumed": not has_sev})
    return pd.DataFrame(rows, columns=["type", "line", "assumed"])


def explain(row, feats, detector) -> list[tuple[str, bool]]:
    """Human-readable reasons behind a score, as (text, is_risk_signal)."""
    tags = []
    if row.type in ("ERROR", "CRITICAL"):
        tags.append((f"{row.type} severity", True))
    if feats.n_ext_ip > 0:
        tags.append((f"{int(feats.n_ext_ip)} external IP{'s' if feats.n_ext_ip > 1 else ''}", True))
    size = float(np.expm1(feats.log_size_mb))
    if size >= 100:
        tags.append((f"large transfer ~{size:,.0f} MB", True))
    count = detector.features.tpl_counts_.get(da.to_template(da.SEV_RE.sub("", row.line)), 0)
    if count == 0:
        tags.append(("pattern unseen in training", True))
    elif feats.rarity >= 5.5:
        tags.append((f"rare pattern ({count} in training)", True))
    elif feats.rarity < 4:
        tags.append(("common traffic pattern", False))
    if row.assumed:
        tags.append(("no severity given, assumed INFO", False))
    return tags


def kpi(label: str, value: str, note: str, tone: str = "") -> str:
    return h(f'<div class="kpi {tone}"><div class="label">{label}</div><div class="value">{value}</div><div class="note">{note}</div></div>')


def section(eyebrow: str, title: str, desc: str):
    st.markdown(h(f'<div class="sec"><div class="eyebrow">{eyebrow}</div><div class="title">{title}</div><div class="desc">{desc}</div></div>'),
                unsafe_allow_html=True)


def chart_header(title: str, desc: str):
    st.markdown(h(f'<div class="ch-title">{esc(title)}</div><div class="ch-desc">{esc(desc)}</div>'), unsafe_allow_html=True)


def style(chart, height: int = 270):
    return (
        chart.properties(height=height, background="transparent")
        .configure_view(stroke=None)
        .configure_axis(gridColor=P["chart_grid"], labelColor=P["muted"], titleColor=P["muted"], domainColor=P["chart_grid"],
                        tickColor=P["chart_grid"], titleFontSize=11, titleFontWeight="normal", labelFontSize=11)
        .configure_legend(orient="top", labelColor=P["text"], title=None, symbolType="square", symbolOpacity=1, labelFontSize=11)
    )


LOG_TICKS = alt.Axis(values=[0, 1, 10, 100, 1000, 10000], labelExpr="format(datum.value, ',d')")


def series_scale():
    return alt.Scale(domain=["All events", "Alerts"], range=[P["bar_soft"], P["danger"]])


def timeline_chart(df: pd.DataFrame):
    d = df[df.ts.notna()]
    span = d.ts.max() - d.ts.min()
    freq = max(pd.Timedelta(minutes=1), (span / 48).ceil("1min"))
    b = d.assign(bucket=d.ts.dt.floor(freq)).groupby("bucket").agg(n_events=("alert", "size"), n_alerts=("alert", "sum"))
    b = b.reindex(pd.date_range(b.index.min(), b.index.max(), freq=freq), fill_value=0).rename_axis("bucket").reset_index()
    log = alt.Scale(type="symlog")
    x = alt.X("bucket:T", title="Time")
    ev = b.assign(series="All events", n=b.n_events)
    al = b[b.n_alerts > 0].assign(series="Alerts", n=b.n_alerts)
    tip = [alt.Tooltip("bucket:T", title="Slot start"), alt.Tooltip("series:N", title="Series"), alt.Tooltip("n:Q", title="Count")]
    area = alt.Chart(ev).mark_area(opacity=0.35, interpolate="step-after", line=True).encode(
        x=x, y=alt.Y("n:Q", scale=log, stack=None, title="Events per slot (log scale)", axis=LOG_TICKS),
        color=alt.Color("series:N", scale=series_scale()), tooltip=tip)
    layers = [area]
    if len(al):
        layers.append(alt.Chart(al).mark_bar(size=7, opacity=0.95).encode(x=x, y=alt.Y("n:Q", scale=log, stack=None, axis=LOG_TICKS),
                                                                      color=alt.Color("series:N", scale=series_scale()), tooltip=tip))
        peak = al.loc[al.n.idxmax()]
        late = peak.bucket > d.ts.min() + span / 2
        note = pd.DataFrame({"bucket": [peak.bucket], "n": [peak.n], "label": [f"Peak: {int(peak.n):,} alerts at {peak.bucket:%H:%M}"]})
        layers.append(alt.Chart(note).mark_point(color=P["text"], size=70, filled=False, strokeWidth=2).encode(x="bucket:T", y=alt.Y("n:Q", scale=log, axis=LOG_TICKS)))
        layers.append(alt.Chart(note).mark_text(color=P["text"], fontWeight="bold", align="right" if late else "left", dx=-10 if late else 10,
                                                dy=-10, fontSize=11).encode(x="bucket:T", y=alt.Y("n:Q", scale=log, axis=LOG_TICKS), text="label:N"))
    return style(alt.layer(*layers))


def severity_chart(df: pd.DataFrame):
    s = df.groupby("severity").agg(events=("alert", "size"), alerts=("alert", "sum")).reindex(SEV_ORDER).fillna(0)
    s = s[s.events > 0].reset_index()
    s["label"] = s.apply(lambda r: f"{int(r.alerts):,} / {int(r.events):,}", axis=1)
    domain = alt.Scale(type="symlog", domain=[0, max(s.events.max() * 30, 10)])
    y = alt.Y("severity:N", sort=SEV_ORDER, title="Severity level")
    xax = alt.X("events:Q", scale=domain, stack=None, title="Events (log scale)", axis=LOG_TICKS)
    total = alt.Chart(s.assign(series="All events")).mark_bar(size=22).encode(y=y, x=xax, color=alt.Color("series:N", scale=series_scale()),
                                                                              tooltip=["severity", "events", "alerts"])
    flagged = alt.Chart(s.assign(series="Alerts")).mark_bar(size=22).encode(y=y, x=alt.X("alerts:Q", scale=domain, stack=None, axis=LOG_TICKS), color=alt.Color("series:N", scale=series_scale()))
    text = alt.Chart(s).mark_text(align="left", dx=6, color=P["text"], fontSize=11).encode(y=y, x=alt.X("events:Q", scale=domain, stack=None, axis=LOG_TICKS), text="label:N")
    return style(alt.layer(total, flagged, text))


def score_chart(df: pd.DataFrame, threshold: float):
    edges = np.linspace(0, 1, 41)
    counts, _ = np.histogram(df.prob, bins=edges)
    hist = pd.DataFrame({"x": edges[:-1], "x2": edges[1:], "n": counts})
    hist["zone"] = np.where((hist.x + hist.x2) / 2 >= threshold, "Alert zone", "Below threshold")
    hist = hist[hist.n > 0].assign(zero=0)
    xs = alt.Scale(domain=[0, 1])
    bars = alt.Chart(hist).mark_bar().encode(
        x=alt.X("x:Q", scale=xs, title="Anomaly score (0 = looks normal, 1 = looks malicious)"), x2="x2:Q",
        y=alt.Y("n:Q", scale=alt.Scale(type="symlog"), stack=None, title="Events (log scale)", axis=LOG_TICKS), y2="zero:Q",
        color=alt.Color("zone:N", scale=alt.Scale(domain=["Below threshold", "Alert zone"], range=[P["accent"], P["danger"]])),
        tooltip=[alt.Tooltip("x:Q", title="Score from", format=".3f"), alt.Tooltip("x2:Q", title="to", format=".3f"), alt.Tooltip("n:Q", title="Events")])
    region = alt.Chart(pd.DataFrame({"x": [threshold], "x2": [1.0]})).mark_rect(color=P["danger"], opacity=0.08).encode(x=alt.X("x:Q", scale=xs), x2="x2:Q")
    rule = alt.Chart(pd.DataFrame({"x": [threshold]})).mark_rule(color=P["text"], strokeDash=[6, 4], size=2).encode(x=alt.X("x:Q", scale=xs))
    label = alt.Chart(pd.DataFrame({"x": [threshold], "t": [f"threshold {threshold:.2f}"]})).mark_text(
        align="right", dx=-6, color=P["text"], fontWeight="bold", fontSize=11).encode(x=alt.X("x:Q", scale=xs), y=alt.value(10), text="t:N")
    zone = alt.Chart(pd.DataFrame({"x": [(threshold + 1) / 2], "t": ["ALERT ZONE"]})).mark_text(
        color=P["danger"], fontWeight="bold", fontSize=11).encode(x=alt.X("x:Q", scale=xs), y=alt.value(26), text="t:N")
    return style(alt.layer(region, bars, rule, label, zone))


def ranked_chart(counts: pd.Series, x_title: str, color: str, label_limit: int = 260):
    d = counts.rename("n").rename_axis("label").reset_index()
    xs = alt.Scale(domain=[0, max(d.n.max() * 1.18, 1)])
    base = alt.Chart(d).encode(y=alt.Y("label:N", sort="-x", title=None, axis=alt.Axis(labelLimit=label_limit)), x=alt.X("n:Q", scale=xs, title=x_title))
    bars = base.mark_bar(color=color, cornerRadiusEnd=4).encode(tooltip=["label", "n"])
    text = base.mark_text(align="left", dx=5, color=P["text"], fontSize=11).encode(text="n:Q")
    return style(alt.layer(bars, text), height=max(150, 34 * len(d) + 30))


def live_chart(res: pd.DataFrame, threshold: float):
    d = res.copy()
    d["name"] = [f"#{i + 1} {s[:38]}{'...' if len(s) > 38 else ''}" for i, s in enumerate(d.line)]
    d["verdict"] = np.where(d.prob >= threshold, "Anomaly", "Normal")
    xs = alt.Scale(domain=[0, 1.12])
    y = alt.Y("name:N", sort=None, title=None, axis=alt.Axis(labelLimit=330))
    bars = alt.Chart(d).mark_bar(cornerRadiusEnd=4, size=18).encode(
        y=y, x=alt.X("prob:Q", scale=xs, title="Anomaly score", axis=alt.Axis(values=[0, .25, .5, .75, 1])),
        color=alt.Color("verdict:N", scale=alt.Scale(domain=["Normal", "Anomaly"], range=[P["ok"], P["danger"]])),
        tooltip=["line", alt.Tooltip("prob:Q", format=".3f", title="score")])
    text = alt.Chart(d).mark_text(align="left", dx=5, color=P["text"], fontSize=11).encode(y=y, x=alt.X("prob:Q", scale=xs), text=alt.Text("prob:Q", format=".3f"))
    rule = alt.Chart(pd.DataFrame({"x": [threshold]})).mark_rule(color=P["text"], strokeDash=[6, 4], size=2).encode(x=alt.X("x:Q", scale=xs))
    label = alt.Chart(pd.DataFrame({"x": [threshold], "t": [f"threshold {threshold:.2f}"]})).mark_text(
        align="left", dx=5, color=P["text"], fontWeight="bold", fontSize=11).encode(x=alt.X("x:Q", scale=xs), y=alt.value(8), text="t:N")
    return style(alt.layer(bars, text, rule, label), height=max(130, 36 * len(d) + 50))


def alerts_table(alerts: pd.DataFrame) -> str:
    cols = [c for c in ["ts", "host", "severity", "source_ip", "username", "message"] if c in alerts.columns]
    names = {"ts": "Time", "host": "Host", "severity": "Severity", "source_ip": "Source IP", "username": "User", "message": "Message"}
    head = "".join(f"<th>{names[c]}</th>" for c in cols) + "<th>Score</th>"
    rows = []
    for _, r in alerts.iterrows():
        cells = []
        for c in cols:
            if c == "ts":
                cells.append(f"<td>{esc(r.ts.strftime('%Y-%m-%d %H:%M:%S')) if pd.notna(r.ts) else ''}</td>")
            elif c == "severity":
                cells.append(f'<td><span class="badge sev">{esc(r.severity)}</span></td>')
            elif c == "message":
                cells.append(f'<td class="msg">{esc(r.message)}</td>')
            else:
                cells.append(f"<td>{esc(r[c])}</td>")
        cells.append(f'<td><div class="mini"><div class="b"><i style="width:{r.prob * 100:.1f}%"></i></div><b>{r.prob:.3f}</b></div></td>')
        rows.append("<tr>" + "".join(cells) + "</tr>")
    return h(f'<div class="tbl-wrap"><table class="alerts"><thead><tr>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>')


def set_examples():
    st.session_state.live_input = "\n".join(LIVE_EXAMPLES)


def clear_input():
    st.session_state.live_input = ""


detector = load_detector()
st.markdown(theme_css(P), unsafe_allow_html=True)
st.session_state.setdefault("live_input", "\n".join(LIVE_EXAMPLES))
logo = base64.b64encode((ASSETS / "logo.svg").read_bytes()).decode()

# ---- Header
with st.container(key="glass_header"):
    c_brand, c_thr, c_theme = st.columns([5, 4, 1.7], vertical_alignment="center")
    with c_brand:
        st.markdown(h(f"""
            <div class="brand"><img src="data:image/svg+xml;base64,{logo}" alt="LogLens logo"/>
            <div><div class="name">LogLens</div><div class="tagline">Threat detection for security logs</div>
            <div style="margin-top:.5rem"><span class="pill"><span class="dot"></span>Model online</span>
            <span class="pill">🛡️ RandomForest</span></div></div></div>"""), unsafe_allow_html=True)
    with c_thr:
        threshold = st.slider("Alert threshold", 0.0, 1.0, float(round(detector.threshold, 3)), 0.01, key="thr",
                              help=f"Events scoring at or above this are flagged. Model default: {detector.threshold:.3f}. "
                                   "Lower it to catch more threats (more false alarms), raise it to be stricter.")
    with c_theme:
        st.toggle("☀️ Light mode", key="light")

# ---- Live check
section("Step 1 · Live check", "Paste logs, get a verdict",
        "Drop one or more log lines below (one per line, starting with INFO, WARNING, ERROR or CRITICAL). "
        "The model scores each line and explains which signals pushed it toward an anomaly.")
with st.container(key="glass_live"):
    st.text_area("Log lines", key="live_input", height=150, label_visibility="collapsed",
                 placeholder='ERROR Port scan detected from 185.114.141.41\nWARNING Failed password for root from 194.45.85.31 port 63228 ssh2')
    b1, b2, b3, _ = st.columns([1.2, 1.4, 1, 6])
    b1.button("Analyze", type="primary", width="stretch")
    b2.button("Load examples", on_click=set_examples, width="stretch")
    b3.button("Clear", on_click=clear_input, width="stretch")
    st.markdown(h('<div class="ch-desc">Press Ctrl+Enter in the box or click Analyze. Lines without a severity are treated as INFO.</div>'), unsafe_allow_html=True)

    frame = parse_live_lines(st.session_state.live_input)
    if len(frame) > MAX_LIVE_LINES:
        st.warning(f"Only the first {MAX_LIVE_LINES} lines are analyzed.")
        frame = frame.head(MAX_LIVE_LINES)
    if frame.empty:
        st.info("Nothing to analyze yet. Paste a log line or load the examples.")
    else:
        frame["prob"] = detector.score(frame)
        feats = detector.features.transform(frame)
        flagged = int((frame.prob >= threshold).sum())
        top = frame.prob.max()
        if flagged:
            st.markdown(h(f'<div class="banner bad">🚨 {flagged} of {len(frame)} line{"s" if len(frame) > 1 else ""} flagged as anomalous · highest score {top:.3f}</div>'),
                        unsafe_allow_html=True)
        else:
            st.markdown(h(f'<div class="banner ok">✅ All {len(frame)} line{"s" if len(frame) > 1 else ""} look normal · highest score {top:.3f}</div>'),
                        unsafe_allow_html=True)
        cards = []
        for i, row in enumerate(frame.itertuples()):
            bad = row.prob >= threshold
            tags = "".join(f'<span class="tag {"hot" if risk else ""}">{esc(t)}</span>' for t, risk in explain(row, feats.iloc[i], detector))
            cards.append(f"""<div class="res {'bad' if bad else 'ok'}"><div class="res-top">
                <span class="badge {'bad' if bad else 'ok'}">{'ANOMALY' if bad else 'NORMAL'}</span><span class="badge sev">{esc(row.type)}</span>
                <span class="score">{row.prob:.3f}</span></div>
                <div class="meter"><div class="fill" style="width:{row.prob * 100:.1f}%;background-size:{10000 / max(row.prob * 100, 1):.0f}% 100%"></div>
                <div class="tick" style="left:{threshold * 100:.1f}%"><span>threshold</span></div></div>
                <div class="logline">{esc(row.line)}</div><div class="tags">{tags}</div></div>""")
        st.markdown(h("".join(cards)), unsafe_allow_html=True)
        if len(frame) > 1:
            chart_header("Score per submitted line",
                         "Each bar is one line you pasted, in order. Bars crossing the dashed threshold are classified as anomalies (red); the rest are normal (green).")
            st.altair_chart(live_chart(frame, threshold), theme=None, width="stretch")

# ---- Dataset analysis
section("Step 2 · Stream analysis", "What does a whole log stream look like?",
        "Analyze a full CSV export to see when threats cluster, where they come from and which patterns trigger alerts. "
        "Uses the bundled sample stream unless you upload your own.")
with st.container(key="glass_source"):
    s1, s2, s3 = st.columns([2, 3, 2], vertical_alignment="top")
    with s1:
        source = st.segmented_control("Data source", ["Sample stream", "Upload CSV"], default="Sample stream", key="source")
    with s2:
        sev_filter = st.pills("Severity filter", SEV_ORDER, selection_mode="multi", default=SEV_ORDER, key="sev")
    with s3:
        top_n = st.slider("Rows in alert table", 10, 200, 25, 5)
    upload = None
    if source == "Upload CSV":
        upload = st.file_uploader("Log stream (CSV)", type="csv", help="Needs `severity` and `message` columns.")

if source == "Upload CSV" and upload is None:
    st.info("Upload a CSV with `severity` and `message` columns to analyze it, or switch back to the sample stream.")
    st.stop()
raw = pd.read_csv(upload if upload is not None else da.DEFAULT_CSV)
source_name = upload.name if upload is not None else da.DEFAULT_CSV.name

missing = {"severity", "message"} - set(raw.columns)
if missing:
    st.error(f"The CSV is missing required columns: {sorted(missing)}")
    st.stop()

df = score_frame(raw)
df = df[df.severity.astype(str).str.upper().isin(sev_filter or [])].copy()
if df.empty:
    st.warning("No events match the current severity filter.")
    st.stop()
df["alert"] = df.prob >= threshold
alerts = df[df.alert]

k = st.columns(5)
k[0].markdown(kpi("Events", f"{len(df):,}", f"scanned from {esc(source_name)}"), unsafe_allow_html=True)
k[1].markdown(kpi("Alerts", f"{len(alerts):,}", f"events scoring ≥ {threshold:.2f}", "danger"), unsafe_allow_html=True)
k[2].markdown(kpi("Alert rate", f"{df.alert.mean():.2%}", "share of events flagged", "accent"), unsafe_allow_html=True)
k[3].markdown(kpi("Peak score", f"{df.prob.max():.3f}", "most suspicious event"), unsafe_allow_html=True)
k[4].markdown(kpi("Unseen patterns", f"{(~df.seen).mean():.1%}", "messages not in training data"), unsafe_allow_html=True)
if (~df.seen).mean() > 0.2:
    st.warning("Many message patterns were never seen in training, so the threshold may not transfer to this stream.")
st.write("")

left, right = st.columns([3, 2])
with left, st.container(key="glass_timeline"):
    chart_header("Threat activity over time",
                 "Events arriving in each time slot (blue) and how many were flagged (red), on a log scale so small attack bursts stay visible next to heavy traffic. "
                 "Clusters of red point to coordinated activity such as brute force or data exfiltration.")
    if "ts" in df and df.ts.notna().any():
        st.altair_chart(timeline_chart(df), theme=None, width="stretch")
    else:
        st.info("No usable `timestamp` column, so the timeline is unavailable.")
with right, st.container(key="glass_severity"):
    chart_header("Flagged events by severity",
                 "Total events per severity (blue) against the part the model flagged (red); labels read flagged / total. Anomalies often hide in low-severity levels, "
                 "which a severity-only rule would miss.")
    st.altair_chart(severity_chart(df), theme=None, width="stretch")

left, right = st.columns(2)
with left, st.container(key="glass_scores"):
    chart_header("How suspicious is the traffic?",
                 "Every event gets a score from 0 (normal) to 1 (malicious). Most traffic sits near 0; bars right of the dashed threshold become alerts. "
                 "Move the threshold at the top to trade missed threats against false alarms.")
    st.altair_chart(score_chart(df, threshold), theme=None, width="stretch")
with right, st.container(key="glass_templates"):
    chart_header("What triggers alerts",
                 "Messages grouped into patterns, with IPs, users and ports replaced by placeholders so similar events count together. "
                 "The longest bars are the activity types behind most alerts.")
    if alerts.empty:
        st.info("No alerts at this threshold.")
    else:
        st.altair_chart(ranked_chart(alerts.groupby("template").size().sort_values(ascending=False).head(8), "Alerts per message pattern", P["danger"]),
                        theme=None, width="stretch")

if not alerts.empty and {"source_ip", "host"} & set(alerts.columns):
    left, right = st.columns(2)
    if "source_ip" in alerts.columns:
        with left, st.container(key="glass_sources"):
            chart_header("Top alert sources", "Source IP addresses behind the most alerts. Good starting points for investigation or blocking.")
            st.altair_chart(ranked_chart(alerts.source_ip.value_counts().head(8), "Alerts per source IP", P["accent2"], 140), theme=None, width="stretch")
    if "host" in alerts.columns:
        with right, st.container(key="glass_hosts"):
            chart_header("Most targeted hosts", "Hosts that logged the most flagged events, showing where suspicious activity is concentrated.")
            st.altair_chart(ranked_chart(alerts.host.value_counts().head(8), "Alerts per host", P["warn"], 140), theme=None, width="stretch")

section("Evidence", "Highest-scoring alerts",
        "The most suspicious events in this stream, ranked by anomaly score. The bar shows how close each one is to a score of 1.")
with st.container(key="glass_alerts"):
    if alerts.empty:
        st.success("No alerts at this threshold.")
    else:
        top_alerts = alerts.sort_values("prob", ascending=False).head(top_n)
        st.markdown(alerts_table(top_alerts), unsafe_allow_html=True)
        st.write("")
        st.download_button("Download all alerts (CSV)", alerts.drop(columns=["ts", "seen"], errors="ignore").to_csv(index=False),
                           file_name="alerts.csv", mime="text/csv")

st.markdown(h(f'<div class="foot">LogLens · message RandomForest · default threshold {detector.threshold:.3f} · '
              'scores are decision support, not proof of an attack</div>'), unsafe_allow_html=True)
