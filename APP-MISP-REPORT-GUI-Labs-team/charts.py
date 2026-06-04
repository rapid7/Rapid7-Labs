import base64
import io
from typing import List
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

_TEMPLATE = "plotly_white"

def _fig_to_b64(fig: go.Figure, fmt: str) -> str:
    buf = io.BytesIO()
    if fmt == "png":    fig.write_image(buf, format="png", scale=2)
    elif fmt == "svg":  fig.write_image(buf, format="svg")
    elif fmt == "pdf":  fig.write_image(buf, format="pdf")
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")

def _export(fig, title: str, formats: List[str]) -> List[dict]:
    safe = title.lower().replace(" ", "_")
    results = []
    for fmt in formats:
        mime = "application/pdf" if fmt == "pdf" else f"image/{fmt}"
        try:
            results.append({"format": fmt, "mimeType": mime,
                            "data": _fig_to_b64(fig, fmt),
                            "title": title, "filename": f"{safe}.{fmt}"})
        except Exception as e:
            results.append({"format": fmt, "error": str(e)})
    return results

def chart_ioc_type_pie(df, title, formats):
    if "type" not in df.columns or df.empty:
        return [{"error": "No type data"}]
    counts = df["type"].value_counts().reset_index()
    counts.columns = ["type", "count"]
    fig = px.pie(counts, names="type", values="count", title=title,
                 template=_TEMPLATE, hole=0.3)
    fig.update_traces(textposition="inside", textinfo="percent+label")
    return _export(fig, title, formats)

def chart_ioc_type_bar(df, title, formats):
    if "type" not in df.columns or df.empty:
        return [{"error": "No type data"}]
    counts = df["type"].value_counts().head(20).reset_index()
    counts.columns = ["type", "count"]
    counts = counts.sort_values("count")
    fig = px.bar(counts, x="count", y="type", orientation="h",
                 title=title, template=_TEMPLATE, text="count")
    fig.update_layout(height=max(400, len(counts) * 28))
    return _export(fig, title, formats)

def chart_tags_bar(df, title, formats):
    if "tags" not in df.columns or df.empty:
        return [{"error": "No tags data"}]
    all_tags = (df["tags"].dropna().loc[lambda s: s.str.len() > 0]
                .str.split(", ").explode().loc[lambda s: s.str.len() > 0])
    if all_tags.empty:
        return [{"error": "No tag values found"}]
    counts = all_tags.value_counts().head(15).reset_index()
    counts.columns = ["tag", "count"]
    counts = counts.sort_values("count")
    fig = px.bar(counts, x="count", y="tag", orientation="h",
                 title=title, template=_TEMPLATE, text="count")
    fig.update_layout(height=max(400, len(counts) * 30))
    return _export(fig, title, formats)

def chart_category_bar(df, title, formats):
    if "category" not in df.columns or df.empty:
        return [{"error": "No category data"}]
    counts = df["category"].value_counts().reset_index()
    counts.columns = ["category", "count"]
    counts = counts.sort_values("count")
    fig = px.bar(counts, x="count", y="category", orientation="h",
                 title=title, template=_TEMPLATE, text="count")
    fig.update_layout(height=max(400, len(counts) * 30))
    return _export(fig, title, formats)

def chart_timeline(df, title, formats):
    if "event_date" not in df.columns or df.empty:
        return [{"error": "No date data"}]
    date_col = pd.to_datetime(df["event_date"], errors="coerce")
    df2 = df.assign(date=date_col).dropna(subset=["date"])
    if df2.empty:
        return [{"error": "No parseable dates"}]
    daily = df2.groupby(df2["date"].dt.date).size().reset_index()
    daily.columns = ["date", "count"]
    daily["date"] = pd.to_datetime(daily["date"])
    fig = px.bar(daily, x="date", y="count", title=title, template=_TEMPLATE)
    return _export(fig, title, formats)
