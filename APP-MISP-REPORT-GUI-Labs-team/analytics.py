from typing import Any, Dict
import pandas as pd

def _extract_tag_names(tag_list) -> str:
    names = []
    for t in tag_list or []:
        if hasattr(t, "name"):       names.append(str(t.name))
        elif isinstance(t, dict):    names.append(str(t.get("name", "")))
        elif isinstance(t, str):     names.append(t)
    return ", ".join(n for n in names if n)

def _attr_to_row(attr, event_id="", event_info="", event_date="") -> dict:
    def _get(obj, key, default=""):
        if hasattr(obj, key):    return getattr(obj, key, default)
        if hasattr(obj, "get"):  return obj.get(key, default)
        return default
    tag_list = _get(attr, "Tag") or _get(attr, "tags") or []
    return {
        "event_id":   str(event_id or _get(attr, "event_id", "")),
        "event_info": str(event_info),
        "event_date": str(event_date),
        "attr_id":    str(_get(attr, "id", "")),
        "type":       str(_get(attr, "type", "")),
        "category":   str(_get(attr, "category", "")),
        "value":      str(_get(attr, "value", "")),
        "timestamp":  str(_get(attr, "timestamp", "")),
        "tags":       _extract_tag_names(tag_list),
        "to_ids":     bool(_get(attr, "to_ids", False)),
        "comment":    str(_get(attr, "comment", "")),
    }

def event_to_dataframe(event) -> pd.DataFrame:
    attrs = []
    if hasattr(event, "attributes"):     attrs = event.attributes or []
    elif hasattr(event, "get"):          attrs = event.get("Attribute", []) or []
    _g = lambda k: event.get(k, "") if hasattr(event, "get") else getattr(event, k, "")
    rows = [_attr_to_row(a, _g("id"), _g("info"), _g("date")) for a in attrs]
    return pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=["event_id","event_info","event_date","attr_id",
                 "type","category","value","timestamp","tags","to_ids","comment"])

def events_to_dataframe(events: list) -> pd.DataFrame:
    frames = [event_to_dataframe(e) for e in events]
    non_empty = [f for f in frames if not f.empty]
    return pd.concat(non_empty, ignore_index=True) if non_empty else pd.DataFrame()

def attributes_to_dataframe(attrs: list) -> pd.DataFrame:
    rows = [_attr_to_row(a) for a in attrs]
    return pd.DataFrame(rows) if rows else pd.DataFrame()

def get_statistics(df: pd.DataFrame) -> Dict[str, Any]:
    if df is None or df.empty:
        return {"total_attributes": 0}
    stats: Dict[str, Any] = {
        "total_attributes": len(df),
        "unique_events": int(df["event_id"].nunique()) if "event_id" in df.columns else 0,
    }
    if "type" in df.columns and not df["type"].dropna().empty:
        tc = df["type"].value_counts()
        stats["ioc_type_distribution"] = tc.head(20).to_dict()
        stats["most_common_type"] = str(tc.idxmax())
        stats["unique_ioc_types"] = int(df["type"].nunique())
    if "category" in df.columns and not df["category"].dropna().empty:
        stats["category_distribution"] = df["category"].value_counts().to_dict()
    if "tags" in df.columns:
        all_tags = (df["tags"].dropna().loc[lambda s: s.str.len() > 0]
                    .str.split(", ").explode().loc[lambda s: s.str.len() > 0])
        if not all_tags.empty:
            stats["top_tags"] = all_tags.value_counts().head(15).to_dict()
            stats["unique_tags"] = int(all_tags.nunique())
    if "event_date" in df.columns:
        dates = df["event_date"].dropna().loc[lambda s: s.str.len() > 0]
        if not dates.empty:
            stats["date_range"] = {"earliest": str(dates.min()), "latest": str(dates.max())}
    if "to_ids" in df.columns:
        stats["to_ids_flagged"] = int(df["to_ids"].sum())
    return stats
