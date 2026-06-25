#!/usr/bin/env python3
"""
EDI (X12 / EDIFACT) Bridge MCP — CSOAI Layer-0 legacy-bridge family.
B2B supply-chain messaging → ONE OS: parse, validate, map, govern. Sibling of cobol-bridge-mcp.
Tools: parse_edi · validate_edi · map_to_modern · govern_edi
"""
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

mcp = FastMCP("EDI Bridge", instructions="Bridge EDI X12 / EDIFACT B2B messages to ONE OS — parse, validate, map, govern.")

X12_TXN = {"850": "Purchase Order", "810": "Invoice", "856": "Advance Ship Notice",
           "855": "PO Acknowledgement", "997": "Functional Acknowledgement", "204": "Motor Carrier Load"}
EDIFACT_MSG = {"ORDERS": "Purchase Order", "INVOIC": "Invoice", "DESADV": "Despatch Advice",
               "ORDRSP": "Order Response", "CONTRL": "Acknowledgement"}


class EDIParsed(BaseModel):
    standard: str
    transaction: str
    description: str
    sender: Optional[str] = None
    receiver: Optional[str] = None
    segments: List[str] = Field(default_factory=list)
    segment_count: int = 0


class Validation(BaseModel):
    valid: bool
    standard: str
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class Governance(BaseModel):
    risk_flags: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    attestable: bool = True
    note: str = ""


def _detect(edi: str) -> str:
    s = edi.lstrip()
    if s.startswith("ISA") or s.startswith("GS"):
        return "X12"
    if s.startswith("UNB") or s.startswith("UNA") or s.startswith("UNH"):
        return "EDIFACT"
    return "unknown"


def _segs(edi: str, standard: str):
    sep = "~" if standard == "X12" else "'"
    raw = [x.strip() for x in edi.replace("\n", "").split(sep) if x.strip()]
    elsep = "*" if standard == "X12" else "+"
    return [r.split(elsep) for r in raw]


@mcp.tool()
def parse_edi(edi: str) -> EDIParsed:
    """Parse an EDI X12 or EDIFACT interchange; detect standard, transaction type, sender/receiver."""
    std = _detect(edi)
    if std == "unknown":
        return EDIParsed(standard="unknown", transaction="unknown", description="unrecognised EDI")
    segs = _segs(edi, std)
    seg_ids = [s[0] for s in segs if s]
    txn = "unknown"
    sender = receiver = None
    for s in segs:
        if std == "X12":
            if s[0] == "ST" and len(s) > 1:
                txn = s[1]
            if s[0] == "ISA" and len(s) > 8:
                sender = s[6].strip() if len(s) > 6 else None
                receiver = s[8].strip() if len(s) > 8 else None
        else:
            if s[0] == "UNH" and len(s) > 2:
                txn = s[2].split(":")[0] if s[2] else "unknown"
            if s[0] == "UNB" and len(s) > 2:
                sender = s[2] if len(s) > 2 else None
                receiver = s[3] if len(s) > 3 else None
    desc = (X12_TXN if std == "X12" else EDIFACT_MSG).get(txn, "EDI transaction")
    return EDIParsed(standard=std, transaction=txn, description=desc, sender=sender,
                     receiver=receiver, segments=seg_ids[:40], segment_count=len(segs))


@mcp.tool()
def validate_edi(edi: str) -> Validation:
    """Validate envelope integrity (X12 ISA/IEA + ST/SE; EDIFACT UNB/UNZ + UNH/UNT)."""
    std = _detect(edi)
    errors, warnings = [], []
    if std == "unknown":
        return Validation(valid=False, standard="unknown", errors=["Unrecognised EDI standard (no ISA/UNB)"])
    seg_ids = [s[0] for s in _segs(edi, std) if s]
    if std == "X12":
        if "ST" not in seg_ids: errors.append("Missing ST (transaction-set header)")
        if "SE" not in seg_ids: warnings.append("Missing SE (transaction-set trailer)")
    else:
        if "UNH" not in seg_ids: errors.append("Missing UNH (message header)")
        if "UNT" not in seg_ids: warnings.append("Missing UNT (message trailer)")
    return Validation(valid=not errors, standard=std, errors=errors, warnings=warnings)


@mcp.tool()
def map_to_modern(edi: str) -> Dict[str, Any]:
    """Map an EDI transaction to a modern JSON event for ONE OS / commerce APIs."""
    p = parse_edi(edi)
    return {"standard": p.standard, "event_type": p.transaction, "description": p.description,
            "trading_partners": {"sender": p.sender, "receiver": p.receiver},
            "segments": p.segments, "target": "modern commerce event"}


@mcp.tool()
def govern_edi(edi: str) -> Governance:
    """Governance: trading-partner + supply-chain compliance surface (attestable for CSOAI)."""
    p = parse_edi(edi)
    flags = []
    if not p.sender or not p.receiver:
        flags.append("Trading partner IDs incomplete — onboarding/authentication review")
    if p.transaction in ("810", "INVOIC"):
        flags.append("Invoice — e-invoicing compliance (e.g., EU ViDA / Peppol) + tax governance")
    return Governance(risk_flags=flags,
                      frameworks=["EDI X12 / EDIFACT", "Peppol / EU ViDA (e-invoicing)", "SOX", "GDPR", "supply-chain due diligence (CSDDD)"],
                      note="CSOAI governs the bridge: B2B transaction + partner lineage attestable on the ledger.")


def main():
    mcp.run()


if __name__ == "__main__":
    main()
