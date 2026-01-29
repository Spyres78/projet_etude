#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from pathlib import Path
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
)
from reportlab.lib.units import cm
from reportlab.lib.colors import black, grey, HexColor


# =========================
# CONFIG
# =========================
INPUT_JSON = Path("MDOS_RESULTS/mdos_global.json")
OUTPUT_PDF = Path.home() / (
    f"MDOS_Report_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.pdf"
)

PRIMARY = HexColor("#1f2937")
SECONDARY = HexColor("#374151")
ACCENT = HexColor("#2563eb")

# =========================
# STYLES
# =========================
styles = getSampleStyleSheet()

title_style = ParagraphStyle(
    "Title",
    fontSize=24,
    textColor=PRIMARY,
    spaceAfter=20,
    alignment=1
)

subtitle_style = ParagraphStyle(
    "Subtitle",
    fontSize=12,
    textColor=SECONDARY,
    spaceAfter=20,
    alignment=1
)

section_style = ParagraphStyle(
    "Section",
    fontSize=16,
    textColor=ACCENT,
    spaceAfter=10
)

text_style = ParagraphStyle(
    "Text",
    fontSize=10,
    spaceAfter=6
)

small_style = ParagraphStyle(
    "Small",
    fontSize=8,
    textColor=grey
)


# =========================
# UTILS
# =========================
def safe(v):
    return str(v).replace("<", "&lt;").replace(">", "&gt;")


# =========================
# PDF GENERATOR
# =========================
def generate_pdf():
    if not INPUT_JSON.exists():
        print("❌ mdos_global.json introuvable.")
        return

    OUTPUT_PDF.parent.mkdir(parents=True, exist_ok=True)

    data = json.loads(INPUT_JSON.read_text(encoding="utf-8"))

    doc = SimpleDocTemplate(
        str(OUTPUT_PDF),
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm
    )

    elements = []

    # =========================
    # PAGE DE GARDE
    # =========================
    elements.append(Spacer(1, 80))
    elements.append(Paragraph("MDOS", title_style))
    elements.append(Paragraph(
        "Rapport d’analyse & reconnaissance",
        subtitle_style
    ))

    elements.append(Spacer(1, 30))
    elements.append(Paragraph(
        f"Généré le : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
        text_style
    ))

    elements.append(PageBreak())

    # =========================
    # RÉSUMÉ
    # =========================
    elements.append(Paragraph("Résumé global", section_style))

    summary = {}
    for e in data:
        cat = e.get("category", "autre")
        summary[cat] = summary.get(cat, 0) + 1

    table_data = [["Catégorie", "Nombre d’actions"]]
    for k, v in summary.items():
        table_data.append([k, str(v)])

    table = Table(table_data, colWidths=[8 * cm, 4 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), black),
        ("GRID", (0, 0), (-1, -1), 0.5, grey),
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (1, 1), (-1, -1), "CENTER"),
    ]))

    elements.append(table)
    elements.append(PageBreak())

    # =========================
    # DÉTAILS
    # =========================
    current_cat = None

    for entry in data:
        cat = entry.get("category", "autre")

        if cat != current_cat:
            elements.append(Paragraph(f"Catégorie : {cat.upper()}", section_style))
            current_cat = cat

        elements.append(Paragraph(
            f"<b>Date :</b> {safe(entry.get('date'))}", text_style
        ))
        elements.append(Paragraph(
            f"<b>Outil :</b> {safe(entry.get('tool'))}", text_style
        ))
        elements.append(Paragraph(
            f"<b>Cible :</b> {safe(entry.get('target'))}", text_style
        ))
        elements.append(Paragraph(
            f"<b>Commande :</b> {safe(entry.get('command'))}", text_style
        ))

        if entry.get("raw_output"):
            elements.append(Paragraph(
                "<b>Résultat :</b><br/><font size=8>" +
                safe(entry["raw_output"]).replace("\n", "<br/>") +
                "</font>",
                text_style
            ))

        elements.append(Spacer(1, 12))

    # =========================
    # EXPORT
    # =========================
    doc.build(elements)

    print("\n✅ Rapport PDF généré avec succès :")
    print(f"📄 {OUTPUT_PDF.resolve()}\n")
