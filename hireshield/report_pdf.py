import re
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

_CTRL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff]')


def make_pdf(result, timeline=None):
    buf = BytesIO(); doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=40, rightMargin=40); styles = getSampleStyleSheet(); story = []

    def safe(x):
        s = _CTRL.sub('', str(x if x is not None else ''))
        return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br/>')
    # Table cells must be Paragraphs: plain strings are neither wrapped (long evidence ran off the page) nor
    # markup-parsed (escaped entities were printed literally). wordWrap='CJK' also breaks long unspaced URLs.
    cell = ParagraphStyle('cell', parent=styles['BodyText'], fontSize=7, leading=9, wordWrap='CJK')
    head = ParagraphStyle('head', parent=cell, textColor=colors.white, fontName='Helvetica-Bold')
    body = ParagraphStyle('body', parent=styles['BodyText'], wordWrap='CJK')
    story += [Paragraph('HireShield AI — Investigation Report', styles['Title']), Spacer(1, 10)]
    for key in ('investigation_id', 'created', 'kind', 'filename', 'reference', 'sha256', 'status'):
        if result.get(key): story.append(Paragraph(f'<b>{safe(key.replace("_", " ").title())}:</b> {safe(result[key])}', body))
    risk = result.get('risk', {}); story.append(Paragraph(f'<b>Heuristic risk:</b> {safe(risk.get("severity"))} ({safe(risk.get("score"))}/100)', body))
    story.append(Paragraph('This score is a heuristic, not a probability. AI text is advisory and cannot alter detection evidence.', styles['Italic']))
    story.append(Spacer(1, 8)); story.append(Paragraph('Findings', styles['Heading2']))
    findings = result.get('findings', [])
    if findings:
        rows = [[Paragraph(h, head) for h in ('Severity', 'Finding', 'Evidence', 'Method')]]
        rows += [[Paragraph(safe(f.get(k)), cell) for k in ('severity', 'title', 'evidence', 'method')] for f in findings[:100]]
        table = Table(rows, repeatRows=1, colWidths=[55, 115, 270, 70])
        table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#243447')), ('GRID', (0, 0), (-1, -1), .3, colors.grey), ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f3f6')])]))
        story.append(table)
        if len(findings) > 100: story.append(Paragraph(f'Showing first 100 of {len(findings)} findings; see the JSON report for the complete list.', styles['Italic']))
    else: story.append(Paragraph('No findings recorded.', body))
    story.append(Spacer(1, 8)); story.append(Paragraph('Analyst notes', styles['Heading2'])); story.append(Paragraph(safe(result.get('analyst_notes', '')) or 'None', body))
    story.append(Spacer(1, 8)); story.append(Paragraph('Timeline', styles['Heading2']))
    for event in timeline or []: story.append(Paragraph(f'{safe(event.get("created"))} — {safe(event.get("event"))}: {safe(event.get("details"))}', body))
    if result.get('ai_explanation', {}).get('explanation'): story += [Spacer(1, 8), Paragraph('Optional local AI explanation (advisory)', styles['Heading2']), Paragraph(safe(result['ai_explanation']['explanation']), body)]
    doc.build(story); return buf.getvalue()
