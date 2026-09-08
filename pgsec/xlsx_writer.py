from __future__ import annotations
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
from xml.sax.saxutils import escape
from datetime import datetime, timezone

STATUS_STYLE = {"PASS":2,"FAIL":3,"WARN":4,"REVIEW":5,"N/A":6,"ERROR":3,"SKIPPED":6}
STATUSES = ('PASS','FAIL','WARN','REVIEW','ERROR','N/A','SKIPPED')


def _col_name(n: int) -> str:
    s = ""
    while n:
        n, r = divmod(n-1, 26)
        s = chr(65+r) + s
    return s


def _cell(ref: str, value, style: int = 0) -> str:
    if value is None:
        value = ""
    if isinstance(value, bool):
        return f'<c r="{ref}" s="{style}" t="b"><v>{1 if value else 0}</v></c>'
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f'<c r="{ref}" s="{style}"><v>{value}</v></c>'
    text = escape(str(value))
    return f'<c r="{ref}" s="{style}" t="inlineStr"><is><t xml:space="preserve">{text}</t></is></c>'


def _sheet_xml(rows: list[dict], sheet_name: str) -> str:
    if not rows:
        rows = [{"Info":"No data"}]
    headers = list(rows[0].keys())
    width_map = {
        "Status":12, "Name":58, "Description":55, "Test Result":70,
        "Solution":70, "Security Comments":58,
        "Required Customer Input":78, "Customer Response / Evidence":65,
        "Auditor Decision":24, "Target":28,
        "Metric":34, "Value":70, "Mode":18, "Host":24, "Scope":12, "OS Hostname":24, "Container":28,
        "PostgreSQL Detected":20, "SQL Access":14, "Version":18, "OS":60,
        "Section":14, "Control":14, "Source":16, "Detail":80,
        "Command":70, "Path Hash (SHA256)":70, "Return Code":14, "Timestamp":25,
        "Role":34, "Type":12, "Login":10, "Superuser":12, "CreateRole":12, "CreateDB":12,
        "Replication":12, "BypassRLS":12, "Connection Limit":16, "Valid Until":22,
        "Password Verifier":20, "Member Of":44,
        "OS Release":40, "Kernel":26, "Architecture":14, "Audit User":18,
        "Container Runtimes":22, "Container Image":42, "Container User":18,
        "Container Privileged":20, "Container Ports":38,
        "Data Directory":42, "Config File":42, "HBA File":42,
        "PostgreSQL Binaries":44, "Systemd Services":44, "Config Files Found":18,
        "CIS Benchmark":40,
    }
    widths=[]
    for h in headers:
        if h in width_map:
            widths.append(width_map[h])
        else:
            vals=[str(r.get(h,"")) for r in rows[:100]]
            mx=max([len(str(h))]+[min(len(v),50) for v in vals])
            widths.append(max(10,min(42,mx+2)))
    cols="".join(f'<col min="{i}" max="{i}" width="{w}" customWidth="1"/>' for i,w in enumerate(widths,1))
    max_col=_col_name(len(headers))
    title=f"PostgreSQL Security Assessment — {sheet_name}"
    out_rows=[]
    out_rows.append(f'<row r="1" ht="30" customHeight="1">{_cell("A1",title,7)}</row>')
    header_cells="".join(_cell(f"{_col_name(i)}2",h,1) for i,h in enumerate(headers,1))
    out_rows.append(f'<row r="2" ht="30" customHeight="1">{header_cells}</row>')
    data_height = 78 if sheet_name == "CIS" else (64 if sheet_name == "ESA" else (46 if sheet_name=="Evidence" else 24))
    for ridx,row in enumerate(rows,3):
        cells=[]
        for cidx,h in enumerate(headers,1):
            v=row.get(h,"")
            if h.lower()=="status":
                style=STATUS_STYLE.get(str(v).upper(),0)
            elif sheet_name == "CIS" and h == "Required Customer Input" and str(v).strip():
                style=8
            elif sheet_name == "CIS" and h in {"Customer Response / Evidence","Auditor Decision"}:
                style=9
            else:
                style=0
            cells.append(_cell(f"{_col_name(cidx)}{ridx}",v,style))
        out_rows.append(f'<row r="{ridx}" ht="{data_height}" customHeight="1">{"".join(cells)}</row>')
    max_row=len(rows)+2
    extras=[]
    if sheet_name == 'CIS' and 'Auditor Decision' in headers and max_row >= 3:
        col=_col_name(headers.index('Auditor Decision')+1)
        extras.append(
            f'<dataValidations count="1"><dataValidation type="list" allowBlank="1" showInputMessage="1" showErrorMessage="1" sqref="{col}3:{col}{max_row}"><formula1>"PASS,FAIL,ACCEPTED RISK,EXCEPTION,REVIEW"</formula1></dataValidation></dataValidations>'
        )
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetViews><sheetView workbookViewId="0"><pane ySplit="2" topLeftCell="A3" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>
<sheetFormatPr defaultRowHeight="20"/>
<cols>{cols}</cols>
<sheetData>{''.join(out_rows)}</sheetData>
<autoFilter ref="A2:{max_col}{max_row}"/>
<mergeCells count="1"><mergeCell ref="A1:{max_col}1"/></mergeCells>
{''.join(extras)}
</worksheet>'''


def _summary_counts(rows: list[dict]) -> dict[tuple[str,str], int]:
    out={}
    for row in rows:
        metric=str(row.get('Metric',''))
        val=row.get('Value',0)
        for sec in ('CIS','ESA'):
            for status in STATUSES:
                if metric == f'{sec} {status}':
                    try: out[(sec,status)]=int(val)
                    except (TypeError,ValueError): out[(sec,status)]=0
    return out


def _summary_sheet_xml(rows: list[dict], scoreboard: list[dict] | None = None) -> str:
    rows=list(rows or [])
    scoreboard=list(scoreboard or [])
    counts=_summary_counts(rows)
    cis_total=sum(counts.get(('CIS',s),0) for s in STATUSES)
    esa_total=sum(counts.get(('ESA',s),0) for s in STATUSES)
    metric_by_row={i:r for i,r in enumerate(rows,4)}
    status_by_row={i:s for i,s in enumerate(STATUSES,4)}
    combined=[]
    combined.append(f'<row r="1" ht="34" customHeight="1">{_cell("A1","PostgreSQL Security Assessment — Executive Summary",7)}</row>')
    combined.append(f'<row r="2" ht="20" customHeight="1">{_cell("A2","Scope, pass rates, status mix, and per-target posture. Host is local for local scans and the entered IP for remote scans.",10)}</row>')
    combined.append(f'<row r="3" ht="26" customHeight="1">{_cell("A3","Metric",1)}{_cell("B3","Value",1)}{_cell("D3","Status",1)}{_cell("E3","CIS",1)}{_cell("F3","ESA",1)}{_cell("G3","CIS %",1)}{_cell("H3","ESA %",1)}</row>')
    max_row=max([10]+list(metric_by_row)+list(status_by_row))
    for rnum in range(4,max_row+1):
        cells=[]
        if rnum in metric_by_row:
            mr=metric_by_row[rnum]
            metric=str(mr.get('Metric',''))
            value=mr.get('Value','')
            style=0
            if metric=='Assessment Posture':
                style={'Healthy':11,'Review':12,'Attention':12,'Critical':13}.get(str(value),0)
            cells += [_cell(f'A{rnum}',metric,0),_cell(f'B{rnum}',value,style)]
        if rnum in status_by_row:
            st=status_by_row[rnum]
            cis_n=counts.get(('CIS',st),0); esa_n=counts.get(('ESA',st),0)
            cis_p=f"{round(100.0*cis_n/cis_total)}%" if cis_total else 'n/a'
            esa_p=f"{round(100.0*esa_n/esa_total)}%" if esa_total else 'n/a'
            cells += [_cell(f'D{rnum}',st,STATUS_STYLE.get(st,0)),_cell(f'E{rnum}',cis_n,0),_cell(f'F{rnum}',esa_n,0),_cell(f'G{rnum}',cis_p,0),_cell(f'H{rnum}',esa_p,0)]
        combined.append(f'<row r="{rnum}" ht="22" customHeight="1">{"".join(cells)}</row>')
    board_start=max_row+2
    sb_headers=['Target','Scope','Host','PostgreSQL','Version','SQL Access','CIS PASS','CIS FAIL','CIS ERROR','ESA FAIL','Posture']
    combined.append(f'<row r="{board_start}" ht="26" customHeight="1">{_cell(f"A{board_start}","Target Scoreboard",7)}</row>')
    header_cells=''.join(_cell(f"{_col_name(i)}{board_start+1}",h,1) for i,h in enumerate(sb_headers,1))
    combined.append(f'<row r="{board_start+1}" ht="24" customHeight="1">{header_cells}</row>')
    if not scoreboard:
        empty={h:'' for h in sb_headers}
        empty['Target']='No targets'
        scoreboard=[empty]
    for i,row in enumerate(scoreboard):
        rnum=board_start+2+i
        cells=[]
        for cidx,h in enumerate(sb_headers,1):
            v=row.get(h,'')
            style=0
            if h=='Posture':
                style={'Healthy':11,'Review':12,'Attention':12,'Critical':13,'Unreachable':13}.get(str(v),0)
            elif h=='Host':
                style=14
            cells.append(_cell(f'{_col_name(cidx)}{rnum}',v,style))
        combined.append(f'<row r="{rnum}" ht="22" customHeight="1">{"".join(cells)}</row>')
    last=board_start+1+max(1,len(scoreboard))
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheetViews><sheetView workbookViewId="0"><pane ySplit="3" topLeftCell="A4" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>
<sheetFormatPr defaultRowHeight="20"/>
<cols><col min="1" max="1" width="36" customWidth="1"/><col min="2" max="2" width="48" customWidth="1"/><col min="3" max="3" width="3" customWidth="1"/><col min="4" max="4" width="14" customWidth="1"/><col min="5" max="8" width="12" customWidth="1"/><col min="9" max="11" width="16" customWidth="1"/></cols>
<sheetData>{''.join(combined)}</sheetData>
<autoFilter ref="A3:B{max_row}"/>
<mergeCells count="2"><mergeCell ref="A1:H1"/><mergeCell ref="A{board_start}:K{board_start}"/></mergeCells>
<drawing r:id="rId1"/>
</worksheet>'''


def _chart_xml(rows: list[dict]) -> str:
    # A clustered status comparison makes REVIEW/WARN/FAIL immediately visible.
    counts=_summary_counts(list(rows or []))
    cat_cache=''.join(f'<c:pt idx="{i}"><c:v>{escape(status)}</c:v></c:pt>' for i,status in enumerate(STATUSES))
    cis_cache=''.join(f'<c:pt idx="{i}"><c:v>{counts.get(("CIS",status),0)}</c:v></c:pt>' for i,status in enumerate(STATUSES))
    esa_cache=''.join(f'<c:pt idx="{i}"><c:v>{counts.get(("ESA",status),0)}</c:v></c:pt>' for i,status in enumerate(STATUSES))
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
<c:chart><c:title><c:tx><c:rich><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr lang="en-US" sz="1400" b="1"/><a:t>Assessment Status Distribution</a:t></a:r></a:p></c:rich></c:tx><c:layout/><c:overlay val="0"/></c:title>
<c:autoTitleDeleted val="0"/><c:plotArea><c:layout/><c:barChart><c:barDir val="col"/><c:grouping val="clustered"/><c:varyColors val="0"/>
<c:ser><c:idx val="0"/><c:order val="0"/><c:tx><c:v>CIS</c:v></c:tx><c:cat><c:strRef><c:f>Summary!$D$4:$D$10</c:f><c:strCache><c:ptCount val="7"/>{cat_cache}</c:strCache></c:strRef></c:cat><c:val><c:numRef><c:f>Summary!$E$4:$E$10</c:f><c:numCache><c:formatCode>0</c:formatCode><c:ptCount val="7"/>{cis_cache}</c:numCache></c:numRef></c:val></c:ser>
<c:ser><c:idx val="1"/><c:order val="1"/><c:tx><c:v>ESA</c:v></c:tx><c:cat><c:strRef><c:f>Summary!$D$4:$D$10</c:f><c:strCache><c:ptCount val="7"/>{cat_cache}</c:strCache></c:strRef></c:cat><c:val><c:numRef><c:f>Summary!$F$4:$F$10</c:f><c:numCache><c:formatCode>0</c:formatCode><c:ptCount val="7"/>{esa_cache}</c:numCache></c:numRef></c:val></c:ser>
<c:axId val="21837824"/><c:axId val="21839872"/></c:barChart>
<c:catAx><c:axId val="21837824"/><c:scaling><c:orientation val="minMax"/></c:scaling><c:delete val="0"/><c:axPos val="b"/><c:tickLblPos val="nextTo"/><c:crossAx val="21839872"/><c:crosses val="autoZero"/><c:auto val="1"/><c:lblAlgn val="ctr"/><c:lblOffset val="100"/></c:catAx>
<c:valAx><c:axId val="21839872"/><c:scaling><c:orientation val="minMax"/><c:min val="0"/></c:scaling><c:delete val="0"/><c:axPos val="l"/><c:majorGridlines/><c:numFmt formatCode="0" sourceLinked="0"/><c:tickLblPos val="nextTo"/><c:crossAx val="21837824"/><c:crosses val="autoZero"/><c:crossBetween val="between"/></c:valAx>
</c:plotArea><c:legend><c:legendPos val="b"/><c:layout/><c:overlay val="0"/></c:legend><c:plotVisOnly val="1"/><c:dispBlanksAs val="zero"/><c:showDLblsOverMax val="0"/></c:chart></c:chartSpace>'''


def _drawing_xml() -> str:
    return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<xdr:wsDr xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<xdr:twoCellAnchor><xdr:from><xdr:col>9</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>2</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:from><xdr:to><xdr:col>17</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>18</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:to>
<xdr:graphicFrame macro=""><xdr:nvGraphicFramePr><xdr:cNvPr id="2" name="Assessment Status Distribution"/><xdr:cNvGraphicFramePr/></xdr:nvGraphicFramePr><xdr:xfrm/><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/chart"><c:chart r:id="rId1"/></a:graphicData></a:graphic></xdr:graphicFrame><xdr:clientData/></xdr:twoCellAnchor></xdr:wsDr>'''


def write_xlsx(data: dict, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    order = [
        ("Summary", data.get("summary", [])),
        ("Discovery", data.get("discovery", [])),
        ("Users", data.get("users", [])),
        ("CIS", data.get("cis", [])),
        ("ESA", data.get("esa", [])),
        ("Evidence", data.get("evidence", [])),
    ]
    content_types = ['''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
<Override PartName="/xl/drawings/drawing1.xml" ContentType="application/vnd.openxmlformats-officedocument.drawing+xml"/>
<Override PartName="/xl/charts/chart1.xml" ContentType="application/vnd.openxmlformats-officedocument.drawingml.chart+xml"/>''']
    for i in range(1,len(order)+1):
        content_types.append(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
    content_types.append('<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>')
    content_types.append('<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>')

    workbook_sheets = ''.join(f'<sheet name="{escape(name)}" sheetId="{i}" r:id="rId{i}"/>' for i,(name,_) in enumerate(order,1))
    workbook = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>{workbook_sheets}</sheets></workbook>'''
    rel_items = ''.join(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>' for i in range(1,len(order)+1))
    rel_items += f'<Relationship Id="rId{len(order)+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
    wb_rels = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{rel_items}</Relationships>'''
    root_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>'''
    styles = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="4"><font><sz val="10"/><name val="Arial"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="10"/><name val="Arial"/></font><font><b/><sz val="10"/><name val="Arial"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="15"/><name val="Arial"/></font></fonts>
<fills count="10"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF17365D"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFC6EFCE"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFFC7CE"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFFEB9C"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFD9EAF7"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFE7E6E6"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFDDEBF7"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFFF2CC"/><bgColor indexed="64"/></patternFill></fill></fills>
<borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border><border><left style="thin"><color rgb="FFD9E2F3"/></left><right style="thin"><color rgb="FFD9E2F3"/></right><top style="thin"><color rgb="FFD9E2F3"/></top><bottom style="thin"><color rgb="FFD9E2F3"/></bottom><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="15"><xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf><xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFill="1" applyFont="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="2" fillId="3" borderId="1" xfId="0" applyFill="1" applyFont="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="2" fillId="4" borderId="1" xfId="0" applyFill="1" applyFont="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="2" fillId="5" borderId="1" xfId="0" applyFill="1" applyFont="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="2" fillId="6" borderId="1" xfId="0" applyFill="1" applyFont="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="2" fillId="7" borderId="1" xfId="0" applyFill="1" applyFont="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="3" fillId="2" borderId="1" xfId="0" applyFill="1" applyFont="1" applyBorder="1" applyAlignment="1"><alignment horizontal="left" vertical="center"/></xf><xf numFmtId="0" fontId="0" fillId="8" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf><xf numFmtId="0" fontId="0" fillId="9" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf><xf numFmtId="0" fontId="0" fillId="7" borderId="0" xfId="0" applyFill="1" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="2" fillId="3" borderId="1" xfId="0" applyFill="1" applyFont="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf><xf numFmtId="0" fontId="2" fillId="5" borderId="1" xfId="0" applyFill="1" applyFont="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf><xf numFmtId="0" fontId="2" fillId="4" borderId="1" xfId="0" applyFill="1" applyFont="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf><xf numFmtId="0" fontId="2" fillId="8" borderId="1" xfId="0" applyFill="1" applyFont="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf></cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>'''
    now = datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
    core = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>PostgreSQL Security Assessment Report</dc:title><dc:creator>pg-sec-audit</dc:creator><dcterms:created xsi:type="dcterms:W3CDTF">{now}</dcterms:created></cp:coreProperties>'''
    app = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Application>pg-sec-audit</Application></Properties>'''
    sheet1_rels='''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/drawing" Target="../drawings/drawing1.xml"/></Relationships>'''
    drawing_rels='''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/chart" Target="../charts/chart1.xml"/></Relationships>'''

    with ZipFile(path, 'w', ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml',''.join(content_types))
        z.writestr('_rels/.rels',root_rels)
        z.writestr('xl/workbook.xml',workbook)
        z.writestr('xl/_rels/workbook.xml.rels',wb_rels)
        z.writestr('xl/styles.xml',styles)
        z.writestr('docProps/core.xml',core)
        z.writestr('docProps/app.xml',app)
        z.writestr('xl/worksheets/_rels/sheet1.xml.rels',sheet1_rels)
        z.writestr('xl/drawings/drawing1.xml',_drawing_xml())
        z.writestr('xl/drawings/_rels/drawing1.xml.rels',drawing_rels)
        z.writestr('xl/charts/chart1.xml',_chart_xml(data.get('summary', [])))
        for i,(name,rows) in enumerate(order,1):
            xml=_summary_sheet_xml(list(rows), data.get('scoreboard') or []) if name=='Summary' else _sheet_xml(list(rows),name)
            z.writestr(f'xl/worksheets/sheet{i}.xml',xml)
