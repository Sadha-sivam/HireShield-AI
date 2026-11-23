from email import policy
from email.parser import BytesParser
from urllib.parse import urlsplit, unquote
import re, ipaddress, hashlib, html, io, os, subprocess, shutil, tempfile
from pathlib import Path, PurePosixPath
import zipfile
import xml.etree.ElementTree as ET

MAX_BYTES = 8 * 1024 * 1024
MAX_ZIP_ENTRIES = 500
MAX_EXTRACTED = 20 * 1024 * 1024
MAX_URLS = 200
BASE_DIR = Path(__file__).resolve().parent.parent

# Hosts that only appear as XML namespace / schema identifiers inside Office packages.
NAMESPACE_HOSTS = {'schemas.openxmlformats.org', 'schemas.microsoft.com', 'purl.org', 'www.w3.org',
                   'schemas.xmlsoap.org', 'www.openxmlformats.org'}
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
              'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy'}
EXEC_EXT = {'.exe', '.scr', '.com', '.pif', '.bat', '.cmd', '.ps1', '.psm1', '.vbs', '.vbe', '.js', '.jse',
            '.wsf', '.wsh', '.hta', '.lnk', '.msi', '.jar', '.dll', '.cpl', '.reg', '.xll', '.sh'}
CONTAINER_EXT = {'.iso', '.img', '.vhd', '.vhdx'}
DOC_EXT = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf', '.jpg', '.jpeg', '.png'}
OFFICE_ZIP_EXT = {'.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm', '.dotx', '.dotm', '.xltx', '.xltm',
                  '.potx', '.potm'}
SEV_RANK = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def finding(title, severity, evidence, confidence='medium', method='heuristic'):
    return {'title': title, 'severity': severity, 'confidence': confidence, 'evidence': evidence, 'method': method}


def _dedupe(findings):
    seen = set(); out = []
    for f in findings:
        key = (f.get('title'), str(f.get('evidence')))
        if key not in seen:
            seen.add(key); out.append(f)
    return out


def _clean_url(u):
    """Strip trailing sentence punctuation that regex extraction drags in."""
    return html.unescape(u).rstrip('.,;:!?)]}>\'"')


def _url_findings(u):
    """URL findings annotated with the URL, so identical findings from different links stay distinguishable."""
    out = []
    for f in analyze_url(u)['findings']:
        f = dict(f); f['evidence'] = f"{f['evidence']} [{u[:120]}]"; out.append(f)
    return out


def _name_findings(filename):
    """Checks on a file name: executable types, double extensions, bidi spoofing."""
    findings = []; name = str(filename or '')
    if re.search('[‪-‮⁦-⁩]', name):
        findings.append(finding('Filename contains bidirectional control characters', 'high', repr(name), 'high', 'file-validation'))
    suffixes = [s.lower() for s in Path(name).suffixes][-3:]
    if suffixes:
        last = suffixes[-1]
        if last in EXEC_EXT:
            findings.append(finding('Executable or script file type', 'high', name, 'high', 'file-validation'))
        elif last in CONTAINER_EXT:
            findings.append(finding('Disk-image container file type', 'medium', name, 'medium', 'file-validation'))
        if len(suffixes) >= 2 and suffixes[-2] in DOC_EXT and (last in EXEC_EXT or last in CONTAINER_EXT):
            findings.append(finding('Double file extension disguises file type', 'high', name, 'high', 'file-validation'))
    return findings


def analyze_email(raw: bytes):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    findings = []; urls = []
    sender = str(msg.get('From', '')); reply = str(msg.get('Reply-To', '')); ret = str(msg.get('Return-Path', ''))

    def addr_domain(s):
        m = re.search(r'@([\w.-]+)', s); return m.group(1).lower().rstrip('.') if m else None
    sd, rd = addr_domain(sender), addr_domain(reply)
    if reply and sd and rd and sd != rd: findings.append(finding('From / Reply-To domain mismatch', 'high', f'From domain: {sd}; Reply-To domain: {rd}', 'high'))
    if ret and sd and addr_domain(ret) and addr_domain(ret) != sd: findings.append(finding('Return-Path differs from sender domain', 'medium', f'{sd} vs {addr_domain(ret)}'))
    subj = str(msg.get('Subject', ''))
    if re.search(r'urgent|verify|password|payment|immediately|account suspended|action required', subj, re.I): findings.append(finding('Pressure or account-action language in subject', 'low', f'Subject: {subj}', 'low'))
    body = ''
    for part in msg.walk():
        if part.get_content_type() in ('text/plain', 'text/html'):
            try: body += str(part.get_content()) + '\n'
            except Exception: pass
    urls = list(dict.fromkeys(_clean_url(u) for u in re.findall(r"https?://[^\s<>\"']+", body)))[:MAX_URLS]
    for u in urls: findings.extend(_url_findings(u))
    attachments = [{'filename': p.get_filename(), 'content_type': p.get_content_type()} for p in msg.walk() if p.get_filename()]
    for a in attachments: findings.extend(_name_findings(a['filename']))
    auth = str(msg.get('Authentication-Results', ''))
    if auth:
        for item in ('spf', 'dkim', 'dmarc'):
            m = re.search(r'\b' + item + r'=([a-z]+)', auth, re.I)
            if m and m.group(1).lower() in ('fail', 'softfail', 'none'): findings.append(finding(f'{item.upper()} authentication result', 'medium', auth.strip(), 'medium', 'header'))
    return {'sender': sender, 'reply_to': reply, 'return_path': ret, 'subject': subj, 'headers': {k: str(v) for k, v in msg.items()}, 'urls': urls, 'findings': _dedupe(findings), 'attachments': attachments}


def _host_matches(host, domains):
    return any(host == d or host.endswith('.' + d) for d in domains)


def analyze_url(url):
    findings = []
    try:
        raw = str(url).strip()
        if '://' in raw or re.match(r'^(javascript|data|vbscript|mailto|file|tel|blob):', raw, re.I):
            parse_target = raw
        else:
            # No scheme: still analyse the host rather than silently skipping it.
            findings.append(finding('URL has no scheme', 'low', 'Analysed as if it were http://; a missing scheme is unusual in a link'))
            parse_target = '//' + raw
        p = urlsplit(parse_target); host = (p.hostname or '').lower(); scheme = p.scheme.lower()
        if scheme and scheme not in ('http', 'https'): findings.append(finding('Non-web URL scheme', 'medium', scheme))
        if p.username or p.password: findings.append(finding('Embedded URL credentials', 'high', 'Username or password embedded in URL', 'high'))
        try:
            ipaddress.ip_address(host); findings.append(finding('IP address used as URL host', 'medium', host))
        except ValueError:
            if re.fullmatch(r'(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}', host):
                findings.append(finding('Obfuscated numeric IP host', 'medium', host, 'medium'))
        if host.startswith('xn--') or '.xn--' in host: findings.append(finding('Punycode domain', 'medium', host))
        if len(host.split('.')) >= 5: findings.append(finding('Deep subdomain structure', 'low', host))
        if len(raw) > 180: findings.append(finding('Unusually long URL', 'low', f'{len(raw)} characters'))
        if _host_matches(host, SHORTENERS): findings.append(finding('URL shortener domain', 'medium', host))
        if re.search(r'@|%40', re.split(r'[?#]', raw, maxsplit=1)[0]) and not (p.username or p.password): findings.append(finding('At-sign in URL', 'low', 'May obscure the true host'))
        if re.search(r'login|verify|secure|account|wallet|password', host, re.I): findings.append(finding('Security/account-related terms in domain', 'low', host))
        if scheme == 'http': findings.append(finding('URL does not use HTTPS', 'low', scheme))
    except Exception as e: findings.append(finding('URL parsing issue', 'low', str(e)))
    return {'url': url, 'findings': findings, 'note': 'No URL was opened or fetched. Heuristic analysis only.'}


def _urls(text):
    return list(dict.fromkeys(_clean_url(u) for u in re.findall(r'https?://[^\s<>\"\']+', text, re.I)))[:MAX_URLS]


_RISKY_FORMULA = re.compile(r'^=?\s*(WEBSERVICE|DDE|DDEAUTO)\s*\(|^=?\s*(cmd|powershell|mshta|msexcel)\s*\|', re.I)
_XLM_FORMULA = re.compile(r'^=?\s*(EXEC|CALL|REGISTER|URLDOWNLOADTOFILE)\s*\(', re.I)


def _zip_inspect(data, findings, extracted_text, urls, metadata, is_archive=False):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = z.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                findings.append(finding('Archive entry limit exceeded', 'medium', f'{len(infos)} entries; inspection capped', 'medium', 'archive-inspection')); infos = infos[:MAX_ZIP_ENTRIES]
            total = 0; limit_reported = False
            for info in infos:
                name = info.filename; lower = name.lower()
                # --- name-based checks run for EVERY entry, so a large decoy file cannot hide later entries ---
                norm = name.replace('\\', '/')
                if norm.startswith('/') or '..' in PurePosixPath(norm).parts or re.match(r'^[a-zA-Z]:', norm):
                    findings.append(finding('Suspicious archive path', 'medium', name, 'medium', 'archive-inspection'))
                if info.flag_bits & 0x1:
                    findings.append(finding('Encrypted archive entry', 'medium', name, 'high', 'archive-inspection'))
                if 'vbaproject.bin' in lower or lower.endswith(('.xlsm', '.docm', '.pptm')):
                    findings.append(finding('Macro-capable Office content detected', 'high', name, 'high', 'office-structure'))
                if lower.startswith(('word/embeddings/', 'xl/embeddings/', 'ppt/embeddings/')):
                    findings.append(finding('Embedded object present', 'medium', name, 'medium', 'office-structure'))
                elif lower.endswith(('.bin', '.ole')) and ('embedding' in lower or 'activex' in lower):
                    findings.append(finding('Potential active/embedded content', 'medium', name, 'medium', 'office-structure'))
                if lower.startswith('xl/macrosheets/'):
                    findings.append(finding('Excel 4.0 (XLM) macro sheet present', 'high', name, 'high', 'office-structure'))
                if is_archive and Path(norm).suffix.lower() in EXEC_EXT:
                    findings.append(finding('Executable or script inside archive', 'high', name, 'high', 'archive-inspection'))
                if info.file_size > 1_000_000 and info.compress_size and info.file_size / info.compress_size > 200:
                    findings.append(finding('Very high compression ratio (possible archive bomb)', 'medium', f'{name}: {info.file_size} bytes from {info.compress_size}', 'medium', 'archive-inspection'))
                # --- content checks are bounded by a total budget ---
                if not lower.endswith(('.xml', '.rels', '.txt', '.html')) or info.flag_bits & 0x1:
                    continue
                total += info.file_size
                if total > MAX_EXTRACTED:
                    if not limit_reported:
                        findings.append(finding('Archive expanded-size limit reached', 'medium', 'ZIP content inspection capped at 20 MiB', 'medium', 'archive-inspection')); limit_reported = True
                    continue
                try: content = z.read(info)
                except Exception:
                    findings.append(finding('Archive entry could not be read', 'low', name, 'low', 'archive-inspection')); continue
                text = content.decode('utf-8', 'replace')
                if lower == '[content_types].xml':
                    ct = text.lower()
                    if 'macroenabled' in ct or 'vbaproject' in ct: findings.append(finding('Macro-enabled package content type', 'high', name, 'high', 'office-structure'))
                if lower.endswith(('.xml', '.rels')):
                    if re.search(rb'<!ENTITY', content, re.I):
                        findings.append(finding('XML entity declaration present', 'medium', name, 'medium', 'office-xml')); continue
                    try:
                        root = ET.fromstring(content)
                        for el in root.iter():
                            local = el.tag.rsplit('}', 1)[-1].lower()
                            attrs = {k.rsplit('}', 1)[-1].lower(): v for k, v in el.attrib.items()}
                            if local == 'sheet' and attrs.get('state', '').lower() in ('hidden', 'veryhidden'):
                                very = attrs['state'].lower() == 'veryhidden'
                                findings.append(finding('Hidden worksheet or sheet state', 'medium' if very else 'low', f"{attrs.get('name', 'sheet')} ({attrs['state']})", 'low', 'office-xml'))
                            if local in ('f', 'formula'):
                                formula = (el.text or '').strip()
                                if _XLM_FORMULA.match(formula):
                                    findings.append(finding('Excel 4.0 (XLM) macro function in formula', 'high', formula[:300], 'medium', 'office-xml'))
                                elif _RISKY_FORMULA.match(formula):
                                    findings.append(finding('Potentially risky spreadsheet formula', 'medium', formula[:300], 'medium', 'office-xml'))
                                elif re.match(r'^=?\s*HYPERLINK\s*\(', formula, re.I):
                                    findings.append(finding('Spreadsheet HYPERLINK formula', 'low', formula[:300], 'low', 'office-xml'))
                            if local == 'hyperlink':
                                target = el.attrib.get('{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id')
                                if target: metadata.setdefault('hyperlink_relationship_ids', []).append(target)
                            if lower.endswith('.rels') and local == 'relationship':
                                target = el.attrib.get('Target', ''); rtype = el.attrib.get('Type', '').lower()
                                if el.attrib.get('TargetMode', '').lower() != 'external': continue
                                if rtype.endswith('/attachedtemplate'):
                                    findings.append(finding('Remote template reference (possible template injection)', 'high', target[:300], 'high', 'office-structure'))
                                elif rtype.endswith('/oleobject'):
                                    findings.append(finding('Externally linked OLE object', 'high', target[:300], 'high', 'office-structure'))
                                if re.match(r'^https?://', target, re.I): urls.append(_clean_url(target))
                                elif re.match(r'^(file:|\\\\|//)', target, re.I):
                                    findings.append(finding('External relationship to local/UNC path', 'high', target[:300], 'high', 'office-structure'))
                                elif re.match(r'^[a-z][a-z0-9+.-]*:', target, re.I) and not target.lower().startswith('mailto:'):
                                    findings.append(finding('External relationship with non-web scheme', 'medium', target[:300], 'medium', 'office-structure'))
                    except Exception: findings.append(finding('XML parsing issue', 'low', name, 'low', 'archive-inspection'))
                    if lower.endswith('.rels'): continue  # relationship Type URIs are identifiers, not links
                    text = re.sub(r'xmlns(:\w+)?="[^"]*"', '', text)  # namespace URIs are identifiers, not links
                if info.file_size < 2_000_000: extracted_text.append(text)
    except zipfile.BadZipFile:
        findings.append(finding('Invalid ZIP-based document', 'high', 'Archive could not be opened', 'high', 'file-validation'))


def _o(x):
    """Resolve a pypdf indirect reference (no-op for direct objects)."""
    try: return x.get_object()
    except Exception: return x


def _pdf_action(action, where, findings, urls):
    action = _o(action)
    if not hasattr(action, 'get'): return
    s = str(action.get('/S', ''))
    if s == '/JavaScript' or '/JS' in action:
        findings.append(finding('PDF JavaScript action', 'high', f'JavaScript action in {where}; not executed', 'high', 'pypdf'))
    elif s == '/Launch':
        findings.append(finding('PDF Launch action', 'high', f'Launch action in {where}; not executed', 'high', 'pypdf'))
    elif s in ('/SubmitForm', '/ImportData', '/GoToR', '/GoToE'):
        findings.append(finding('PDF external-interaction action', 'medium', f'{s} in {where}', 'medium', 'pypdf'))
    elif s == '/URI' and action.get('/URI'):
        urls.append(_clean_url(str(action.get('/URI'))))


def _pdf_inspect(data, findings, text_parts, urls):
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            findings.append(finding('Encrypted PDF', 'medium', 'Document is encrypted; text and actions may not be fully inspectable', 'medium', 'pypdf'))
            try:
                if not reader.decrypt(''):
                    findings.append(finding('PDF could not be decrypted', 'low', 'A password is required; contents not inspected', 'medium', 'pypdf')); return
            except Exception: return
        pages = reader.pages
        if len(pages) > 200: findings.append(finding('PDF page limit exceeded', 'medium', f'{len(pages)} pages; parsing limited to first 200', 'medium', 'pypdf'))
        for i, page in enumerate(pages[:200]):
            try: text_parts.append(page.extract_text() or '')
            except Exception: findings.append(finding('PDF page extraction error', 'low', f'Page {i + 1} could not be parsed', 'low', 'pypdf'))
            try:
                for annot in _o(page.get('/Annots')) or []:
                    obj = _o(annot)
                    if obj.get('/A'): _pdf_action(obj.get('/A'), f'annotation on page {i + 1}', findings, urls)
                    if obj.get('/AA'): findings.append(finding('PDF annotation additional actions', 'medium', f'Additional-action dictionary on page {i + 1}', 'medium', 'pypdf'))
            except Exception: pass
        try: root = _o(reader.trailer.get('/Root'))
        except Exception: root = None
        if root is not None and hasattr(root, 'get'):
            if root.get('/OpenAction'):
                findings.append(finding('PDF open action present', 'high', 'Document has an OpenAction entry; action not executed', 'high', 'pypdf'))
                _pdf_action(root.get('/OpenAction'), 'OpenAction', findings, urls)
            if root.get('/AA'): findings.append(finding('PDF additional actions present', 'high', 'Document catalog contains /AA', 'high', 'pypdf'))
            names = _o(root.get('/Names')) if root.get('/Names') else None
            if names is not None and hasattr(names, 'get'):
                if names.get('/JavaScript'): findings.append(finding('PDF document-level JavaScript', 'high', 'Catalog name tree contains /JavaScript; not executed', 'high', 'pypdf'))
                if names.get('/EmbeddedFiles'): findings.append(finding('PDF embedded files', 'medium', 'Catalog name tree contains /EmbeddedFiles', 'medium', 'pypdf'))
        if not any('JavaScript' in f['title'] for f in findings) and re.search(rb'/JavaScript\b|/JS\s*[(<]', data):
            findings.append(finding('PDF JavaScript marker', 'medium', '/JavaScript or /JS token observed in raw bytes (structure not confirmed)', 'low', 'byte-marker'))
    except ImportError: findings.append(finding('PDF parser unavailable', 'info', 'Install pypdf to enable structured PDF inspection', 'low', 'dependency'))
    except Exception as e: findings.append(finding('PDF parsing error', 'low', type(e).__name__, 'low', 'pypdf'))


_YARA_CACHE = {}


def _yara_scan(data, findings):
    try: import yara
    except ImportError: return {'tool': 'YARA', 'status': 'not installed'}
    env = os.environ.get('HIRESHIELD_YARA_DIR')
    rules_dir = Path(env) if env else BASE_DIR / 'detection' / 'yara'
    rulefiles = sorted(list(rules_dir.glob('*.yar')) + list(rules_dir.glob('*.yara'))) if rules_dir.is_dir() else []
    if not rulefiles: return {'tool': 'YARA', 'status': 'no rules configured'}
    try:
        key = tuple((str(p), p.stat().st_mtime_ns) for p in rulefiles)
        compiled = _YARA_CACHE.get(key)
        if compiled is None:
            compiled = yara.compile(filepaths={f'r{i}': str(p) for i, p in enumerate(rulefiles)})
            _YARA_CACHE.clear(); _YARA_CACHE[key] = compiled
        matches = compiled.match(data=data, timeout=5)
        for m in matches: findings.append(finding('YARA rule match', 'high', f'Rule: {m.rule}; tags: {list(m.tags)}', 'high', 'YARA'))
        return {'tool': 'YARA', 'status': 'completed', 'matches': [m.rule for m in matches]}
    except Exception as e: return {'tool': 'YARA', 'status': 'error', 'detail': type(e).__name__}


def _clam_scan(data, sha, findings):
    exe = shutil.which('clamscan')
    if not exe: return {'tool': 'ClamAV', 'status': 'not installed'}
    try: timeout = int(os.environ.get('HIRESHIELD_CLAM_TIMEOUT', '90'))
    except ValueError: timeout = 90
    path = None
    try:
        with tempfile.NamedTemporaryFile(prefix='hireshield_', suffix='.bin', delete=False) as tf:
            tf.write(data); path = tf.name
        res = subprocess.run([exe, '--no-summary', path], capture_output=True, text=True, timeout=timeout, check=False)
        output = (res.stdout + ' ' + res.stderr).replace(path, '<uploaded file>').strip()[:2000]
        if res.returncode == 1:
            findings.append(finding('ClamAV detection', 'critical', output, 'high', 'ClamAV')); status = 'detected'
        elif res.returncode == 0: status = 'clean'
        else: status = 'error'
        return {'tool': 'ClamAV', 'status': status, 'exit_code': res.returncode, 'output': output}
    except subprocess.TimeoutExpired: return {'tool': 'ClamAV', 'status': 'timeout'}
    except Exception as e: return {'tool': 'ClamAV', 'status': 'error', 'detail': type(e).__name__}
    finally:
        if path:
            try: os.unlink(path)
            except OSError: pass


def _sniff(data):
    """Identify the container type from content, independent of the claimed extension."""
    if b'%PDF-' in data[:1024]: return 'pdf'
    if data.startswith(b'PK'): return 'zip'
    if data.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'): return 'ole'
    return None


_KNOWN = {'.pdf': 'pdf', '.docx': 'zip', '.xlsx': 'zip', '.pptx': 'zip', '.docm': 'zip', '.xlsm': 'zip', '.pptm': 'zip',
          '.zip': 'zip', '.doc': 'ole', '.xls': 'ole', '.ppt': 'ole'}


def inspect_file(filename, data):
    findings = []; filename = str(filename or 'upload.bin'); ext = Path(filename).suffix.lower(); sig = data[:16]
    sha = hashlib.sha256(data).hexdigest(); urls = []; text_parts = []; metadata = {'parser': None}
    findings.extend(_name_findings(filename))
    kind = _sniff(data)
    if ext in _KNOWN and kind != _KNOWN[ext]: findings.append(finding('File signature does not match extension', 'high', f'Extension {ext}, signature {sig.hex()}', 'high'))
    if kind == 'pdf' and not data.startswith(b'%PDF'): findings.append(finding('PDF header not at start of file', 'medium', f'%PDF- found at offset {data.find(b"%PDF-")}', 'medium', 'file-validation'))
    if len(data) > MAX_BYTES:
        findings.append(finding('File exceeds analysis size limit', 'high', f'{len(data)} bytes; content parsing skipped'))
        return {'filename': filename, 'size': len(data), 'sha256': sha, 'extension': ext, 'findings': _dedupe(findings), 'urls': [], 'metadata': metadata, 'external_tools': [], 'note': 'File was not executed or parsed (over size limit).'}
    if kind == 'pdf':
        metadata['parser'] = 'pypdf'; _pdf_inspect(data, findings, text_parts, urls)
    elif kind == 'zip':
        metadata['parser'] = 'zip-xml'; _zip_inspect(data, findings, text_parts, urls, metadata, is_archive=ext not in OFFICE_ZIP_EXT)
    elif kind == 'ole':
        findings.append(finding('Legacy OLE document', 'medium', 'OLE compound file detected; deep parsing unavailable', 'medium', 'file-validation'))
        if re.search(rb'V\x00B\x00A\x00(?:_\x00P\x00R\x00O\x00J\x00E\x00C\x00T\x00)?|M\x00a\x00c\x00r\x00o\x00s\x00', data):
            findings.append(finding('Macro-capable Office content detected', 'high', 'VBA/Macros storage name found in OLE directory; not proof of malicious macros', 'medium', 'byte-marker'))
    elif ext in ('.txt', '.html', '.htm'):
        text = data.decode('utf-8', 'replace'); text_parts.append(text)
        if ext in ('.html', '.htm') and re.search(r'<script\b|javascript:|\bon(?:load|error|click)\s*=', text, re.I):
            findings.append(finding('Script content in HTML file', 'medium', 'HTML attachment contains script or inline event handlers', 'medium', 'byte-marker'))
    combined = '\n'.join(text_parts)
    urls.extend(_urls(combined))
    if kind == 'zip': urls = [u for u in urls if (urlsplit(u).hostname or '').lower() not in NAMESPACE_HOSTS]
    urls = list(dict.fromkeys(urls))[:MAX_URLS]
    for url in urls: findings.extend(_url_findings(url))
    # Only the unambiguous marker is checked on opaque content; words like "macro"/"JavaScript" occur in ordinary resumes.
    if kind not in ('zip', 'ole') and re.search(rb'vbaProject\.bin', data, re.I): findings.append(finding('Macro-related marker', 'medium', 'vbaProject.bin reference observed; this is not proof of executable macros', 'medium', 'byte-marker'))
    external = [_clam_scan(data, sha, findings), _yara_scan(data, findings)]
    return {'filename': filename, 'size': len(data), 'sha256': sha, 'extension': ext, 'findings': _dedupe(findings), 'urls': urls, 'metadata': metadata, 'external_tools': external, 'note': 'File was not executed. Document parsing is bounded and best-effort; results are not a guarantee of safety.'}


def score(findings):
    weights = {'critical': 30, 'high': 20, 'medium': 10, 'low': 4, 'info': 0}
    points = min(100, sum(weights.get(f.get('severity', 'low'), 4) for f in findings))
    top = max((SEV_RANK.get(f.get('severity'), 1) for f in findings), default=0)
    # A single confirmed critical/high finding must not be diluted into a lower band by the additive total.
    if top >= SEV_RANK['critical']: points = max(points, 75)
    elif top >= SEV_RANK['high']: points = max(points, 50)
    return {'score': points, 'severity': 'critical' if points >= 75 else 'high' if points >= 50 else 'medium' if points >= 25 else 'low' if points else 'informational', 'confidence': 'heuristic score, not probability'}
