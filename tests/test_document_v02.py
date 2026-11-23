import io, zipfile
from hireshield.core import inspect_file, _zip_inspect

def make_zip(files):
    b=io.BytesIO()
    with zipfile.ZipFile(b,'w') as z:
        for name,content in files.items(): z.writestr(name,content)
    return b.getvalue()

def test_docx_macro_marker_detected():
    data=make_zip({'word/document.xml':'<document/>','word/vbaProject.bin':'synthetic marker'})
    r=inspect_file('sample.docm',data)
    assert any('Macro-capable' in f['title'] for f in r['findings'])

def test_external_relationship_url_extracted():
    rels='''<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="r1" Target="https://example.invalid/a" TargetMode="External" Type="hyperlink"/></Relationships>'''
    data=make_zip({'word/_rels/document.xml.rels':rels})
    r=inspect_file('sample.docx',data)
    assert 'https://example.invalid/a' in r['urls']

def test_embedded_object_flag():
    data=make_zip({'word/embeddings/oleObject1.bin':'dummy'})
    r=inspect_file('sample.docx',data)
    assert any('Embedded object' in f['title'] for f in r['findings'])

def test_invalid_docx_zip_reported():
    r=inspect_file('bad.docx',b'PK but not zip')
    assert any('Invalid ZIP' in f['title'] for f in r['findings'])

def test_zip_path_suspicion():
    data=make_zip({'../unsafe.xml':'<root/>'})
    r=inspect_file('sample.docx',data)
    assert any('archive path' in f['title'].lower() for f in r['findings'])

def test_pdf_header_mismatch():
    r=inspect_file('sample.pdf',b'not a pdf')
    assert any('signature' in f['title'].lower() for f in r['findings'])

def test_pdf_parser_handles_minimal_generated_pdf():
    try:
        from pypdf import PdfWriter
    except ImportError:
        return
    b=io.BytesIO(); writer=PdfWriter(); writer.add_blank_page(width=72,height=72); writer.write(b)
    r=inspect_file('blank.pdf',b.getvalue())
    assert r['metadata']['parser']=='pypdf'
