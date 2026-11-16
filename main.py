"""
remove-ai-marks compatible cleaning service.
Implements: /health /capabilities /inspect /detect /clean (+ auto /openapi.json via FastAPI)
"""
import base64
import io
import re
import unicodedata
import zipfile
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="remove-ai-marks service", version="1.0.0")

VERSION = "1.0.0"

# ---------- text helpers ----------

INVISIBLE = [
    "​", "‌", "‍", "⁠", "﻿", "‪", "‫",
    "‬", "‭", "‮", "᠎", " ", " ", " ", " ",
    " ", " ", " ", " ", " ", " ", " ", " ",
    " ", "　",
]
HIDDEN_FORMAT_CATS = {"Cf", "Cc", "Mn"}


def clean_text(s: str, nfkc: bool = True):
    findings = {"invisible_chars": 0, "format_chars": 0}
    removed = 0
    for ch in INVISIBLE:
        c = s.count(ch)
        if c:
            findings["invisible_chars"] += c
            s = s.replace(ch, "")
            removed += c
    # strip any remaining Unicode format chars (Cf)
    out = []
    for ch in s:
        if unicodedata.category(ch) in ("Cf",):
            findings["format_chars"] += 1
            removed += 1
            continue
        out.append(ch)
    s = "".join(out)
    if nfkc:
        s = unicodedata.normalize("NFKC", s)
    findings["removed_total"] = removed
    return s, findings


def scan_text(s: str):
    n_inv = sum(s.count(ch) for ch in INVISIBLE)
    n_cf = sum(1 for ch in s if unicodedata.category(ch) == "Cf")
    return {"invisible_chars": n_inv + n_cf, "length": len(s)}


# ---------- container helpers ----------

def detect_kind(name: str, data: bytes) -> str:
    ext = (name.rsplit(".", 1)[-1] or "").lower() if "." in name else ""
    if data[:5] == b"%PDF-":
        return "pdf"
    if data[:2] == b"PK":
        return "docx" if ext in ("docx",) else ("odt" if ext == "odt" else "zip")
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image"
    if data[:3] == b"\xff\xd8\xff":
        return "image"
    if ext in ("png", "jpg", "jpeg", "webp", "gif", "bmp", "tiff"):
        return "image"
    if ext in ("txt", "md", "html", "tex", "ltx", "svg", "csv"):
        return "text"
    return "unknown"


def inspect_pdf(data: bytes):
    import pikepdf
    findings = {}
    pdf = pikepdf.open(io.BytesIO(data))
    try:
        di = {str(k): str(v) for k, v in (pdf.docinfo or {}).items()}
        findings["docinfo"] = di
        findings["has_xmp_metadata"] = "/Metadata" in pdf.Root
        if "/Metadata" in pdf.Root:
            try:
                xmp = bytes(pdf.Root.Metadata.read_bytes()).decode("utf-8", "ignore")
                findings["xmp_mentions"] = [
                    t for t in ("pdfaid", "xmp", "c2pa", "ai", "generator", "producer")
                    if t.lower() in xmp.lower()
                ]
            except Exception:
                pass
        findings["pages"] = len(pdf.pages)
    finally:
        pdf.close()
    return findings


def clean_pdf(data: bytes):
    import pikepdf
    src = io.BytesIO(data)
    dst = io.BytesIO()
    pdf = pikepdf.open(src)
    removed = []
    if pdf.docinfo:
        for k in list(pdf.docinfo.keys()):
            del pdf.docinfo[k]
        removed.append("docinfo")
    if "/Metadata" in pdf.Root:
        del pdf.Root.Metadata
        removed.append("xmp_metadata")
    try:
        del pdf.trailer.Info
        removed.append("trailer_info")
    except Exception:
        pass
    pdf.save(dst, linearize=True)
    pdf.close()
    return dst.getvalue(), {"removed": removed}


def inspect_docx(data: bytes):
    findings = {}
    z = zipfile.ZipFile(io.BytesIO(data))
    for part in ("docProps/core.xml", "docProps/app.xml"):
        try:
            xml = z.read(part).decode("utf-8", "ignore")
            fields = re.findall(r"<(?:dc:|cp:)?(\w+)[^>]*>([^<]+)<", xml)
            findings[part] = {k: v for k, v in fields if v.strip()}
        except KeyError:
            pass
    # invisible unicode inside the document text
    try:
        doc = z.read("word/document.xml").decode("utf-8", "ignore")
        findings["document_text_scan"] = scan_text(doc)
    except KeyError:
        pass
    return findings


CORE_CLEAR_TAGS = [
    "dc:title", "dc:subject", "dc:creator", "cp:keywords", "dc:description",
    "cp:lastModifiedBy", "cp:revision", "cp:lastPrinted", "dc:language",
    "dc:identifier", "cp:contentStatus", "dc:category", "dc:version",
    "dcterms:created", "dcterms:modified",
]


def clean_docx(data: bytes):
    src = zipfile.ZipFile(io.BytesIO(data))
    out = io.BytesIO()
    removed = []
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for item in src.infolist():
            blob = src.read(item.filename)
            if item.filename == "docProps/core.xml":
                xml = blob.decode("utf-8", "ignore")
                for tag in CORE_CLEAR_TAGS:
                    xml_new = re.sub(rf"<{tag}[^>]*>.*?</{tag}>", "", xml, flags=re.S)
                    xml_new = re.sub(rf"<{tag}[^>]*/>", "", xml_new)
                    if xml_new != xml:
                        removed.append(tag)
                        xml = xml_new
                blob = xml.encode("utf-8")
            elif item.filename == "docProps/app.xml":
                xml = blob.decode("utf-8", "ignore")
                xml = re.sub(r"<Application>.*?</Application>", "<Application></Application>", xml, flags=re.S)
                xml = re.sub(r"<AppVersion>.*?</AppVersion>", "", xml, flags=re.S)
                xml = re.sub(r"<Company>.*?</Company>", "<Company></Company>", xml, flags=re.S)
                removed.append("app.xml")
                blob = xml.encode("utf-8")
            elif item.filename == "word/document.xml":
                xml = blob.decode("utf-8", "ignore")
                xml, tfind = clean_text(xml, nfkc=False)
                if tfind["removed_total"]:
                    removed.append(f"invisible_unicode:{tfind['removed_total']}")
                blob = xml.encode("utf-8")
            dst.writestr(item, blob)
    return out.getvalue(), {"removed": removed}


def inspect_image(data: bytes):
    from PIL import Image
    img = Image.open(io.BytesIO(data))
    findings = {"format": img.format, "size": list(img.size)}
    exif = img.getexif()
    if exif:
        findings["exif_tags"] = len(exif)
    info_keys = [k for k in img.info.keys() if k not in ("exif",)]
    if "exif" in img.info:
        info_keys.append("exif(raw)")
    if info_keys:
        findings["metadata_blocks"] = info_keys
    return findings


def clean_image(data: bytes, fmt_hint: str):
    from PIL import Image
    img = Image.open(io.BytesIO(data))
    fmt = img.format or ("JPEG" if fmt_hint in ("jpg", "jpeg") else "PNG")
    clean = Image.new(img.mode, img.size)
    clean.putdata(list(img.getdata()))
    out = io.BytesIO()
    save_kwargs = {}
    if fmt == "JPEG":
        if clean.mode != "RGB":
            clean = clean.convert("RGB")
        save_kwargs["quality"] = 95
    clean.save(out, format=fmt, **save_kwargs)
    return out.getvalue(), {"removed": ["exif", "xmp", "all_info_blocks"]}


# ---------- API ----------

class Payload(BaseModel):
    file: str
    name: str
    options: dict = {}


@app.get("/health")
def health():
    return {"ok": True, "version": VERSION}


@app.get("/capabilities")
def capabilities():
    return {
        "version": VERSION,
        "tools": {
            "pikepdf": True,
            "pillow": True,
            "python-zipfile": True,
            "unicodedata": True,
            "exiftool": False,
            "qpdf": False,
            "c2patool": False,
            "ghostscript": False,
        },
        "kinds": ["pdf", "docx", "image", "text"],
        "options": ["nfkc", "strip_all_metadata", "also_layer_a_text"],
        "notes": "Metadata + invisible-Unicode cleaning. No pixel or token watermark removal.",
    }


@app.post("/inspect")
def inspect(p: Payload):
    data = base64.b64decode(p.file)
    kind = detect_kind(p.name, data)
    try:
        if kind == "pdf":
            findings = inspect_pdf(data)
        elif kind == "docx":
            findings = inspect_docx(data)
        elif kind == "image":
            findings = inspect_image(data)
        elif kind == "text":
            findings = scan_text(data.decode("utf-8", "ignore"))
        else:
            findings = {"warning": "unsupported kind"}
        return {"kind": kind, "findings": findings}
    except Exception as e:
        return {"kind": kind, "error": str(e)}


@app.post("/detect")
def detect(p: Payload):
    data = base64.b64decode(p.file)
    kind = detect_kind(p.name, data)
    res = {"kind": kind, "detectors": {}}
    if kind == "text":
        res["detectors"]["invisible_unicode"] = scan_text(data.decode("utf-8", "ignore"))
    else:
        res["detectors"]["note"] = "no statistical detector configured; metadata scan only"
    return res


@app.post("/clean")
def clean(p: Payload):
    data = base64.b64decode(p.file)
    kind = detect_kind(p.name, data)
    opts = p.options or {}
    try:
        if kind == "pdf":
            cleaned, report = clean_pdf(data)
        elif kind == "docx":
            cleaned, report = clean_docx(data)
        elif kind == "image":
            ext = p.name.rsplit(".", 1)[-1].lower()
            cleaned, report = clean_image(data, ext)
        elif kind == "text":
            text, tfind = clean_text(data.decode("utf-8", "ignore"),
                                     nfkc=opts.get("nfkc", True))
            cleaned = text.encode("utf-8")
            report = {"removed": tfind}
        else:
            return {"kind": kind, "error": "unsupported kind; nothing cleaned"}
        return {
            "kind": kind,
            "cleaned": base64.b64encode(cleaned).decode("ascii"),
            "report": report,
            "limitations": "Pixel-domain watermarks, C2PA soft bindings and statistical text signals are NOT addressed.",
        }
    except Exception as e:
        return {"kind": kind, "error": str(e)}
