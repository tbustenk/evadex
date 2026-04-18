"""Barcode/QR code image writers for evadex generate.

Siphon's ``extract_barcode`` pipeline (see dlpscan-rs
``src/extractors.rs``) decodes PNG/JPG/GIF/BMP/TIFF/WEBP images via the
``rxing`` library. It recognises QR Code, Data Matrix, Aztec, PDF417,
UPC-A/E, EAN-8/13, Code 39, Code 128, ITF, and Codabar — and can detect
up to 100 barcodes per image with a 4 KB text cap per code.

These writers produce test fixtures that exercise that pipeline. They
are gated behind the ``evadex[barcodes]`` optional install (``qrcode``,
``python-barcode``, ``Pillow``) so the core package stays small; a clear
error is raised if the extras are missing.
"""
from __future__ import annotations

import io
import os
import random
import re
from collections import defaultdict
from typing import Optional

from evadex.generate.generator import GeneratedEntry


BARCODE_DEPS_HINT = (
    "Barcode generation requires optional dependencies. "
    "Install with: pip install evadex[barcodes]"
)

# Safety cap on barcodes per image. Large grids balloon the output (a 700-entry
# grid rendered at 300 px/cell would be >200 megapixels) and hit PIL's
# decompression-bomb limit downstream. Siphon also caps decoding at 100 per
# image, so anything above ~60 is lost recall for wasted pixels. Users who
# want more volume should run --format multiple times or use --formats.
MAX_BARCODES_PER_IMAGE = 60


def _require_qrcode():
    try:
        import qrcode  # type: ignore
        import qrcode.constants  # type: ignore
        return qrcode
    except ImportError as exc:
        raise RuntimeError(BARCODE_DEPS_HINT) from exc


def _require_barcode():
    try:
        import barcode  # type: ignore
        from barcode.writer import ImageWriter  # type: ignore
        return barcode, ImageWriter
    except ImportError as exc:
        raise RuntimeError(BARCODE_DEPS_HINT) from exc


def _require_pil():
    try:
        from PIL import Image, ImageDraw, ImageFont  # type: ignore
        return Image, ImageDraw, ImageFont
    except ImportError as exc:
        raise RuntimeError(BARCODE_DEPS_HINT) from exc


# ── Public writers registered via writers.__init__ ──────────────────────────

def write_png(entries: list[GeneratedEntry], path: str) -> None:
    """Single PNG with one barcode per entry, arranged in a grid."""
    _write_barcode_grid(entries, path, image_format="PNG")


def write_jpg(entries: list[GeneratedEntry], path: str) -> None:
    _write_barcode_grid(entries, path, image_format="JPEG")


def write_multi_barcode_png(entries: list[GeneratedEntry], path: str) -> None:
    """PNG that looks like a scanned form — mix of barcode types per entry."""
    _write_multi(entries, path)


# ── Core implementation ────────────────────────────────────────────────────

def _active_barcode_type() -> str:
    """Read the currently-configured --barcode-type (set by the CLI)."""
    from evadex.generate.writers import _active_barcode_type as t  # late import
    return t or "qr"


def _active_seed() -> Optional[int]:
    from evadex.generate.writers import _active_seed
    return _active_seed


def _encode_one(
    value: str,
    barcode_type: str,
    rng: random.Random,
):
    """Return a PIL image for ``value`` encoded as ``barcode_type``.

    Falls back to QR when a 1D barcode can't represent the value (e.g.
    EAN-13 needs 12 digits; credit card numbers, etc.). Never raises.
    """
    Image, _, _ = _require_pil()

    kind = barcode_type
    if kind == "random":
        kind = rng.choice(["qr", "code128", "ean13", "pdf417", "datamatrix"])

    if kind == "qr":
        return _render_qr(value)
    if kind == "code128":
        return _render_code1d(value, "code128")
    if kind == "ean13":
        return _render_ean13(value, rng)
    if kind == "pdf417":
        return _render_pdf417(value) or _render_qr(value)
    if kind == "datamatrix":
        return _render_datamatrix(value) or _render_qr(value)
    return _render_qr(value)


def _render_qr(value: str):
    """Render ``value`` as a QR-code PIL image with a quiet zone."""
    qrcode = _require_qrcode()
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=6,
        border=4,
    )
    qr.add_data(value)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    # qrcode returns a PilImage wrapper; convert to plain PIL Image for uniform handling.
    return img.get_image() if hasattr(img, "get_image") else img


def _render_code1d(value: str, kind: str):
    """Render a 1D barcode (Code 128). Clamps value to the alphabet Code 128 accepts."""
    barcode, ImageWriter = _require_barcode()
    # Code 128 tolerates ASCII printable; strip characters outside that range.
    safe = re.sub(r"[^\x20-\x7e]", "", value) or "EVADEX"
    # python-barcode caps at reasonable lengths; truncate overlong values.
    if len(safe) > 80:
        safe = safe[:80]
    cls = barcode.get_barcode_class("code128")
    writer = ImageWriter()
    # Suppress per-image file writes; render_to_pil via write(None) -> BytesIO.
    buf = io.BytesIO()
    cls(safe, writer=writer).write(buf)
    buf.seek(0)
    Image, _, _ = _require_pil()
    return Image.open(buf).convert("RGB")


def _render_ean13(value: str, rng: random.Random):
    """Render an EAN-13 barcode. EAN-13 needs exactly 12 data digits."""
    barcode, ImageWriter = _require_barcode()
    digits = re.sub(r"[^0-9]", "", value)
    if len(digits) >= 12:
        payload = digits[:12]
    else:
        # Pad with derived digits so the code stays deterministic for a given value.
        payload = (digits + "0" * 12)[:12]
    try:
        cls = barcode.get_barcode_class("ean13")
        buf = io.BytesIO()
        cls(payload, writer=ImageWriter()).write(buf)
        buf.seek(0)
        Image, _, _ = _require_pil()
        return Image.open(buf).convert("RGB")
    except Exception:
        return _render_code1d(payload, "code128")


def _render_pdf417(value: str):
    """PDF417 via pdf417gen if available; returns None so caller can fall back."""
    try:
        from pdf417gen import encode, render_image  # type: ignore
    except ImportError:
        return None
    codes = encode(value)
    return render_image(codes, scale=3, ratio=3).convert("RGB")


def _render_datamatrix(value: str):
    """Data Matrix via pylibdmtx if available; returns None for graceful fallback."""
    try:
        from pylibdmtx.pylibdmtx import encode  # type: ignore
    except ImportError:
        return None
    Image, _, _ = _require_pil()
    encoded = encode(value.encode("utf-8"))
    return Image.frombytes("RGB", (encoded.width, encoded.height), encoded.pixels)


def _add_label(img, text: str):
    """Return a new image with the value printed underneath the barcode."""
    Image, ImageDraw, ImageFont = _require_pil()
    try:
        font = ImageFont.load_default()
    except Exception:
        font = None
    # Crop display text to a reasonable width so long values don't spill out.
    display = text if len(text) < 60 else text[:57] + "..."
    pad = 20
    label_height = 24
    new_w = max(img.width, 200)
    new_h = img.height + label_height + pad
    canvas = Image.new("RGB", (new_w, new_h), "white")
    canvas.paste(img, ((new_w - img.width) // 2, 0))
    draw = ImageDraw.Draw(canvas)
    draw.text(
        ((new_w - len(display) * 6) // 2, img.height + 4),
        display,
        fill="black",
        font=font,
    )
    return canvas


def _grid_layout(images: list, max_cols: int = 3):
    """Stack ``images`` in a tidy grid and return the composited PIL image."""
    Image, _, _ = _require_pil()
    if not images:
        # 100×100 placeholder so downstream tooling doesn't crash on empty inputs.
        return Image.new("RGB", (100, 100), "white")
    cols = min(max_cols, len(images))
    rows = (len(images) + cols - 1) // cols
    cell_w = max(im.width for im in images)
    cell_h = max(im.height for im in images)
    margin = 20
    canvas = Image.new(
        "RGB",
        (cols * cell_w + (cols + 1) * margin, rows * cell_h + (rows + 1) * margin),
        "white",
    )
    for i, im in enumerate(images):
        r, c = divmod(i, cols)
        x = margin + c * (cell_w + margin)
        y = margin + r * (cell_h + margin)
        canvas.paste(im, (x, y))
    return canvas


def _write_barcode_grid(
    entries: list[GeneratedEntry],
    path: str,
    image_format: str,
) -> None:
    """Render all entries into one grid image at ``path``."""
    Image, _, _ = _require_pil()
    _require_qrcode()  # trigger dep check early with a clear error

    rng = random.Random(_active_seed())
    barcode_type = _active_barcode_type()

    if len(entries) > MAX_BARCODES_PER_IMAGE:
        entries = entries[:MAX_BARCODES_PER_IMAGE]

    images = []
    for e in entries:
        images.append(_render_entry(e, barcode_type, rng))

    canvas = _grid_layout(images, max_cols=3)
    _ensure_dir(path)
    if image_format == "JPEG":
        canvas = canvas.convert("RGB")
        canvas.save(path, "JPEG", quality=92)
    else:
        canvas.save(path, "PNG")


def _render_entry(entry: GeneratedEntry, barcode_type: str, rng: random.Random):
    """Render one entry, dispatching to the evasion transform when marked.

    When the entry carries a barcode_evasion technique we apply an image-level
    transform on top of the base barcode render. Plain entries follow the
    default render → label path.
    """
    value = entry.variant_value
    technique = entry.technique
    label = entry.variant_value

    # Strip zero-width markers before encoding so the barcode content is clean.
    # \x1e is the split marker for barcode_split (kept as-is for the split
    # path, stripped for everything else).
    clean = value.replace("\u200b", "").replace("\u200c", "").replace("\u200d", "")

    if technique == "barcode_split":
        # Split marker is a record separator; render two barcodes side by side.
        # Also accept a literal newline in case old payloads are encountered.
        for sep in ("\x1e", "\n"):
            if sep in clean:
                parts = clean.split(sep, 1)
                break
        else:
            parts = [clean[:len(clean) // 2], clean[len(clean) // 2:]]
        parts = [p for p in parts if p]
        if len(parts) < 2:
            parts = [clean]
        imgs = [_encode_one(p, barcode_type, rng) for p in parts]
        img = _grid_layout(imgs, max_cols=2)
    elif technique == "barcode_noise":
        img = _apply_noise(_encode_one(clean, barcode_type, rng), rng)
    elif technique == "barcode_rotate":
        img = _apply_rotate(_encode_one(clean, barcode_type, rng), angle=15)
    elif technique == "barcode_embed":
        img = _embed_in_document(_encode_one(clean, barcode_type, rng))
    else:
        # Strip the split marker for non-split paths (older payloads, etc.).
        img = _encode_one(clean.replace("\x1e", ""), barcode_type, rng)

    return _add_label(img, label)


def _apply_noise(img, rng: random.Random, density: float = 0.02):
    """Overlay salt-and-pepper noise; rxing tolerates this, it's a soft test."""
    Image, _, _ = _require_pil()
    noisy = img.convert("RGB").copy()
    pixels = noisy.load()
    w, h = noisy.size
    n = int(w * h * density)
    for _ in range(n):
        x = rng.randint(0, w - 1)
        y = rng.randint(0, h - 1)
        pixels[x, y] = (0, 0, 0) if rng.random() < 0.5 else (255, 255, 255)
    return noisy


def _apply_rotate(img, angle: float = 15):
    """Rotate by ``angle`` degrees on a white background."""
    return img.rotate(angle, expand=True, fillcolor="white")


def _embed_in_document(img):
    """Paste the barcode onto a larger document-style canvas.

    Layout:
        [ header bar with title + date ]
        [ body text                     ]
        [ ┌─────── barcode ───────┐     ]
        [ footer note                   ]
    """
    Image, ImageDraw, ImageFont = _require_pil()
    try:
        font = ImageFont.load_default()
    except Exception:
        font = None
    canvas_w = max(600, img.width + 120)
    canvas_h = img.height + 180
    canvas = Image.new("RGB", (canvas_w, canvas_h), "white")
    draw = ImageDraw.Draw(canvas)
    # Header bar
    draw.rectangle([0, 0, canvas_w, 40], fill="#003366")
    draw.text((12, 12), "ACMECORP — INVOICE 2026-0042", fill="white", font=font)
    # Body text
    draw.text((20, 60), "Please scan the code below to verify the transaction.", fill="black", font=font)
    # Barcode
    x = (canvas_w - img.width) // 2
    y = 100
    canvas.paste(img, (x, y))
    # Footer
    draw.text((20, y + img.height + 20), "Internal use only — DLP control sample.", fill="#666", font=font)
    return canvas


def _write_multi(entries: list[GeneratedEntry], path: str) -> None:
    """Multi-barcode PNG: alternating barcode types to simulate a scanned form.

    The image is laid out with a title bar and per-category sections — each
    entry placed in a different barcode format so Siphon sees a mixed bag
    of formats in a single image.
    """
    Image, ImageDraw, ImageFont = _require_pil()
    _require_qrcode()

    rng = random.Random(_active_seed())

    if len(entries) > MAX_BARCODES_PER_IMAGE:
        entries = entries[:MAX_BARCODES_PER_IMAGE]

    by_cat: dict = defaultdict(list)
    for e in entries:
        by_cat[e.category].append(e)

    type_cycle = ["qr", "code128", "ean13"]
    rendered = []
    for idx, e in enumerate(entries):
        btype = type_cycle[idx % len(type_cycle)]
        value = e.embedded_text or e.variant_value
        img = _encode_one(value, btype, rng)
        rendered.append(_add_label(img, f"{e.category.value}: {e.variant_value[:32]}"))

    # Title bar
    title = "FORM A-12 — SUBMISSION RECORDS (INTERNAL)"
    canvas = _grid_layout(rendered, max_cols=2)
    top_pad = 40
    Image, ImageDraw, ImageFont = _require_pil()
    final = Image.new("RGB", (canvas.width, canvas.height + top_pad), "white")
    draw = ImageDraw.Draw(final)
    try:
        font = ImageFont.load_default()
    except Exception:
        font = None
    draw.text((20, 12), title, fill="black", font=font)
    final.paste(canvas, (0, top_pad))
    _ensure_dir(path)
    final.save(path, "PNG")


def _ensure_dir(path: str) -> None:
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
