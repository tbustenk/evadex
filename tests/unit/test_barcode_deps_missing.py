"""Verify the barcode writer fails gracefully when optional deps are absent.

We can't uninstall ``qrcode`` for the test run, so instead we patch
``_require_qrcode`` to raise the error it would raise on a fresh system.
The behaviour that matters is: the error message must point the user at
``pip install evadex[barcodes]`` rather than a bare ImportError.
"""
import pytest

from evadex.core.result import PayloadCategory
from evadex.generate.generator import GeneratedEntry


def _dummy_entry():
    return GeneratedEntry(
        category=PayloadCategory.CREDIT_CARD,
        plain_value="4532015112830366",
        variant_value="4532015112830366",
        technique=None,
        generator_name=None,
        transform_name=None,
        has_keywords=False,
        embedded_text="4532015112830366",
    )


def test_missing_qrcode_yields_install_hint(tmp_path, monkeypatch):
    from evadex.generate.writers import barcode_writer

    def _fake_require():
        raise RuntimeError(barcode_writer.BARCODE_DEPS_HINT)

    monkeypatch.setattr(barcode_writer, "_require_qrcode", _fake_require)

    with pytest.raises(RuntimeError) as exc:
        barcode_writer.write_png([_dummy_entry()], str(tmp_path / "out.png"))
    assert "evadex[barcodes]" in str(exc.value)


def test_missing_pil_yields_install_hint(tmp_path, monkeypatch):
    from evadex.generate.writers import barcode_writer

    def _fake_require():
        raise RuntimeError(barcode_writer.BARCODE_DEPS_HINT)

    monkeypatch.setattr(barcode_writer, "_require_pil", _fake_require)

    with pytest.raises(RuntimeError) as exc:
        barcode_writer.write_png([_dummy_entry()], str(tmp_path / "out.png"))
    assert "evadex[barcodes]" in str(exc.value)
