"""
Stamps an offer-letter PDF with a QR code + verification footer on its
last page, then returns the finished bytes. The offer's SHA-256 hash is
computed AFTER stamping, because the hash has to cover the exact file
the candidate will receive (including the QR code).
"""
import io
import qrcode
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader


def stamp_pdf(pdf_bytes: bytes, offer_id: str, verify_base_url: str) -> bytes:
    reader = PdfReader(io.BytesIO(pdf_bytes))
    writer = PdfWriter()

    qr_img = qrcode.make(f"{verify_base_url}/v/{offer_id}")
    qr_buf = io.BytesIO()
    qr_img.save(qr_buf, format="PNG")
    qr_buf.seek(0)

    last_page_index = len(reader.pages) - 1

    for i, page in enumerate(reader.pages):
        if i == last_page_index:
            width = float(page.mediabox.width)
            height = float(page.mediabox.height)

            overlay_buf = io.BytesIO()
            c = canvas.Canvas(overlay_buf, pagesize=(width, height))

            qr_size = 64
            c.drawImage(
                ImageReader(qr_buf), width - qr_size - 36, 24, qr_size, qr_size,
                preserveAspectRatio=True, mask="auto",
            )
            c.setFont("Helvetica", 8)
            c.drawString(36, 46, "This offer was signed and verified by Vouch.")
            c.drawString(36, 34, f"Verify at {verify_base_url}/v/{offer_id}")
            c.drawString(36, 22, f"Offer ID: {offer_id}")
            c.save()
            overlay_buf.seek(0)

            overlay_reader = PdfReader(overlay_buf)
            page.merge_page(overlay_reader.pages[0])

        writer.add_page(page)

    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def extract_offer_id(pdf_bytes: bytes) -> str | None:
    """
    Recovers the offer ID by reading the stamped footer text back out of
    the PDF. Used when a candidate uploads a PDF without going through
    the QR code (e.g. they forwarded the file instead of scanning it).
    """
    import re

    reader = PdfReader(io.BytesIO(pdf_bytes))
    text = reader.pages[-1].extract_text() or ""
    match = re.search(r"Offer ID:\s*([A-Z0-9\-]+)", text)
    return match.group(1) if match else None


if __name__ == "__main__":
    # self-test: build a tiny one-page PDF, stamp it, and read the ID back
    from reportlab.pdfgen import canvas as _canvas

    buf = io.BytesIO()
    c = _canvas.Canvas(buf, pagesize=(612, 792))
    c.setFont("Helvetica", 14)
    c.drawString(72, 700, "Offer of Employment")
    c.drawString(72, 680, "Role: Software Engineer")
    c.drawString(72, 660, "Salary: $120,000")
    c.save()
    buf.seek(0)

    stamped = stamp_pdf(buf.getvalue(), "VCH-ABC123", "https://vouch.app")
    recovered = extract_offer_id(stamped)
    assert recovered == "VCH-ABC123", f"got {recovered!r}"
    print(f"pdf_stamp self-test passed ({len(stamped)} bytes stamped PDF)")
