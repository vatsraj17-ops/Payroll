from __future__ import annotations

from pathlib import Path

import pdfplumber


def main() -> None:
    pdf_path = Path(r"c:\Users\USER\Downloads\t4127-01-26e.pdf")
    out_path = Path(__file__).resolve().parents[1] / "t4127-01-26e.txt"

    if not pdf_path.exists():
        raise SystemExit(f"PDF not found: {pdf_path}")

    text_parts: list[str] = []
    with pdfplumber.open(str(pdf_path)) as pdf:
        for i, page in enumerate(pdf.pages, start=1):
            text_parts.append(f"\n\n--- PAGE {i} ---\n")
            text_parts.append(page.extract_text() or "")

    out_path.write_text("\n".join(text_parts), encoding="utf-8")
    print(f"Wrote {out_path} ({out_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
