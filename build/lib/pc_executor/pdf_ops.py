from __future__ import annotations

import io
import re
import textwrap
from pathlib import Path
from typing import Any, Mapping, Sequence

from pypdf import PdfReader, PdfWriter
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


PAGE_BREAK = '<div style="page-break-before: always;"></div>'
MAX_PDF_OPERATIONS = 128
MAX_INSERTED_SOURCE_PAGES = 500


class PdfOperationError(ValueError):
    pass


def _plain_markdown_lines(markdown: str) -> list[str | None]:
    parts = markdown.replace("\r\n", "\n").replace("\r", "\n").split(PAGE_BREAK)
    output: list[str | None] = []
    for part_index, part in enumerate(parts):
        if part_index:
            output.append(None)
        for raw in part.split("\n"):
            line = re.sub(r"<[^>]+>", "", raw)
            line = re.sub(r"^#{1,6}\s*", "", line)
            line = re.sub(r"^\s*[-*+]\s+", "• ", line)
            line = re.sub(r"[*_]", "", line).replace("`", "")
            wrapped = textwrap.wrap(
                line,
                width=96,
                replace_whitespace=False,
                drop_whitespace=False,
            ) or [""]
            output.extend(wrapped)
    return output


def render_markdown_pdf_bytes(markdown: str) -> bytes:
    buffer = io.BytesIO()
    doc = canvas.Canvas(buffer, pagesize=letter, pageCompression=1)
    _, height = letter
    left = 54
    top = height - 54
    bottom = 54
    line_height = 14
    y = top
    doc.setFont("Helvetica", 10)

    for line in _plain_markdown_lines(markdown):
        if line is None or y < bottom:
            doc.showPage()
            doc.setFont("Helvetica", 10)
            y = top
            if line is None:
                continue
        safe_line = line.encode("latin-1", errors="replace").decode("latin-1")
        doc.drawString(left, y, safe_line[:500])
        y -= line_height
    doc.save()
    return buffer.getvalue()


def create_markdown_pdf(
    markdown: str,
    output_path: Path,
    *,
    max_output_bytes: int,
) -> dict[str, Any]:
    payload = render_markdown_pdf_bytes(markdown)
    if len(payload) > max_output_bytes:
        raise PdfOperationError(
            f"generated PDF exceeds output bound: {len(payload)} > {max_output_bytes}"
        )
    output_path.write_bytes(payload)
    return {
        "output_path": str(output_path),
        "output_bytes": len(payload),
        "pages": len(PdfReader(io.BytesIO(payload)).pages),
        "mode": "create",
    }


def _reader(path: Path, max_input_bytes: int) -> PdfReader:
    size = path.stat().st_size
    if size > max_input_bytes:
        raise PdfOperationError(
            f"PDF input exceeds bound: {size} > {max_input_bytes}"
        )
    try:
        return PdfReader(str(path), strict=True)
    except Exception as exc:
        raise PdfOperationError(f"invalid PDF input: {type(exc).__name__}") from exc


def _insert_markdown_pages(markdown: str) -> list[Any]:
    try:
        reader = PdfReader(io.BytesIO(render_markdown_pdf_bytes(markdown)), strict=True)
    except Exception as exc:
        raise PdfOperationError(
            f"unable to render inserted markdown: {type(exc).__name__}"
        ) from exc
    return list(reader.pages)


def modify_pdf_to_new_output(
    input_path: Path,
    operations: Sequence[Mapping[str, Any]],
    output_path: Path,
    *,
    max_input_bytes: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    if len(operations) > MAX_PDF_OPERATIONS:
        raise PdfOperationError(
            f"too many PDF operations: {len(operations)} > {MAX_PDF_OPERATIONS}"
        )
    pages = list(_reader(input_path, max_input_bytes).pages)
    for op_index, operation in enumerate(operations):
        op_type = operation.get("type")
        if op_type == "delete":
            indexes = operation.get("page_indexes")
            if not isinstance(indexes, list) or not indexes:
                raise PdfOperationError(
                    f"operation {op_index} delete requires non-empty page_indexes"
                )
            if any(
                isinstance(index, bool)
                or not isinstance(index, int)
                or index < 0
                or index >= len(pages)
                for index in indexes
            ):
                raise PdfOperationError(
                    f"operation {op_index} delete page index out of range"
                )
            if len(set(indexes)) != len(indexes):
                raise PdfOperationError(
                    f"operation {op_index} delete page indexes must be unique"
                )
            for index in sorted(indexes, reverse=True):
                del pages[index]
            continue

        if op_type != "insert":
            raise PdfOperationError(f"operation {op_index} has unsupported type")
        page_index = operation.get("page_index")
        if (
            isinstance(page_index, bool)
            or not isinstance(page_index, int)
            or page_index < 0
            or page_index > len(pages)
        ):
            raise PdfOperationError(
                f"operation {op_index} insert page_index out of range"
            )
        markdown = operation.get("markdown")
        source_pdf_path = operation.get("source_pdf_path")
        if (markdown is None) == (source_pdf_path is None):
            raise PdfOperationError(
                f"operation {op_index} insert requires exactly one content source"
            )
        if markdown is not None:
            inserted = _insert_markdown_pages(str(markdown))
        else:
            inserted = list(
                _reader(Path(str(source_pdf_path)), max_input_bytes).pages
            )
        if len(inserted) > MAX_INSERTED_SOURCE_PAGES:
            raise PdfOperationError(
                f"operation {op_index} inserts too many pages"
            )
        pages[page_index:page_index] = inserted

    writer = PdfWriter()
    for page in pages:
        writer.add_page(page)
    buffer = io.BytesIO()
    try:
        writer.write(buffer)
    except Exception as exc:
        raise PdfOperationError(
            f"unable to serialize PDF output: {type(exc).__name__}"
        ) from exc
    payload = buffer.getvalue()
    if len(payload) > max_output_bytes:
        raise PdfOperationError(
            f"generated PDF exceeds output bound: {len(payload)} > {max_output_bytes}"
        )
    output_path.write_bytes(payload)
    return {
        "input_path": str(input_path),
        "output_path": str(output_path),
        "output_bytes": len(payload),
        "pages": len(pages),
        "mode": "modify_new_output",
    }
