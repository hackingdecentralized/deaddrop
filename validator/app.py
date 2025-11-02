from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import HTMLResponse, PlainTextResponse
from pathlib import Path
import shutil, uvicorn

app = FastAPI()
DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

HTML = """
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Validator</title></head>
  <body style="max-width:680px;margin:2rem auto;font-family:sans-serif;">
    <h1>Validator</h1>
    <form action="/run" method="post" enctype="multipart/form-data">
      <p><label>Contract Address:
        <input type="text" name="contract_addr" placeholder="0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413">
      </label></p>
      <p><label>Block Height:
        <input type="text" name="block_height" placeholder="1920000">
      </label></p>
      <p><input type="file" name="bug_condition"></p>
      <p><input type="file" name="bug_report"></p>
      <button type="submit">Run</button>
    </form>
  </body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML

async def save_if_nonempty(upload: UploadFile | None, dst: Path) -> str:
    """
    Overwrite dst only if `upload` is provided, has a non-empty filename,
    and the payload is non-empty. Otherwise keep existing file.
    """
    if upload is None or not (upload.filename or "").strip():
        return f"No file selected; kept existing {dst if dst.exists() else '(none)'}"

    # Peek 1 byte to detect empty uploads without truncating existing file
    first = await upload.read(1)
    if not first:
        return f"Empty upload; kept existing {dst if dst.exists() else '(none)'}"

    # Write first byte, then stream the rest
    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("wb") as out:
        out.write(first)
        while True:
            chunk = await upload.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)
    return f"Uploaded {upload.filename} -> {dst}"

@app.post("/run", response_class=PlainTextResponse)
async def run(
    bug_condition: UploadFile | None = File(None),
    bug_report: UploadFile | None = File(None),
    contract_addr: str = Form("0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413"),
    block_height: str = Form("1920000"),
):
    cond_path = DATA_DIR / "bug_cond.sol"
    rep_path  = DATA_DIR / "bug_report.sol"

    cond_status = await save_if_nonempty(bug_condition, cond_path)
    rep_status  = await save_if_nonempty(bug_report, rep_path)

    blk_file = DATA_DIR / "block.txt"
    addr_file = DATA_DIR / "addr.txt"
    blk_file.write_text(block_height.strip() + "\n", encoding="utf-8")
    addr_file.write_text(contract_addr.strip() + "\n", encoding="utf-8")

    summary = [
        cond_status,
        rep_status,
        f"Block file: {blk_file}",
        f"Addr file: {addr_file}",
        "(Ready to invoke Rust binary.)",
    ]
    return "\n".join(summary)

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8080)
