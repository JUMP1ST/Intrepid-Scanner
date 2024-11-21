import os
import shutil
import logging
import aiofiles
from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from starlette.staticfiles import StaticFiles

from scanners.trivy_fs_scanner import run_trivy_fs_scan
from scanners.trivy_image_scanner import run_trivy_image_scan
from scanners.trivy_repo_scanner import run_trivy_repo_scan
from scanners.clone_and_local_scan import scan_git_repository
from scanners.clamav_scanner import run_clamav_fs_scan
from scanners.grype_scanner import run_grype_image_scan
from scanners.syft_scanner import run_syft_sbom_scan
from scanners.yara_scanner import run_yara_scan
from utils.extract import extract_files
from utils.rezip import zip_directory

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --- Configuration ---
UPLOAD_FOLDER = "/app/uploads"
SCAN_RESULTS_FOLDER = "/app/scan-results"
YARA_RULES_FOLDER = "/app/yara_rules"
CLAMAV_SOCKET_DIR = "/var/run/clamav"

def ensure_directories():
    """Ensure necessary directories exist."""
    try:
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(SCAN_RESULTS_FOLDER, exist_ok=True)
        os.makedirs(YARA_RULES_FOLDER, exist_ok=True)
        os.makedirs(CLAMAV_SOCKET_DIR, exist_ok=True)
        logger.info("All directories created successfully.")
    except Exception as e:
        logger.error(f"Directory creation failed: {e}")
        raise

# Ensure directories are created
ensure_directories()

# --- FastAPI App Setup ---
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def get_index(request: Request):
    """Render the index page."""
    return templates.TemplateResponse("index.html", {"request": request, "scan_results": []})

@app.post("/scan/", response_class=HTMLResponse)
async def scan_file(
    request: Request,
    scan_type: str = Form(...),
    file: UploadFile = File(None),
    image_name: str = Form(None),
    repo_url: str = Form(None),
):
    """Handle scan requests."""
    scan_results = []

    try:
        if scan_type == "filesystem" and file:
            scan_results = await handle_filesystem_scan(file)
        elif scan_type == "image" and image_name:
            scan_results = await handle_image_scan(image_name)
        elif scan_type == "repo" and repo_url:
            scan_results = await handle_repo_scan(repo_url)
        else:
            raise HTTPException(status_code=400, detail="Invalid scan type or missing parameters.")
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise HTTPException(status_code=500, detail="Scan failed.")
    return templates.TemplateResponse("scan.html", {"request": request, "scan_results": scan_results})

# --- Helper Functions ---
async def handle_filesystem_scan(file: UploadFile):
    """Perform filesystem scans."""
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    extract_path = os.path.join(UPLOAD_FOLDER, "extracted")
    results = []

    try:
        # Save uploaded file
        async with aiofiles.open(file_path, "wb") as f:
            await f.write(await file.read())

        os.makedirs(extract_path, exist_ok=True)
        if extract_files(file_path, extract_path):
            # Run filesystem scans
            results.append(await run_trivy_fs_scan(extract_path))
            results.append(await run_yara_scan(extract_path))
            results.append(await run_clamav_fs_scan(extract_path))

            # Re-zip scanned files
            zip_file_path = os.path.join(UPLOAD_FOLDER, f"{file.filename}_scanned.zip")
            zip_directory(extract_path, zip_file_path)
            results.append({"path": zip_file_path, "scan_type": "Re-zipped Archive", "details": "Re-zipped after scan."})

        # Cleanup temporary files
        shutil.rmtree(extract_path)
        os.remove(file_path)
    except Exception as e:
        logger.error(f"Filesystem scan error: {e}")
        raise HTTPException(status_code=500, detail="Filesystem scan error.")
    return results

async def handle_image_scan(image_name: str):
    """Perform image scans."""
    try:
        return [
            await run_trivy_image_scan(image_name),
            await run_grype_image_scan(image_name),
            await run_syft_sbom_scan(image_name),
        ]
    except Exception as e:
        logger.error(f"Image scan error: {e}")
        raise HTTPException(status_code=500, detail="Image scan error.")

async def handle_repo_scan(repo_url: str):
    """Perform repository scans."""
    try:
        # Perform repository scans
        logger.info(f"Starting repository scan for: {repo_url}")
        results = await scan_git_repository(repo_url)  # Ensure the coroutine is awaited
        return results
    except Exception as e:
        logger.error(f"Repository scan error: {e}")
        raise HTTPException(status_code=500, detail="Repository scan error.")


# --- Main ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
