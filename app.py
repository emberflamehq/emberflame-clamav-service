from fastapi import FastAPI, File, UploadFile
import subprocess as sp
from pydantic import BaseModel
from typing import Optional
import shutil
import uuid
import os

app = FastAPI()

class ClamAV(BaseModel):
    vendor: str = ""
    infected: Optional[bool] = None
    result: Optional[str] = ""
    engine: Optional[str] = ""
    known: Optional[str] = ""
    updated: Optional[str] = ""
    error: Optional[str] = ""

def sanitize_filename(filename: str) -> str:
    # Replace spaces with underscores
    return filename.replace(" ", "_")

@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.post("/scan", response_model=ClamAV)
def scan(malware: UploadFile = File(...)) -> ClamAV:
    try:
        clamav = ClamAV()
        clamav.vendor = "ClamAV"
        sanitized_filename = sanitize_filename(malware.filename)
        file_location = f"/malware/{uuid.uuid4()}-{sanitized_filename}"
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(malware.file, buffer)
        output = sp.getoutput(f"clamdscan {file_location}")
        version_output = sp.getoutput(f"clamdscan --version")
        # Split the string by spaces and get the second element
        parts = version_output.split()
        if len(parts) >= 2:
            version = parts[1].split('/')[0]
            clamav.engine = version
        else:
            clamav.engine = "Version not found"
        result = output
        result_line_arr = result.split('\n')
        virus_result = result_line_arr[0].split(": ")[1].replace(" FOUND", "") or ""
        clamav.result = virus_result
        clamav.infected = "FOUND" in result_line_arr[0]
        
        for line in result.splitlines():
            if "Known viruses:" in line:
                clamav.known = line.split(": ")[1]
            if "Engine version:" in line:
                print("engine", line)
                clamav.engine = line.split(": ")[1]
        os.remove(file_location)
        return clamav
    except Exception as e:
        print(e)
        return {"error": str(e)}, 500

@app.get("/update") 
async def update():
    try:
        output = sp.getoutput('freshclam')
        print(output)
        return {"status": 200, "message": output}
    except Exception as e:
        return {"status": 500, "message": str(e)}
    return {"status": 200}
