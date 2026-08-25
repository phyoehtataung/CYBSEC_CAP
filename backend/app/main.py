from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from .config import APP_NAME, APP_VERSION, FRONTEND_DIST
from .database import Base, SessionLocal, engine
from .routers import cases, meta, reports, scans
from .seed import seed_if_empty

Base.metadata.create_all(bind=engine)

with SessionLocal() as db:
    seed_if_empty(db)

app = FastAPI(title=APP_NAME, version=APP_VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(meta.router)
app.include_router(cases.router)
app.include_router(scans.router)
app.include_router(reports.router)


@app.get("/api")
def root():
    return {
        "product": APP_NAME,
        "version": APP_VERSION,
        "contract": "shared/scan-result.schema.json",
    }


if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="ui")
else:

    @app.get("/")
    def ui_hint():
        return HTMLResponse(
            """
            <html><body style="font-family:sans-serif;background:#071018;color:#e9f2ea;padding:40px">
            <p>WebSET API is running.</p>
            <p>Open the dashboard at <a href="http://127.0.0.1:5173" style="color:#9ef2c3">http://127.0.0.1:5173</a></p>
            </body></html>
            """
        )
