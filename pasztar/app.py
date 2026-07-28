from fastapi import FastAPI

from pasztar.routers import clients, health, messages

app = FastAPI(title="Pasztar")
app.include_router(health.router)
app.include_router(clients.router)
app.include_router(messages.router)
