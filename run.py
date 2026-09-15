import uvicorn

from app.config import bind_host, bind_port

if __name__ == "__main__":
    uvicorn.run("app.main:app", host=bind_host(), port=bind_port(), reload=False)
