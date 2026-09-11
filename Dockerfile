# Portable image: runs the dashboard in WSL/Docker today, on a 24/7 server later.
# Kali base ships the recon tooling (nmap, tshark) the AI uses.
FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv \
      nmap tshark whois dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .

EXPOSE 8000
# Bind 0.0.0.0 inside the container; map the port on the host side.
CMD ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
