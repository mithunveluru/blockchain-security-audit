FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY blockaudit ./blockaudit
COPY static ./static
COPY adaptive_merkle_tree.py integrity_monitor.py ml_anomaly_detector.py network_flow_analyzer.py network_packet_analyzer.py wsgi.py gunicorn.conf.py ./
RUN useradd --system --uid 10001 --home-dir /app blockaudit && mkdir /data && chown blockaudit /data
USER blockaudit
ENV BLOCKAUDIT_ENV=production HOST=0.0.0.0 PORT=5000 DATA_DIR=/data CHAIN_FILE=/data/network_blockchain.json
VOLUME /data
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s CMD python -c "import urllib.request,os,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','5000')+'/readyz', timeout=2).status==200 else 1)"
CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:app"]
