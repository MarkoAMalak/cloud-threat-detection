docker build -f .\infra\docker\Dockerfile -t cloud-threat-detection-dashboard .
docker run --rm -p 8501:8501 cloud-threat-detection-dashboard