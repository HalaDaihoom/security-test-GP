FROM owasp/zap2docker-stable

EXPOSE 8081

ENTRYPOINT ["zap.sh", "-daemon", "-host", "0.0.0.0", "-port", "8081", "-config", "api.disablekey=false", "-config", "api.key=4lnic55esp90ftfb1or8pvggd7"]
