FROM python:3.12-alpine
WORKDIR /app
COPY server.py .
COPY static ./static
ENV RULES_FILE=/data/iptables.rules PORT=8080
EXPOSE 8080
USER nobody:nogroup
CMD ["python", "server.py"]
