FROM python:3.12-alpine
WORKDIR /app
COPY server.py .
COPY static ./static
ENV PORT=8080
EXPOSE 8080
USER nobody
CMD ["python", "server.py"]
