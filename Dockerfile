FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y nmap php && rm -rf /var/lib/apt/lists/*
COPY index.php .
COPY nmap.cls.php .
EXPOSE 8080
CMD [ "php", "-S", "0.0.0.0:8080", "index.php" ]