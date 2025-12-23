# Python 3.12 Slim versiyonunu kullanıyoruz (Hafif ve hızlı)
FROM python:3.12-slim

# Gereksiz .pyc dosyalarını engelle ve logları anlık göster
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Çalışma dizinini ayarla
WORKDIR /app

# Önce gereksinimleri kopyala ve kur (Cache performansı için)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Şimdi tüm proje kodlarını kopyala
COPY . /app

# 8000 portunu dışarı aç
EXPOSE 8000

# Server'ı başlat
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]