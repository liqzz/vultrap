FROM python:3.10.12 as base
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.2.6/nuclei_3.2.6_linux_amd64.zip
RUN unzip nuclei_3.2.6_linux_amd64.zip -d nuclei
RUN rm nuclei_3.2.6_linux_amd64.zip
RUN cp ./nuclei/nuclei /usr/local/bin/nuclei
RUN rm -rf ./nuclei
RUN chmod +x /usr/local/bin/nuclei
RUN nuclei -ut
COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt
COPY . /app/vultrap
RUN mkdir -p /data/log/vultrap
COPY ./docker/easyserver.py /app/easyserver.py
ENV PYTHONPATH=/app/vultrap/
ENTRYPOINT ["python3", "/app/vultrap/main.py"]
