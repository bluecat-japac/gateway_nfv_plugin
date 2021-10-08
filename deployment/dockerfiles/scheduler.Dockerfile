FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install python3-pip -y

COPY common /common/
COPY memcached /memcached/
COPY statistics_collection /statistics_collection/
COPY statistics_collection/statisticcollection /etc/init.d/statisticcollection

RUN chmod +x /etc/init.d/statisticcollection && \
    pip install -r /statistics_collection/requirements.txt && \
    echo "service statisticcollection start" >> /etc/bash.bashrc

CMD ["/bin/bash"]
