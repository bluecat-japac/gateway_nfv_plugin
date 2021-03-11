FROM ubuntu:18.04

RUN apt-get update && \
    apt-get install python3.6 python3-pip -y

COPY common /common/
COPY memcached /memcached/
COPY statistics_collection /statistics_collection/
COPY /statistics_collection/statisticcollection /etc/init.d/statisticcollection

RUN chmod +x /etc/init.d/statisticcollection && \
    pip3 install -r /statistics_collection/requirements.txt && \
    echo "service statisticcollection start" >> /etc/bash.bashrc

CMD ["/bin/bash"]
