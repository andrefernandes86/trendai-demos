FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        tcpreplay tcpdump python3 python3-pip iproute2 ca-certificates \
    && python3 -m pip install --no-cache-dir rich requests \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /data
COPY *.py /data/
# Fetch the sample pcaps at build time (keeps them out of git). ~100 MB.
RUN python3 fetch_pcaps.py || echo "pcap fetch incomplete; run fetch_pcaps.py at runtime"
# Idle by default. A presenter triggers a replay explicitly, e.g.:
#   docker compose exec net-replay python3 replay_cron.py --iface ens18 --categories exploits,c2
# Requires network_mode host + NET_RAW/NET_ADMIN so packets egress the real NIC.
ENTRYPOINT ["sleep", "infinity"]
