# Network PCAP replay (Demo Center)

Replays benign and malicious sample traffic out a real host NIC with `tcpreplay`,
so a Trend Vision One Network Security sensor (NDR / Deep Discovery Inspector /
TippingPoint) on that segment detects it. Vendored from `demo-v1ns-pcap-replay`.

- Enabled only with the `attack-sim` Compose profile.
- Runs with `network_mode: host` and `NET_RAW` / `NET_ADMIN` so packets egress
  the physical interface. Idle until a replay is triggered:

  ```
  docker compose exec net-replay python3 replay_cron.py --iface <nic> --categories all
  ```

Set the replay interface in the Demo Center under **Settings → Demo infrastructure**.
The sample pcaps are fetched at image build (~100 MB) and are not committed.
