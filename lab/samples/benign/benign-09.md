# Ops notes

- Bastion: `ssh deploy@10.0.4.12` (VPN required).
- Metrics dashboard: http://10.0.4.20:3000
- Logs are shipped to Loki; retention is 14 days.
- Restart a service with `sudo systemctl restart billing`.
