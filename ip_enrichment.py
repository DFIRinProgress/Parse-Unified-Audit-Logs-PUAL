import json
import requests
import time

class IPEnrichment:
    def load_config(self):
        try:
            with open('config.json', 'r') as file:
                config = json.load(file)
            return config['ipinfo']['token']
        except FileNotFoundError:
            raise FileNotFoundError("Configuration file 'config.json' is missing.")
        except KeyError:
            raise KeyError("Missing 'token' key in 'ipinfo' section of the configuration file.")

    def enrich_ip_information(self, unique_ips, enriched_ip_info, progress_bar, root):
        token = self.load_config()
        enriched_data = []

        for i, ip in enumerate(unique_ips):
            if ip in enriched_ip_info:
                enriched_data.append(enriched_ip_info[ip])
            else:
                response = requests.get(f"https://ipinfo.io/{ip}/json?token={token}")
                if response.status_code == 200:
                    data = response.json()
                    enrichment_info = {
                        "IP": ip,
                        "IPEnrichment_City": data.get("city", ""),
                        "IPEnrichment_Region": data.get("region", ""),
                        "IPEnrichment_Country": data.get("country", ""),
                        "IPEnrichment_Org": data.get("org", "")
                    }
                    enriched_ip_info[ip] = enrichment_info
                    enriched_data.append(enrichment_info)
                time.sleep(0.1)  # To avoid rate limiting

            # Update progress bar
            progress_bar["value"] = i + 1
            root.update_idletasks()

        return enriched_data
