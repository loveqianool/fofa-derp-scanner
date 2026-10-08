import json
import re
import argparse
from html.parser import HTMLParser
from statistics import median


MAX_LATENCY_MS = 100


class TableParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows = []
        self.row = None
        self.cell = None

    def handle_starttag(self, tag, attrs):
        if tag == 'tr':
            self.row = []
        elif tag == 'td' and self.row is not None:
            self.cell = []

    def handle_data(self, data):
        if self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag == 'td' and self.cell is not None:
            self.row.append(' '.join(''.join(self.cell).split()))
            self.cell = None
        elif tag == 'tr' and self.row:
            self.rows.append(self.row)
            self.row = None


def milliseconds(value):
    match = re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)(ns|us|µs|ms|s)', value)
    if not match:
        return None
    number, unit = match.groups()
    return float(number) * {'ns': 1e-6, 'us': 1e-3, 'µs': 1e-3, 'ms': 1, 's': 1000}[unit]


def process(html_file, json_file, output_file, start_region):
    # Load HTML
    with open(html_file, 'r', encoding='utf-8') as f:
        html_content = f.read()

    # Parse HTML and find all successful nodes
    parser = TableParser()
    parser.feed(html_content)

    # Track stable low-latency mesh regions and their latest latency
    successful_regions = {}

    # The structure has a row for each probe
    for tds in parser.rows:
        if len(tds) < 7:
            continue

        if not re.search(r'\bclass=(derp_udp|tls)\b', tds[1]) or tds[5].split()[0] != 'succeeded':
            continue

        results_match = re.search(r'Recent: \[([^]]*)\]', tds[5])
        recent_results = results_match.group(1).split() if results_match else []
        latency_match = re.search(r'Recent: \[([^]]*)\]', tds[6])
        recent_latencies = [milliseconds(value) for value in latency_match.group(1).split()] if latency_match else []
        latest_latency = milliseconds(tds[6].split()[0])
        region_match = re.search(r'region_id=(\d+)', tds[1])

        if (region_match and recent_results and all(result == 'true' for result in recent_results)
                and latest_latency is not None and recent_latencies and None not in recent_latencies
                and latest_latency < MAX_LATENCY_MS and median(recent_latencies) < MAX_LATENCY_MS):
            successful_regions[region_match.group(1)] = latest_latency

    print(f"Found {len(successful_regions)} successful region IDs")

    # Load original derp.json
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Filter the regions
    original_regions_count = len(data.get("Regions", {}))
    new_regions = {}

    regions = data.get("Regions", {})
    ordered_regions = (
        region_id
        for region_id in sorted(successful_regions, key=lambda region_id: (successful_regions[region_id], int(region_id)))
        if region_id in regions
    )
    for new_region_id, region_id in enumerate(ordered_regions, start_region):
        region = regions[region_id]
        region["RegionID"] = new_region_id
        region["RegionCode"] = f"custom{new_region_id}"
        for node in region.get("Nodes", []):
            node["RegionID"] = new_region_id
            if "Name" in node:
                node["Name"] = re.sub(r'^\d+-', f'{new_region_id}-', node["Name"])
        new_regions[str(new_region_id)] = region

    data["Regions"] = new_regions

    # Save to a new file
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    print(f"Original regions: {original_regions_count}")
    print(f"Filtered regions: {len(new_regions)}")
    print(f"Saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract successful DERP regions from HTML report.')
    parser.add_argument('--html', type=str, required=True, help='Path to the HTML file saved from DERP Prober')
    parser.add_argument('--json', type=str, required=True, help='Path to the original derp.json file')
    parser.add_argument('--output', type=str, default='derp-success-prober.json', help='Path for the output JSON file')
    parser.add_argument('--start', type=int, default=900, help='Start ID for renumbered regions')

    args = parser.parse_args()
    process(args.html, args.json, args.output, args.start)
