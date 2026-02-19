# pcap-extractor

Extract UDP payload data from Wireshark `.pcapng` (or `.pcap`) capture files.

## Setup

```bash
uv sync
```

## Usage

```
uv run pcapx.py <capture.pcapng> [options]
```

### Options

| Flag | Description |
|------|-------------|
| `--frames START-END` | Frame range, e.g. `--frames 10-200` (1-based, Wireshark numbering) |
| `--frame-start N` | First frame to include (default: 1) |
| `--frame-end N` | Last frame to include (inclusive) |
| `--src-ip IP` | Filter by source IP address |
| `--dst-ip IP` | Filter by destination IP address |
| `--src-port PORT` | Filter by source UDP port |
| `--dst-port PORT` | Filter by destination UDP port |
| `--format / -f` | Output format: `hex` (default), `raw`, `json`, `text` |
| `--output / -o FILE` | Write to FILE instead of stdout |

### Output formats

- **`hex`** – annotated hex dump with frame metadata, one block per packet
- **`raw`** – concatenated raw binary payloads (pipe-friendly, use `-o file.bin`)
- **`json`** – JSON array; each element has `frame`, `src`, `dst`, `length`, `payload` (hex string)
- **`text`** – payloads decoded as UTF-8 (fallback to latin-1), one block per packet

Frame numbers match Wireshark's 1-based display numbering.

## Examples

```bash
# Hex dump of all UDP packets between frames 100 and 300
uv run pcapx.py capture.pcapng --frames 100-300

# All UDP traffic from a specific host, saved as JSON
uv run pcapx.py capture.pcapng --src-ip 192.168.1.10 --format json -o out.json

# Raw binary payloads on a specific port, saved to a file
uv run pcapx.py capture.pcapng --dst-port 5005 --format raw -o payloads.bin

# Text dump of a conversation between two hosts
uv run pcapx.py capture.pcapng \
    --src-ip 10.0.0.1 --dst-ip 10.0.0.2 \
    --frames 50-500 --format text
```
