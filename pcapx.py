#!/usr/bin/env python3
"""
UDP payload extractor for Wireshark .pcapng/.pcap captures.

Usage:
    uv run pcapx.py <file.pcapng> [options]

Examples:
    uv run pcapx.py capture.pcapng --frame-start 10 --frame-end 50
    uv run pcapx.py capture.pcapng --src-ip 192.168.1.5 --format json -o out.json
    uv run pcapx.py capture.pcapng --frames 100-200 --dst-port 5005 --format raw -o payload.bin
"""

import argparse
import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract UDP payload data from a .pcapng or .pcap capture file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument("pcap_file", help="Path to the capture file (.pcapng or .pcap)")

    # Frame range – two styles accepted
    range_group = parser.add_argument_group("frame range (mutually exclusive styles)")
    me = range_group.add_mutually_exclusive_group()
    me.add_argument(
        "--frames",
        metavar="START-END",
        help="Frame range as 'START-END', e.g. --frames 10-200 (1-based, inclusive, Wireshark numbering)",
    )
    me.add_argument(
        "--frame-start",
        type=int,
        metavar="N",
        help="First frame to include (1-based). May be combined with --frame-end.",
    )
    range_group.add_argument(
        "--frame-end",
        type=int,
        metavar="N",
        help="Last frame to include (1-based, inclusive). Requires --frame-start or used with default start=1.",
    )

    # Endpoint filters
    flt = parser.add_argument_group("endpoint filters")
    flt.add_argument("--src-ip",   metavar="IP",   help="Keep only packets with this source IP")
    flt.add_argument("--dst-ip",   metavar="IP",   help="Keep only packets with this destination IP")
    flt.add_argument("--src-port", metavar="PORT", type=int, help="Keep only packets with this source UDP port")
    flt.add_argument("--dst-port", metavar="PORT", type=int, help="Keep only packets with this destination UDP port")

    # Output
    out = parser.add_argument_group("output")
    out.add_argument(
        "--format", "-f",
        choices=["hex", "raw", "json", "text"],
        default="hex",
        help=(
            "Output format  (default: hex)\n"
            "  hex  – annotated hex dump, one block per packet\n"
            "  raw  – concatenated raw binary payloads\n"
            "  json – JSON array with frame metadata and hex payload\n"
            "  text – payload decoded as UTF-8 (falls back to latin-1)"
        ),
    )
    out.add_argument("--output", "-o", metavar="FILE", help="Write output to FILE instead of stdout")

    return parser.parse_args()


def resolve_frame_range(args: argparse.Namespace) -> tuple[int, int | None]:
    """Return (frame_start, frame_end) from the various argument forms."""
    if args.frames:
        parts = args.frames.split("-", 1)
        if len(parts) != 2 or not all(p.isdigit() for p in parts):
            print("Error: --frames must be in the form START-END, e.g. 10-200", file=sys.stderr)
            sys.exit(1)
        return int(parts[0]), int(parts[1])
    start = args.frame_start if args.frame_start is not None else 1
    end = args.frame_end  # may be None (= read to end of file)
    return start, end


# ---------------------------------------------------------------------------
# Packet reading & filtering
# ---------------------------------------------------------------------------

def extract_udp_packets(
    pcap_file: Path,
    frame_start: int,
    frame_end: int | None,
    src_ip: str | None,
    dst_ip: str | None,
    src_port: int | None,
    dst_port: int | None,
) -> list[dict]:
    """
    Read the capture file and return a list of matching UDP packet records.

    Each record is a dict with keys:
        frame, src_ip, dst_ip, src_port, dst_port, length, payload (bytes)
    """
    # Import here so startup is fast even if scapy prints its banner
    from scapy.all import PcapNgReader, PcapReader, IP, IPv6, UDP  # type: ignore

    results: list[dict] = []

    # Choose reader based on file extension
    suffix = pcap_file.suffix.lower()
    if suffix == ".pcapng":
        reader_cls = PcapNgReader
    else:
        reader_cls = PcapReader  # handles plain .pcap

    print(f"Reading: {pcap_file}", file=sys.stderr)

    with reader_cls(str(pcap_file)) as reader:
        frame_num = 0
        for pkt in reader:
            frame_num += 1

            # ---- frame-range filter ----
            if frame_num < frame_start:
                continue
            if frame_end is not None and frame_num > frame_end:
                break  # file is sequential; we're done

            # ---- must be UDP ----
            if not pkt.haslayer(UDP):
                continue

            udp = pkt[UDP]

            # ---- IP layer (v4 or v6) ----
            if pkt.haslayer(IP):
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
            elif pkt.haslayer(IPv6):
                ip_src = pkt[IPv6].src
                ip_dst = pkt[IPv6].dst
            else:
                continue  # no IP layer – skip

            # ---- endpoint filters ----
            if src_ip   and ip_src      != src_ip:   continue
            if dst_ip   and ip_dst      != dst_ip:   continue
            if src_port and udp.sport   != src_port: continue
            if dst_port and udp.dport   != dst_port: continue

            payload = bytes(udp.payload)

            results.append(
                dict(
                    frame=frame_num,
                    src_ip=ip_src,
                    dst_ip=ip_dst,
                    src_port=udp.sport,
                    dst_port=udp.dport,
                    length=len(payload),
                    payload=payload,
                )
            )

    return results


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _hex_dump(data: bytes, width: int = 16) -> str:
    lines: list[str] = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part  = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:08x}  {hex_part:<{width * 3}}  |{ascii_part}|")
    return "\n".join(lines)


def write_hex(packets: list[dict], out) -> None:
    for p in packets:
        out.write(
            f"Frame {p['frame']:>6}:  "
            f"{p['src_ip']}:{p['src_port']}  ->  "
            f"{p['dst_ip']}:{p['dst_port']}  "
            f"({p['length']} bytes)\n"
        )
        if p["payload"]:
            out.write(_hex_dump(p["payload"]))
        else:
            out.write("  (empty payload)")
        out.write("\n\n")


def write_json(packets: list[dict], out) -> None:
    records = [
        {
            "frame":    p["frame"],
            "src":      f"{p['src_ip']}:{p['src_port']}",
            "dst":      f"{p['dst_ip']}:{p['dst_port']}",
            "length":   p["length"],
            "payload":  p["payload"].hex(),
        }
        for p in packets
    ]
    json.dump(records, out, indent=2)
    out.write("\n")


def write_raw(packets: list[dict], out_binary) -> None:
    for p in packets:
        out_binary.write(p["payload"])


def write_text(packets: list[dict], out) -> None:
    for p in packets:
        out.write(
            f"=== Frame {p['frame']}: "
            f"{p['src_ip']}:{p['src_port']} -> "
            f"{p['dst_ip']}:{p['dst_port']} "
            f"({p['length']} bytes) ===\n"
        )
        try:
            text = p["payload"].decode("utf-8")
        except UnicodeDecodeError:
            text = p["payload"].decode("latin-1")
        out.write(text)
        if not text.endswith("\n"):
            out.write("\n")
        out.write("\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    pcap_file = Path(args.pcap_file)
    if not pcap_file.exists():
        print(f"Error: file not found: {pcap_file}", file=sys.stderr)
        sys.exit(1)

    frame_start, frame_end = resolve_frame_range(args)

    # Describe what we're doing
    range_desc = f"frames {frame_start}–{frame_end if frame_end else 'end'}"
    filters = [
        f for f in [
            f"src-ip={args.src_ip}"     if args.src_ip   else None,
            f"dst-ip={args.dst_ip}"     if args.dst_ip   else None,
            f"src-port={args.src_port}" if args.src_port else None,
            f"dst-port={args.dst_port}" if args.dst_port else None,
        ] if f
    ]
    filter_desc = (", ".join(filters)) if filters else "no endpoint filter"
    print(f"Extracting UDP payloads  [{range_desc}]  [{filter_desc}]", file=sys.stderr)

    packets = extract_udp_packets(
        pcap_file,
        frame_start, frame_end,
        args.src_ip, args.dst_ip,
        args.src_port, args.dst_port,
    )

    # Summary
    total_bytes = sum(p["length"] for p in packets)
    print(
        f"Matched {len(packets)} UDP packet(s), {total_bytes} payload byte(s) total.",
        file=sys.stderr,
    )

    if not packets:
        sys.exit(0)

    # Dispatch output
    fmt = args.format
    out_path = args.output

    if fmt == "raw":
        if out_path:
            with open(out_path, "wb") as f:
                write_raw(packets, f)
            print(f"Wrote raw binary -> {out_path}", file=sys.stderr)
        else:
            write_raw(packets, sys.stdout.buffer)
    else:
        writers = {"hex": write_hex, "json": write_json, "text": write_text}
        if out_path:
            with open(out_path, "w", encoding="utf-8") as f:
                writers[fmt](packets, f)
            print(f"Wrote {fmt} output -> {out_path}", file=sys.stderr)
        else:
            writers[fmt](packets, sys.stdout)


if __name__ == "__main__":
    main()
