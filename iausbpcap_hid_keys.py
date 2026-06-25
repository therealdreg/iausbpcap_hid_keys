#!/usr/bin/env python3
"""
iausbpcap_hid_keys.py

therealdreg - MIT LICENSE
https://github.com/therealdreg/iausbpcap_hid_keys

Extracts HID keyboard keystrokes from a capture made with USBPcap.

Reads the pcap/pcapng, locates the keyboard HID reports (8-byte interrupt IN
transfers), decodes them to text, and prints at the end of the whole capture:
  1) The complete sequence of pressed keys.
  2) The reconstructed text (applying Backspace, Shift and Caps Lock).

No external dependencies: it parses the pcap/pcapng container and the USBPcap
header directly.

Usage:
    python3 iausbpcap_hid_keys.py capture.pcap
    python3 iausbpcap_hid_keys.py capture.pcapng -v
    python3 iausbpcap_hid_keys.py capture.pcap --device 2
    python3 iausbpcap_hid_keys.py capture.pcap --all-devices

A note on the layout: the key table assumes a US layout, which is the usual
convention in USB forensic analysis. The HID report carries the physical key
code (Usage ID), not the final character, which depends on the operating
system layout. A Spanish keyboard using AltGr (for example AltGr+2 = @) would
need a dedicated ES table.
"""

import sys
import struct
import argparse
from collections import OrderedDict


HID_KEYS = {
    0x04: ('a', 'A'), 0x05: ('b', 'B'), 0x06: ('c', 'C'), 0x07: ('d', 'D'),
    0x08: ('e', 'E'), 0x09: ('f', 'F'), 0x0A: ('g', 'G'), 0x0B: ('h', 'H'),
    0x0C: ('i', 'I'), 0x0D: ('j', 'J'), 0x0E: ('k', 'K'), 0x0F: ('l', 'L'),
    0x10: ('m', 'M'), 0x11: ('n', 'N'), 0x12: ('o', 'O'), 0x13: ('p', 'P'),
    0x14: ('q', 'Q'), 0x15: ('r', 'R'), 0x16: ('s', 'S'), 0x17: ('t', 'T'),
    0x18: ('u', 'U'), 0x19: ('v', 'V'), 0x1A: ('w', 'W'), 0x1B: ('x', 'X'),
    0x1C: ('y', 'Y'), 0x1D: ('z', 'Z'),
    0x1E: ('1', '!'), 0x1F: ('2', '@'), 0x20: ('3', '#'), 0x21: ('4', '$'),
    0x22: ('5', '%'), 0x23: ('6', '^'), 0x24: ('7', '&'), 0x25: ('8', '*'),
    0x26: ('9', '('), 0x27: ('0', ')'),
    0x28: ('\n', '\n'),
    0x2B: ('\t', '\t'),
    0x2C: (' ', ' '),
    0x2D: ('-', '_'), 0x2E: ('=', '+'), 0x2F: ('[', '{'), 0x30: (']', '}'),
    0x31: ('\\', '|'), 0x32: ('#', '~'), 0x33: (';', ':'), 0x34: ("'", '"'),
    0x35: ('`', '~'), 0x36: (',', '<'), 0x37: ('.', '>'), 0x38: ('/', '?'),
    0x54: ('/', '/'), 0x55: ('*', '*'), 0x56: ('-', '-'), 0x57: ('+', '+'),
    0x58: ('\n', '\n'), 0x59: ('1', '1'), 0x5A: ('2', '2'), 0x5B: ('3', '3'),
    0x5C: ('4', '4'), 0x5D: ('5', '5'), 0x5E: ('6', '6'), 0x5F: ('7', '7'),
    0x60: ('8', '8'), 0x61: ('9', '9'), 0x62: ('0', '0'), 0x63: ('.', '.'),
}

HID_NAMES = {
    0x28: 'ENTER', 0x29: 'ESC', 0x2A: 'BACKSPACE', 0x2B: 'TAB',
    0x2C: 'SPACE', 0x39: 'CAPSLOCK',
    0x3A: 'F1', 0x3B: 'F2', 0x3C: 'F3', 0x3D: 'F4', 0x3E: 'F5', 0x3F: 'F6',
    0x40: 'F7', 0x41: 'F8', 0x42: 'F9', 0x43: 'F10', 0x44: 'F11', 0x45: 'F12',
    0x46: 'PRINTSCREEN', 0x47: 'SCROLLLOCK', 0x48: 'PAUSE',
    0x49: 'INSERT', 0x4A: 'HOME', 0x4B: 'PAGEUP', 0x4C: 'DELETE',
    0x4D: 'END', 0x4E: 'PAGEDOWN', 0x4F: 'RIGHT', 0x50: 'LEFT',
    0x51: 'DOWN', 0x52: 'UP', 0x53: 'NUMLOCK',
}

MOD_SHIFT = 0x02 | 0x20
MOD_CTRL  = 0x01 | 0x10
MOD_ALT   = 0x04 | 0x40
MOD_GUI   = 0x08 | 0x80

XFER_ISOCH, XFER_INTERRUPT, XFER_CONTROL, XFER_BULK = 0, 1, 2, 3

LINKTYPE_USBPCAP = 249


def iter_packets(path):
    with open(path, 'rb') as f:
        raw = f.read()
    if len(raw) < 4:
        raise ValueError("File too small to be a pcap")
    magic = raw[0:4]
    if magic == b'\x0a\x0d\x0d\x0a':
        yield from iter_pcapng(raw)
    elif magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
        yield from iter_pcap_classic(raw, '<')
    elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
        yield from iter_pcap_classic(raw, '>')
    else:
        raise ValueError(
            "Unrecognized format (magic=%s). It does not look like pcap or pcapng."
            % magic.hex())


def iter_pcap_classic(raw, en):
    if len(raw) < 24:
        return
    linktype = struct.unpack_from(en + 'I', raw, 20)[0]
    off, n = 24, len(raw)
    while off + 16 <= n:
        _, _, incl, _ = struct.unpack_from(en + 'IIII', raw, off)
        off += 16
        if off + incl > n:
            break
        yield linktype, raw[off:off + incl]
        off += incl


def iter_pcapng(raw):
    if len(raw) < 12 or raw[0:4] != b'\x0a\x0d\x0d\x0a':
        raise ValueError("Not a valid pcapng")
    bom = raw[8:12]
    if bom == b'\x4d\x3c\x2b\x1a':
        en = '<'
    elif bom == b'\x1a\x2b\x3c\x4d':
        en = '>'
    else:
        raise ValueError("Unknown byte-order magic in the pcapng")
    off, n, linktype = 0, len(raw), None
    while off + 12 <= n:
        btype = struct.unpack_from(en + 'I', raw, off)[0]
        blen = struct.unpack_from(en + 'I', raw, off + 4)[0]
        if blen < 12 or off + blen > n:
            break
        body = raw[off + 8: off + blen - 4]
        if btype == 0x00000001:
            if len(body) >= 2:
                linktype = struct.unpack_from(en + 'H', body, 0)[0]
        elif btype == 0x00000006:
            if len(body) >= 20:
                cap_len = struct.unpack_from(en + 'I', body, 12)[0]
                yield linktype, body[20:20 + cap_len]
        elif btype == 0x00000003:
            if len(body) >= 4:
                orig = struct.unpack_from(en + 'I', body, 0)[0]
                yield linktype, body[4:4 + orig]
        off += blen


def parse_usbpcap(data):
    if len(data) < 27:
        return None
    header_len = struct.unpack_from('<H', data, 0)[0]
    if header_len < 27 or header_len > len(data):
        return None
    info_byte = data[16]
    bus = struct.unpack_from('<H', data, 17)[0]
    device = struct.unpack_from('<H', data, 19)[0]
    endpoint = data[21]
    transfer = data[22]
    data_length = struct.unpack_from('<I', data, 23)[0]
    payload = data[header_len:header_len + data_length]
    return {
        'transfer': transfer,
        'endpoint': endpoint,
        'from_device': bool(info_byte & 0x01),
        'bus': bus,
        'device': device,
        'payload': payload,
    }


def _key_label(code, ch):
    name = HID_NAMES.get(code)
    if name:
        return '[%s]' % name
    return ch


def decode_device(reports, apply_backspace=True, verbose=False):
    """
    Decodes a list of reports (bytes) using the diff method: only the keys that
    appear in a report and were not present in the previous one are counted.
    This way auto-repeats and duplicated reports are ignored.
    Returns (reconstructed_text, token_list, printable_count).
    """
    prev = set()
    caps = False
    text = []
    seq = []
    printable = 0

    for idx, raw in enumerate(reports):
        if len(raw) == 9:
            raw = raw[1:]
        if len(raw) < 8:
            continue
        modifier = raw[0]
        shift = bool(modifier & MOD_SHIFT)
        current = [c for c in raw[2:8] if c != 0x00]

        new_tokens = []
        for code in current:
            if code in prev:
                continue

            if code == 0x39:
                caps = not caps
                seq.append('[CAPSLOCK]')
                new_tokens.append('[CAPSLOCK]')
                continue
            if code == 0x2A:
                if apply_backspace and text:
                    text.pop()
                seq.append('[BACKSPACE]')
                new_tokens.append('[BACKSPACE]')
                continue

            if code in HID_KEYS:
                normal, shifted = HID_KEYS[code]
                is_letter = len(normal) == 1 and normal.isalpha()
                eff_shift = (shift != caps) if is_letter else shift
                ch = shifted if eff_shift else normal
                text.append(ch)
                printable += 1
                tok = _key_label(code, ch)
                seq.append(tok)
                new_tokens.append(tok)
            elif code in HID_NAMES:
                tok = '[%s]' % HID_NAMES[code]
                seq.append(tok)
                new_tokens.append(tok)
            else:
                tok = '[0x%02X]' % code
                seq.append(tok)
                new_tokens.append(tok)

        if verbose:
            mods = []
            if modifier & MOD_CTRL:  mods.append('Ctrl')
            if modifier & MOD_SHIFT: mods.append('Shift')
            if modifier & MOD_ALT:   mods.append('Alt')
            if modifier & MOD_GUI:   mods.append('Gui')
            mod_str = '+'.join(mods) if mods else '-'
            hexrep = ' '.join('%02x' % b for b in raw[:8])
            out = ' '.join(new_tokens) if new_tokens else '(no new key)'
            print("    [%04d] %s | mod=%-14s | %s" % (idx, hexrep, mod_str, out))

        prev = set(current)

    return ''.join(text), seq, printable


def main():
    print("David Reguera Garcia aka Dreg - dreg@rootkit.es - MIT LICENSE")
    print("https://github.com/therealdreg/iausbpcap_hid_keys")
    ap = argparse.ArgumentParser(
        description="Extract HID keyboard keystrokes from a USBPcap capture.")
    ap.add_argument('pcap', help=".pcap or .pcapng file captured with USBPcap")
    ap.add_argument('-d', '--device', type=int, default=None,
                    help="Process only this device address (number)")
    ap.add_argument('-a', '--all-devices', action='store_true',
                    help="Process all detected devices")
    ap.add_argument('-v', '--verbose', action='store_true',
                    help="Show each report in hexadecimal")
    ap.add_argument('--no-backspace', action='store_true',
                    help="Do not apply Backspace to the reconstructed text")
    args = ap.parse_args()

    groups = OrderedDict()
    total_pkts = usb_pkts = other_linktype = 0

    try:
        for linktype, pkt in iter_packets(args.pcap):
            total_pkts += 1
            if linktype != LINKTYPE_USBPCAP:
                other_linktype += 1
                continue
            info = parse_usbpcap(pkt)
            if not info:
                continue
            usb_pkts += 1
            direction_in = info['from_device'] or bool(info['endpoint'] & 0x80)
            if (info['transfer'] == XFER_INTERRUPT and direction_in
                    and len(info['payload']) in (8, 9)):
                key = (info['bus'], info['device'], info['endpoint'])
                groups.setdefault(key, []).append(info['payload'])
    except (OSError, ValueError) as e:
        print("[!] Error reading the capture: %s" % e, file=sys.stderr)
        sys.exit(1)

    print("[*] File            : %s" % args.pcap)
    print("[*] Total packets   : %d" % total_pkts)
    print("[*] USBPcap packets : %d" % usb_pkts)
    if other_linktype:
        print("[!] %d packets with a linktype other than USBPcap (ignored)."
              % other_linktype)

    if not groups:
        print("\n[!] No keyboard reports found "
              "(8-byte interrupt IN). "
              "Check that the capture comes from USBPcap and contains a keyboard.")
        sys.exit(0)

    decoded = OrderedDict()
    for key, reports in groups.items():
        text, seq, printable = decode_device(
            reports, apply_backspace=not args.no_backspace, verbose=False)
        decoded[key] = (text, seq, printable, len(reports))

    print("\n[*] Devices with keyboard-like traffic:")
    for (bus, dev, ep), (_, _, printable, nrep) in decoded.items():
        print("      bus=%d device=%d ep=0x%02x -> %d reports, %d printable keys"
              % (bus, dev, ep, nrep, printable))

    if args.device is not None:
        targets = [k for k in decoded if k[1] == args.device]
        if not targets:
            print("\n[!] There is no device with device address %d."
                  % args.device)
            sys.exit(0)
    elif args.all_devices:
        targets = list(decoded.keys())
    else:
        best = max(decoded, key=lambda k: decoded[k][2])
        targets = [best]
        b, d, e = best
        print("\n[*] Keyboard detected : bus=%d device=%d ep=0x%02x" % (b, d, e))

    for key in targets:
        bus, dev, ep = key
        reports = groups[key]
        print("\n" + "=" * 64)
        print("DEVICE  bus=%d device=%d ep=0x%02x  (%d reports)"
              % (bus, dev, ep, len(reports)))
        print("=" * 64)

        if args.verbose:
            print("\n--- Reports ---")
            text, seq, _ = decode_device(
                reports, apply_backspace=not args.no_backspace, verbose=True)
        else:
            text, seq, _ = decoded[key][0], decoded[key][1], None

        print("\n--- Sequence of pressed keys ---")
        print(' '.join(seq) if seq else "(none)")

        print("\n--- Reconstructed text%s ---"
              % ("" if not args.no_backspace else " (Backspace not applied)"))
        print(text if text else "(empty)")

    print("\n" + "=" * 64)
    print("End of pcap.")


if __name__ == '__main__':
    main()
