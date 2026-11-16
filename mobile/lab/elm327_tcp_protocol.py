"""Fixed ELM327 test replies for the authorized TCP fixture."""

# 注入的"车况"：改这里就能改对账值。注释里写清换算，便于人工核对。
PIDS = {
    "0100": "41 00 BE 1F A8 13",   # 支持的 PID 位图（01-20），注意别漏掉 41 00
    "0120": "41 20 80 08 00 01",   # 支持的 PID 位图（21-40）
    "0101": "41 01 00 07 E1 00",  # monitor status since DTC cleared
    "0103": "41 03 01",         # fuel system status: closed loop
    "0104": "41 04 53",         # 发动机负荷 0x53=83 → 83*100/255 = 32.5%
    "0105": "41 05 82",         # 冷却液 0x82=130 → 130-40 = 90 °C
    "0106": "41 06 80",         # 短期燃油修正 0x80=128 → 0%
    "0107": "41 07 7F",         # 长期燃油修正 0x7F=127 → -0.8%
    "010B": "41 0B 33",         # 进气压力 0x33=51 kPa
    "010C": "41 0C 1A F8",      # 转速 (256*0x1A+0xF8)/4 = 1726 rpm
    "010D": "41 0D 58",         # 车速 0x58 = 88 km/h
    "010E": "41 0E 80",         # 点火提前角 (128/2)-64 = 0°
    "010F": "41 0F 48",         # 进气温度 0x48=72 → 72-40 = 32 °C
    "0110": "41 10 01 2C",      # MAF (256*1+0x2C)/100 = 3.00 g/s
    "0111": "41 11 33",         # 节气门 0x33=51 → 20.0%
    "011F": "41 1F 0A F0",      # 运行时间 2800 s
    "0121": "41 21 00 64",      # 距故障灯 100 km
    "0133": "41 33 65",         # 大气压 101 kPa
    "0142": "41 42 37 98",      # 控制模块电压 0x3798/1000 = 14.232 V
    "0146": "41 46 5A",         # 环境温度 0x5A=90 → 50 °C
    "014C": "41 4C 00",         # 当前驾驶循环
    "0151": "41 51 01",         # 燃油类型：汽油
}

# 09 02（VIN）走 ISO-TP 多帧：ELM327 在 ATH0 下用 "0: / 1: / 2:" 行号格式回。
VIN = "WVWZZZ3CME0012345"


def vin_frames() -> list[str]:
    payload = bytes([0x49, 0x02, 0x01]) + VIN.encode()   # 49 02 01 + 17 字节
    head = f"{len(payload):03X}"                          # 014 = 20 字节
    rows, chunk = ["0: " + " ".join(f"{b:02X}" for b in payload[:6])], payload[6:]
    idx = 1
    while chunk:
        rows.append(f"{idx}: " + " ".join(f"{b:02X}" for b in chunk[:8]))
        chunk, idx = chunk[8:], idx + 1
    return [head] + rows


def with_headers(lines: list[str]) -> list[str]:
    """ATH1 时每条要带 ISO-TP 头。

    AndrOBD 的 ECU 探测序列是 `ATSP0 → ATH1 → 0100 → ATH0`：那一步**要**看
    `7E8 06 41 00 …` 才知道 ECU 地址。只回裸 `41 00 …` 会让它以为没找到 ECU，
    反复重发 0100（2026-11-15 实测：窗口内 688 条全是 0100）。
    """
    out = []
    for line in lines:
        body = line.split()
        if len(body) >= 2 and all(len(b) == 2 for b in body):
            out.append(f"7E8 {len(body):02X} " + " ".join(body))
        else:
            out.append(line)
    return out


def vin_iso_tp() -> list[str]:
    """09 02 在 ATH1 下的 ISO-TP 形式：首帧 10 14 + 前 6 字节，后续 21/22 帧。"""
    payload = bytes([0x49, 0x02, 0x01]) + VIN.encode()
    rows = [f"7E8 10 {len(payload):02X} " + " ".join(f"{b:02X}" for b in payload[:6])]
    rest, seq = payload[6:], 0x21
    while rest:
        rows.append(f"7E8 {seq:02X} " + " ".join(f"{b:02X}" for b in rest[:7]))
        rest, seq = rest[7:], seq + 1
    return rows


AT_REPLIES = {
    "ATZ": "ELM327 v1.5",
    "ATI": "ELM327 v1.5",
    "AT@1": "OBDII to RS232 Interpreter",
    "AT@2": "?",
    "ATRV": "12.6V",
    "ATDP": "AUTO, ISO 15765-4 (CAN 11/500)",
    "ATDPN": "A6",
    "ATSP0": "OK",
    "ATSP3": "OK",
    "ATSP6": "OK",
    "ATE0": "OK",
    "ATE1": "OK",
    "ATL0": "OK",
    "ATL1": "OK",
    "ATS0": "OK",
    "ATS1": "OK",
    "ATH0": "OK",
    "ATH1": "OK",
    "ATAL": "OK",
    "ATST": "OK",
    "ATAT": "OK",
    "ATAT0": "OK",
    "ATAT1": "OK",
    "ATAT2": "OK",
    "ATSH": "OK",
    "ATCRA": "OK",
    "ATKW": "OK",
    "ATKW0": "OK",
    "ATSW": "OK",
    "ATIB": "OK",
    "ATIB10": "OK",
    "ATIIA": "OK",
    "ATWM": "OK",
    "ATSI": "OK",
    "ATSR": "OK",
    "ATBI": "OK",
    "ATTA": "OK",
    "ATFE": "OK",
    "ATFI": "OK",
    "ATCV": "OK",
    "ATPP": "OK",
    "ATBD": "OK",
    "ATD": "OK",
    "ATAMC": "OK",
    "ATAMT": "OK",
    "ATDM1": "OK",
    "ATIGN": "ON",
}


def normalise(cmd: str) -> str:
    return cmd.replace(" ", "").replace("\t", "").upper()


def reply_for(cmd: str, headers: bool = False) -> list[str] | None:
    """返回要发的行；None 表示这条不认，回 '?'（ELM 的真实行为）。"""
    key = normalise(cmd)
    if not key:
        return None
    if key.startswith("AT"):
        if key in AT_REPLIES:
            return [AT_REPLIES[key]]
        for prefix in ("ATST", "ATSH", "ATSW", "ATIB", "ATIIA", "ATCRA", "ATKW", "ATWM", "ATCV", "ATPP"):
            if key.startswith(prefix):
                return ["OK"]
        return ["?"]
    if key.startswith("09") and (key.startswith("0902") or len(key) == 2):
        if not key.startswith("0902"):
            return ["NO DATA"] if not headers else with_headers(["NO DATA"])
        return vin_iso_tp() if headers else ["014", *vin_frames()[1:]]
    if key == "03":
        return with_headers(["43 00"]) if headers else ["43 00"]   # 无故障码
    if key == "04":
        return with_headers(["44"]) if headers else ["44"]          # 清除故障码
    # 01xx：可能一次问多个 PID（010C0D），逐个拼回去
    if key.startswith("01") and len(key) >= 4:
        out = []
        body = key[2:]
        for i in range(0, len(body) - 1, 2):
            pid = "01" + body[i:i + 2]
            line = PIDS.get(pid)
            if line:
                out.append(line)
        if not out:
            return with_headers(["NO DATA"]) if headers else ["NO DATA"]
        return with_headers(out) if headers else out
    return ["?"]
