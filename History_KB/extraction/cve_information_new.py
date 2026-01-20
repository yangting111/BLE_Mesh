"""
fetch_protocol_cves_enhanced.py

Requirements:
    pip install nvdlib

Usage:
    python cve_information_new.py \
        --out_all all_protocol_like_cves.csv \
        --out_core protocol_core_cves.csv \
        --since_days 3650 \
        --api_key YOUR_NVD_API_KEY
"""

import nvdlib
import argparse
import time
import csv
import os
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

# ---------- Config: implementation lists (protocol -> impl keywords / cpe keywords) ----------
PROTOCOL_IMPLS = {
    "TLS/DTLS": [
        "openssl", "mbedtls", "gnutls", "libressl", "boringssl",
        "wolfssl", "nss", "s2n", "polarssl"
    ],
    "SSH": ["openssh", "libssh", "libssh2", "dropbear", "putty", "paramiko"],
    "HTTP": ["apache:http_server", "nginx", "lighttpd", "curl", "libcurl"],
    "MQTT": ["mosquitto", "eclipse paho", "emqx", "vernemq", "mqtt.js"],
    "CoAP": ["libcoap", "aiocoap", "californium", "microcoap"],
    "IP/ICMP/ARP": ["linux kernel", "freebsd", "lwip", "uip"],
    "Wi-Fi": ["wpa_supplicant", "hostapd", "iwlwifi", "broadcom"],
    "BT/BLE": ["bluez", "zephyr", "esp-idf", "mynewt", "nrfconnect", "realtek", "ti"],
    "ZigBee": ["z-stack", "zigpy", "silabs", "ti zigbee", "contiki"]
}

# Keywords to use in Path B broadly (protocol names + useful tokens)
GLOBAL_KEYWORDS = [
    "TLS", "DTLS", "SSL", "SSH", "HTTP", "MQTT", "CoAP",
    "Wi-Fi", "802.11", "Bluetooth", "BLE", "ZigBee", "ICMP", "ARP", "IP"
]

# ---------- 增强过滤规则 ----------
CORE_PROTOCOL_TERMS = [
    "handshake", "state machine", "statemachine",
    "packet parsing", "message parsing", "frame parsing",
    "pdu", "mtu", "segmentation", "reassembly",
    "link layer", "l2cap", "smp", "gatt", "gap",
    "key exchange", "psk", "certificate", "renegotiation",
    "content-type", "record layer", "hello message",
    "pairing", "provisioning",
    "buffer overflow", "out-of-bounds", "memory corruption",
    "use-after-free", "double free", "crash", "assert", "infinite loop",
    "ll_", "att_", "mesh", "provision", "netkey", "appkey"
]

LIKELY_NON_PROTOCOL_TERMS = [
    "web interface", "webui", "admin panel", "cms", "wordpress",
    "joomla", "default credential", "unauthenticated access",
    "router", "nas", "camera", "iot device", "mobile app"
]

CORE_IMPL_NAMES = set(sum(PROTOCOL_IMPLS.values(), []))

# ---------- Helpers ----------
def sleep_delay(delay):
    time.sleep(delay)

def format_nvd_datetime(dt: datetime) -> str:
    """Format datetime to NVD-friendly string (no microseconds): YYYY-MM-DD HH:MM"""
    return dt.replace(microsecond=0).strftime('%Y-%m-%d %H:%M')

def iter_time_windows(start_dt: datetime, end_dt: datetime, window_days: int = 120):
    """Yield (start, end) windows with length <= window_days to satisfy NVD limits."""
    cur = start_dt
    step = timedelta(days=window_days)
    while cur < end_dt:
        nxt = min(cur + step, end_dt)
        yield cur, nxt
        cur = nxt

def search_cpes_for_keyword(keyword, api_key, delay, max_cpes=50, verbose=False):
    """Return list of CPE objects for a keyword."""
    # 兼容不同版本 nvdlib 的参数名差异
    param_variants = [
        {"keywordSearch": keyword},  # 优先使用这个，因为 Core 版本中使用这个
        {"keyword": keyword},
        {"cpeMatchString": keyword},
        {"matchStringSearch": keyword},
    ]
    for params in param_variants:
        try:
            cpes = nvdlib.searchCPE(key=api_key, delay=delay, limit=max_cpes, **params)
            cpe_list = list(cpes)
            if verbose:
                if cpe_list:
                    print(f"      Found {len(cpe_list)} CPEs for '{keyword}'")
                else:
                    print(f"      No CPEs found for '{keyword}'")
            return cpe_list
        except TypeError:
            # 参数名不被该版本接受，尝试下一个
            continue
        except Exception as e:
            if verbose:
                error_msg = str(e)
                if "404" in error_msg or "Not Found" in error_msg:
                    print(f"      API endpoint issue for '{keyword}': {type(e).__name__}")
                else:
                    print(f"      Error searching CPE for '{keyword}': {type(e).__name__}: {error_msg[:100]}")
            continue
    if verbose:
        print(f"      CPE search failed for '{keyword}': no compatible parameter variant")
    return []

def cpe_to_cves(cpe_name, api_key, delay, max_cves=500, verbose=False):
    """Return list of CVE objects for a cpeName."""
    try:
        cves = nvdlib.searchCVE(cpeName=cpe_name, key=api_key, delay=delay, limit=max_cves)
        cve_list = list(cves)
        if verbose and cve_list:
            print(f"        Found {len(cve_list)} CVEs for CPE: {cpe_name[:80]}")
        return cve_list
    except Exception as e:
        if verbose:
            print(f"        Error searching CVE for CPE '{cpe_name[:50]}': {type(e).__name__}: {e}")
        return []

def keyword_cve_search(keyword, api_key, delay, start_date=None, end_date=None, max_results=1000, verbose=False):
    """
    搜索 CVE，处理日期格式问题
    nvdlib 可能对日期格式有特定要求
    """
    try:
        # 尝试搜索，如果日期格式有问题，nvdlib 可能会抛出 ValueError
        cves = nvdlib.searchCVE(keywordSearch=keyword, key=api_key, delay=delay,
                                pubStartDate=start_date, pubEndDate=end_date, limit=max_results)
        cve_list = []
        # 逐个处理 CVE，捕获可能的日期解析错误
        for cve in cves:
            try:
                # 尝试访问 CVE 对象，如果日期格式有问题会在这里抛出异常
                _ = getattr(cve, "id", None)
                cve_list.append(cve)
            except (ValueError, AttributeError) as e:
                # 如果单个 CVE 对象有问题，跳过它
                if verbose:
                    print(f"        Warning: Skipping CVE due to date format issue: {e}")
                continue
        if verbose and cve_list:
            if start_date and end_date:
                print(f"      Found {len(cve_list)} CVEs for keyword '{keyword}' ({start_date} to {end_date})")
            else:
                print(f"      Found {len(cve_list)} CVEs for keyword '{keyword}'")
        return cve_list
    except ValueError as e:
        # 日期格式错误，尝试不使用日期范围搜索
        if verbose:
            print(f"      Date format error for '{keyword}', trying without date range: {e}")
        try:
            cves = nvdlib.searchCVE(keywordSearch=keyword, key=api_key, delay=delay, limit=max_results)
            cve_list = []
            for cve in cves:
                try:
                    _ = getattr(cve, "id", None)
                    cve_list.append(cve)
                except (ValueError, AttributeError):
                    continue
            if verbose and cve_list:
                print(f"      Found {len(cve_list)} CVEs for keyword '{keyword}' (no date filter)")
            return cve_list
        except Exception as e2:
            if verbose:
                print(f"      Error searching CVE for keyword '{keyword}' (fallback): {type(e2).__name__}: {e2}")
            return []
    except Exception as e:
        if verbose:
            print(f"      Error searching CVE for keyword '{keyword}': {type(e).__name__}: {e}")
        return []

def extract_short_desc(cve_obj):
    """best-effort extract short description"""
    try:
        if getattr(cve_obj, "descriptions", None):
            first = cve_obj.descriptions[0]
            if isinstance(first, dict):
                return first.get("value", "")
            else:
                return getattr(first, "value", "") or ""
    except Exception:
        pass
    return ""

# ---------- 协议族识别 ----------
def detect_protocol_family(cve_obj):
    """识别 CVE 所属的协议族"""
    desc = extract_short_desc(cve_obj).lower()
    cpe_text = ",".join([str(x).lower() for x in getattr(cve_obj, "cpe", []) or []])
    for proto, impls in PROTOCOL_IMPLS.items():
        # 匹配协议实现名或协议名本身
        if any(impl.lower() in desc or impl.lower() in cpe_text for impl in impls):
            return proto
        if any(proto_part.lower() in desc for proto_part in proto.split("/")):
            return proto
    return "Unknown"

# ---------- 协议核心漏洞判定 ----------
def is_protocol_core_vuln(cve_obj):
    """判断是否为协议核心漏洞"""
    desc = extract_short_desc(cve_obj).lower()

    # 排除非协议相关的漏洞
    for bad in LIKELY_NON_PROTOCOL_TERMS:
        if bad in desc:
            return False

    # 检查核心协议术语
    for good in CORE_PROTOCOL_TERMS:
        if good in desc:
            return True

    # 检查 CPE 中是否包含核心实现名称
    for cpe in getattr(cve_obj, "cpe", []) or []:
        cpe_str = str(cpe).lower()
        for impl in CORE_IMPL_NAMES:
            if impl.lower() in cpe_str:
                return True

    # 弱匹配：协议名 + 解析相关术语
    weak_terms = ["parse", "parsing", "packet", "frame", "pdu", "malformed"]
    if any(proto.lower() in desc for proto in ["tls", "dtls", "ssh", "mqtt", "coap", "bluetooth", "ble", "zigbee"]):
        if any(w in desc for w in weak_terms):
            return True

    return False

def is_impl_related(cve_obj, impl_keywords):
    """Heuristic: check descriptions, cpe, configurations for any impl keyword or protocol tokens."""
    desc = extract_short_desc(cve_obj).lower()
    # check description tokens
    for kw in impl_keywords + GLOBAL_KEYWORDS:
        if kw.lower() in desc:
            return True
    # check cpe entries
    for cpe in getattr(cve_obj, "cpe", []) or []:
        if any(kw.lower() in str(cpe).lower() for kw in impl_keywords):
            return True
    # check configurations text fallback
    try:
        if getattr(cve_obj, "configurations", None):
            if any(kw.lower() in str(cve_obj.configurations).lower() for kw in impl_keywords):
                return True
    except Exception:
        pass
    return False

def cve_to_record(cve_obj):
    """
    将 CVE 对象转换为记录字典，安全处理日期字段
    """
    try:
        # 安全获取日期字段，处理可能的格式问题
        published = getattr(cve_obj, "published", "")
        last_modified = getattr(cve_obj, "lastModified", "")
        
        # 如果日期是 datetime 对象，转换为字符串
        if hasattr(published, 'strftime'):
            published = published.isoformat() + 'Z' if published else ""
        if hasattr(last_modified, 'strftime'):
            last_modified = last_modified.isoformat() + 'Z' if last_modified else ""
        
        # 如果是字符串，保持原样（CSV 可以接受 ISO 格式）
        
        return {
            "id": getattr(cve_obj, "id", ""),
            "published": published,
            "lastModified": last_modified,
            "v3_severity": getattr(cve_obj, "cvssV3", {}).get("baseSeverity", "") if getattr(cve_obj, "cvssV3", None) else "",
            "v3_score": getattr(cve_obj, "cvssV3", {}).get("baseScore", "") if getattr(cve_obj, "cvssV3", None) else "",
            "summary": extract_short_desc(cve_obj).replace("\n", " "),
            "cpe_list": ",".join([str(x) for x in getattr(cve_obj, "cpe", [])]) if getattr(cve_obj, "cpe", None) else "",
            "protocol_family": detect_protocol_family(cve_obj)
        }
    except Exception as e:
        # 如果转换失败，返回基本信息
        return {
            "id": getattr(cve_obj, "id", ""),
            "published": "",
            "lastModified": "",
            "v3_severity": "",
            "v3_score": "",
            "summary": extract_short_desc(cve_obj).replace("\n", " "),
            "cpe_list": "",
            "protocol_family": "Unknown"
        }

# ---------- Main orchestration ----------
def run_pipeline(api_key,
                 out_all=None,
                 out_core=None,
                 out_csv=None,  # 向后兼容参数
                 since_days=3650,
                 cpe_max_per_impl=20,
                 cve_max_per_cpe=500,
                 keyword_max_results=800,
                 delay_no_key=6.0,
                 delay_with_key=0.6,
                 use_cpe_search=True,  # 是否使用 CPE 搜索
                 use_date_range=True):  # 是否使用日期范围搜索
    """
    主流程函数
    
    Args:
        out_all: 输出所有协议相关 CVE 的 CSV 文件
        out_core: 输出协议核心 CVE 的 CSV 文件
        out_csv: 向后兼容参数，如果设置了会同时写入此文件（单输出模式）
        use_cpe_search: 是否在 Path A 中使用 CPE 搜索（True）或直接关键字搜索（False）
        use_date_range: 是否在 Path B 中使用日期范围搜索
    """
    # 确定输出路径：默认保存到 data 文件夹
    script_dir = Path(__file__).parent
    data_dir = script_dir.parent / "data"
    data_dir.mkdir(exist_ok=True)  # 确保 data 文件夹存在
    
    # 处理输出文件参数
    if out_csv and not out_all and not out_core:
        # 向后兼容：如果只提供了 out_csv，则只输出一个文件
        if not os.path.isabs(out_csv):
            out_csv = str(data_dir / out_csv)
        out_all = out_csv
        out_core = None
        single_output = True
    else:
        single_output = False
        if out_all is None:
            out_all = str(data_dir / "all_protocol_like_cves.csv")
        if out_core is None:
            out_core = str(data_dir / "protocol_core_cves.csv")
        
        # 如果传入的是相对路径，也保存到 data 文件夹
        if not os.path.isabs(out_all):
            out_all = str(data_dir / out_all)
        if out_core and not os.path.isabs(out_core):
            out_core = str(data_dir / out_core)
    
    delay = delay_with_key if api_key else delay_no_key
    end = datetime.utcnow()
    start = end - timedelta(days=since_days)
    print(f"[*] Running pipeline from {start.date()} to {end.date()} (since_days={since_days})")
    print(f"[*] Output files will be saved to:")
    if single_output:
        print(f"    - OUTPUT: {out_all}")
    else:
        print(f"    - ALL: {out_all}")
        if out_core:
            print(f"    - CORE: {out_core}")
    
    # 检查 API key
    if not api_key:
        print("[!] WARNING: No API key provided. Requests will be rate-limited (6s delay).")
        print("[!] Get a free API key from: https://nvd.nist.gov/developers/request-an-api-key")
        print("[!] Usage: --api_key YOUR_API_KEY")
    else:
        print(f"[*] Using API key: {api_key[:10]}... (delay: {delay}s)")
    
    # 测试 API 连接
    print("[*] Testing API connection...")
    try:
        test_cves = nvdlib.searchCVE(keywordSearch="openssl", key=api_key, delay=delay, limit=1)
        test_list = list(test_cves)
        if test_list:
            print(f"[+] API connection successful! Found test CVE: {test_list[0].id}")
        else:
            print("[!] WARNING: API connection test returned no results (may be rate-limited)")
    except Exception as e:
        print(f"[!] ERROR: API connection test failed: {type(e).__name__}: {e}")
        print("[!] Please check your API key and network connection")

    all_cves = {}
    provenance = {}  # cve_id -> set of sources

    # Path A: CPE-based (precise) 或 关键字搜索
    if use_cpe_search:
        print(f"\n[Path A] CPE-based search (precise)")
        for proto, impls in PROTOCOL_IMPLS.items():
            print(f"  [Path A] protocol: {proto}")
            for impl in impls:
                print(f"    - impl keyword: {impl}")
                # 1) search CPEs for impl
                cpes = search_cpes_for_keyword(impl, api_key, delay, max_cpes=cpe_max_per_impl, verbose=True)
                print(f"      -> found {len(cpes)} candidate CPE entries")
                for cpe in cpes:
                    # get canonical cpe string
                    cpe_name = getattr(cpe, "cpe23Uri", None) or getattr(cpe, "cpeName", None) or str(cpe)
                    print(f"        fetching CVEs for: {cpe_name}")
                    cves = cpe_to_cves(cpe_name, api_key, delay, max_cves=cve_max_per_cpe, verbose=True)
                    for cve in cves:
                        cid = getattr(cve, "id", None)
                        if not cid:
                            continue
                        # store if heuristic shows it's impl-related (relaxed here since cpe came from impl)
                        if cid not in all_cves:
                            all_cves[cid] = cve
                            provenance[cid] = set()
                        provenance[cid].add(f"CPE:{impl}:{cpe_name}")
                    sleep_delay(0.05)
    else:
        # Path A: 直接使用关键字搜索 CVE（因为 CPE 搜索 API 可能不可用）
        print(f"\n[Path A] Searching CVEs by implementation names (using keyword search)...")
        print(f"  Note: Using keyword search instead of CPE search due to API limitations")
        total_cves_from_impl = 0
        for proto, impls in PROTOCOL_IMPLS.items():
            print(f"  [Path A] protocol: {proto} ({len(impls)} implementations)")
            proto_cve_count = 0
            for impl in impls:
                # 直接使用关键字搜索 CVE
                cves = keyword_cve_search(
                    impl, api_key, delay,
                    start_date=None,  # 不使用日期范围，因为 Path B 会处理
                    end_date=None,
                    max_results=keyword_max_results,
                    verbose=False
                )
                proto_cve_count += len(cves)
                total_cves_from_impl += len(cves)
                for cve in cves:
                    cid = getattr(cve, "id", None)
                    if not cid:
                        continue
                    all_cves.setdefault(cid, cve)
                    provenance.setdefault(cid, set()).add(f"IMPL:{impl}")
                sleep_delay(0.05)
            if proto_cve_count > 0:
                print(f"    -> {proto}: {proto_cve_count} CVEs found")
        print(f"[Path A Summary] Total: {total_cves_from_impl} CVEs found from implementation names")

    # Path B: keyword-based (supplement)
    print("\n[Path B] Keyword supplement search")
    keywords = set(GLOBAL_KEYWORDS)
    # augment with implementation names for broader coverage
    for impls in PROTOCOL_IMPLS.values():
        for i in impls:
            keywords.add(i)
    
    total_windows = sum(1 for _ in iter_time_windows(start, end, window_days=120)) if use_date_range else 1
    print(f"  Searching {len(keywords)} keywords across {total_windows} time window(s)...")
    
    kw_count = 0
    total_cves_from_keywords = 0
    
    for kw in sorted(keywords):
        kw_count += 1
        kw_cve_count = 0
        try:
            if use_date_range:
                # 使用时间窗口搜索
                for ws, we in iter_time_windows(start, end, window_days=120):
                    cves = keyword_cve_search(
                        kw, api_key, delay,
                        start_date=format_nvd_datetime(ws),
                        end_date=format_nvd_datetime(we),
                        max_results=keyword_max_results,
                        verbose=(kw_count <= 5 and total_windows <= 3)  # 只对前几个关键字显示详细日志
                    )
                    kw_cve_count += len(cves)
                    total_cves_from_keywords += len(cves)
                    for cve in cves:
                        cid = getattr(cve, "id", None)
                        if not cid:
                            continue
                        # heuristic filter: check if impl-related (using impl list)
                        if not is_impl_related(cve, sum(PROTOCOL_IMPLS.values(), [])):
                            continue
                        if cid not in all_cves:
                            all_cves[cid] = cve
                            provenance[cid] = set()
                        provenance[cid].add(f"KW:{kw}")
                    sleep_delay(0.05)
            else:
                # 不使用日期范围，直接搜索所有结果
                cves = keyword_cve_search(
                    kw, api_key, delay,
                    start_date=None,
                    end_date=None,
                    max_results=keyword_max_results,
                    verbose=(kw_count <= 5)  # 只对前5个关键字显示详细日志
                )
                kw_cve_count += len(cves)
                total_cves_from_keywords += len(cves)
                for cve in cves:
                    cid = getattr(cve, "id", None)
                    if not cid:
                        continue
                    # heuristic filter: check if impl-related (using impl list)
                    if not is_impl_related(cve, sum(PROTOCOL_IMPLS.values(), [])):
                        continue
                    if cid not in all_cves:
                        all_cves[cid] = cve
                        provenance[cid] = set()
                    provenance[cid].add(f"KW:{kw}")
                sleep_delay(0.05)
            
            if kw_cve_count > 0:
                print(f"    '{kw}': {kw_cve_count} CVEs found")
        except Exception as e:
            print(f"    keyword search exception for '{kw}': {e}")
    
    print(f"[Path B Summary] Total: {total_cves_from_keywords} CVEs found from keywords")

    print(f"\n[*] Total unique CVEs collected: {len(all_cves)}")

    # 确保输出目录存在
    os.makedirs(os.path.dirname(out_all) if os.path.dirname(out_all) else ".", exist_ok=True)
    if out_core:
        os.makedirs(os.path.dirname(out_core) if os.path.dirname(out_core) else ".", exist_ok=True)

    # 导出：全部
    with open(out_all, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["cve_id", "protocol_family", "published", "lastModified",
                         "v3_severity", "v3_score", "summary", "cpe_list", "provenance"])
        for cid, cve in all_cves.items():
            rec = cve_to_record(cve)
            writer.writerow([rec["id"], rec["protocol_family"], rec["published"],
                             rec["lastModified"], rec["v3_severity"], rec["v3_score"],
                             rec["summary"], rec["cpe_list"],
                             ";".join(sorted(provenance.get(cid, [])))])
    print(f"[+] Written ALL CSV to: {out_all}")

    # 导出：核心协议漏洞（如果启用）
    if out_core:
        core_cves = {cid: cve for cid, cve in all_cves.items() if is_protocol_core_vuln(cve)}
        with open(out_core, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["cve_id", "protocol_family", "published", "lastModified",
                             "v3_severity", "v3_score", "summary", "cpe_list", "provenance"])
            for cid, cve in core_cves.items():
                rec = cve_to_record(cve)
                writer.writerow([rec["id"], rec["protocol_family"], rec["published"],
                                 rec["lastModified"], rec["v3_severity"], rec["v3_score"],
                                 rec["summary"], rec["cpe_list"],
                                 ";".join(sorted(provenance.get(cid, [])))])
        print(f"[+] Written CORE CSV to: {out_core}")
        print(f"[*] CORE/ALL ratio: {len(core_cves)} / {len(all_cves)}")

    # Simple summary by severity
    severity_count = defaultdict(int)
    for cve in all_cves.values():
        sev = ""
        try:
            sev = getattr(cve, "cvssV3", {}).get("baseSeverity", "") if getattr(cve, "cvssV3", None) else ""
        except Exception:
            sev = ""
        severity_count[sev] += 1
    print("\n[*] Severity summary (CVSSv3 baseSeverity if present):")
    for sev, cnt in severity_count.items():
        print(f"  {sev or 'UNKNOWN'} : {cnt}")

# ---------- CLI ----------
if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Fetch protocol-related CVEs with protocol_family tagging and core vulnerability filtering.")
    p.add_argument("--api_key", type=str, default="0387715d-2bee-472a-88a8-75d79c70dad8", help="NVD API key (recommended)")
    p.add_argument("--out", type=str, default=None, help="Output CSV file (single file mode, backward compatible)")
    p.add_argument("--out_all", type=str, default=None, help="Output CSV for all collected CVEs (default: data/all_protocol_like_cves.csv)")
    p.add_argument("--out_core", type=str, default=None, help="Output CSV for filtered protocol-core CVEs (default: data/protocol_core_cves.csv)")
    p.add_argument("--since_days", type=int, default=3650, help="How many days back to search (default 10 years)")
    p.add_argument("--cpe_max_per_impl", type=int, default=20, help="Max CPE entries to fetch per impl")
    p.add_argument("--cve_max_per_cpe", type=int, default=500, help="Max CVEs to fetch per CPE")
    p.add_argument("--keyword_max_results", type=int, default=800, help="Max results per keyword search")
    p.add_argument("--no_cpe_search", action="store_true", help="Disable CPE search in Path A, use keyword search instead")
    p.add_argument("--no_date_range", action="store_true", help="Disable date range filtering in Path B")
    args = p.parse_args()

    # 处理向后兼容：如果只提供了 --out，则使用单文件模式
    out_csv = args.out if args.out else None

    run_pipeline(api_key=args.api_key,
                 out_all=args.out_all,
                 out_core=args.out_core,
                 out_csv=out_csv,
                 since_days=args.since_days,
                 cpe_max_per_impl=args.cpe_max_per_impl,
                 cve_max_per_cpe=args.cve_max_per_cpe,
                 keyword_max_results=args.keyword_max_results,
                 use_cpe_search=not args.no_cpe_search,
                 use_date_range=not args.no_date_range)

