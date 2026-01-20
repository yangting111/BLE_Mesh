"""
输出映射表
将 Scapy summary 中的关键字映射为统一的 *_pkt 名称，便于状态机使用
"""
from __future__ import annotations

from typing import Dict, List, Tuple

from Transfer.Send_Packet import constant

# 与 BluetoothMesh_SUL 中的分类保持一致
_PBADV_PKTS = [
    "link_open_message_pkt",
    "link_ack_message_pkt",
    "link_close_message_pkt",
    "provisioning_invite_pkt",
    "provisioning_capability_pkt",
    "provisioning_start_pkt",
    "provisioning_public_key_pkt",
    "provisioning_confirmation_pkt",
    "provisioning_random_pkt",
    "provisioning_data_pkt",
    "provisioning_complete_pkt",
    "provisioning_failed_pkt",
    "transaction_acknowledgment_pkt",
]

_BEACON_PKTS = [
    "unprovisioned_device_beacon_pkt",
    "secure_network_beacon_pkt",
    "mesh_private_beacon_pkt",
]

_MESSAGE_PKTS = [
    "config_beacon_get_pkt",
    "config_beacon_set_pkt",
    "config_beacon_status_pkt",
    "config_composition_data_get_pkt",
    "config_default_ttl_get_pkt",
    "config_default_ttl_set_pkt",
    "config_default_ttl_status_pkt",
    "config_gatt_proxy_get_pkt",
    "config_gatt_proxy_set_pkt",
    "config_gatt_proxy_status_pkt",
    "config_relay_get_pkt",
    "config_relay_set_pkt",
    "config_relay_status_pkt",
    "config_model_publication_get_pkt",
    "config_model_publication_set_pkt",
    "config_model_publication_virtual_address_set_pkt",
    "config_model_publication_status_pkt",
    "config_model_subscription_add_pkt",
    "config_model_subscription_virtual_address_add_pkt",
    "config_model_subscription_delete_pkt",
    "config_model_subscription_virtual_address_delete_pkt",
    "config_model_subscription_overwrite_pkt",
    "config_model_subscription_virtual_address_overwrite_pkt",
    "config_model_subscription_status_pkt",
    "config_sig_model_subscription_get_pkt",
    "config_sig_model_subscription_list_pkt",
    "config_vendor_model_subscription_get_pkt",
    "config_vendor_model_subscription_list_pkt",
    "config_netkey_add_pkt",
    "config_netkey_update_pkt",
    "config_netkey_delete_pkt",
    "config_netkey_status_pkt",
    "config_netkey_get_pkt",
    "config_netkey_list_pkt",
    "config_app_key_add_pkt",
    "config_app_key_update_pkt",
    "config_app_key_delete_pkt",
    "config_app_key_status_pkt",
    "config_app_key_get_pkt",
    "config_app_key_list_pkt",
    "config_node_identity_get_pkt",
    "config_node_identity_set_pkt",
    "config_node_identity_status_pkt",
    "config_model_app_bind_pkt",
    "config_model_app_status_pkt",
    "config_model_app_unbind_pkt",
    "config_sig_model_app_get_pkt",
    "config_sig_model_app_list_pkt",
    "config_vendor_model_app_get_pkt",
    "config_vendor_model_app_list_pkt",
    "config_node_reset_pkt",
    "config_node_reset_status_pkt",
    "config_friend_get_pkt",
    "config_friend_set_pkt",
    "config_friend_status_pkt",
    "config_key_refresh_phase_get_pkt",
    "config_key_refresh_phase_set_pkt",
    "config_key_refresh_phase_status_pkt",
    "config_heartbeat_publication_get_pkt",
    "config_heartbeat_publication_set_pkt",
    "config_heartbeat_publication_status_pkt",
    "config_heartbeat_subscription_get_pkt",
    "config_heartbeat_subscription_set_pkt",
    "config_heartbeat_subscription_status_pkt",
    "config_low_power_node_poll_timeout_get_pkt",
    "config_low_power_node_poll_timeout_status_pkt",
    "config_network_transmit_get_pkt",
    "config_network_transmit_set_pkt",
    "config_network_transmit_status_pkt",
    "segment_ack_pkt",
]

_ALL_PKTS: List[str] = _PBADV_PKTS + _BEACON_PKTS + _MESSAGE_PKTS


def _normalize(text: str) -> str:
    return text.replace("_", " ").strip().lower()


def _build_keyword_map() -> List[Tuple[str, str]]:
    keyword_map: Dict[str, str] = {}
    for name in _ALL_PKTS:
        base = name.replace("_pkt", "")
        keyword_map[_normalize(base)] = name

    # 额外同义词（Scapy summary 中常见的写法）
    keyword_map["link open message"] = "link_open_message_pkt"
    keyword_map["link ack message"] = "link_ack_message_pkt"
    keyword_map["link close message"] = "link_close_message_pkt"
    keyword_map["transaction acknowledgment"] = "transaction_acknowledgment_pkt"
    keyword_map["transaction acknowledgment pdu"] = "transaction_acknowledgment_pkt"
    keyword_map["unprovisioned device beacon"] = "unprovisioned_device_beacon_pkt"
    keyword_map["secure network beacon"] = "secure_network_beacon_pkt"
    keyword_map["mesh private beacon"] = "mesh_private_beacon_pkt"

    # 按关键字长度排序，优先匹配更精确的字符串
    return sorted(keyword_map.items(), key=lambda item: len(item[0]), reverse=True)


_SORTED_KEYWORDS = _build_keyword_map()


def get_map(result: str) -> str:
    """
    将 summary 串映射为 *_pkt 名称；若无法识别则返回原始字符串。
    """
    if not result:
        return constant.EMPTY

    tokens = [token.strip() for token in result.split("|") if token.strip()]
    search_space = tokens + [" ".join(tokens)]

    for token in search_space:
        norm = _normalize(token)
        if not norm:
            continue
        if norm == constant.EMPTY:
            return constant.EMPTY
        for keyword, mapped in _SORTED_KEYWORDS:
            if keyword in norm:
                return mapped

    # 回退到原始字符串，便于调试
    return result

