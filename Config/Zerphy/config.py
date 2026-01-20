device = {
    "unprovisioned_device_address": "e0:9c:f0:d1:72:a4",
    "sul_type": 0,
    "algorithm": 1,
    "iat": 1,
    "rat": 0,
    "role": 1,
    "rx_len": 251,
    "tx_len": 251,
    "packet_layer": 4,
    "config_file": "/home/yangting/Documents/BleMeshTest/srcs/Config_File/Esp32/esp_ble_security.ini",
    "learned_model_path": "/home/yangting/Documents/BleMeshTest/result/dot_file/Esp32/esp_ble_security_l2cap.dot",
    "log_path": "/home/yangting/Documents/BleMeshTest/result/log_file/Esp32/esp_ble_security.log",
    "port_name": "/dev/ttyACM9",
    "logs_pcap": True,
    "pcap_filename": "/home/yangting/Documents/BleMeshTest/result/log_file/Esp32/test_smp_legency.pcap",
    "return_handle_layer": [1,3] ,
    "send_handle_layer":[1,3], # Uncomment and modify if needed
    "key_path": "/home/yangting/Documents/Transfer/Result/Zerphy/key.json",
}

fuzz = {
    "learned_model_path": "/home/yangting/Documents/BleMeshTest/result/dot_file/Template/pairing_sm_encryption2.dot",
    "fuzz_pcap_filename": "/home/yangting/Documents/BleMeshTest/result/log_file/Esp32/esp_ble_security.pcap",
    "fuzz_time": 300,
    "untested_layer": [],
    "unadd_layer": [] , # 如果有需要，可以在这里添加未添加的层
    "block_packet": [],
    "start" : "start",
    "end" : "end",
    "data_add" : True,
    "date_remove" : True, 
}
