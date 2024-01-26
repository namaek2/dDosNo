from scapy.all import sniff, IP
from collections import defaultdict
import time
import subprocess

# 패킷 수를 저장하는 defaultdict 초기화
packet_counter = defaultdict(int)

def run_ban_ip(ip):
    batch_file_path = r'ban.bat'

    try:
        # subprocess.call()을 사용하여 배치 파일 실행
        subprocess.call([batch_file_path] + ip)
    except Exception as e:
        print(f"배치 파일 실행 중 오류 발생: {e}")

def packet_callback(packet):
    current_time = time.time()

    if IP in packet:
        # 모든 IP 주소에 대해 패킷을 감지하면 해당 시간에 패킷 수 증가
        packet_counter[(packet[IP].src, current_time)] += 1

        # 일정 시간 동안의 패킷 수를 계산 (예: 0.3초 동안의 패킷 수)
        recent_packet_count = sum(
            count for (ip, timestamp), count in packet_counter.items() if current_time - timestamp <= 0.3
        )

        # 일정 시간 동안의 패킷 수가 100을 초과하면 해당 IP 주소 출력
        if recent_packet_count >= 100:
            run_ban_ip(packet[IP].src)
            packet_counter = defaultdict(int)

# sniff 함수를 사용하여 패킷 캡처
sniff(prn=packet_callback, store=0, count=0)