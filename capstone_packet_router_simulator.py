"""
CAPSTONE PROJECT: The Host-to-Gateway Packet Router & ARP Simulator
Topic: First-Principles Networking (IP, Subnet Masks, MAC Addresses, ARP)
"""

from typing import Dict, Optional


def ip_to_int(ip_str: str) -> int:
    """
    Convert a dotted-decimal IPv4 string (e.g. "192.168.1.15") into a 32-bit integer.
    
    Explanation:
    - Split "192.168.1.15" into 4 integer octets: [192, 168, 1, 15].
    - Shift octet 0 left by 24 bits (occupies bits 24..31).
    - Shift octet 1 left by 16 bits (occupies bits 16..23).
    - Shift octet 2 left by 8 bits  (occupies bits 8..15).
    - Octet 3 occupies the lowest bits (0..7).
    - Combine them using bitwise OR (|).
    """
    octets = [int(part) for part in ip_str.split(".")]
    return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]


def is_local_network(my_ip: str, target_ip: str, netmask: str) -> bool:
    """
    Determines if target_ip is on the same local subnet as my_ip using netmask.
    
    Explanation:
    - Convert all three dotted strings into 32-bit integers.
    - Applying bitwise AND (&) with netmask strips away the host portion,
      leaving ONLY the Network portion (the street name).
    - If (my_ip & mask) == (target_ip & mask), both devices reside on the same wire!
    """
    my_int = ip_to_int(my_ip)
    target_int = ip_to_int(target_ip)
    mask_int = ip_to_int(netmask)

    my_network = my_int & mask_int
    target_network = target_int & mask_int

    return my_network == target_network


def route_and_build_frame(
    my_ip: str,
    my_mac: str,
    netmask: str,
    default_gateway_ip: str,
    target_ip: str,
    payload: str,
    arp_table: Dict[str, str]
) -> Dict:
    """
    Simulates the core routing and frame encapsulation logic of an OS network stack.
    
    Explanation:
    1. Ask: Is target_ip on our local subnet?
       - If YES: We can talk directly to target_ip. Next-Hop IP = target_ip.
       - If NO:  We cannot reach it directly. Next-Hop IP = default_gateway_ip (our home router).
    2. Consult the ARP cache to find the MAC address of that Next-Hop IP.
    3. Construct the packet:
       - Layer 3 (IP): Source IP is my_ip; Destination IP is ALWAYS target_ip.
       - Layer 2 (Ethernet): Source MAC is my_mac; Destination MAC is Next-Hop MAC.
    """
    # Step 1: Subnet check
    is_local = is_local_network(my_ip, target_ip, netmask)

    # Step 2: Determine next-hop IP
    if is_local:
        next_hop_ip = target_ip
    else:
        next_hop_ip = default_gateway_ip

    # Step 3: ARP resolution
    if next_hop_ip not in arp_table:
        raise ValueError(f"ARP lookup failed: Destination {next_hop_ip} unreachable on local link")
    
    dst_mac = arp_table[next_hop_ip]

    # Step 4: Assemble frame
    return {
        "layer2_frame": {
            "src_mac": my_mac,
            "dst_mac": dst_mac
        },
        "layer3_packet": {
            "src_ip": my_ip,
            "dst_ip": target_ip,
            "payload": payload
        }
    }


# =====================================================================
# TEST HARNESS
# =====================================================================
if __name__ == "__main__":
    print("=" * 65)
    print("  RUNNING TESTS: HOST-TO-GATEWAY ROUTING SIMULATOR")
    print("=" * 65)

    # 1. Test ip_to_int
    print("\n[*] Testing ip_to_int()...")
    test_ip = "192.168.1.1"
    expected_int = (192 << 24) + (168 << 16) + (1 << 8) + 1
    actual_int = ip_to_int(test_ip)
    assert actual_int == expected_int, f"Failed ip_to_int: Expected {expected_int}, got {actual_int}"
    print(f"  [+] ip_to_int('192.168.1.1') = {actual_int} (Binary: {bin(actual_int)})")
    print("  [+] ip_to_int passed!")

    # 2. Test is_local_network
    print("\n[*] Testing is_local_network()...")
    my_laptop = "192.168.1.15"
    mask = "255.255.255.0"
    
    # Neighbor on same Wi-Fi
    assert is_local_network(my_laptop, "192.168.1.20", mask) is True, "Failed: 192.168.1.20 should be LOCAL"
    # Router on same Wi-Fi
    assert is_local_network(my_laptop, "192.168.1.1", mask) is True, "Failed: 192.168.1.1 should be LOCAL"
    # Google DNS outside the house
    assert is_local_network(my_laptop, "8.8.8.8", mask) is False, "Failed: 8.8.8.8 should be REMOTE"
    # Different subnet in 192.168.x.x
    assert is_local_network(my_laptop, "192.168.2.15", mask) is False, "Failed: 192.168.2.15 should be REMOTE"
    print("  [+] is_local_network passed!")

    # 3. Test Full Routing & ARP Frame Assembly
    print("\n[*] Testing route_and_build_frame()...")
    
    my_mac = "AA:BB:CC:11:22:33"
    gateway_ip = "192.168.1.1"
    
    mock_arp_table = {
        "192.168.1.1": "RO:UT:ER:00:11:22",   # Your Home Router's MAC
        "192.168.1.20": "PR:IN:TE:RR:44:55",  # Local Wi-Fi Printer's MAC
    }

    # SCENARIO A: Printing a document to your local Wi-Fi printer (192.168.1.20)
    local_frame = route_and_build_frame(
        my_ip=my_laptop,
        my_mac=my_mac,
        netmask=mask,
        default_gateway_ip=gateway_ip,
        target_ip="192.168.1.20",
        payload="PRINT: resume.pdf",
        arp_table=mock_arp_table
    )
    
    assert local_frame["layer3_packet"]["dst_ip"] == "192.168.1.20"
    assert local_frame["layer2_frame"]["dst_mac"] == "PR:IN:TE:RR:44:55", (
        f"Failed Local Hop! Expected Printer MAC, got {local_frame['layer2_frame']['dst_mac']}"
    )
    print("  [+] Scenario A (Local Delivery): Successfully addressed to PRINTER'S MAC!")
    print(f"      Frame: {local_frame}")

    # SCENARIO B: Loading Google (8.8.8.8)
    remote_frame = route_and_build_frame(
        my_ip=my_laptop,
        my_mac=my_mac,
        netmask=mask,
        default_gateway_ip=gateway_ip,
        target_ip="8.8.8.8",
        payload="GET https://google.com",
        arp_table=mock_arp_table
    )

    assert remote_frame["layer3_packet"]["dst_ip"] == "8.8.8.8", "Destination IP should be 8.8.8.8"
    assert remote_frame["layer2_frame"]["dst_mac"] == "RO:UT:ER:00:11:22", (
        f"Failed Remote Hop! Expected ROUTER'S MAC, got {remote_frame['layer2_frame']['dst_mac']}"
    )
    print("  [+] Scenario B (Remote Delivery): Successfully addressed to ROUTER'S MAC!")
    print(f"      Frame: {remote_frame}")

    print("\n" + "=" * 65)
    print("  [SUCCESS] ALL FIRST-PRINCIPLE NETWORKING TESTS PASSED!")
    print("=" * 65 + "\n")
