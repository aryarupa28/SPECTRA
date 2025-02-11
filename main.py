from wsn.sensor_simulation import generate_sensor_data
from wsn.anomaly_detection import detect_anomaly
from wsn.encryption import encrypt_data
from manet.routing_simulation import Node, simulate_routing
from manet.secure_transmission import forward_data
from manet.intrusion_detection import detect_intrusion, take_action
from ethernet.data_processing import process_data
from ethernet.threat_analysis import analyze_threats
from ethernet.genai_response import generate_response
from shared_config import cipher


if __name__ == "__main__":
    # Step 1: Generate sensor data
    print("Step 1: Generating Sensor Data...")
    sensor_data = generate_sensor_data()
    print("Sensor Data:", sensor_data)

    # Step 2: Check for anomalies
    print("\nStep 2: Checking for Anomalies...")
    if detect_anomaly(sensor_data):
        print("Anomaly detected! Taking action...")
        # You can add custom actions here for anomalies
    else:
        print("Data is normal. Proceeding to encryption...")

    # Step 3: Encrypt the data
    print("\nStep 3: Encrypting Data...")
    encrypted_data = encrypt_data(sensor_data)
    print("Encrypted Data:", encrypted_data)

    # Step 4: Simulate MANET routing
    print("\nStep 4: Simulating MANET Routing...")
    nodes = [Node(node_id=i) for i in range(1, 4)]  # Create 3 nodes
    simulate_routing(nodes, data=encrypted_data)

    # Step 5: Securely forward the encrypted data
    print("\nStep 5: Forwarding Data Securely...")
    # Test encryption and decryption
    test_data = "Test message"
    encrypted_test_data = cipher.encrypt(test_data.encode())
    decrypted_test_data = cipher.decrypt(encrypted_test_data).decode()
    print("Encryption Test - Encrypted Data:", encrypted_test_data)
    print("Encryption Test - Decrypted Data:", decrypted_test_data)

    # Step 6: Detect intrusions in MANET
    print("\nStep 6: Detecting Intrusions...")
    # Example traffic data for testing
    traffic_data = [
        "normal traffic",
        "ddos attack detected",
        "man-in-the-middle detected",
        "blackhole detected"
    ]

    for traffic in traffic_data:
        print(f"\nAnalyzing Traffic: {traffic}")
        attack_type = detect_intrusion(traffic)

        if attack_type:
            take_action(attack_type)
    print("\nStep 7: Processing Data in Ethernet Layer...")
    processed_data = process_data(encrypted_data)

    # Step 8: Analyze threats in the processed data
    print("\nStep 8: Analyzing Threats...")
threats = analyze_threats(processed_data.decode())
if threats:
    print("Threats Detected:", threats)
else:
    print("No threats detected.")

# Step 9: Generate GenAI-Based Responses
if threats:
    print("\nStep 9: Generating GenAI-Based Response...")
    responses = generate_response(threats)
    for threat, response in responses.items():
        print(f"Threat: {threat}")
        print(f"Response: {response}")