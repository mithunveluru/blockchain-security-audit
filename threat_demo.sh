#!/bin/bash

# Get your IP
YOUR_IP=$(hostname -I | awk '{print $1}')

echo "🚨 COMPLETE THREAT SIMULATION"
echo "Target: $YOUR_IP"
echo "====================================\n"

# ATTACK 1: PORT SCAN
echo "[1/2] Launching PORT SCAN..."
sudo nmap -p 80,443,22,3306,5432,8080,9000,27017,6379,5000 $YOUR_IP 2>/dev/null
echo "✓ Port scan sent\n"
sleep 3

# ATTACK 2: DDoS
echo "[2/2] Launching DDoS ATTACK (5 seconds)..."
sudo timeout 5 hping3 -p 5000 -i u100 -c 2000 $YOUR_IP 2>/dev/null
echo "✓ DDoS sent\n"

echo "✅ SIMULATION COMPLETE!"
echo "📊 Check: http://localhost:5000/soc"
