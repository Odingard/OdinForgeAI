#!/bin/bash
# OdinForge Agent Connectivity Diagnostic Script
# This script tests if an EC2 instance can reach the OdinForge server

SERVER_URL="${1:-https://uncleavable-jesse-inkier.ngrok-free.dev}"

echo "========================================="
echo "OdinForge Agent Connectivity Diagnostics"
echo "========================================="
echo "Server URL: $SERVER_URL"
echo ""

# Test 1: DNS Resolution
echo "[1/6] Testing DNS resolution..."
if host "uncleavable-jesse-inkier.ngrok-free.dev" > /dev/null 2>&1; then
    echo "✅ DNS resolution successful"
    host "uncleavable-jesse-inkier.ngrok-free.dev"
else
    echo "❌ DNS resolution failed"
fi
echo ""

# Test 2: Basic HTTPS connectivity
echo "[2/6] Testing HTTPS connectivity..."
if curl -s -o /dev/null -w "%{http_code}" "$SERVER_URL" | grep -q "200\|301\|302"; then
    echo "✅ HTTPS connection successful"
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$SERVER_URL")
    echo "   HTTP Status: $HTTP_CODE"
else
    echo "❌ HTTPS connection failed"
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$SERVER_URL" 2>&1)
    echo "   HTTP Status: $HTTP_CODE"
fi
echo ""

# Test 3: Agent download endpoint
echo "[3/6] Testing agent download endpoint..."
DOWNLOAD_URL="$SERVER_URL/api/agents/download/linux-amd64"
if curl -s -I "$DOWNLOAD_URL" | head -1 | grep -q "200"; then
    echo "✅ Agent download endpoint accessible"
    FILE_SIZE=$(curl -s -I "$DOWNLOAD_URL" | grep -i "content-length" | awk '{print $2}' | tr -d '\r')
    echo "   Binary size: $FILE_SIZE bytes (~8MB expected)"
else
    echo "❌ Agent download endpoint not accessible"
fi
echo ""

# Test 4: Outbound internet connectivity (test with known endpoint)
echo "[4/6] Testing general outbound internet connectivity..."
if curl -s -o /dev/null -w "%{http_code}" "https://www.google.com" | grep -q "200\|301"; then
    echo "✅ Outbound HTTPS working (tested with google.com)"
else
    echo "❌ Outbound HTTPS blocked or no internet"
fi
echo ""

# Test 5: Check if port 443 is reachable
echo "[5/6] Testing port 443 connectivity to ngrok..."
if nc -z -w5 uncleavable-jesse-inkier.ngrok-free.dev 443 2>/dev/null; then
    echo "✅ Port 443 is reachable"
else
    echo "❌ Port 443 is not reachable (may be blocked by security group)"
fi
echo ""

# Test 6: Test agent registration endpoint
echo "[6/6] Testing agent registration endpoint..."
REG_URL="$SERVER_URL/api/agents/register"
if curl -s -o /dev/null -w "%{http_code}" -X POST "$REG_URL" -H "Content-Type: application/json" -d '{"test":"connectivity"}' | grep -q "400\|401\|403"; then
    echo "✅ Registration endpoint accessible (expected 400/401 for invalid data)"
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$REG_URL" -H "Content-Type: application/json" -d '{"test":"connectivity"}')
    echo "   HTTP Status: $HTTP_CODE"
else
    echo "❌ Registration endpoint not accessible"
fi
echo ""

echo "========================================="
echo "Diagnostic Summary"
echo "========================================="
echo "If all tests pass ✅, the instance can reach OdinForge."
echo "If tests fail ❌, check:"
echo "  1. Security Group outbound rules (allow HTTPS/443)"
echo "  2. Network ACLs"
echo "  3. Route tables and internet gateway"
echo "========================================="
