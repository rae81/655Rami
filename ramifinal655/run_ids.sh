#!/bin/bash
# LLDP IDS Launcher
# Quick deployment script for controller VM

set -e

echo "LLDP IDS - Starting deployment..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 not found"
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
python3 -m pip install -r requirements.txt

# Create directories
mkdir -p logs runs

# Set environment
export RYU_LOG_DIR=./logs
export CONFIG_FILE=${CONFIG:-config.yaml}
export MPLBACKEND=Agg  # Headless plotting

# Verify model file exists
if [ ! -f "mlmodel/02_Training/lldp_rf_model.pkl" ]; then
    echo "Error: Model file not found at mlmodel/02_Training/lldp_rf_model.pkl"
    exit 1
fi

# Run controller
# From: github.com/faucetsdn/ryu (--observe-links enables topology discovery)
echo "Starting Ryu controller with topology discovery..."
if command -v ryu-manager &> /dev/null; then
    ryu-manager --observe-links ryu.topology.switches lldp_ids_system.py --verbose
else
    # Fallback to python module invocation
    python3 -m ryu.cmd.manager --observe-links ryu.topology.switches lldp_ids_system.py --verbose
fi
