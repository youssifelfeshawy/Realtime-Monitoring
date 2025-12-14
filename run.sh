#!/bin/sh

# Activate the virtual environment
. /opt/venv/bin/activate

# Start the CICFlowMeter in the background
./cfm -live /tmp/captures &

# Start the prediction script in the foreground
python3 /CICFlowMeter/prediction/prediction.py
