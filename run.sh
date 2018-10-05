#!/bin/bash
# Setup staging db
python3 setup_db.py
# Run script
python3 process_threats.py
