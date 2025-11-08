#!/usr/bin/env python3
import os
from aws_cdk import App
from dotenv import load_dotenv
from stacks.ta_iac_stack import TAIaCStack

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

# 🔍 DEBUG: Check if .env actually loaded
print("Loaded keys:", {k: os.getenv(k) for k in ["OTX_API_KEY", "SHODAN_API_KEY", "ABUSEIPDB_API_KEY", "GREYNOISE_API_KEY"]})

app = App()
TAIaCStack(app, "ta-iac-stack")
app.synth()
