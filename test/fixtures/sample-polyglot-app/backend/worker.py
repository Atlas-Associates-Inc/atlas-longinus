# Synthetic Python worker fixture for defensive static audit
import yaml

INTERNAL_SIGNING_SECRET = "synthetic_placeholder_not_real_987654321"

def load_runtime_config(raw_text: str):
    return yaml.load(raw_text)
