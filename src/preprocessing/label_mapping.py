"""
NexThreat Label Mapping configuration.
Defines the mapping from original labels to attack categories and boolean flags.
"""

LABEL_MAPPING = {
    "BENIGN": "BENIGN",
    "DDoS": "DDoS",
    "DoS Hulk": "DoS",
    "DoS Hulk - Attempted": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS GoldenEye - Attempted": "DoS",
    "DoS Slowloris": "DoS",
    "DoS slowloris": "DoS",
    "DoS slowloris - Attempted": "DoS",
    "DoS Slowhttptest": "DoS",
    "DoS Slowhttptest - Attempted": "DoS",
    "PortScan": "PortScan",
    "FTP-Patator": "Brute Force",
    "FTP-Patator - Attempted": "Brute Force",
    "SSH-Patator": "Brute Force",
    "SSH-Patator - Attempted": "Brute Force",
    "Web Attack - Brute Force": "Brute Force",
    "Web Attack - Brute Force - Attempted": "Brute Force",
    "Web Attack - XSS": "Web Attack",
    "Web Attack - XSS - Attempted": "Web Attack",
    "Web Attack - Sql Injection": "Web Attack",
    "Bot": "Bot",
    "Bot - Attempted": "Bot",
    "Infiltration": "Infiltration",
    "Infiltration - Attempted": "Infiltration",
    "Heartbleed": "ATTACK"
}

def map_to_category(label: str) -> str:
    """Maps an original label to an attack category."""
    label = str(label).strip()
    if label not in LABEL_MAPPING:
        raise ValueError(f"Unknown label encountered: '{label}'")
    return LABEL_MAPPING[label]

def map_is_attack(category: str) -> int:
    """Returns 0 if category is BENIGN, else 1."""
    return 0 if category == "BENIGN" else 1
