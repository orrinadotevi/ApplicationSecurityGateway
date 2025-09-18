{
  "type": "object",
  "required": ["id", "prompt", "label"],
  "properties": {
    "id": {"type": "string"},
    "prompt": {"type": "string"},
    "label": {"type": "string", "enum": ["malicious","safe"]},
    "metadata": {"type": "object"}
  }
}
