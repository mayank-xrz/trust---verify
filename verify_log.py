#!/usr/bin/env python3
"""Operator CLI: verify an audit log hash chain and ML-DSA-65 checkpoints.

Examples:
    python verify_log.py --chain --checkpoints --log audit.log \
        --public-key-file checkpoint_pub.b64
    python verify_log.py --chain --checkpoints --self-test
"""

from __future__ import annotations

import sys

from src.audit.verifier import main


if __name__ == "__main__":
    sys.exit(main())
