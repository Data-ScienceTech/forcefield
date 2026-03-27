"""Allow running ``python -m forcefield``."""
import sys
from .cli import main
sys.exit(main())
