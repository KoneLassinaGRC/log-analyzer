"""
Core module for log security analyzer
"""
def __init__(self, config_file: str = "config.json"):
    self.config_file = config_file
    self.logger = logging.getLogger(__name__)  # doit être créé avant
    logging.basicConfig(
        level=getattr(logging, self.DEFAULT_CONFIG["log_level"]),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    self.config = self.load_config()


__version__ = "1.0.0"
__author__ = "Security Analysis Tool"

q