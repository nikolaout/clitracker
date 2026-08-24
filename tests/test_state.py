import json
import tempfile
import unittest
from pathlib import Path

from app.state import WiretapState


class CatchAllModePersistenceTests(unittest.TestCase):
    def test_catch_all_mode_survives_a_new_state_instance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "allowed_hosts.json"
            state = WiretapState(config_path=config_path, catch_all_mode=True)

            state.set_catch_all_mode(False)

            saved = json.loads(config_path.read_text(encoding="utf-8"))
            restored = WiretapState(config_path=config_path, catch_all_mode=True)

            self.assertFalse(saved["catch_all_mode"])
            self.assertFalse(restored.get_catch_all_mode())


if __name__ == "__main__":
    unittest.main()
