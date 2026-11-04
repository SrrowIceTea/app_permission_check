"""Write minimal HA test configuration; no production services. 授权测试专用。"""
from pathlib import Path

CONFIG = '''homeassistant:
  name: VScanner isolated lab
  latitude: 30.0
  longitude: 120.0
  elevation: 0
  unit_system: metric
  time_zone: Asia/Shanghai
http:
  server_host: 127.0.0.1
  server_port: 18123
frontend:
api:
websocket_api:
config:
onboarding:
mobile_app:
input_boolean:
  audit_test_light:
    name: Audit test light
    initial: false
logger:
  default: info
'''


def write_config(folder):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / 'configuration.yaml'
    if path.exists() and path.read_text(encoding='utf-8') != CONFIG:
        raise ValueError('refusing to overwrite an existing non-lab HA configuration')
    path.write_text(CONFIG, encoding='utf-8')
    return path
