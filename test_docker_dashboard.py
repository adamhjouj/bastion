"""Opt-in smoke test of built proxy/actuator images with their real shared log DB.
Build first: docker compose build proxy actuator
Run: RUN_DOCKER_APP_TESTS=1 python -m pytest -q test_docker_dashboard.py
"""
import os
import subprocess
import time
import uuid

import httpx
import pytest

pytestmark = pytest.mark.skipif(os.getenv("RUN_DOCKER_APP_TESTS") != "1", reason="requires built Docker application images")


def test_built_proxy_reads_logs_collected_by_actuator():
    project = "bastion-dashboard-test-" + uuid.uuid4().hex[:10]
    volume = project + "-data"
    containers = []
    token = "test-only-management-token-1234567890"

    def run(args):
        return subprocess.check_output(['docker', *args], text=True, timeout=30).strip()

    def start(service, image, env, command, ports=None, socket=False):
        args = ['run', '-d', '--label', f'com.docker.compose.project={project}',
                '--label', f'com.docker.compose.service={service}', '-v', volume + ':/app/data']
        if socket:
            args += ['-v', '/var/run/docker.sock:/var/run/docker.sock']
        if ports:
            args += ['-p', ports]
        for key, value in env.items():
            args += ['-e', key + '=' + value]
        cid = run([*args, image, *command])
        containers.append(cid)
        return cid

    run(['volume', 'create', volume])
    try:
        proxy = start('proxy', 'bastion-app', {'MANAGEMENT_TOKEN': token, 'BASTION_MODE': 'observe'},
                      ['uvicorn', 'proxy:app', '--host', '0.0.0.0', '--port', '8080', '--no-proxy-headers'],
                      ports='127.0.0.1::8080')
        start('actuator', 'bastion-actuator', {'ACTUATOR_TOKEN': token, 'BASTION_PROJECT': project},
              ['uvicorn', 'actuator_app:app', '--host', '0.0.0.0', '--port', '9010'], socket=True)
        address = run(['port', proxy, '8080/tcp']).splitlines()[0]
        with httpx.Client(base_url='http://' + address, headers={'Authorization': 'Bearer ' + token}, timeout=3) as client:
            deadline = time.monotonic() + 40
            payload = None
            while time.monotonic() < deadline:
                try:
                    response = client.get('/__api/v1/logs/proxy')
                    if response.status_code == 200:
                        payload = response.json()
                        if payload['entries']:
                            break
                except httpx.HTTPError:
                    pass
                time.sleep(.5)
            assert payload and payload['entries'], 'no live Docker output reached the dashboard API'
            assert any('startup' in row['text'].lower() or 'uvicorn' in row['text'].lower() for row in payload['entries'])
            assert client.get('/__api/v1/overview').json()['schema_version'] == 1
            assert client.get('/__api/v1/logs/proxy', headers={'Authorization': ''}).status_code == 401
    finally:
        for cid in reversed(containers):
            subprocess.run(['docker', 'rm', '-f', cid], capture_output=True, timeout=15)
        subprocess.run(['docker', 'volume', 'rm', volume], capture_output=True, timeout=15)
