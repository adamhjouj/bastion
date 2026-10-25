"""Opt-in live Docker smoke test; creates only isolated, network-disabled fixtures.
Run: RUN_DOCKER_TESTS=1 python -m pytest -q test_docker_logs.py
"""
import asyncio
import os
import subprocess
import time
import uuid

import pytest

from bastion import log_store
from bastion.log_collector import DockerLogCollector

pytestmark = pytest.mark.skipif(os.getenv("RUN_DOCKER_TESTS") != "1", reason="set RUN_DOCKER_TESTS=1 for isolated Docker fixtures")


def test_real_stdout_stderr_restart_and_recreation():
    project = "bastion-logs-test-" + uuid.uuid4().hex[:10]
    containers = []

    def start(source):
        command = ['docker', 'run', '-d', '--network', 'none', '--memory', '16m', '--pids-limit', '16',
                   '--label', f'com.docker.compose.project={project}', '--label', f'com.docker.compose.service={source}',
                   'busybox:1.37', 'sh', '-c',
                   'printf "%s stdout\\n" "$1"; printf "%s stderr\\n" "$1" >&2; sleep 60', '--', source]
        cid = subprocess.check_output(command, text=True, timeout=30).strip()
        containers.append(cid)
        return cid

    async def wait_for(predicate, timeout=35):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            await asyncio.sleep(.2)
        raise AssertionError('Docker log ingestion did not reach the expected state')

    async def scenario():
        ids = {source: await asyncio.to_thread(start, source) for source in log_store.SOURCES}
        collector = DockerLogCollector(project)
        await collector.start()
        try:
            await wait_for(lambda: all(len(log_store.page(source)['entries']) >= 2 for source in log_store.SOURCES))
            for source in log_store.SOURCES:
                entries = log_store.page(source)['entries']
                assert {r['stream'] for r in entries} == {'stdout', 'stderr'}
                assert {r['text'] for r in entries} == {source + ' stdout', source + ' stderr'}
            await asyncio.to_thread(subprocess.run, ['docker', 'restart', '-t', '1', ids['blue']],
                                    capture_output=True, check=True, timeout=15)
            await wait_for(lambda: len(log_store.page('blue')['entries']) >= 4)
            # Existing captured entries must not be duplicated during replay.
            await asyncio.sleep(4)
            assert len(log_store.page('blue')['entries']) == 4
            await asyncio.to_thread(subprocess.run, ['docker', 'rm', '-f', ids['proxy']],
                                    capture_output=True, check=True, timeout=15)
            new_id = await asyncio.to_thread(start, 'proxy')
            await wait_for(lambda: len(log_store.page('proxy')['entries']) >= 4)
            assert log_store.watermark('proxy', new_id[:12]) is not None
        finally:
            await collector.close()
            assert not collector.processes

    try:
        asyncio.run(scenario())
    finally:
        for cid in containers:
            subprocess.run(['docker', 'rm', '-f', cid], capture_output=True, timeout=15)
