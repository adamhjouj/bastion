"""Actuator-owned Docker stdout/stderr ingestion with restart recovery and bounds."""
import asyncio
import collections
import hashlib
import re

from bastion import log_store

_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z")


async def bounded_lines(reader, maximum=8192):
    """Drain oversized lines without ever buffering their complete contents."""
    buffer, truncated = bytearray(), False
    while chunk := await reader.read(4096):
        pieces = chunk.split(b"\n")
        for index, piece in enumerate(pieces):
            room = maximum - len(buffer)
            buffer.extend(piece[:max(0, room)])
            truncated = truncated or len(piece) > room
            if index < len(pieces) - 1:
                yield buffer.decode("utf-8", "replace").rstrip("\r"), truncated
                buffer, truncated = bytearray(), False
    if buffer or truncated:
        yield buffer.decode("utf-8", "replace"), truncated


class DockerLogCollector:
    def __init__(self, project, docker="docker", sources=log_store.SOURCES, retention=1000):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", project):
            raise ValueError("invalid Compose project")
        if not set(sources) <= set(log_store.SOURCES):
            raise ValueError("invalid log source")
        if not 1 <= retention <= 10000:
            raise ValueError("LOG_RETENTION_LINES must be between 1 and 10000")
        self.project, self.docker, self.sources, self.retention = project, docker, sources, retention
        self.tasks, self.processes = [], set()

    async def start(self):
        self.tasks = [asyncio.create_task(self._supervise(source)) for source in self.sources]

    async def close(self):
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        for source in self.sources:
            await asyncio.to_thread(log_store.set_source, source, "stopped", "Collector stopped")

    async def _discover(self, source):
        process = await asyncio.create_subprocess_exec(
            self.docker, "ps", "-a", "--format", "{{.ID}} {{.State}}", "--filter", f"label=com.docker.compose.project={self.project}",
            "--filter", f"label=com.docker.compose.service={source}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        try:
            output = await asyncio.wait_for(process.stdout.read(16384), 5)
            await asyncio.wait_for(process.wait(), 5)
            rows = [line.split() for line in output.decode().splitlines() if line.strip()]
            if process.returncode == 0 and len(rows) == 1 and len(rows[0]) == 2 and re.fullmatch(r"[a-f0-9]{12,64}", rows[0][0]):
                return rows[0][0], rows[0][1] == "running"
            return None
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()

    async def _supervise(self, source):
        while True:
            try:
                target = await self._discover(source)
                if target is None:
                    await asyncio.to_thread(log_store.set_source, source, "waiting", "No unique container found for this Compose service")
                else:
                    cid, running = target
                    if not running and await asyncio.to_thread(log_store.watermark, source, cid):
                        await asyncio.to_thread(log_store.set_source, source, "stopped", "Container stopped; captured output is retained", cid)
                    else:
                        await self._follow(source, cid)
            except asyncio.CancelledError:
                raise
            except Exception:
                # Never persist raw Docker diagnostics (which may include credentials).
                try:
                    await asyncio.to_thread(log_store.set_source, source, "unavailable", "Docker log reader unavailable; check the actuator service")
                except Exception:
                    pass  # retry discovery even while the shared store is unavailable
            await asyncio.sleep(3)

    async def _follow(self, source, cid):
        since = await asyncio.to_thread(log_store.watermark, source, cid)
        args = [self.docker, "logs", "--follow", "--timestamps", "--tail", "all" if since else "200"]
        if since:
            args += ["--since", since]
        process = await asyncio.create_subprocess_exec(*args, cid, stdout=asyncio.subprocess.PIPE,
                                                       stderr=asyncio.subprocess.PIPE)
        self.processes.add(process)
        queue = asyncio.Queue(maxsize=400)
        counts = collections.OrderedDict()

        async def read(pipe, stream):
            async for line, truncated in bounded_lines(pipe):
                ts, separator, text = line.partition(" ")
                if not separator or not _TIMESTAMP.fullmatch(ts):
                    continue  # Docker CLI diagnostics, not container output
                digest = hashlib.sha256(text.encode()).hexdigest()
                key = (ts, stream, digest)
                occurrence = counts.get(key, 0)
                counts[key] = occurrence + 1
                counts.move_to_end(key)
                if len(counts) > 4096:
                    counts.popitem(last=False)
                await queue.put({"container_id": cid, "ts": ts, "stream": stream, "text": text,
                                 "digest": digest, "occurrence": occurrence, "truncated": truncated})

        async def write():
            while True:
                first = await queue.get()
                batch = [first]
                while len(batch) < 200 and not queue.empty():
                    batch.append(queue.get_nowait())
                await asyncio.to_thread(log_store.append, source, batch, self.retention)
                for _ in batch:
                    queue.task_done()

        readers = [asyncio.create_task(read(process.stdout, "stdout")), asyncio.create_task(read(process.stderr, "stderr"))]
        writer = asyncio.create_task(write())
        try:
            while True:
                if writer.done():
                    writer.result()
                for reader in readers:
                    if reader.done():
                        reader.result()
                await asyncio.to_thread(log_store.set_source, source, "streaming", "Following container stdout and stderr", cid)
                if process.returncode is not None:
                    await asyncio.gather(*readers)
                    # Bound shutdown even when the store is unavailable.
                    await asyncio.wait_for(queue.join(), 15)
                    break
                await asyncio.sleep(3)
                target = await self._discover(source)
                if target is None or target[0] != cid:
                    break  # replacement container or daemon reconnect; rediscover before following
            failed = process.returncode not in (None, 0)
            await asyncio.to_thread(log_store.set_source, source, "unavailable" if failed else "reconnecting",
                                   "Docker refused the log stream; check the service logging driver" if failed else "Reconnecting to the container log stream", cid)
        finally:
            if process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), 3)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
            for task in readers + [writer]:
                task.cancel()
            await asyncio.gather(*readers, writer, return_exceptions=True)
            self.processes.discard(process)
