import pytest
import socket
import subprocess
import time

import polytracker

from pathlib import Path

# The maximum duration for the test case (to prevent hangs)
MAX_DURATION_SECS = 10.0


def expected_source_name(binary_ip, binary_port, python_ip, python_port):
    """Return taint source name given connection info"""
    return f"socket:{binary_ip}:{binary_port}-{python_ip}:{python_port}"


@pytest.mark.skip(reason="test may time out and never complete")
@pytest.mark.program_trace("test_socket_read_write.cpp")
@pytest.mark.parametrize("mode", ["client", "server"])
def test_socket_read_write(instrumented_binary: Path, trace_file: Path, mode: str):
    """Tests reads from the socket, introducing source taint.

    The mode is seen from the instrumented binary point of view. That is, client
    is when the instrumented binary connects to this python server and server is
    vice versa.
    """
    start = time.time()

    def abort_on_timeout():
        """Aborts if the timeout has passed, returns remaining time if not"""
        elapsed = time.time() - start
        assert elapsed < MAX_DURATION_SECS
        return MAX_DURATION_SECS - elapsed

    # Data to write to stdin, one byte at a time
    send_data = "abcdef".encode("utf-8")
    port_number = 63455
    host = "127.0.0.1"

    def start_proc():
        return subprocess.Popen(
            [str(instrumented_binary), mode, str(port_number), send_data],
            env={"POLYDB": str(trace_file)},
        )

    def read_n(sock, n):
        """Read n bytes from the socket, abort on test case timeout"""
        remaining_bytes = n
        response = bytearray()
        while remaining_bytes > 0:
            abort_on_timeout()
            response += sock.recv(remaining_bytes)
            remaining_bytes = n - len(response)
        return response

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if mode == "client":
            s.bind((host, port_number))
            s.listen()

            proc = start_proc()

            conn, addr = s.accept()
            conn.sendall(send_data)
            response = read_n(conn, len(send_data))
            conn.shutdown(socket.SHUT_RDWR)

            source_name = expected_source_name(addr[0], addr[1], host, port_number)

        else:
            assert mode == "server"
            proc = start_proc()

            # Retry connections until timeout
            while True:
                try:
                    abort_on_timeout()
                    s.connect((host, port_number))
                    break
                except ConnectionRefusedError:
                    print("Retry connect")

            client_host, client_port = s.getsockname()
            source_name = expected_source_name(
                host, port_number, client_host, client_port
            )
            s.sendall(send_data)

            # Read response, might come in chunks
            response = read_n(s, len(send_data))

            s.shutdown(socket.SHUT_RDWR)

    # Wait for process to terminate, should be quick unless error
    remaining_time = abort_on_timeout()
    proc.wait(remaining_time)

    # Ensure actual program logic worked out ok
    assert proc.returncode == 0
    assert send_data == response

    # Check taint operations
    program_trace = polytracker.PolyTrackerTrace.load(trace_file)
    input_labels = list(program_trace.tdfile.input_labels())
    inputs = list(program_trace.inputs)
    sinkops = list(program_trace.tdfile.sinks)

    # Ensure socket reads are accounted for
    assert len(input_labels) == len(send_data)

    assert len(inputs) == 1
    assert inputs[0].path == source_name

    # Ensure socket writes are accounted for
    assert len(sinkops) == len(send_data)
    for i in range(0, len(send_data)):
        assert inputs[sinkops[i].fdidx].path == source_name
        assert sinkops[i].offset == i
        # As label zero is unused the labels are offset by one
        assert sinkops[i].label == i + 1
