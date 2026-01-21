#!/usr/bin/env python3
"""
Test script for stoffel-networking FFI bindings.

Usage:
    python tests/test_ffi.py

Requires the shared library to be built:
    cargo build --release
"""

import ctypes
import os
import sys
from ctypes import c_char_p, c_int32, c_uint64, c_void_p, c_size_t, POINTER, c_uint8

# Find the shared library
def find_library():
    # Try different locations
    paths = [
        "target/release/libstoffelnet.dylib",  # macOS release
        "target/debug/libstoffelnet.dylib",    # macOS debug
        "target/release/libstoffelnet.so",     # Linux release
        "target/debug/libstoffelnet.so",       # Linux debug
    ]

    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)

    for path in paths:
        full_path = os.path.join(project_dir, path)
        if os.path.exists(full_path):
            return full_path

    raise FileNotFoundError(
        "Could not find libstoffelnet. Run 'cargo build --release' first."
    )

# Load the library
lib_path = find_library()
print(f"Loading library from: {lib_path}")
lib = ctypes.CDLL(lib_path)

# Define function signatures
# Error handling
lib.stoffelnet_last_error.restype = c_char_p
lib.stoffelnet_last_error.argtypes = []

lib.stoffelnet_clear_error.restype = None
lib.stoffelnet_clear_error.argtypes = []

# Runtime
lib.stoffelnet_runtime_new.restype = c_void_p
lib.stoffelnet_runtime_new.argtypes = []

lib.stoffelnet_runtime_destroy.restype = None
lib.stoffelnet_runtime_destroy.argtypes = [c_void_p]

# Node
lib.stoffelnet_node_new.restype = c_void_p
lib.stoffelnet_node_new.argtypes = [c_char_p, c_uint64]

lib.stoffelnet_node_new_random_id.restype = c_void_p
lib.stoffelnet_node_new_random_id.argtypes = [c_char_p]

lib.stoffelnet_node_destroy.restype = None
lib.stoffelnet_node_destroy.argtypes = [c_void_p]

lib.stoffelnet_node_address.restype = c_char_p
lib.stoffelnet_node_address.argtypes = [c_void_p]

lib.stoffelnet_node_party_id.restype = c_uint64
lib.stoffelnet_node_party_id.argtypes = [c_void_p]

lib.stoffelnet_free_string.restype = None
lib.stoffelnet_free_string.argtypes = [c_char_p]

# Network Manager
lib.stoffelnet_manager_new.restype = c_void_p
lib.stoffelnet_manager_new.argtypes = [c_void_p, c_char_p, c_uint64]

lib.stoffelnet_manager_destroy.restype = None
lib.stoffelnet_manager_destroy.argtypes = [c_void_p]

lib.stoffelnet_manager_add_node.restype = c_int32
lib.stoffelnet_manager_add_node.argtypes = [c_void_p, c_char_p, c_uint64]

lib.stoffelnet_manager_is_party_connected.restype = c_int32
lib.stoffelnet_manager_is_party_connected.argtypes = [c_void_p, c_uint64]

# Memory
lib.stoffelnet_free_bytes.restype = None
lib.stoffelnet_free_bytes.argtypes = [POINTER(c_uint8), c_size_t]

# Constants
STOFFELNET_OK = 0
STOFFELNET_ERR_NULL_POINTER = -1


def test_error_handling():
    """Test error handling functions."""
    print("\n=== Test: Error Handling ===")

    # Clear any existing error
    lib.stoffelnet_clear_error()

    # Check that there's no error
    error = lib.stoffelnet_last_error()
    assert error is None, "Expected no error after clear"
    print("  [PASS] Error cleared successfully")

    # Trigger an error by passing invalid address
    node = lib.stoffelnet_node_new(b"invalid-address", 1)
    assert node is None, "Expected None for invalid address"

    error = lib.stoffelnet_last_error()
    assert error is not None, "Expected error message"
    print(f"  [PASS] Error captured: {error.decode()}")

    lib.stoffelnet_clear_error()
    print("  [PASS] Error handling works correctly")


def test_runtime_lifecycle():
    """Test runtime creation and destruction."""
    print("\n=== Test: Runtime Lifecycle ===")

    runtime = lib.stoffelnet_runtime_new()
    assert runtime is not None, "Failed to create runtime"
    print("  [PASS] Runtime created")

    lib.stoffelnet_runtime_destroy(runtime)
    print("  [PASS] Runtime destroyed")


def test_node_operations():
    """Test node creation and operations."""
    print("\n=== Test: Node Operations ===")

    # Create node with specific party ID
    address = b"127.0.0.1:9000"
    party_id = 42

    node = lib.stoffelnet_node_new(address, party_id)
    assert node is not None, "Failed to create node"
    print(f"  [PASS] Node created with party_id={party_id}")

    # Get party ID
    retrieved_id = lib.stoffelnet_node_party_id(node)
    assert retrieved_id == party_id, f"Expected {party_id}, got {retrieved_id}"
    print(f"  [PASS] Party ID retrieved: {retrieved_id}")

    # Get address
    addr_ptr = lib.stoffelnet_node_address(node)
    assert addr_ptr is not None, "Failed to get address"
    addr_str = addr_ptr.decode()
    print(f"  [PASS] Address retrieved: {addr_str}")

    # Note: We need to free the string, but ctypes doesn't give us a way to
    # get the raw pointer back after decode(). In real usage, you'd manage this.

    lib.stoffelnet_node_destroy(node)
    print("  [PASS] Node destroyed")

    # Create node with random ID
    node2 = lib.stoffelnet_node_new_random_id(b"127.0.0.1:9001")
    assert node2 is not None, "Failed to create node with random ID"

    random_id = lib.stoffelnet_node_party_id(node2)
    assert random_id > 0, "Expected non-zero random ID"
    print(f"  [PASS] Node with random ID created: {random_id}")

    lib.stoffelnet_node_destroy(node2)
    print("  [PASS] Node operations work correctly")


def test_network_manager():
    """Test network manager creation."""
    print("\n=== Test: Network Manager ===")

    # Create runtime first
    runtime = lib.stoffelnet_runtime_new()
    assert runtime is not None, "Failed to create runtime"
    print("  [PASS] Runtime created")

    # Create network manager
    bind_address = b"127.0.0.1:0"  # Port 0 = auto-assign
    party_id = 1

    manager = lib.stoffelnet_manager_new(runtime, bind_address, party_id)
    assert manager is not None, f"Failed to create manager: {lib.stoffelnet_last_error()}"
    print("  [PASS] Network manager created")

    # Add a node
    result = lib.stoffelnet_manager_add_node(manager, b"127.0.0.1:9002", 2)
    assert result == STOFFELNET_OK, f"Failed to add node: {result}"
    print("  [PASS] Node added to manager")

    # Check connection status (should be disconnected)
    is_connected = lib.stoffelnet_manager_is_party_connected(manager, 2)
    assert is_connected == 0, "Expected party to be disconnected"
    print("  [PASS] Party correctly reported as disconnected")

    # Cleanup
    lib.stoffelnet_manager_destroy(manager)
    lib.stoffelnet_runtime_destroy(runtime)
    print("  [PASS] Network manager works correctly")


def test_null_safety():
    """Test that null pointers are handled safely."""
    print("\n=== Test: Null Safety ===")

    # These should not crash
    lib.stoffelnet_runtime_destroy(None)
    lib.stoffelnet_node_destroy(None)
    lib.stoffelnet_manager_destroy(None)
    print("  [PASS] Null destroy calls handled safely")

    # These should return error codes or null
    result = lib.stoffelnet_manager_add_node(None, b"127.0.0.1:9000", 1)
    assert result == STOFFELNET_ERR_NULL_POINTER
    print("  [PASS] Null manager returns error code")

    party_id = lib.stoffelnet_node_party_id(None)
    assert party_id == 0
    print("  [PASS] Null node returns 0 for party_id")

    print("  [PASS] Null safety works correctly")


def main():
    print("=" * 50)
    print("stoffel-networking FFI Test Suite")
    print("=" * 50)

    try:
        test_error_handling()
        test_runtime_lifecycle()
        test_node_operations()
        test_network_manager()
        test_null_safety()

        print("\n" + "=" * 50)
        print("ALL TESTS PASSED!")
        print("=" * 50)
        return 0

    except AssertionError as e:
        print(f"\n[FAILED] {e}")
        error = lib.stoffelnet_last_error()
        if error:
            print(f"Last error: {error.decode()}")
        return 1
    except Exception as e:
        print(f"\n[ERROR] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
