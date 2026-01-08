/**
 * @file stoffelnet.h
 * @brief C FFI bindings for stoffel-networking (QUIC-based networking for MPC)
 *
 * This header provides C-compatible functions for:
 * - Creating and managing tokio runtime instances
 * - Creating and managing QUIC network managers
 * - Establishing connections to peers
 * - Sending and receiving messages
 *
 * Thread Safety:
 * - All handle types use Arc internally for thread-safe sharing
 * - Callbacks may be invoked from any thread in the tokio runtime thread pool
 * - Thread-local error storage is used for error messages
 *
 * Memory Management:
 * - All handles must be freed with their corresponding _destroy functions
 * - Byte buffers returned by receive functions must be freed with stoffelnet_free_bytes
 * - Strings returned by accessor functions must be freed with stoffelnet_free_string
 */

#ifndef STOFFELNET_H
#define STOFFELNET_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * ERROR CODES
 * ============================================================================ */

/** Operation completed successfully */
#define STOFFELNET_OK                    0
/** Null pointer was passed where a valid pointer was expected */
#define STOFFELNET_ERR_NULL_POINTER     -1
/** Invalid network address format */
#define STOFFELNET_ERR_INVALID_ADDRESS  -2
/** Connection establishment failed */
#define STOFFELNET_ERR_CONNECTION       -3
/** Send operation failed */
#define STOFFELNET_ERR_SEND             -4
/** Receive operation failed */
#define STOFFELNET_ERR_RECEIVE          -5
/** Operation timed out */
#define STOFFELNET_ERR_TIMEOUT          -6
/** Party not found in network */
#define STOFFELNET_ERR_PARTY_NOT_FOUND  -7
/** Runtime error occurred */
#define STOFFELNET_ERR_RUNTIME          -8
/** Invalid UTF-8 string */
#define STOFFELNET_ERR_INVALID_UTF8     -9
/** Operation cancelled */
#define STOFFELNET_ERR_CANCELLED        -10

/* ============================================================================
 * CONNECTION STATE CONSTANTS
 * ============================================================================ */

/** Connection is active and healthy */
#define STOFFELNET_STATE_CONNECTED      0
/** Connection is gracefully closing */
#define STOFFELNET_STATE_CLOSING        1
/** Connection has been closed */
#define STOFFELNET_STATE_CLOSED         2
/** Connection failed/disconnected unexpectedly */
#define STOFFELNET_STATE_DISCONNECTED   3

/* ============================================================================
 * OPAQUE HANDLE TYPES
 * ============================================================================ */

/** Opaque pointer to a tokio runtime */
typedef void* StoffelTokioRuntimeHandle;

/** Opaque pointer to a network manager */
typedef void* StoffelNetworkManagerHandle;

/** Opaque pointer to a peer connection */
typedef void* StoffelPeerConnectionHandle;

/** Opaque pointer to an async operation */
typedef void* StoffelAsyncOperationHandle;

/** Opaque pointer to a node */
typedef void* StoffelNodeHandle;

/* ============================================================================
 * CALLBACK TYPES
 * ============================================================================ */

/**
 * Callback type for connection completion
 * @param result STOFFELNET_OK on success, or an error code
 * @param user_data User-provided context pointer
 */
typedef void (*StoffelConnectCallback)(int32_t result, void* user_data);

/**
 * Callback type for receive completion
 * @param result STOFFELNET_OK on success, or an error code
 * @param data Pointer to received data (only valid during callback)
 * @param len Length of received data in bytes
 * @param user_data User-provided context pointer
 */
typedef void (*StoffelReceiveCallback)(int32_t result, const uint8_t* data, size_t len, void* user_data);

/**
 * Callback type for send completion
 * @param result STOFFELNET_OK on success, or an error code
 * @param user_data User-provided context pointer
 */
typedef void (*StoffelSendCallback)(int32_t result, void* user_data);

/* ============================================================================
 * ERROR HANDLING
 * ============================================================================ */

/**
 * Gets the last error message for the current thread
 * @return Pointer to error message, or NULL if no error. Do not free this pointer.
 */
const char* stoffelnet_last_error(void);

/**
 * Clears the last error message for the current thread
 */
void stoffelnet_clear_error(void);

/* ============================================================================
 * RUNTIME MANAGEMENT
 * ============================================================================ */

/**
 * Creates a new tokio runtime for async operations
 * @return Handle to the runtime, or NULL on failure. Check stoffelnet_last_error() for details.
 */
StoffelTokioRuntimeHandle stoffelnet_runtime_new(void);

/**
 * Destroys a tokio runtime
 * @param runtime Handle to the runtime to destroy
 */
void stoffelnet_runtime_destroy(StoffelTokioRuntimeHandle runtime);

/* ============================================================================
 * NODE MANAGEMENT
 * ============================================================================ */

/**
 * Creates a new node with a specified party ID
 * @param address Network address as null-terminated string (e.g., "127.0.0.1:9000")
 * @param party_id Party ID for this node
 * @return Handle to the node, or NULL on failure
 */
StoffelNodeHandle stoffelnet_node_new(const char* address, uint64_t party_id);

/**
 * Creates a new node with a random UUID-based ID
 * @param address Network address as null-terminated string
 * @return Handle to the node, or NULL on failure
 */
StoffelNodeHandle stoffelnet_node_new_random_id(const char* address);

/**
 * Destroys a node handle
 * @param node Handle to the node to destroy
 */
void stoffelnet_node_destroy(StoffelNodeHandle node);

/**
 * Gets the address of a node as a string
 * @param node Handle to the node
 * @return Newly allocated C string, or NULL on error. Caller must free with stoffelnet_free_string.
 */
char* stoffelnet_node_address(StoffelNodeHandle node);

/**
 * Gets the party ID of a node
 * @param node Handle to the node
 * @return Party ID, or 0 on error
 */
uint64_t stoffelnet_node_party_id(StoffelNodeHandle node);

/* ============================================================================
 * NETWORK MANAGER
 * ============================================================================ */

/**
 * Creates a new network manager
 * @param runtime Handle to the tokio runtime
 * @param bind_address Address to bind for incoming connections (null-terminated string)
 * @param party_id Party ID for this node
 * @return Handle to the network manager, or NULL on failure
 */
StoffelNetworkManagerHandle stoffelnet_manager_new(
    StoffelTokioRuntimeHandle runtime,
    const char* bind_address,
    uint64_t party_id
);

/**
 * Destroys a network manager
 * @param manager Handle to the network manager to destroy
 */
void stoffelnet_manager_destroy(StoffelNetworkManagerHandle manager);

/**
 * Adds a node to the network manager
 * @param manager Handle to the network manager
 * @param address Network address of the node (null-terminated string)
 * @param party_id Party ID of the node
 * @return STOFFELNET_OK on success, or an error code
 */
int32_t stoffelnet_manager_add_node(
    StoffelNetworkManagerHandle manager,
    const char* address,
    uint64_t party_id
);

/**
 * Connects to a party (blocking)
 * @param manager Handle to the network manager
 * @param party_id Party ID to connect to
 * @return STOFFELNET_OK on success, or an error code
 */
int32_t stoffelnet_manager_connect_to_party(
    StoffelNetworkManagerHandle manager,
    uint64_t party_id
);

/**
 * Connects to a party asynchronously with a callback
 * @param manager Handle to the network manager
 * @param party_id Party ID to connect to
 * @param callback Callback function invoked when connection completes
 * @param user_data User data passed to the callback
 * @return Handle to the async operation, or NULL on error
 */
StoffelAsyncOperationHandle stoffelnet_manager_connect_to_party_async(
    StoffelNetworkManagerHandle manager,
    uint64_t party_id,
    StoffelConnectCallback callback,
    void* user_data
);

/**
 * Accepts an incoming connection (blocking)
 * @param manager Handle to the network manager
 * @param out_party_id Pointer to store the connected party's ID
 * @return STOFFELNET_OK on success, or an error code
 */
int32_t stoffelnet_manager_accept_connection(
    StoffelNetworkManagerHandle manager,
    uint64_t* out_party_id
);

/**
 * Gets a connection handle for a specific party
 * @param manager Handle to the network manager
 * @param party_id Party ID to get connection for
 * @return Handle to the connection, or NULL if not connected
 */
StoffelPeerConnectionHandle stoffelnet_manager_get_connection(
    StoffelNetworkManagerHandle manager,
    uint64_t party_id
);

/**
 * Checks if a party is connected
 * @param manager Handle to the network manager
 * @param party_id Party ID to check
 * @return 1 if connected, 0 otherwise
 */
int32_t stoffelnet_manager_is_party_connected(
    StoffelNetworkManagerHandle manager,
    uint64_t party_id
);

/* ============================================================================
 * PEER CONNECTION
 * ============================================================================ */

/**
 * Sends data on a connection (blocking)
 * @param conn Handle to the peer connection
 * @param runtime Handle to the tokio runtime
 * @param data Pointer to data to send
 * @param data_len Length of data in bytes
 * @return STOFFELNET_OK on success, or an error code
 */
int32_t stoffelnet_connection_send(
    StoffelPeerConnectionHandle conn,
    StoffelTokioRuntimeHandle runtime,
    const uint8_t* data,
    size_t data_len
);

/**
 * Receives data from a connection (blocking)
 * @param conn Handle to the peer connection
 * @param runtime Handle to the tokio runtime
 * @param out_data Pointer to store received data pointer
 * @param out_len Pointer to store received data length
 * @return STOFFELNET_OK on success, or an error code
 * @note Caller must free received data with stoffelnet_free_bytes
 */
int32_t stoffelnet_connection_receive(
    StoffelPeerConnectionHandle conn,
    StoffelTokioRuntimeHandle runtime,
    uint8_t** out_data,
    size_t* out_len
);

/**
 * Sends data asynchronously with a callback
 * @param conn Handle to the peer connection
 * @param runtime Handle to the tokio runtime
 * @param data Pointer to data to send (data is copied)
 * @param data_len Length of data in bytes
 * @param callback Callback function invoked when send completes
 * @param user_data User data passed to the callback
 * @return Handle to the async operation, or NULL on error
 */
StoffelAsyncOperationHandle stoffelnet_connection_send_async(
    StoffelPeerConnectionHandle conn,
    StoffelTokioRuntimeHandle runtime,
    const uint8_t* data,
    size_t data_len,
    StoffelSendCallback callback,
    void* user_data
);

/**
 * Receives data asynchronously with a callback
 * @param conn Handle to the peer connection
 * @param runtime Handle to the tokio runtime
 * @param callback Callback function invoked when receive completes
 * @param user_data User data passed to the callback
 * @return Handle to the async operation, or NULL on error
 * @note Data pointer in callback is only valid during the callback
 */
StoffelAsyncOperationHandle stoffelnet_connection_receive_async(
    StoffelPeerConnectionHandle conn,
    StoffelTokioRuntimeHandle runtime,
    StoffelReceiveCallback callback,
    void* user_data
);

/**
 * Cancels an async operation
 * @param op Handle to the async operation
 * @return STOFFELNET_OK on success
 */
int32_t stoffelnet_async_cancel(StoffelAsyncOperationHandle op);

/**
 * Gets the connection state
 * @param conn Handle to the peer connection
 * @param runtime Handle to the tokio runtime
 * @return One of STOFFELNET_STATE_* constants, or -1 on error
 */
int32_t stoffelnet_connection_state(
    StoffelPeerConnectionHandle conn,
    StoffelTokioRuntimeHandle runtime
);

/**
 * Checks if a connection is alive
 * @param conn Handle to the peer connection
 * @param runtime Handle to the tokio runtime
 * @return 1 if connected, 0 otherwise
 */
int32_t stoffelnet_connection_is_connected(
    StoffelPeerConnectionHandle conn,
    StoffelTokioRuntimeHandle runtime
);

/**
 * Closes a connection
 * @param conn Handle to the peer connection
 * @param runtime Handle to the tokio runtime
 */
void stoffelnet_connection_close(
    StoffelPeerConnectionHandle conn,
    StoffelTokioRuntimeHandle runtime
);

/**
 * Destroys a connection handle
 * @param conn Handle to the peer connection
 */
void stoffelnet_connection_destroy(StoffelPeerConnectionHandle conn);

/* ============================================================================
 * MEMORY MANAGEMENT
 * ============================================================================ */

/**
 * Frees a byte buffer allocated by stoffel-networking
 * @param data Pointer to the data to free
 * @param len Length of the data in bytes
 */
void stoffelnet_free_bytes(uint8_t* data, size_t len);

/**
 * Frees a string allocated by stoffel-networking
 * @param str Pointer to the string to free
 */
void stoffelnet_free_string(char* str);

#ifdef __cplusplus
}
#endif

#endif /* STOFFELNET_H */
