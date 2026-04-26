package main

import (
	"encoding/json"
	"net"
)

const socketPath = "/tmp/system_agent.sock"

// SendPayload serializes any Go value into JSON and delivers it to the orchestrator over UDS.
func SendPayload(payload interface{}) error {
	// Serialize payload first so no socket connection is opened for invalid data.
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// Append a newline because the Node.js server expects line-delimited JSON frames.
	message := append(jsonBytes, '\n')

	// Open a Unix domain socket connection for this send operation.
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		// Return dial errors (including connection refused) to avoid panic and let caller decide.
		return err
	}
	defer conn.Close()

	// Write the full message and propagate any write/disconnect errors safely.
	_, err = conn.Write(message)
	if err != nil {
		return err
	}

	return nil
}
