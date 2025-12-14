# Summary of Changes for Live Capture Feature

This document outlines the code modifications made to enable live network traffic capture via the command-line interface and Docker.

### 1. `src/main/java/cic/cs/unb/ca/ifm/Cmd.java`

*   **Added Live Capture Mode:** The `main` method was updated to parse a `-live <output_dir>` command-line argument. This triggers a new `startLiveCapture` method, while the existing file-based processing is preserved as the default behavior.
*   **Implemented `startLiveCapture()`:** This new method contains the core logic for the live capture session:
    *   **Finds Network Interfaces:** Uses `Pcap.findAllDevs()` to get a list of all available network devices.
    *   **Creates Output Directory:** Ensures the specified output directory (`/tmp/captures` in the Docker context) exists.
    *   **Manages Capture Threads:** Starts a new thread for each network interface to capture packets simultaneously.
    *   **Handles Packet Processing:** In each thread, `Pcap.openLive()` starts a session, and a `PacketReader` reads packets, which are then added to a central `FlowGenerator`.
    *   **Schedules CSV-dumping:** A `ScheduledExecutorService` is used to run a task every 60 seconds. This task dumps all current flows into a timestamped CSV file and then clears the `FlowGenerator`'s list of current flows to save memory.

### 2. `src/main/java/cic/cs/unb/ca/jnetpcap/FlowGenerator.java`

*   **Added `clearCurrentFlows()` Method:** A new public method `clearCurrentFlows()` was added. This method simply clears the `currentFlows` map. It is called by the `Cmd` class after each 60-second CSV dump to prevent memory leaks and ensure that subsequent CSV files do not contain duplicate flow data.

### 3. `src/main/java/cic/cs/unb/ca/jnetpcap/PacketReader.java`

*   **Added New Constructor for Live Capture:** A new constructor, `public PacketReader(Pcap pcap)`, was added. Unlike the existing constructors that take a file path and use `Pcap.openOffline()`, this new constructor accepts an already-opened `Pcap` object. This was the key change needed to fix the compilation error and allow `PacketReader` to be used for live capture sessions initiated with `Pcap.openLive()`.

### 4. `Dockerfile`

*   **Updated Entrypoint for Live Capture:** The `ENTRYPOINT` was changed from `["./cfm"]` to `["./cfm", "-live", "/tmp/captures"]`. This makes live capture the default behavior when running the Docker container.
*   **Added Usage Instructions:** A comment was added to the `Dockerfile` with an example `docker run` command, instructing the user to run the container with the `--net=host` and `--privileged` or `--cap-add=NET_ADMIN` flags to grant the necessary permissions for network interface access.
