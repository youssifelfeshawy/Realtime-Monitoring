# Improved version of the CICFlowMeter tool

This repository contains an improved version of the CICFlowMeter tool, originally forked from [this repository](https://github.com/GintsEngelen/CICFlowMeter). The original improvements were made as part of our [WTMC 2021 paper](https://downloads.distrinet-research.be/WTMC2021/Resources/wtmc2021_Engelen_Troubleshooting.pdf). If you use this improved CICFlowMeter tool, please cite their paper:

            @inproceedings{engelen2021troubleshooting,
            title={Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study},
            author={Engelen, Gints and Rimmer, Vera and Joosen, Wouter},
            booktitle={2021 IEEE Security and Privacy Workshops (SPW)},
            pages={7--12},
            year={2021},
            organization={IEEE}
            }

A detailed list of all fixes and improvements, as well as implications of the changes can be found on [their webpage](https://downloads.distrinet-research.be/WTMC2021/),
which hosts the extended documentation of their paper. 

Here is a brief summary of the original changes to the CICFlowMeter tool: 

- A TCP flow is no longer terminated after a single FIN packet. It now terminates after mutual exchange of 
FIN packets, which is more in line with the TCP specification.
  
- An RST packet is no longer ignored. Instead, the RST packet also terminates a TCP flow.

- The Flow Active and Idle time features no longer encode an absolute timestamp.

- The values for *Fwd PSH Flags*, *Bwd PSH Flags*, *Fwd URG Flags* and *Bwd URG Flags* are now correctly incremented.

## Running the tool

### Live Capture (Docker)

The tool can be run in a Docker container to capture live network traffic from all interfaces. The captured flow data will be saved periodically as timestamped CSV files in the specified output directory.

1.  **Build the Docker image:**
    ```bash
    docker build -t cicflowmeter .
    ```

2.  **Run the Docker container:**

    To capture live traffic, the container needs access to the host's network interfaces. Use the following command, replacing `/path/to/your/output` with the directory on your host machine where you want to save the CSV files.

    ```bash
    docker run --rm -it --cap-add=NET_ADMIN --net=host -v /path/to/your/output:/tmp/captures cicflowmeter
    ```
    *   `--rm`: Automatically removes the container when it exits.
    *   `-it`: Runs the container in interactive mode so you can see the logs and stop it with `Ctrl+C`.
    *   `--cap-add=NET_ADMIN`: Grants the container the necessary network administration capabilities.
    *   `--net=host`: Shares the host's network namespace with the container, allowing it to see all network interfaces.
    *   `-v /path/to/your/output:/tmp/captures`: Mounts a host directory into the container's `/tmp/captures` directory to persist the output CSV files.

### Offline PCAP Processing (Docker)
To use the tool inside a Docker container for processing PCAP files, follow these steps:

1. Set Up Directories:
     - Create a directory at `/path/to/pcap`.
     - Inside this directory, make two subfolders: 
       - `input` (for your input files)
       - `output` (where the tool will save its results).
2. Build the image.
    ```bash
    docker build -t cicflowmeter .
    ```
2. Run the Docker Command:
    ```bash
    docker run -v /path/to/pcap:/tmp/pcap cicflowmeter /tmp/pcap/input /tmp/pcap/output
    ```
    This command mounts your local /path/to/pcap directory to /tmp/pcap inside the Docker container and then runs the tool on the input, saving results to the output directory.

### Local
To run the tool locally, please refer to the [original CICFlowMeter repository](https://github.com/ahlashkari/CICFlowMeter) for instructions.

## Changes

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

### 5. Prediction Feature Integration

*   **Integrated Prediction Model:** Added a `prediction` folder containing a Python-based prediction model.
*   **Updated `prediction.py`:** Modified the Python script to monitor the correct directory for CSV files (`/tmp/captures`).
*   **Updated `Dockerfile`:**
    *   Installed Python, pip, and required libraries (`pandas`, `numpy`, `scikit-learn`, `joblib`).
    *   Added `build-base` and `python3-dev` to compile `scikit-learn`.
    *   Created a virtual environment to manage Python dependencies.
    *   Copied the `prediction` folder into the Docker image.
    *   Set the `ENTRYPOINT` to run a new `run.sh` script.
*   **Created `run.sh`:** This script starts both the Java traffic capture application and the Python prediction script.
