# Fixed version of the CICFlowMeter tool

As part of our [WTMC 2021 paper](https://downloads.distrinet-research.be/WTMC2021/Resources/wtmc2021_Engelen_Troubleshooting.pdf), we analysed and improved the CICFlowMeter tool, the result of 
which can be found in this repository. If you use this improved CICFlowMeter tool, please cite our paper:

            @inproceedings{engelen2021troubleshooting,
            title={Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study},
            author={Engelen, Gints and Rimmer, Vera and Joosen, Wouter},
            booktitle={2021 IEEE Security and Privacy Workshops (SPW)},
            pages={7--12},
            year={2021},
            organization={IEEE}
            }

A detailed list of all fixes and improvements, as well as implications of the changes can be found on [our webpage](https://downloads.distrinet-research.be/WTMC2021/),
which hosts the extended documentation of our paper. 

Here we stick to a brief summary of all changes to the CICFlowMeter tool: 

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
    docker build -t cicflowmeter-live .
    ```

2.  **Run the Docker container:**

    To capture live traffic, the container needs access to the host's network interfaces. Use the following command, replacing `/path/to/your/output` with the directory on your host machine where you want to save the CSV files.

    ```bash
    docker run --rm -it --cap-add=NET_ADMIN --net=host -v /path/to/your/output:/tmp/captures cicflowmeter-live
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
