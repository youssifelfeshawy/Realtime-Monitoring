# Gemini Project: Improved CICFlowMeter

## Project Overview

This project contains an improved version of CICFlowMeter, a tool for analyzing network traffic and generating flow-based features from PCAP files. It is a Java-based desktop application that uses Swing for its graphical user interface. The core functionality relies on the `jnetpcap` library to capture and read network packets.

The primary goal of this improved version, as detailed in the project's `README.md` and associated research paper, was to fix bugs in the original CICFlowMeter to ensure more accurate TCP flow analysis.

## Key Technologies

*   **Language:** Java 1.8
*   **Build Tool:** Gradle
*   **UI:** Java Swing
*   **Core Libraries:**
    *   `jnetpcap`: For packet capture and analysis.
    *   `log4j`: For logging.
    *   `weka-stable`: Likely for data mining or machine learning tasks on the generated flow data.
    *   `jfreechart`: For creating charts and visualizations.

## Building and Running

The project uses a Gradle wrapper (`gradlew`), so a local Gradle installation is not required. The build configuration is defined in `build.gradle`.

### Building the Project

To build the project and create a JAR file, run the following command from the project root:

```bash
./gradlew build
```

### Running the Application

The application has both a GUI and a command-line interface.

**GUI Application:**

To run the main GUI application, use the `execute` task in Gradle. This task correctly sets the `java.library.path` to load the native `jnetpcap` libraries.

```bash
./gradlew execute
```

**Command-Line Application:**

To run the command-line version, use the `exeCMD` task. Note that the input and output paths are currently hardcoded in the `build.gradle` file.

```bash
./gradlew exeCMD
```

**Docker:**

The `README.md` provides instructions for building and running the application within a Docker container, which handles the environment setup.

1.  **Build the image:**
    ```bash
    docker build -t cicflowmeter .
    ```
2.  **Run the container:**
    ```bash
    docker run -v /path/to/pcap:/tmp/pcap cicflowmeter /tmp/pcap/input /tmp/pcap/output
    ```

## Development Conventions

*   The source code is located in the `src/main/java` directory.
*   The main class for the Swing application is `cic.cs.unb.ca.ifm.App`.
*   The main class for the command-line tool is `cic.cs.unb.ca.ifm.Cmd`.
*   Native libraries for `jnetpcap` are included in the `jnetpcap/` directory and must be available on the `java.library.path` at runtime. The provided Gradle tasks handle this.
*   Dependencies are managed in the `build.gradle` file.
