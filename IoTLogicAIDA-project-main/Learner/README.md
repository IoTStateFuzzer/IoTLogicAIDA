# IoTLogicAIDA Learner

IoTLogicAIDA Learner is a Java project for actively learning the state machine of a System Under Test (SUT). It uses [LearnLib](https://learnlib.de/) to build Mealy-machine models from observed input/output behavior and writes the learned models to the `result` directory.

The project is designed for IoT or GUI-driven systems where the learner communicates with an external SUT controller over TCP. The learner sends input symbols to the SUT, receives output symbols, refines its hypothesis, and exports the resulting automata as Graphviz DOT files.

## What It Does

- Loads an input alphabet from `src/main/resources/input_bat`.
- Starts a TCP server and waits for a SUT client to connect.
- Uses LearnLib's TTT Mealy learner for active automata learning.
- Uses the Wp-method equivalence oracle to search for counterexamples.
- Caches membership-query results to reduce repeated SUT interactions.
- Checks unstable counterexamples by voting when direct SUT interaction is used.
- Learns a base model first, then optionally performs state exploration.
- Saves intermediate hypotheses and final models under `result`.

## Project Structure

```text
.
+-- pom.xml
+-- README.md
+-- result/
+-- src/main/java/org/example/
|   +-- IoTStateFuzzer.java      # Program entry point
|   +-- Learner.java             # LearnLib learning loop
|   +-- Mediator.java            # SUL adapter between LearnLib, cache, and SUT
|   +-- NetworkManager.java      # TCP communication with the SUT client
|   +-- CacheManager.java        # Query cache persistence
|   +-- Configuration.java       # Configuration loader
|   +-- AlphabetManager.java     # Alphabet loader
|   +-- Tool.java                # DOT export and voting helpers
|   +-- LogManager.java          # Logging wrapper
+-- src/main/resources/
    +-- conf.properties          # Runtime configuration
    +-- input_bat                # Input alphabet, one symbol per line
    +-- logback.xml              # Logging configuration
```

## Requirements

- JDK 11 or later
- Maven
- Graphviz, if you want PDF files generated from DOT output
- A SUT/client process that can connect to the learner TCP server

Graphviz is optional for learning itself, but `Tool.writeDotModel` calls the `dot` command after writing each DOT file. If Graphviz is not installed or `dot` is not on `PATH`, DOT files can still be used directly.

## Configuration

The default configuration file is:

```text
src/main/resources/conf.properties
```

Important options:

| Property | Description |
| --- | --- |
| `proName` | Logger/project name. |
| `port` | TCP port used by the learner server. Default: `9999`. |
| `outputDir` | Directory for generated models, caches, logs, and statistics. Default: `result`. |
| `alphabetFile` | Path to the alphabet file. Default: `src/main/resources/input_bat`. |
| `cacheFile` | Cache file for base-model learning. Stored under `outputDir`. |
| `checkCacheFile` | Cache file for state-exploration learning. Stored under `outputDir`. |
| `baseDepth` | Wp-method search depth for the base model. |
| `fuzzDepth` | Wp-method search depth for state exploration. If `0`, state exploration stops immediately. |
| `voteNum` | Number of repeated checks used when validating counterexamples. |
| `stateNum` | Expected or configured state count used by the project logic. |
| `useCache` | `yes` to replay cached query results before interacting with the SUT. |
| `useTimestamp` | `yes` to store query timestamps in cache files. |
| `useNoElement` | `yes` to short-circuit following outputs after `NoElement`. |
| `useKnowledge` | `yes` to use the base model during state exploration. |
| `useHistory` | `yes` to reuse historical query-prefix results. |
| `queryOut` | `yes` to print query logs. |

## Alphabet File

The alphabet file contains the input symbols used by LearnLib. Put one symbol on each line:

```text
user1|local|Invite
```

The learner also uses special protocol symbols internally:

- `Reset`
- `NoElement`
- `Reset_suc`
- `RestartLearning`

Avoid reusing those names as ordinary SUT actions unless your client intentionally implements that protocol behavior.

## SUT Communication

`IoTStateFuzzer` creates a `NetworkManager`, opens a server socket on the configured port, and waits for a client connection. After the client connects, the learner sends an `alphabet` system message.

Messages are sent as bytes where the first byte identifies the message type:

| Type index | Meaning |
| --- | --- |
| `0` | System message |
| `1` | LearnLib/reset message |
| `2` | Query message |

The remaining bytes are the UTF-8 string payload. The SUT client should return messages in the same format: one leading type byte followed by the response payload.

## Build

```bash
mvn clean package
```

## Run

1. Configure `src/main/resources/conf.properties`.
2. Fill `src/main/resources/input_bat` with the SUT input alphabet.
3. Start the SUT/client process so it can connect to the configured learner port.
4. Run the learner:

```bash
mvn exec:java -Dexec.mainClass=org.example.IoTStateFuzzer
```

If the Maven Exec plugin is not configured in your environment, run the compiled class directly with the Maven-built classpath, or add the plugin to `pom.xml`.

## Output

Generated files are written to `result` by default.

Typical model files:

```text
result/base_model_hypothesis_<round>.dot
result/base_model_final_model.dot
result/state_fuzzing_hypothesis_<round>.dot
result/state_fuzzing_final_model.dot
```

When Graphviz is available, corresponding PDF files are also generated by the `dot` command.

Other output files include:

- `cache.txt`: cached base-model query traces.
- `cache_check.txt`: cached state-exploration query traces.
- `statistics.txt`: conflict and counterexample-check statistics.
- `myLogFile.log`: runtime logs.

## Learning Flow

1. Load configuration and input alphabet.
2. Wait for the SUT client to connect.
3. Initialize the cache and LearnLib learner.
4. Learn the base Mealy-machine model with TTT.
5. Search for counterexamples with the Wp-method.
6. Refine the hypothesis until no counterexample is found.
7. Save `base_model_final_model.dot`.
8. Reconfigure for state exploration.
9. Learn and save the state-exploration model when `fuzzDepth > 0`.

## Notes

- The current entry point is `org.example.IoTStateFuzzer`.
- The default alphabet file in this repository may be empty; add SUT actions before running meaningful learning.
- The learner depends on an external SUT/client implementation. This repository contains the learner side, not the SUT controller.
