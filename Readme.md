# Message Oriented Transport over UDP

**Instructor:** Prof. Sandip Chakraborty  
**Course:** Computer Networks Lab, IIT Kharagpur

## Overview

This project implements a **message-oriented transport layer** on top of UDP by designing a custom wrapper over the C Socket API. It ensures message boundary preservation, safe concurrency, and resilience under unreliable network conditions.

## Features

- **Message-Oriented Semantics**
  - Preserves application-level message boundaries over UDP.
  - Maintains per-socket send/receive tables to handle fixed-size datagram aggregation.

- **Thread-safe Socket Handling**
  - Uses POSIX `pthread` library to support concurrent send/receive operations.
  - Protects shared state with **mutex locks** to ensure safe multi-threaded access.

- **Resource Management**
  - Ensures proper deallocation of memory buffers and internal tables upon socket closure.
  - Prevents memory leaks even under abnormal termination.

- **Unreliable Channel Simulation**
  - Simulates packet drops based on configurable probability.
  - Validates retransmission logic and robustness of message delivery under high-loss environments.

## Key Concepts

- UDP is inherently datagram-oriented and does not guarantee delivery, order, or message boundaries.
- This layer simulates a reliable, message-oriented protocol by:
  - Explicit boundary tracking,
  - Message buffering and assembly,
  - Retry logic for dropped messages.

## Technologies Used

- **Language:** C  
- **Concurrency:** POSIX Threads (`pthread`)  
- **Networking:** BSD Sockets over UDP  
- **Synchronization:** Mutex locks and condition variables

Use the provided config to set packet drop probability for testing.


## Author

**Sumit Kumar**
Third-year Undergraduate, IIT Kharagpur
[GitHub: SumitKumar-17](https://github.com/SumitKumar-17)

> "Designed with reliability in mind, layered with concurrency, and tested under failure."
