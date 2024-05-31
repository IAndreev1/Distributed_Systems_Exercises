# Distributed Systems Exercises

This repository contains the solutions for two distributed systems exercises from the Distributed Systems Group (DSG) course at the Institute of Information Systems Engineering.

## Overview
The project is implemented in Java and consists of multiple components organized into different packages. The exercises involve developing a basic electronic mail service with a custom message transfer protocol (DMTP) and a message access protocol (DMAP).


## Exercise 1: Basic Mail Service

### Objective
To implement a basic mail service that includes a message transfer protocol (DMTP), a message access protocol (DMAP), and core server components.

### Components

1. **Message Transfer Protocol (DMTP)**
    - A plaintext application-layer protocol for exchanging messages.
    - Commands: `begin`, `to`, `from`, `subject`, `data`, `send`, `quit`.
    - Server responses: `ok`, `error <explanation>`.

2. **Message Access Protocol (DMAP)**
    - Protocol for accessing stored messages.
    - Commands: `login`, `list`, `show`, `delete`, `logout`, `quit`.
    - Server responses follow a similar pattern to DMTP.

3. **Servers**
    - **Transfer Server**: Forwards messages to mailbox servers and performs domain lookups.
    - **Mailbox Server**: Stores and manages emails for specific domains, providing user access through DMAP.
    - **Monitoring Server**: Receives and displays usage statistics from transfer servers via UDP.

### Implementation Details
- **Transfer Server**: Manages domain lookups and forwards messages. Handles message delivery failures by notifying the sender.
- **Mailbox Server**: Accepts and stores messages, providing access through DMAP. Handles multiple connections and manages user mailboxes.
- **Monitoring Server**: Receives statistics on outgoing traffic and provides a command-line interface for data access.

### Technologies Used
- Java
- TCP and UDP socket communication
- Multithreading

## Exercise 2: Advanced Message Service

### Objective
To extend the basic mail service by adding advanced features such as encryption, authentication, and improved error handling.

### Components

1. **Enhanced DMTP and DMAP Protocols**
    - Addition of encryption for secure message transfer.
    - Improved authentication mechanisms for user access.

2. **Servers**
    - **Enhanced Transfer Server**: Includes encrypted message forwarding and advanced error notifications.
    - **Enhanced Mailbox Server**: Improved security features for storing and accessing emails.
    - **Enhanced Monitoring Server**: Provides more detailed usage statistics and anomaly detection.

### Implementation Details
- **Encryption**: Secure communication using TLS/SSL for message transfer.
- **Authentication**: Implemented robust user authentication mechanisms.
- **Error Handling**: Improved handling and logging of errors to enhance reliability.

### Technologies Used
- Java
- TLS/SSL for encryption
- Secure authentication protocols

## How to Run

1. **Clone the Repository**
    ```bash
    git clone https://github.com/yourusername/distributed-systems-exercises.git
    cd distributed-systems-exercises
    ```

2. **Compile the Code**
    ```bash
    javac -d bin $(find . -name "*.java")
    ```

3. **Run the Servers**
    Each server application can be started using specific Gradle tasks. The main method of each server receives the application's component ID as its first argument.

    - To list all available tasks:
        ```bash
        ./gradlew tasks --all
        ```

    - Start the Monitoring Server:
        ```bash
        ./gradlew --console=plain run-monitoring
        ```

    - Start the Transfer Server (example for transfer-1):
        ```bash
        ./gradlew --console=plain run-transfer -Pargs=transfer-1
        ```

    - Start the Mailbox Server (example for mailbox-1):
        ```bash
        ./gradlew --console=plain run-mailbox -Pargs=mailbox-1
        ```

4. **Communicate with the servers**
    - Use tools like Netcat or Telnet to communicate with the servers.
