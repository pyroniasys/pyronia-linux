# Pyronia Design Outline

## Language-runtime components
* Developer policy parser
* Stack inspection and callgraph generator
* Inter-lib (i.e. at main application level) data tracking
* API for protecting security-critical library state
* Restrict dangerous/insecure language features
  * Function pointer checker at language compile time
  * Modify reflection library to trigger security check

#### Developer policy parser
* Look at apparmor_parser code in apparmor userland API
* Translates the high-level Pyronia permissions (e.g. CAM_PERM) into corresponding path and file access rules
* Hook into policy_unpack.c

#### Stack inspection and callgraph generator
* Stack inspection thread constructs the callgraph at runtime
* SI thread generates the callgraph upon request from the LSM (e.g. at the time of a file open); callgraph includes the called module and any data tags at each stack frame
* SI thread registers with LSM at startup and sends the collected callgraph via the LSM-communication channel

#### Inter-lib data tracking
Goal: Track different data types between libraries at the main application level to ensure that the expected data type is sent to the specified destination server

#### Security-critical library state protection
* Concern: Malicious library may call into a trusted library in order to change security-critical state (e.g. call networking library to change data destination)
* Goal: Protect sensitive library state against tampering and access by malicious/untrusted callers
* Provide a security API that allows benevolent library developers to mark security critical state
* Any access to marked state triggers an access control check much like a sensitive resource access in Pyronia
* Provides an additional layer of security for an IoT application

#### Restrict dangerous/insecure language features
Some language features are considered dangerous in the context of library-level MAC, and should no longer be supported by the language:
* Monkey-patching (dynamic function pointer reassignment) --> forbidden (check function pointer at compile time)
* Reflection library --> trigger security check
* Stack frame manipulation (via stack tracer) --> forbidden

## LSM components
* Secure Callgraph-LSM communication
* Native code callgraph generator
* Library permissions checker in LSM
* Library FS sandbox
* Subprocess exec sandbox

## Implementation
Due to the heavy use of native libraries and tools in IoT application development, the most suitable place for mediating access to sensors and other system resources is in the kernel, where the system calls resulting from accesses to these resources can be interposed. Thanks to its general design, we chose to implement the Pyronia reference monitor as a Linux Security Module (LSM), allowign us to realize our intra-process mandatory access control model. The Pyronia LSM is built on top of a fork of the AppArmor LSM and add additional checks to the existing AppArmor MAC checks.

#### Callgraph-LSM communication
* LSM opens a secure communication channel (dedicated Unix socket) to SI thread in language runtime at startup
* Whenever a callgraph check is required, the LSM calls back into the SI thread to request callgraph information

#### Native code callgraph generator
This is needed to create a comprehensive callgraph across the language runtime and native contexts.

#### Library Permissions checker in LSM
* Maintain separate permissions database for lib-level permissions
* Apply library-level permissions to process level as first step (this is the original AppArmor behaviour)
* Check the library-level permissions by traversing the callgraph if the process-level access control check passes
* Permissions computation: If there's an ACL for the library, compute intersection of permissions so far, otherwise inherit
* Callgraph check: traverse starting from root node, check the resulting permission
* Hook into file.c `pyr_path_perm()` for file access control checks

#### Library file system sandbox
Create a library-specific "scratch space" on the file system that can only be accessed by the specified library and the main application.

#### Subprocess exec sandbox
Sandbox each binary that is executed by the main application or any library into its own process and track together with the main application.

## Open Questions
* What API do we expose from the LSM to the language runtime?
* Which memory protection approach do we use?
* How to handle multi-threaded programs?
