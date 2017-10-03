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
* Need to enumerate all possible ways to access various resources and determine which one to allow at runtime? Or should we require more hints from the developer?

#### Callgraph generator
* In progress
* Stack inspection thread constructs the callgraph at runtime
* SI thread generates the callgraph upon request from the LSM (e.g. at the time of a file open); callgraph includes the called module
* SI thread registers with LSM at startup and sends the collected callgraph via the LSM-communication channel

#### Inter-lib data tracking
Goal: Track different data types between libraries at the main application level to ensure that the expected data type is sent to the specified destination server

#### Security-critical library state protection
* Concern: Malicious library may call into a trusted library in order to change security-critical state (e.g. call networking library to change data destination)
* Goal: Protect sensitive library state against tampering and access by malicious/untrusted callers
* Provide a security API that allows benevolent library developers to mark security critical state
* Any access to marked state triggers an access control check much like a sensitive resource access in Pyronia
* Provides an additional layer of security for an IoT application
* Decorators?

#### Restrict dynamic language features
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

#### Process-based memory isolation of native libraries
* Pass exec'd native library process info to kernel
* Need to be able to link the sandbox process to the main app python process (parent could be tricky if there are multiple levels of execs)
* Build a whitelist of libraries that don't need to be triggered everytime
* Evaluate forking new proc every time vs caching common libs
* Get call graph via ptrace syscall?

#### Stack inspection and permissions checker in LSM
* Mostly done
* Maintain separate permissions database for lib-level permissions
* Apply library-level permissions to process level as first step (this is the original AppArmor behaviour)
* Inspect the callgraph received from the SI thread in python: check the library-level permissions by traversing the callgraph if the process-level access control check passes
* Permissions computation: If there's an ACL for the library, compute intersection of permissions so far, otherwise inherit
* Callgraph check: traverse starting from root node, check the resulting permission
* Hook into file.c `pyr_path_perm()` for file access control checks
* Need to check the permissions at read and write time as well: only checking access at file open time doesn't prevent the app from passing an allowed file pointer to a library without access to that file.
* Question: How do we reason about the semantics of the stack inspection decision? What are the possible side-effects? Need to enumrate all possible side-effects.
* Simple logic: based on intersection of all known libraries on stack

#### Library file system sandbox
* Create a library-specific "scratch space" on the file system that can only be accessed by the specified library and the main application.

#### Subprocess exec sandbox
Sandbox each binary that is executed by the main application or any library into its own process and track together with the main application.
* Do exec'd python processes need to be handled differently as exec'd binaries?

## Open Questions
* What API do we expose from the LSM to the language runtime?
* How to handle multi-threaded programs?
* What are all the possible side-effects of our MAC system?
* How do libs interact with the file system, in particular, which write policies do we allow?
* How do isolated third-party libraries share files?
