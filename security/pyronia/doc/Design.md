# Pyronia Design Outline

## Language-runtime components
* Developer policy parser
* Function pointer checker at language compile time
* Callgraph generator
* Inter-lib (i.e. at main application level) data tracking

#### Callgraph generator
* Stack inspection thread constructs the callgraph at runtime, recording the called module and any data tags at each stack frame
* SI thread registers with LSM and sends the collected callgraph to the LSM upon request

#### Inter-lib data tracking
* Goal: Track different data types between libraries to ensure that the correct data is sent to the correct destination server

## LSM components
* Callgraph-LSM communication
* Library memory protection
* Native code callgraph generator
* Library permissions checker in LSM
* Library FS namespace sandbox
* Exec sandbox

## Implementation
Due to the heavy use of native libraries and tools in IoT application development, the most suitable place for mediating access to sensors and other system resources is in the kernel, where the system calls resulting from accesses to these resources can be interposed. Thanks to its general design, we chose to implement the Pyronia reference monitor as a Linux Security Module (LSM), allowign us to realize our intra-process mandatory access control model. The Pyronia LSM is built on top of a fork of the AppArmor LSM and add additional checks to the existing AppArmor MAC checks.

#### Callgraph-LSM communication
* LSM opens a secure communication channel (dedicated Unix socket) to SI thread in language runtime at startup
* Whenever a callgraph check is required, the LSM calls back into the SI thread to request the collected callgraph information

#### Library Permissions checker in LSM
* Maintain separate permissions database for lib-level permissions
* Apply library-level permissions to process level as first step (this is the original AppArmor behaviour)
* Check the library-level permissions by traversing the callgraph if the process-level access control check passes
* Permissions computation: If there's an ACL for the library, compute itnersection of permissions so far, otherwise inherit
* Callgraph check: traverse starting from root node, check the resulting permission
* Hook into file.c `pyr_path_perm()` for file access control checks

## Open Questions
* What API do we expose from the LSM to the language runtime?
* Which memory protection approach do we use?
* How to handle multi-threaded programs?
