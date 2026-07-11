3) Docker hardening:
Behavioral telemetry: Expand beyond network connections to include process trees, file access, registry/startup persistence (on Windows), child processes, and installation behavior. This gives ClawNet much richer evidence.


Sandbox hardening: Treat Docker as one layer, not the security boundary. Run containers with reduced privileges (rootless where possible, dropped capabilities, read-only filesystem where appropriate, seccomp/AppArmor, resource limits) and make those protections part of the product.

- "Open source repos aren't the only threat."

Your product says
Scan GitHub repos.
Reality:
The dangerous part is usually
pip install
npm install
cargo install
go get
Dependencies execute code.
You need to monitor installation too.


- make sure Malware never escapes Docker.