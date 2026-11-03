// Disabled: `NamedPipe`, a Linux-only `AutoCloseable` over a FIFO path. It
// created the pipe with `mkfifo` on construction and removed it in `close()`,
// both through `Runtime.exec`, and threw on any non-Linux OS. Nothing references
// it, so the whole file stays out of the build.
