// Disabled: interactive int-input helpers for a console-driven flow.
// `inputIntInRange` ran the reader on a throwaway `Thread` joined with a timeout
// and fell back to a default when no input arrived, so a headless run could not
// block on stdin. Nothing references it, so the whole file stays out of the build.
