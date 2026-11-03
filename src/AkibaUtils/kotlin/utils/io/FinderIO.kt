// Disabled: per-coroutine stdout capture for FinderIO. `CoroutineOutputBuffer`
// was a `ThreadContextElement` that swapped a ThreadLocal `StringWriter` in on
// dispatch, so a coroutine's output could be captured instead of reaching the
// console. Nothing references it, so the whole file stays out of the build.
