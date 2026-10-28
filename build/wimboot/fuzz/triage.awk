# One line per crash report in fuzzer logs: "<kind> @ <first wimboot frame>"
function flush() { if (kind != "") print kind " @ " loc; kind = "" }
/==fuzz== BUG:|ERROR: AddressSanitizer:|AddressSanitizer: hard rss limit|runtime error:|==fuzz== timeout|==fuzz== killed/ {
  flush(); kind = $0; loc = "?"
  sub(/^.*==fuzz== /, "", kind)
  sub(/^.*AddressSanitizer: hard rss/, "memory limit: asan hard rss", kind)
  sub(/^killed by the memory cap/, "memory limit: killed by the scope cap", kind)
  sub(/^.*ERROR: AddressSanitizer: /, "asan: ", kind); sub(/ on (unknown )?address.*/, "", kind)
  sub(/^asan: (requested allocation size|out of memory|allocation-size-too-big).*/, "memory limit: asan allocation over max_allocation_size_mb", kind)
  sub(/^.*runtime error: /, "ubsan: ", kind); gsub(/[0-9]+/, "N", kind)
  next
}
kind != "" && loc == "?" && / in [A-Za-z_0-9]+ .*\/src\/src\// {
  match($0, / in [A-Za-z_0-9]+ /); fn = substr($0, RSTART + 4, RLENGTH - 5)
  f = $NF; sub(/.*\/src\/src\//, "", f); loc = fn " " f
}
END { flush() }
