buff="\\xff\\xff\\xff\\x7f\\xdf\\xce\\x00\\xff"
echo -e "\n\n>>Debug build"
echo -e "$buff" | ./debug/ub

echo -e "\n\n>>Release build"
echo -e "$buff" | ./release/ub

echo -e "\n\n>>Instrumented debug build"
echo -e "$buff" | POLYDB=Debug.tdag POLYTRACKER_STDIN_SOURCE=1 POLYTRACKER_STDOUT_SINK=1 POLYTRACKER_STDERR_SINK=1 POLYTRACKER_LOG_CONTROL_FLOW=1 ./debug/ub.instrumented 

echo -e "\n>>Instrumented release build"
echo -e "$buff" | POLYDB=Release.tdag POLYTRACKER_STDIN_SOURCE=1 POLYTRACKER_STDOUT_SINK=1 POLYTRACKER_STDERR_SINK=1 POLYTRACKER_LOG_CONTROL_FLOW=1 ./release/ub.instrumented 