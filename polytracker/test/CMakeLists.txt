message(STATUS "Looking for python3.7")
find_program(Python37 "python3.7")
if(Python37 STREQUAL "Python37-NOTFOUND")
    message(STATUS "Looking for python3.7 - not found")
    message(FATAL_ERROR "The `python3.7` program was not found; that program is necessary to run tests")
endif()
message(STATUS "Looking for python3.7 - found: ${Python37}")

message(STATUS "Looking for python3.7 venv module")
execute_process(COMMAND ${Python37} -mvenv -h
                RESULT_VARIABLE rc
                OUTPUT_VARIABLE output
                ERROR_VARIABLE output)
if (NOT (rc EQUAL 0))
    message(STATUS "Looking for python3.7 venv module - not found")
    message(FATAL_ERROR "${output}The `venv` module for python3.7 doesn't seem to be installed; that module is necessary to run tests")
endif()
message(STATUS "Looking for python3.7 venv module - found")
