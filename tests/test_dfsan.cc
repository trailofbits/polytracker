/*
 * test_dfsan.cc
 *
 *  Created on: Mar 19, 2020
 *      Author: carson
 */
#include <cstdlib>
//TODO Restructure the polytracker directory hierarchy
#include "../dfsan/dfsan_includes/catch2/catch.hpp"
#include "../dfsan/dfsan_rt/dfsan/dfsan.h"
#include "../dfsan/dfsan_rt/dfsan_interface.h"

#define BUFFER_SIZE 10

//Unit tests for dfsan interface
TEST_CASE( "dfsan_set_label", "[dfsan_set_label]" ) {
    char * mem = malloc(sizeof(char) * BUFFER_SIZE);

    REQUIRE(mem != nullptr);

    SECTION( "Testing set label single size" ) {
        dfsan_set_label(1, mem, sizeof(char));
        REQUIRE( mem[0] == 1 );
        memset(mem, 0, sizeof(char) * BUFFER_SIZE);
    }
    SECTION( "Testing set label multiple size" ) {
    	dfsan_set_label(1, mem, sizeof(char) * BUFFER_SIZE);
    	REQUIRE( mem[0] == 1 );
    	REQUIRE( mem[9] == 1 );
    	memset(mem, 0, sizeof(char) * BUFFER_SIZE);
    }
    free(mem);
}
