/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <catch2/catch.hpp>
#include <stdlib.h>

#include "taintdag/storage.h"

#include "utils.h"

namespace taintdag {
    TEST_CASE("Type properties of FixedSizeFile", "[FixedSizeFile]") {
        // Don't want multiple copies referring to the same file
        REQUIRE(!std::is_copy_constructible_v<FixedSizeFile>);
        REQUIRE(!std::is_copy_assignable_v<FixedSizeFile>);
      
        // NOTE(hbrodin): The FixedSizeFile is currently not move
        // constructible/assignable. There is nothing preventing such an
        // implementation. Currently there is no need so leave this as is.
        REQUIRE(!std::is_move_assignable_v<FixedSizeFile>);
        REQUIRE(!std::is_move_constructible_v<FixedSizeFile>);
    }
      
    TEST_CASE("Type properties of MMapFile", "[MMapFile]") {
        // Don't want multiple copies referring to the same regions
        REQUIRE(!std::is_copy_constructible_v<MMapFile>);
        REQUIRE(!std::is_copy_assignable_v<MMapFile>);
        
        // NOTE(hbrodin): The MMapFile is currently not move constructible/assignable.
        // Behavior is currently inherited from FixedSizeFile. Should that change,
        // the MMapFile would change as well.
        REQUIRE(!std::is_move_assignable_v<MMapFile>);
        REQUIRE(!std::is_move_constructible_v<MMapFile>);
    }
} // namespace taintdag