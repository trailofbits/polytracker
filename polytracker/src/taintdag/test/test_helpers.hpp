#pragma once

template<typename T = unsigned long>
T rand_limit(T limit) {
  return static_cast<T>(rand()) % limit;
}