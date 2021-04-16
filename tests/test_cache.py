from polytracker.cache import LRUCache


def test_cache():
    cache: LRUCache[int, str] = LRUCache(max_size=10)
    for i in range(10):
        cache[i] = str(i)
    assert len(cache) == 10
    cache[10] = "10"
    assert len(cache) == 10
    assert 0 not in cache
    _ = 1 in cache
    cache[11] = "11"
    assert len(cache) == 10
    assert 1 in cache
    assert 2 not in cache
    for _ in cache:
        # make sure we can iterate over the cache, because it will mutate the underlying ordered dict in the process
        pass
    # the cache should now look like this:
    assert list(cache) == [3, 4, 5, 6, 7, 8, 9, 10, 11, 1]
    # make sure we update the LRU cache on partial iteration
    for i, _ in enumerate(cache):
        if i == 4:
            break
    assert list(cache) == [8, 9, 10, 11, 1, 3, 4, 5, 6, 7]
    for number, string in cache.items():
        assert str(number) == string
