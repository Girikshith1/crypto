from src.bloom_filter import BloomFilter

def test_inserted_item_is_found():
    bf = BloomFilter(expected_items=100, bits_per_item=10)
    bf.add("malware-example.com")
    assert bf.might_contain("malware-example.com") is True

def test_uninserted_item_can_be_negative():
    bf = BloomFilter(expected_items=100, bits_per_item=20)
    bf.add("known-bad.example")
    assert bf.might_contain("completely-different-safe-domain.example") is False

def test_fp_probability_is_bounded():
    bf = BloomFilter(expected_items=100, bits_per_item=10)
    assert 0 <= bf.estimated_false_positive_rate(100) <= 1
