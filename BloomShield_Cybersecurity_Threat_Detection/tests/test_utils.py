from src.utils import normalize_indicator, indicator_features

def test_normalization():
    assert normalize_indicator("HTTPS://Example.COM/") == "example.com"

def test_features_exist():
    f = indicator_features("example.com")
    assert f["length"] > 0
    assert "entropy" in f
