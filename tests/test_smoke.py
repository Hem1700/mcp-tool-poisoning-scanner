def test_package_imports():
    import tool_scan  # noqa: F401


def test_package_has_version():
    import tool_scan

    assert tool_scan.__version__ == "0.1.0"
