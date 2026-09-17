def test_package_version_is_050():
    import masterkey_agent

    assert masterkey_agent.__version__ == "0.5.0"
