from evadex.variants.context_injection import ContextInjectionGenerator

VALUE = "4111111111111111"


def _variants(value=VALUE):
    return list(ContextInjectionGenerator().generate(value))


def test_generates_all_templates():
    variants = _variants()
    # 10 English + 10 French CA templates
    assert len(variants) == 20


def test_every_variant_contains_value():
    for v in _variants():
        assert VALUE in v.value, f"Expected {VALUE!r} in {v.technique!r} variant: {v.value!r}"


def test_generator_name():
    for v in _variants():
        assert v.generator == "context_injection"


def test_email_body_contains_newlines():
    variants = _variants()
    email = next(v for v in variants if v.technique == "email_body")
    assert "\n" in email.value
    assert VALUE in email.value


def test_json_record_is_valid_json():
    import json
    variants = _variants()
    rec = next(v for v in variants if v.technique == "json_record")
    parsed = json.loads(rec.value)
    assert parsed["ref"] == VALUE


def test_xml_record_contains_value():
    variants = _variants()
    xml = next(v for v in variants if v.technique == "xml_record")
    assert f"<data>{VALUE}</data>" in xml.value


def test_value_with_braces_is_safe():
    # Values containing { or } should not raise or corrupt output
    tricky = "{not_a_template}"
    variants = list(ContextInjectionGenerator().generate(tricky))
    for v in variants:
        assert tricky in v.value


def test_no_applicable_categories_restriction():
    gen = ContextInjectionGenerator()
    assert gen.applicable_categories is None


def test_technique_names_are_unique():
    techniques = [v.technique for v in _variants()]
    assert len(techniques) == len(set(techniques))
