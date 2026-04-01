from evadex.variants.splitting import SplittingGenerator


def test_generates_multiple():
    gen = SplittingGenerator()
    variants = list(gen.generate("4532015112830366"))
    assert len(variants) >= 6


def test_json_split():
    gen = SplittingGenerator()
    variants = list(gen.generate("4532015112830366"))
    jsplit = [v for v in variants if v.technique == "json_field_split"]
    assert jsplit
    assert '"part1"' in jsplit[0].value


def test_html_comment():
    gen = SplittingGenerator()
    variants = list(gen.generate("AB"))
    html_c = [v for v in variants if v.technique == "html_comment_injection"]
    assert html_c
    assert '<!---->' in html_c[0].value
