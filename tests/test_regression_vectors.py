import json
from io import BytesIO
from pathlib import Path

import pytest

from mail_auth_review.headers import read_auth_fields
from mail_auth_review.report import render_json, review

VECTORS = {
    path.stem: json.loads(path.read_text(encoding="utf-8"))
    for path in sorted(Path(__file__).with_name("regression_vectors").glob("*.json"))
}


@pytest.mark.parametrize("vector", VECTORS.values(), ids=VECTORS.keys())
def test_regression_vector(vector):
    source = BytesIO("".join(vector["headers"]).encode("utf-8"))
    report = review(read_auth_fields(source), vector["servers"])
    payload = json.loads(render_json(report))
    assert {
        key: payload[key]
        for key in ("server_filter", "total_fields", "excluded_fields", "fields")
    } == vector["expected"]


def test_regression_vector_titles():
    titles = [vector["title"] for vector in VECTORS.values()]
    assert titles and all(
        isinstance(title, str)
        and title.strip()
        and title.isprintable()
        and len(title) < 72
        for title in titles
    )
    assert len(set(titles)) == len(titles)
