"""Realistic fake filler for Parquet and SQLite tables.

Kept separate from the text templates because structured data needs
per-column fake values (names, addresses, dates, amounts), not prose.
Shared by ``parquet_writer`` and ``sqlite_writer`` so column content
stays consistent between the two formats.
"""
from __future__ import annotations

import datetime as _dt
import random
import uuid
from typing import Optional


EN_FIRST = [
    "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael",
    "Linda", "William", "Elizabeth", "David", "Barbara", "Richard", "Susan",
    "Joseph", "Jessica", "Thomas", "Sarah", "Charles", "Karen",
]
EN_LAST = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
    "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
]
# Canadian French names — common in QC registries.
FR_FIRST = [
    "Jean", "Marie", "Pierre", "Louise", "Michel", "Sylvie", "François",
    "Nicole", "Luc", "Hélène", "Marc", "Martine", "Paul", "Christine",
    "Philippe", "Josée", "Claude", "Lise", "Daniel", "Diane",
]
FR_LAST = [
    "Tremblay", "Gagnon", "Roy", "Côté", "Bouchard", "Gauthier", "Morin",
    "Lavoie", "Fortin", "Gagné", "Ouellet", "Bélanger", "Pelletier",
    "Lévesque", "Bergeron", "Leblanc", "Paquette", "Girard", "Simard",
    "Boucher",
]

EN_CITIES = [
    ("Toronto", "ON"), ("Vancouver", "BC"), ("Calgary", "AB"), ("Ottawa", "ON"),
    ("Edmonton", "AB"), ("Winnipeg", "MB"), ("Hamilton", "ON"),
    ("Halifax", "NS"), ("Victoria", "BC"), ("Saskatoon", "SK"),
]
FR_CITIES = [
    ("Montréal", "QC"), ("Québec", "QC"), ("Laval", "QC"), ("Gatineau", "QC"),
    ("Sherbrooke", "QC"), ("Saguenay", "QC"), ("Lévis", "QC"),
    ("Trois-Rivières", "QC"), ("Longueuil", "QC"), ("Terrebonne", "QC"),
]

STREETS_EN = ["Main St", "King St", "Queen St", "Dundas St", "Yonge St",
              "Bloor St", "College St", "Bay St", "Front St", "Adelaide St"]
STREETS_FR = ["rue Sainte-Catherine", "boulevard René-Lévesque", "rue Notre-Dame",
              "avenue du Mont-Royal", "rue Saint-Denis", "rue Sherbrooke",
              "boulevard Saint-Laurent", "avenue du Parc", "rue Peel",
              "rue Crescent"]


def fake_name(rng: random.Random, language: str = "en") -> str:
    if language == "fr-CA":
        return f"{rng.choice(FR_FIRST)} {rng.choice(FR_LAST)}"
    # Mix French-Canadian names into English runs at ~20% to reflect the
    # real distribution at Canadian banks (where we expect evadex to be run).
    if rng.random() < 0.2:
        return f"{rng.choice(FR_FIRST)} {rng.choice(FR_LAST)}"
    return f"{rng.choice(EN_FIRST)} {rng.choice(EN_LAST)}"


def fake_address(rng: random.Random, language: str = "en") -> str:
    if language == "fr-CA":
        street_num = rng.randint(1, 9999)
        street = rng.choice(STREETS_FR)
        city, prov = rng.choice(FR_CITIES)
        return f"{street_num} {street}, {city}, {prov}"
    street_num = rng.randint(1, 9999)
    street = rng.choice(STREETS_EN)
    city, prov = rng.choice(EN_CITIES)
    return f"{street_num} {street}, {city}, {prov}"


def fake_date(rng: random.Random, start_year: int = 1960, end_year: int = 2010) -> str:
    """ISO date string in [start_year, end_year]. Dates pre-2011 for DOB realism."""
    start = _dt.date(start_year, 1, 1)
    end = _dt.date(end_year, 12, 31)
    days = (end - start).days
    return (start + _dt.timedelta(days=rng.randint(0, days))).isoformat()


def fake_timestamp(rng: random.Random, years_back: int = 3) -> str:
    """ISO timestamp within the last *years_back* years."""
    now = _dt.datetime(2026, 4, 18, 12, 0, 0)
    delta_seconds = rng.randint(0, years_back * 365 * 24 * 3600)
    return (now - _dt.timedelta(seconds=delta_seconds)).isoformat()


def fake_amount(rng: random.Random) -> float:
    """Transaction amount in (10, 5000) with two decimals."""
    return round(rng.uniform(10.0, 5000.0), 2)


def fake_uuid(rng: random.Random) -> str:
    """Deterministic UUID for reproducible test fixtures under a seeded RNG."""
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def normalize_language(language: Optional[str]) -> str:
    """Normalise ``--language`` values to either 'en' or 'fr-CA'."""
    if not language:
        return "en"
    lang = language.strip().lower()
    if lang in ("fr-ca", "fr_ca", "frca", "fr"):
        return "fr-CA"
    return "en"
