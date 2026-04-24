"""Shared pytest fixtures — builds a temporary SQLite DB for tests."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest


@pytest.fixture
def sample_db(tmp_path: Path) -> Path:
    """A small SQLite file with two tables and a view for tests to query."""
    db_path = tmp_path / "sample.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            plan TEXT
        );

        INSERT INTO users (email, plan) VALUES
            ('alice@example.com', 'pro'),
            ('bob@example.com', 'free'),
            ('charlie@example.com', 'pro'),
            ('dave@example.com', 'enterprise');

        CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            amount_cents INTEGER NOT NULL,
            placed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        INSERT INTO orders (user_id, amount_cents) VALUES
            (1, 1200),
            (1, 4500),
            (2, 800),
            (3, 2000),
            (4, 15000);

        CREATE VIEW active_pro_users AS
            SELECT id, email FROM users WHERE plan = 'pro';
        """
    )
    conn.commit()
    conn.close()
    return db_path
