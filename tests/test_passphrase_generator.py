"""Unit tests for the passphrase_generator module."""

import math

import pytest

from src.core.passphrase_generator import FALLBACK_WORDLIST, generate_passphrase, load_wordlist


class TestGeneratePassphrase:
    def test_default_word_count_is_six(self):
        result = generate_passphrase(wordlist=FALLBACK_WORDLIST)
        assert result.word_count == 6
        assert len(result.passphrase.split("-")) == 6

    def test_custom_word_count(self):
        result = generate_passphrase(word_count=4, wordlist=FALLBACK_WORDLIST)
        assert result.word_count == 4
        assert len(result.passphrase.split("-")) == 4

    def test_custom_separator(self):
        result = generate_passphrase(word_count=3, separator="_", wordlist=FALLBACK_WORDLIST)
        assert result.passphrase.count("_") == 2

    def test_entropy_matches_formula(self):
        result = generate_passphrase(word_count=5, wordlist=FALLBACK_WORDLIST)
        expected = round(5 * math.log2(len(FALLBACK_WORDLIST)), 2)
        assert result.entropy_bits == expected

    def test_zero_word_count_raises(self):
        with pytest.raises(ValueError):
            generate_passphrase(word_count=0, wordlist=FALLBACK_WORDLIST)

    def test_append_random_digit_adds_digit(self):
        result = generate_passphrase(
            word_count=3, wordlist=FALLBACK_WORDLIST, append_random_digit=True
        )
        assert result.passphrase[-1].isdigit()

    def test_words_come_from_wordlist(self):
        small_list = ["alpha", "bravo"]
        result = generate_passphrase(word_count=10, wordlist=small_list, separator="-")
        for word in result.passphrase.split("-"):
            assert word.lower() in small_list

    def test_two_generations_differ(self):
        first = generate_passphrase(word_count=6, wordlist=FALLBACK_WORDLIST).passphrase
        second = generate_passphrase(word_count=6, wordlist=FALLBACK_WORDLIST).passphrase
        assert first != second


class TestLoadWordlist:
    def test_falls_back_when_file_missing(self, tmp_path):
        words = load_wordlist(tmp_path / "does_not_exist.txt")
        assert words == FALLBACK_WORDLIST

    def test_loads_from_file_when_present(self, tmp_path):
        wordfile = tmp_path / "custom.txt"
        wordfile.write_text("one\ntwo\nthree\n", encoding="utf-8")
        words = load_wordlist(wordfile)
        assert words == ["one", "two", "three"]
