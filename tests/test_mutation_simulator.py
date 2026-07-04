"""Unit tests for the mutation_simulator module."""

from src.core.mutation_simulator import apply_mutations, simulate_mutation_attack


class TestApplyMutations:
    def test_includes_original_and_case_variants(self):
        variants = apply_mutations("password")
        assert "password" in variants
        assert "Password" in variants
        assert "PASSWORD" in variants

    def test_includes_suffixed_variants(self):
        variants = apply_mutations("password")
        assert "password123" in variants
        assert "password1" in variants

    def test_includes_reversed_variant(self):
        variants = apply_mutations("abc")
        assert "cba" in variants

    def test_includes_leetspeak_variant(self):
        variants = apply_mutations("password")
        assert "p@$$w0rd" in variants


class TestSimulateMutationAttack:
    def test_direct_wordlist_match(self):
        result = simulate_mutation_attack("password", wordlist={"password"})
        assert result.vulnerable is True
        assert result.base_word == "password"

    def test_suffixed_mutation_detected(self):
        result = simulate_mutation_attack("password123", wordlist={"password"})
        assert result.vulnerable is True
        assert result.base_word == "password"

    def test_capitalized_mutation_detected(self):
        result = simulate_mutation_attack("Password", wordlist={"password"})
        assert result.vulnerable is True

    def test_leetspeak_mutation_detected(self):
        result = simulate_mutation_attack("p@$$w0rd", wordlist={"password"})
        assert result.vulnerable is True

    def test_unrelated_strong_password_not_vulnerable(self):
        result = simulate_mutation_attack("Xk9$mQ2vL7!p_random", wordlist={"password"})
        assert result.vulnerable is False
        assert result.base_word is None