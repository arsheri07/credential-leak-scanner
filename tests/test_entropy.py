from credscan.entropy import shannon_entropy


def test_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_single_repeated_char_is_zero():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_two_symbols_evenly_is_one_bit():
    assert abs(shannon_entropy("abababab") - 1.0) < 1e-9


def test_random_key_beats_english_word(fake):
    assert shannon_entropy(fake["generic"]) > shannon_entropy("passwordpassword") + 1
