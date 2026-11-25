from re import compile as compile_regex


# reference: https://www.w3.org/TR/xml/#charsets
# > Character Range
# >
# > [2] Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
# >        /* any Unicode character, excluding the surrogate blocks, FFFE, and FFFF. */
XML_CHARACTER_RANGE_INVALID_PATTERN = (
    compile_regex("[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF]")
)


def is_invalid_xml_string(value):
    match = XML_CHARACTER_RANGE_INVALID_PATTERN.search(value)
    return match


def is_valid_xml_string(value):
    match = not is_invalid_xml_string(value)
    return match
