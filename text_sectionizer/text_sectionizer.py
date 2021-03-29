import re

# Filepath to default rules which are included in package
from os import path
from pathlib import Path

DEFAULT_RULES_FILEPATH = path.join(
    Path(__file__).resolve().parents[1],
    "resources",
    "section_rules.json",
)


class TextSectionizer:
    name = "text_sectionizer"

    def __init__(self, rules="default"):
        self._rules = []
        self._compiled_patterns = dict()
        self._section_titles = set()

        if rules is not None:
            if rules == "default":
                import os

                if not os.path.exists(DEFAULT_RULES_FILEPATH):
                    raise FileNotFoundError(
                        "The expected location of the default rules file cannot be found. Please either "
                        "add rules manually or add a jsonl file to the following location: ",
                        DEFAULT_RULES_FILEPATH,
                    )
                self.add(self.load_patterns_from_json(DEFAULT_RULES_FILEPATH))
            # If a list, add each of the rules in the list
            elif isinstance(rules, list):
                self.add(rules)
            elif isinstance(rules, str):
                import os

                assert os.path.exists(rules)
                self.add(self.load_patterns_from_json(rules))

    def add(self, rules, cflags=None):
        """
        Add compiled regular expressions defined in rules
        Positional arguments:
        - rules --
        Keyword arguments:
        - cflags -- a list of regular expression compile flags
                 If cflags==None then cflags is set to [re.I]
        """

        def _mycomp(rex, flags=None):

            if flags is None:
                flags = [re.I]
            cflags = 0
            for f in flags:
                if isinstance(f, re.RegexFlag):
                    cflags = cflags | f
            return re.compile(rex, flags=cflags)

        for rule in rules:
            if not isinstance(rule, dict):
                if "SectionRule" not in type(rule):
                    raise ValueError("Rules must be either a dictionary or medspaCy SectionRule, not", type(rule))
                else:
                    rule = rule.to_dict()
            # Required arguments: category and either literal or pattern
            category = rule.get("category")
            literal = rule.get("literal")
            pattern = rule.get("pattern")
            if not any((literal, pattern)):
                raise ValueError("A section rule must contain either literal or pattern")
            elif literal and not pattern:
                pattern = literal

            if isinstance(pattern, str):
                self._compiled_patterns.setdefault(category, [])
                self._compiled_patterns[category].append(
                    _mycomp(pattern, flags=cflags)
                )
            else:
                # TODO: Change the default rules
                # continue
                raise ValueError(
                    "Patterns added to the TextSectionizer must be strings",
                    rule,
                )
            self._rules.append(rule)
            self._section_titles.add(category)

    @property
    def patterns(self):
        return self._rules

    @property
    def section_titles(self):
        return self._section_titles

    @classmethod
    def load_patterns_from_json(self, filepath):

        import json

        patterns = []
        with open(filepath) as f:
            rules = json.loads(f.read())["section_rules"]


        return rules

    def __call__(self, text):
        matches = []
        for (name, patterns) in self._compiled_patterns.items():
            for pattern in patterns:
                pattern_matches = list(pattern.finditer(text))
                for match in pattern_matches:
                    matches.append((name, match))

        if len(matches) == 0:
            return [(None, None, text)]

        matches = sorted(matches, key=lambda x: (x[1].start(), 0 - x[1].end()))
        matches = self._dedup_matches(matches)

        sections = []
        # If the first section doesn't start at the very beginning,
        # add an unknown section at the beginning
        if matches[0][1].start() != 0:
            sections.append((None, None, text[: matches[0][1].start()]))

        for i, (section_title, match) in enumerate(matches):
            section_header = match.group()
            # If this is the final section, it should include the rest of the text
            if i == len(matches) - 1:
                section_text = text[match.start() :]
                sections.append((section_title, section_header, section_text))
            # Otherwise, it will include all of the text up until the next section header
            else:
                next_match = matches[i + 1][1]
                section_text = text[match.start() : next_match.start()]
                sections.append((section_title, section_header, section_text))
        return sections

    def extract_sections(self, text):
        matches = []
        for name, sect_patterns in self.patterns.items():
            for pattern in sect_patterns:
                sect_matches = list(pattern.finditer(text))
                for match in sect_matches:
                    matches.append((name, match))
        if len(matches) == 0:
            return [(None, text)]

        matches = sorted(matches, key=lambda x: (x[1].start(), 0 - x[1].end()))
        matches = self._dedup_matches(matches)

        sections = []
        if matches[0][1].start() != 0:
            sections.append(("UNK", text[: matches[0][1].start()]))
        for i, (name, match) in enumerate(matches):
            if i == len(matches) - 1:
                sections.append((name, text[match.start() :]))
            else:
                next_match = matches[i + 1][1]
                sections.append(
                    (name, text[match.start() : next_match.start()])
                )

        return sections

    def _dedup_matches(self, matches):
        deduped = []
        # TODO: Make this smarter
        deduped.append(matches[0])
        for i, match in enumerate(matches[1:], start=1):
            if not self._overlaps(deduped[-1], match):
                deduped.append(match)
        return deduped

    def _overlaps(self, a, b):
        (_, a) = a
        (_, b) = b
        if a.start() <= b.start() < a.end():
            return True
        if b.start() <= a.start() < b.end():
            return True