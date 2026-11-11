"""Reproducible guard evaluation: attack and false-positive sets, and their scoring (#198).

``build_sets`` writes the sets (garak 0.17.1 probes, generated false-positive corpora);
``score`` runs detectors over them and writes a JSON summary. Neither prints prompt text.
"""
