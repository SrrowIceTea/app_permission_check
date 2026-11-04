"""Expose multiple read candidates; value equality never proves unique origin."""
from collections import defaultdict


def annotate_candidates(pairs):
    """Called per property/data type. Does not drop or invent candidate pairs.

    Nested API wrappers can also yield multiple read events for one real call;
    without a proven invocation grouping they remain explicitly non-unique.
    """
    candidates = defaultdict(set)
    for pair in pairs:
        key = (pair.get('flow_src', 'proxy'), pair['flow_event_id'], pair.get('uid'))
        candidates[key].add((pair.get('read_src', 'vhal'), pair['read_event_id']))
    for pair in pairs:
        key = (pair.get('flow_src', 'proxy'), pair['flow_event_id'], pair.get('uid'))
        count = len(candidates[key])
        pair['matching_read_candidates_for_flow'] = count
        pair['source_read_unique'] = count == 1
        pair.setdefault('origin_proven', False)
    return sum(len(rows) > 1 for rows in candidates.values())
