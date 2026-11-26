# Offline coherent stack preview

Given a whole-batch list of existing changed paths and ordered coherent candidate path groups, the preview lists each accepted cohort by its one-based position, counts overlapping paths only once, and stops at the first existing policy boundary. A stopped group is neither accepted nor split. Output contains counts and fixed dispositions only. It cannot create a draft, delay preservation, authorize an action, or request review.

Example: with 190 existing paths, a group of 15 containing five existing paths adds ten and reaches 200. If the next group would take the batch to 220, the historical single-cohort policy stops at the 200 freeze; 280 remains a separate hard limit. A coherent group can reach exactly 280 when the starting count is below the freeze threshold. These are offline policy fixtures, not instructions for managing a live PR.

Use `preview_json(existing_paths, cohorts, final_boundary="final_scope")` for a deterministic aggregate handoff. The optional final boundary applies when all submitted cohorts fit, not as permission to override a stop. Structural bounds cover the whole proposal; path validation uses the existing rules, only for entries evaluated before the first stop.

Opt in to whole-proposal diagnostics with `preview_checked(existing_paths, cohorts, final_boundary="final_scope")`. It validates all paths after the same bounds check, including cohorts at or beyond the first decision stop. For a valid proposal, its returned aggregate is identical to `preview`; neither accepts later cohorts after a stop. The default `preview` and `preview_json` retain their original first-stop validation behavior.
