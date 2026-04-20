"""Named, saved evadex test configurations.

A *profile* is a YAML file that bundles scan flags, optional false-positive
settings, optional C2 push config, and scheduling metadata under a single
name. Profiles let teams run the same compliance check on a schedule without
re-typing flags, and are the configuration surface for the Siphon-C2
adversarial-testing integration.

Public API:

* :func:`load_profile` – resolve a name to a :class:`Profile`
* :func:`save_profile` – write a profile to the user profiles directory
* :func:`delete_profile` / :func:`list_profiles` / :func:`profiles_dir`
* :func:`list_builtin_profiles` / :func:`load_builtin_profile`
* :func:`profile_to_scan_argv` – translate a profile into ``evadex scan`` argv
* :func:`profile_to_falsepos_argv` – translate into ``evadex falsepos`` argv
"""

from evadex.profiles.schema import Profile, ProfileError
from evadex.profiles.storage import (
    delete_profile,
    list_builtin_profiles,
    list_profiles,
    load_builtin_profile,
    load_profile,
    profile_path,
    profiles_dir,
    save_profile,
)
from evadex.profiles.runner import (
    profile_to_falsepos_argv,
    profile_to_scan_argv,
)

__all__ = [
    "Profile",
    "ProfileError",
    "delete_profile",
    "list_builtin_profiles",
    "list_profiles",
    "load_builtin_profile",
    "load_profile",
    "profile_path",
    "profile_to_falsepos_argv",
    "profile_to_scan_argv",
    "profiles_dir",
    "save_profile",
]
