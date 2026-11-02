# Dedicated runtime lab

The reproducible setup is implemented in `scripts/lab.py` and explained in `docs/LIVE_LAB.md`. The current node image is digest-pinned; Calico is versioned; trusted fixture digests are resolved on your own machine.

No credentials, cluster dumps, or fabricated live reports are distributed in this directory. Local runner kubeconfig and setup state are written under `~/.netscope/`, outside the repository. A successful bootstrap is not a successful verification run.
