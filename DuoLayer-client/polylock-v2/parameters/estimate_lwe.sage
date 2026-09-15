"""Reproduce the LWE estimates for the frozen PolyLock candidate profiles.

Run from a clone of https://github.com/malb/lattice-estimator at commit
53da5982597709ba0fdf94ea37a84d822310fd84:

    cp estimate_lwe.sage /path/to/lattice-estimator/
    cd /path/to/lattice-estimator
    sage estimate_lwe.sage
"""

from estimator import *
from estimator.reduction import ADPS16
from math import pi, sqrt

Q = 2**31 - 1
ELL_K = 256
PROFILES = {
    "polylock-100": {"n": 896, "sigma": 128},
    "polylock-128": {"n": 1024, "sigma": 256},
}

for name, profile in PROFILES.items():
    n = profile["n"]
    sigma = profile["sigma"]
    m_l = 3 * n * 31
    params = LWE.Parameters(
        n=n,
        q=Q,
        Xs=ND.UniformMod(Q),
        Xe=ND.DiscreteGaussian(sigma / sqrt(2 * pi)),
        m=2 * m_l + ELL_K,
        tag=name,
    )
    print(f"[{name}] n={n}, q={Q}, m={params.m}, sigma={sigma}, "
          f"stddev={sigma / sqrt(2*pi):.12f}")
    for mode in ("classical", "quantum"):
        result = LWE.estimate(
            params,
            red_cost_model=ADPS16(mode=mode),
            deny_list=("arora-gb", "bkw"),
            quiet=True,
        )
        costs = sorted(
            (float(log(cost["rop"], 2)), attack)
            for attack, cost in result.items()
            if "rop" in cost
        )
        print(f"  {mode}: {costs[0][0]:.6f} bits ({costs[0][1]})")
