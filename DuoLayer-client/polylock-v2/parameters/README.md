# PolyLock fixed ring parameter profile

论文主实验只改变 \(|\mathcal U|\)、\(|\mathcal S_\Sigma|\)、策略选择比例、
对象大小以及部署环境。正式实验前先比较一次 `ring100` 与 `ring128`，选定
安全档后，其余主实验固定该档全部密码参数。

| Parameter | Fixed value | Purpose |
|---|---:|---|
| `ring100` | \(N=512,q=12289\), Falcon-512 family | N=512 implementation comparison profile |
| `ring128` | \(N=1024,q=12289\), Falcon-1024 family | N=1024 thesis implementation profile |
| Root embedding | \(H(\boldsymbol a)\mapsto a+bX\in R_q\) | injective encoding of up to \(q^2-1\) legal profiles without duplicating the predicate equation |
| Bucket capacity | \(d_{\max}=4<N\) | prevents reduction modulo \(X^N+1\) inside the vanishing-polynomial identity |
| Radix base | 32 | three digits for every \(\mathbb F_q\) coordinate |
| Lock encoding | 14 bits/coefficient | canonical lossless packing because \(q=12289<2^{14}\) |
| Error | fixed-weight ternary, weight 32 | nonzero short masking in both profiles; the larger ring has a larger support set |
| KEM seed | 128 bits | encapsulated entropy source |
| Error correction | RS(\(N/8\),16) | protects the seed across all ring coefficients |
| KDF | HKDF-HMAC-SHA256 | derives a 256-bit AES key bound to AAD/CID |
| DEM | AES-256-GCM | data confidentiality and integrity |

The Falcon parameter sets establish well-studied sources for the NTRU trapdoor
dimensions. They do not by themselves prove the security of the composed
predicate-lock construction. The low-degree root embedding preserves exact
root evaluation because all intermediate predicate polynomials have degree
strictly below \(N\); it does not remove Ring-LWE errors or reuse encapsulation
randomness. The thesis therefore states the complete set of
assumptions explicitly. The strings `ring100` and `ring128` are retained as
implementation profile identifiers for compatibility; they do not certify an
exact concrete-security bit value for the complete PolyLock construction.
