# Chapter 5 experiment pipeline

All sweep runners are located in the `zk-Guard-client` root.  Every measured
observation independently performs `down -> parameter rewrite -> Fabric up and
chaincode deployment -> end-to-end test`.  Consequently, observations with
different `AttrNum` never reuse a chaincode or client binary compiled for a
different circuit dimension.

| Dissertation output | Runner | Plot-ready CSV |
|---|---|---|
| Attribute-evolution two-panel figure | `run_attribute_update_sweep.sh` | `attribute_update_by_attr_num.csv`, `attribute_update_by_affected_users.csv` |
| Policy-update breakdown table and runtime heat map | `run_policy_update_sweep.sh` | `policy_update_breakdown_table.csv`, `policy_update_runtime_heatmap.csv` |
| Five-panel system-level comparison (PolyLock/zk-Guard rows) | `run_system_level_comparison_sweep.sh` | `system_comparison_polylock_wide.csv`, `system_comparison_polylock_long.csv` |

The default repetition count is five.  A first functional run can use one
observation per point:

```bash
./run_attribute_update_sweep.sh 1
./run_policy_update_sweep.sh 1
./run_system_level_comparison_sweep.sh 1
```

For final measurements, pass the selected repetition count, for example:

```bash
./run_attribute_update_sweep.sh 10
./run_policy_update_sweep.sh 10
./run_system_level_comparison_sweep.sh 10
```

The system-level comparison uses the complete Landsat Collection 2 Level-2
`QA_PIXEL` Cloud Optimized GeoTIFF configured by `DATA_OBJECT_FILE`.  The
default asset is approximately 2 MB and is encrypted, published to IPFS,
retrieved, decapsulated and decrypted without truncation or synthetic padding
at the plaintext layer.  A different complete geospatial asset can be selected
without modifying source code:

```bash
DATA_OBJECT_FILE=/absolute/path/to/asset.tif \
  ./run_system_level_comparison_sweep.sh 1
```

The runner temporarily sets Fabric `BatchTimeout` to `1ms`, which is suitable
for the isolated single-request latency experiment, and restores the previous
value on normal completion or interruption.  This avoids carrying the `2s`
batching configuration used by the Chapter 3 concurrency experiment into the
Chapter 5 end-to-end latency measurements.

Each runner prints its result directory. Raw logs, per-run summaries, a run
manifest and `plot_data/*.csv` are retained together under that directory.
