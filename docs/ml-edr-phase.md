# ML EDR Phase Status

Last validated: 2026-06-14

## Current Phase

The ML endpoint-detection work is in the integrated prototype and pre-evaluation phase.
The pipeline can build endpoint behavior windows, train anomaly models, score windows
into ML alerts, persist results, and display alerts in the local web UI. The next
research step is controlled evaluation on real traffic with precision, recall,
alert-volume, and analyst-review measurements.

The model has been upgraded from a River-only deployed scorer to an auto-selected
anomaly scorer. Training now evaluates River Half-Space Trees, raw Isolation
Forest metrics, and a log-scaled Isolation Forest scorer. Auto-selection keeps
River for tiny or tied datasets and switches to `isolation-forest-log1p` when it
clears River ROC-AUC by a small margin.

## Implemented

- Endpoint-window feature generation from normalized honeypot and NSM events.
- Packet-level endpoint windows from pcap replay or Linux interface capture.
- Weak labels from Suricata alerts, reverse-shell commands, persistence commands,
  payload downloads, file hashes, and scanner command patterns.
- River Half-Space Trees training and scoring.
- Raw Isolation Forest comparison metrics during training.
- Log-scaled Isolation Forest training and scoring.
- Auto-selection of the deployed scorer by weak-label ROC-AUC.
- Calibrated high-severity thresholds from the selected scorer's training-score
  tail.
- Temporal train/test evaluation for River, raw Isolation Forest, and log-scaled
  Isolation Forest.
- Leakage-free evaluation mode (`evaluate --exclude-rule-features`) that removes
  the six weak-label-defining features from the model input to measure
  behavioral detection independent of the rule signal.
- Train/calibration/test threshold tuning for the same scorers.
- Threshold objectives for best F1, target false-positive rate, and target
  alerts/day.
- Calibrated deployable thresholds via `train --threshold-objective` on a
  temporal calibration holdout, recorded in model metadata and the artifact as
  `threshold_source` so scoring consumes the tuned threshold automatically.
- Repeatable loop runner at `scripts/ml-edr-loop.sh` across local real T-Pot
  exports.
- Near-real-time honeypot ingest architecture documented in
  `docs/realtime-honeypot-ingest.md`.
- Evaluation-time exclusion of placeholder timestamps before year 2000 by
  default.
- JSON and CSV endpoint-window dataset export.
- JSON ML-alert export.
- DuckDB tables for model metadata, endpoint windows, and ML alerts.
- CLI commands: `dataset`, `train`, `score`, `evaluate`, `tune`, and
  `live-sensor`.
- Web UI navigation and table view for `ML Alerts`.

## Validation Log

Pixi executable used:

```bash
pixi --version
```

Result: `pixi 0.70.2`.

Full test suite:

```bash
pixi run test
```

Result: 36 tests passed with no skips.

Tuning smoke task:

```bash
pixi run tune-sample
```

The sample tuning task is only a command smoke test because the calibration and
test slices each contain one benign window and no malicious windows.

Temporal evaluation smoke task:

```bash
pixi run python -m honeypot_ai evaluate \
  data/ml/sample-windows.json \
  --format markdown
```

The sample evaluation is only a command smoke test because the test partition
contains two benign windows and no malicious windows, so ROC-AUC and PR-AUC are
not meaningful.

Sample endpoint-window workflow:

```bash
pixi run dataset-sample
pixi run train-sample
pixi run score-sample
```

Results:

- `data/ml/sample-windows.json`: 4 endpoint windows.
- `data/ml/sample-alerts.json`: 4 alerts because the sample scoring task uses
  `--include-below-threshold`.
- `data/models/sample/metadata.json`: model `c2334a5194d6277fba8b`, selected
  scorer `river-half-space-trees`, threshold `0.05`, high threshold `0.1`,
  2 training windows, 4 dataset windows.

The sample corpus is only a smoke test. Its model scores are flat because there
are too few endpoint windows to learn a meaningful anomaly distribution.

Sample DuckDB persistence validation:

```bash
pixi run python -m honeypot_ai dataset \
  sample_logs/honeypot.ndjson \
  --protected-cidr 10.0.5.0/24 \
  --output /tmp/ml-edr-sample-windows.json \
  --db /tmp/ml-edr-validation.duckdb

pixi run python -m honeypot_ai train \
  /tmp/ml-edr-sample-windows.json \
  --model-dir /tmp/ml-edr-sample-model \
  --db /tmp/ml-edr-validation.duckdb

pixi run python -m honeypot_ai score \
  /tmp/ml-edr-sample-windows.json \
  --model /tmp/ml-edr-sample-model/model.joblib \
  --include-below-threshold \
  --output /tmp/ml-edr-sample-alerts.json \
  --db /tmp/ml-edr-validation.duckdb
```

Resulting DuckDB row counts:

- `endpoint_windows`: 4.
- `ml_models`: 1.
- `ml_alerts`: 4.

Fresh T-Pot subset validation:

```bash
pixi run python -m honeypot_ai dataset \
  --source tpot \
  --protected-cidr 10.0.5.0/24 \
  --output /tmp/tpot-windows-validate.json \
  data/tpot_logs_2

pixi run python -m honeypot_ai train \
  /tmp/tpot-windows-validate.json \
  --model-dir /tmp/tpot-model-improved

pixi run python -m honeypot_ai score \
  /tmp/tpot-windows-validate.json \
  --model /tmp/tpot-model-improved/model.joblib \
  --output /tmp/tpot-alerts-improved.json
```

Results:

- Placeholder windows excluded: 2.
- Evaluated windows: 6,552.
- Endpoint windows: 6,554 total.
- Labels after exclusion: 3,376 benign, 3,176 malicious.
- Roles after exclusion: 3,356 inbound, 3,196 outbound.
- Endpoint: `<protected-endpoint-ip>`.
- Model: `3e0d1ee9d73ad283089e`.
- Selected scorer: `isolation-forest-log1p`.
- Threshold: `0.09236642990157481`.
- High threshold: `0.16028360664964192`.
- Alerts above threshold: 1,542 total, with 462 high and 1,080 medium.
- River ROC-AUC: `0.7215102575115617`; F1 at threshold:
  `0.3706009097438353`.
- Raw Isolation Forest ROC-AUC: `0.8553138417497722`.
- Log-scaled Isolation Forest ROC-AUC: `0.880982600781766`; precision at
  threshold `0.8904020752269779`, recall `0.43230478589420657`, F1
  `0.5820262823230182`.

Fresh T-Pot temporal evaluation:

```bash
pixi run python -m honeypot_ai evaluate \
  /tmp/tpot-windows-validate.json \
  --format json \
  --output /tmp/tpot-evaluate-v3.json
```

Results:

- Excluded placeholder rows: 2.
- Train rows: 4,586; fit rows: 2,346 benign windows; test rows: 1,966.
- Test labels: 1,030 benign, 936 malicious.
- Best ROC-AUC, PR-AUC, precision, recall, and F1 at threshold:
  `isolation-forest-log1p`.
- River: ROC-AUC `0.8522332171604016`, PR-AUC `0.7916572329989304`,
  F1 `0.2824956672443674`, best-F1 diagnostic `0.8288557213930349`,
  false-positive rate `0.05339805825242718`.
- Raw Isolation Forest: ROC-AUC `0.8652383619616629`, PR-AUC
  `0.8468556567341677`, F1 `0.5860597439544808`, best-F1 diagnostic
  `0.8206863218946351`, false-positive rate `0.05631067961165048`.
- Log-scaled Isolation Forest: ROC-AUC `0.8841937391087877`, PR-AUC
  `0.8631790721619331`, F1 `0.6158113730929264`, best-F1 diagnostic
  `0.8344497607655501`, false-positive rate `0.06019417475728155`.

Existing saved T-Pot artifacts:

- `data/ml/tpot-windows.json`: 68,373 endpoint windows.
- `data/ml/tpot-alerts.json`: 14,888 alerts.
- `data/models/tpot-baseline/metadata.json`: model
  `aadb1e082f06d8f55220`, threshold `0.22253275929549898`, 27,109
  training windows, 68,373 dataset windows.
- Existing saved metrics: River ROC-AUC `0.711301510810171`; Isolation Forest
  ROC-AUC `0.8858862005160875`.

Improved full-artifact validation using `data/ml/tpot-windows.json`:

```bash
pixi run python -m honeypot_ai train \
  data/ml/tpot-windows.json \
  --model-dir /tmp/tpot-full-model-improved

pixi run python -m honeypot_ai score \
  data/ml/tpot-windows.json \
  --model /tmp/tpot-full-model-improved/model.joblib \
  --output /tmp/tpot-full-alerts-improved.json
```

Results:

- Model: `127166d6eb8d298d374c`.
- Selected scorer: `isolation-forest-log1p`.
- Threshold: `0.1027443170278265`.
- High threshold: `0.16980054258336671`.
- Alerts above threshold: 19,832 total, with 5,285 high and 14,547 medium.
- River ROC-AUC: `0.711301510810171`; F1 at threshold:
  `0.4543382248183502`.
- Raw Isolation Forest ROC-AUC: `0.8858862005160875`; F1 at threshold:
  `0.6196120340684608`.
- Log-scaled Isolation Forest ROC-AUC: `0.8961912768403791`; precision at
  threshold `0.9316256555062525`, recall `0.4477510663047693`, F1
  `0.6048186460652089`.

Improved full-artifact temporal evaluation:

```bash
pixi run python -m honeypot_ai evaluate \
  data/ml/tpot-windows.json \
  --format json \
  --output /tmp/tpot-full-evaluate-v3.json
```

Results:

- Excluded placeholder rows: 2.
- Train rows: 47,859; fit rows: 20,168 benign windows; test rows: 20,512.
- Test labels: 6,939 benign, 13,573 malicious.
- Best ROC-AUC and PR-AUC: `isolation-forest-log1p`.
- Best F1, precision, and recall at the default threshold quantile:
  `river-half-space-trees`.
- River: ROC-AUC `0.8833179712268173`, PR-AUC `0.9323962697989895`,
  F1 `0.8039098514597917`, best-F1 diagnostic `0.8841211065127423`,
  false-positive rate `0.06312148724600086`.
- Raw Isolation Forest: ROC-AUC `0.8965736370792932`, PR-AUC
  `0.9334758232613336`, F1 `0.7347012077403133`, best-F1 diagnostic
  `0.8852470141150923`, false-positive rate `0.07465052601239372`.
- Log-scaled Isolation Forest: ROC-AUC `0.9013780632941297`, PR-AUC
  `0.9378700312218051`, F1 `0.7105903974270618`, best-F1 diagnostic
  `0.8910238623751386`, false-positive rate `0.06614785992217899`.

Loop result: log-scaled Isolation Forest has the strongest ranking metrics,
while threshold calibration still needs work because River currently has the
best full-artifact F1 at the default 95th-percentile threshold. The best-F1
diagnostic shows log-scaled Isolation Forest can outperform River if calibrated
to a lower threshold on a validation set.

Train/calibration/test threshold tuning:

```bash
pixi run python -m honeypot_ai tune \
  data/ml/tpot-windows.json \
  --format json \
  --output /tmp/tpot-full-tune-v1.json
```

Full saved T-Pot result:

- Excluded placeholder rows: 2.
- Train rows: 41,022; fit rows: 17,066 benign windows; calibration rows:
  13,674; test rows: 13,675.
- Test labels: 4,591 benign, 9,084 malicious.
- Best held-out ROC-AUC, PR-AUC, F1, and precision at tuned threshold:
  `isolation-forest-log1p`.
- River tuned threshold `0.20091741682974562`: ROC-AUC
  `0.9060112945694968`, PR-AUC `0.9375561852144106`, F1
  `0.8930164989104493`, false-positive rate `0.3450228708342409`.
- Raw Isolation Forest tuned threshold `-0.1111070900608862`: ROC-AUC
  `0.899834944041244`, PR-AUC `0.9337444620978097`, F1
  `0.8870886585488578`, false-positive rate `0.4301895011979961`.
- Log-scaled Isolation Forest tuned threshold `-0.027892364923039648`:
  ROC-AUC `0.9077355869528584`, PR-AUC `0.9424428009523487`, F1
  `0.8954122720423963`, false-positive rate `0.3367458070137225`.

Repeatable loop runner:

```bash
ML_LOOP_OUT_DIR=/tmp/ml-edr-loop-objectives scripts/ml-edr-loop.sh
```

The loop processed `data/ml/tpot-windows.json`, `data/tpot_logs`,
`data/tpot_logs_2`, and `data/tpot_logs_with_rsync_instead`; it skips the broad
`data/logs_only` tree by default because that parse is slow. It writes
best-F1 tuning, target-FPR tuning, target-alerts/day tuning, and train/test
evaluation JSON for each dataset. `TARGET_FPR` and `TARGET_ALERTS_PER_DAY`
control the operational objectives.

Best-F1 objective summary:

| Dataset | Rows | Best F1 scorer | Best ROC-AUC scorer | Best F1 | Log-IF ROC-AUC | Log-IF PR-AUC |
| --- | ---: | --- | --- | ---: | ---: | ---: |
| `tpot-saved` | 68,371 | `isolation-forest-log1p` | `isolation-forest-log1p` | `0.8954122720423963` | `0.9077355869528584` | `0.9424428009523487` |
| `tpot-logs` | 4,354 | `isolation-forest-log1p` | `isolation-forest-log1p` | `0.8508064516129032` | `0.9171443652678807` | `0.9209763411243763` |
| `tpot-logs-2` | 6,552 | `isolation-forest-log1p` | `isolation-forest-log1p` | `0.8307233407904548` | `0.8790263021356755` | `0.8553832635644818` |
| `tpot-rsync` | 4,364 | `river-half-space-trees` | `isolation-forest-log1p` | `0.8533057851239669` | `0.9185164534590137` | `0.9236983877781532` |

Target-FPR objective summary, with `TARGET_FPR=0.10`:

| Dataset | Best held-out F1 scorer | Held-out F1 | Held-out FPR | Precision | Recall | Alerts |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `tpot-saved` | `isolation-forest-raw` | `0.848155156102176` | `0.142888259638423` | `0.9161982626469085` | `0.7895200352267724` | `7,828` |
| `tpot-logs` | `isolation-forest-log1p` | `0.800976800976801` | `0.09738717339667459` | `0.8888888888888888` | `0.7288888888888889` | `369` |
| `tpot-logs-2` | `river-half-space-trees` | `0.7319304666056725` | `0.11461318051575932` | `0.8333333333333334` | `0.6525285481239804` | `480` |
| `tpot-rsync` | `isolation-forest-raw` | `0.8` | `0.10576923076923077` | `0.8835978835978836` | `0.7308533916849015` | `378` |

The target-FPR thresholds satisfy the calibration budget, but held-out FPR can
drift above 0.10 on later traffic. Compared with best-F1 tuning, target-FPR
usually cuts false positives substantially while preserving usable recall.

Target-alerts/day objective summary, with `TARGET_ALERTS_PER_DAY=50`:

| Dataset | Best held-out F1 scorer | Held-out F1 | Held-out FPR | Recall | Alerts/day | Alerts |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `tpot-saved` | `isolation-forest-raw` | `0.14145744029393753` | `0.004574166848181224` | `0.0762879788639366` | `147.15328467153284` | `714` |
| `tpot-logs` | `isolation-forest-raw` | `0.245136186770428` | `0.0023752969121140144` | `0.14` | `203.89380530973452` | `64` |
| `tpot-logs-2` | `isolation-forest-log1p` | `0.05087440381558029` | `0.0` | `0.026101141924959218` | `31.135135135135137` | `16` |
| `tpot-rsync` | `isolation-forest-raw` | `0.20743639921722112` | `0.002403846153846154` | `0.11597374179431072` | `171.65562913907286` | `54` |

The alert-budget objective is too conservative with the default budget and is
not stable on the current temporal slices. It is still useful as a guardrail,
but target-FPR is the stronger deployment candidate for the next pass.

Fresh remote retrieval status:

```bash
scripts/sync-tpot-logs.sh --env .env
```

Result: succeeded on 2026-06-14 after populating `.env` with the remote T-Pot
SSH settings and a host-specific `TPOT_REMOTE_DIR`. The latest batch synced into
the ignored local log directory. Treat the local batch size, file count, and raw
contents as publish-excluded operational data.

The existing saved artifacts were not overwritten during validation. The fresh
T-Pot validation used `/tmp` outputs.

Leakage-free behavioral evaluation (2026-06-14):

The six weak-label-defining features (`suricata_alerts`, `reverse_shells`,
`persistence_attempts`, `download_commands`, `scanner_commands`, `hash_count`)
are both model inputs and the weak-label definition, so they were suspected of
inflating the evaluation metrics. The new `evaluate --exclude-rule-features`
flag drops them from the model input (22 -> 16 features) while keeping the
stored labels as ground truth.

```bash
pixi run python -m honeypot_ai evaluate \
  data/ml/tpot-windows.json \
  --format json \
  --output /tmp/tpot-evaluate-all.json

pixi run python -m honeypot_ai evaluate \
  data/ml/tpot-windows.json \
  --exclude-rule-features \
  --format json \
  --output /tmp/tpot-evaluate-behavioral.json
```

The all-feature run reproduced the previously recorded full-artifact temporal
numbers exactly (log-scaled Isolation Forest ROC-AUC `0.9013780632941297`),
confirming the comparison is valid. Held-out test split: 6,939 benign, 13,573
malicious.

| Scorer | Metric | All features | Behavioral only |
| --- | --- | ---: | ---: |
| River | ROC-AUC | `0.8833179712268173` | `0.8816538394643358` |
| River | PR-AUC | `0.9323962697989895` | `0.9281587017633206` |
| Raw Isolation Forest | ROC-AUC | `0.8965736370792932` | `0.8873462067966437` |
| Raw Isolation Forest | PR-AUC | `0.9334758232613336` | `0.9259807285290069` |
| Log-scaled Isolation Forest | ROC-AUC | `0.9013780632941297` | `0.9009985576278924` |
| Log-scaled Isolation Forest | PR-AUC | `0.9378700312218051` | `0.9364300302909490` |
| Log-scaled Isolation Forest | best-F1 | `0.8910238623751386` | `0.8920514658202792` |

Finding: removing the rule features barely changes the ranking metrics
(log-scaled Isolation Forest ROC-AUC moves by `-0.0004`), so the headline AUC and
PR-AUC are **not** driven by feature leakage. The unsupervised scorers fit on
benign-only windows, where the rule features are constant zero, so they cannot
use them; the discriminative signal comes from the 16 behavioral features (byte
volumes, peer fan-out, port/protocol spread, event rates, durations). This rules
out feature leakage but does not address two remaining concerns: the labels are
still weak rule-derived proxies, and "benign" honeypot traffic is not real
endpoint-benign behavior. The River F1-at-threshold drop (`0.8039` -> `0.6991`)
with a stable best-F1 (`0.8841` -> `0.8906`) is a fixed-quantile thresholding
artifact, reinforcing the need to promote calibrated thresholds (Next Work item
below).

## Next Work

1. Identify and document the exact input set used to create the 68,373-window
   saved T-Pot artifact.
2. Add a repeatable real-data Pixi task once that input set is confirmed.
3. Replace routine rsync/cron pulls with a push-based honeypot forwarder and
   narrow research-server collector.
4. Compare best-F1, target-FPR, and target-alerts/day thresholds for each real
   T-Pot export and select the operational objective for deployment.
5. Promote tuned thresholds into deployable model metadata once the chosen
   operational objective is selected.
6. Review top alerts manually and record whether the reason strings are useful
   for analyst triage.
7. Push selected ML alerts into the SIEM or report path used by the downstream
   LLM analyst summary workflow.

## Operational Notes

- Use a deployment-specific protected CIDR. The sample README uses
  `10.0.5.0/24`; replace it with the protected network for the deployment being
  evaluated.
- Live interface capture requires root or `CAP_NET_RAW`.
- Keep generated model, alert, and local database artifacts out of Git unless a
  specific fixture is needed for tests.
