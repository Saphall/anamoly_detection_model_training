# Log anomaly detection: model behaviour and how to improve it

Source: `anomaly_detection.ipynb`, run top to bottom (all code cells, in order) on `data/train.csv`, `data/test.csv` and `data/combined_train.csv`.
Saved outputs are in `artifacts/`.

## 1. Data

| File                 | Rows              | What it is                                                                         | Usable for training?                                                                                                                                                                                                               |
| -------------------- | ----------------- | ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `train.csv`          | 159 (40 distinct) | `type`, `line`, `anomaly_score`                                                    | No. Labels are a fixed, arbitrary function of the message text (for example "Failed login attempt detected" is normal, "Query executed successfully" is anomalous), 62% are anomalous, and it shares no templates with the stream. |
| `test.csv`           | 10,000            | A ~9 minute event stream with 135 anomalies (1.35%) from 6 attack types            | Yes, but it has no ground truth. Evaluation uses proxy labels built from `event_type`, `source_ip` and `bytes_out`.                                                                                                                |
| `combined_train.csv` | 7,000             | 40 distinct `train.csv` rows + 6,960 sampled `test.csv` rows, 157 anomalous (2.2%) | Partly. It has 2,220 distinct lines, 4,780 rows are exact repeats of normal events, and there are only 134 distinct anomalous lines.                                                                                               |

The 6 proxy attack types are `ssh_brute_force` (98), `exfiltration` (19), `suspicious_login` (8), `port_scan` (6), `privilege_escalation` (2) and `data_dump` (2).

## 2. Models trained

1. **Stream Isolation Forest (unsupervised, Parts 4-7).** Uses time-aware features: severity, template rarity, message size, external IPs, and entity concentration over the last 10 and 60 seconds. Needs no labels.
2. **Message RandomForest (supervised, Part 9).** Trained on `combined_train.csv` rows from `test.csv` (the 40 `train.csv` rows were excluded because they did not help). Features: severity, template rarity, message size, external-IP count and 6 text components. Parameters: `max_depth=8`, `min_samples_leaf=5`, `max_features="sqrt"`, balanced class weights. Alert threshold 0.256 (best F1 on out-of-fold predictions).

## 3. Results

### 3.1 Comparison on the full test stream (proxy labels, 10,000 events, 135 anomalies)

| Detector                                        | ROC-AUC | AP    | Alerts | TP  | FP  | Precision | Recall | F1    |
| ----------------------------------------------- | ------- | ----- | ------ | --- | --- | --------- | ------ | ----- |
| Severity rule (>= ERROR)                        | 0.955   | 0.346 | 37     | 37  | 0   | 1.000     | 0.274  | 0.430 |
| Stream Isolation Forest                         | 0.999   | 0.916 | 153    | 135 | 18  | 0.882     | 1.000  | 0.938 |
| Message RF, out-of-fold (honest)                | 1.000   | 1.000 | 135    | 135 | 0   | 1.000     | 1.000  | 1.000 |
| Message RF, final model (in-sample, optimistic) | 1.000   | 1.000 | 135    | 135 | 0   | 1.000     | 1.000  | 1.000 |
| Hybrid (RF out-of-fold OR stream IF)            | 1.000   | 0.958 | 153    | 135 | 18  | 0.882     | 1.000  | 0.938 |

"Out-of-fold" means each line was scored by a model that never saw that line.
The severity rule misses every `ssh_brute_force` event because those are WARNING level.
The hybrid adds nothing over the RF alone here, because it inherits the Isolation Forest's 18 false positives.

### 3.2 Cross-validation on `combined_train.csv` (scored on `test.csv` rows only)

| Model                               | AP, unseen lines | AP, unseen templates |
| ----------------------------------- | ---------------- | -------------------- |
| Severity rule                       | 0.35             | 0.87                 |
| Isolation Forest (no time features) | 0.77             | 0.96                 |
| LogReg (balanced)                   | 0.999            | 1.00                 |
| RandomForest (balanced)             | 1.00             | 1.00                 |
| HistGB (balanced)                   | 1.00             | 0.62                 |

The AP of the severity rule and Isolation Forest for unseen templates is not comparable with the first column: only folds that contain anomalies are scored, and the held-out anomalies differ per fold.

### 3.3 Other checks

- **Isolation Forest stability:** AP 0.932 +/- 0.017 over 10 seeds. Best configuration (text SVD added) reaches AP 0.948.
- **Train on the past, score the future** (fit on the first half only): precision 0.946, recall 1.0, F1 0.972 on the second half (53 anomalies).
- **Streaming check:** the micro-batch simulation reproduces batch scores exactly (153 alerts both ways).
- **RF hyper-parameter grid** (12 settings): every setting scores about 1.0, so tuning made no difference.
- **Feature ablation (RF, unseen lines):** removing `n_ext_ip` drops AP from 1.00 to 0.54. Removing `sev_ord` drops AP on unseen templates from 1.00 to 0.81. Removing the text components drops it to 0.87.

## 4. How the model behaves

**Strengths**

- Finds all 6 attack types, including the 98 WARNING-level SSH brute-force events that a severity rule can never see.
- On known attack types with new IPs, users or sizes, the message RF makes 0 errors out of 6,960 held-out rows.
- The stream Isolation Forest needs no labels, and its scores are stable across seeds and across a past/future split.

**Weaknesses**

1. **Circular labels.** The proxy labels come from `event_type`, `source_ip` and `bytes_out`, and the message text exposes most of that (for example, an external IP in the message). A perfect score means the model recovered the labelling rule, not that it catches real attacks.
2. **Unseen message types.** The ranking still works (per-fold AP about 1.0), but the fixed threshold does not transfer: pooled precision 0.05 and recall 0.27 at 0.256, with 747 alerts for 134 anomalies.
3. **Few distinct anomalies.** There are 134 distinct anomalous lines from 6 attack types, and `combined_train.csv` has no new information beyond about 2,200 rows. Its extra rows are repeated normal events.
4. **No burst view.** The message RF scores one line at a time, so it cannot see volume-based attacks that look normal line by line.
5. **False positives of the stream Isolation Forest (18):** firewall DROP lines (9), a benign VPN login that precedes an impossible-travel event (6), two internal failed logins (2) and one session close (1).
6. **Very short window.** The stream covers about 9 minutes, so drift and daily patterns are untested.

## 5. What to do to improve it (in priority order)

1. **Get real labels.** Have an analyst label 300-1,000 events, covering each attack type (about 100 or more per class for a supervised model). This is the only way to know the true accuracy, and it removes the circular-label problem.
2. **Collect more normal traffic and more attacks.** Days or weeks of logs, and replayed attacks (red-team or lab) with known ground truth, will add distinct anomalies. Padding the file with repeated normal rows does not help.
3. **Keep time and entity columns in the training file.** `combined_train.csv` has only `type`, `line` and `anomaly_score`. Adding `timestamp`, `host` and `source_ip` would let a supervised model use the entity-share and burst features that carry most of the Isolation Forest's accuracy.
4. **Combine the two detectors with a learned rule, not an OR.** Use the Isolation Forest score and burst features as inputs to the supervised model (stacking), so the supervised model can reject the Isolation Forest's known false positives.
5. **Handle new log sources.** Alert on the top-k scores or a fixed alert budget (for example 1.5% of events) instead of a fixed probability threshold, and fall back to the unsupervised detector. Use a template miner such as Drain3 instead of hand-written regexes.
6. **Validate properly.** Use time-based splits and leave-one-attack-type-out validation, and never evaluate on rows used for training.
7. **Cut false positives.** Add suppression for the known benign patterns (firewall DROPs, routine VPN logins) after review, or give them their own template-level baseline.
8. **Operate it.** Refit on a trailing window of recent normal traffic, track alert rate and score drift, and re-check the threshold when the log mix changes.

## 6. Saved files

| File                                         | Format | Content                                                           |
| -------------------------------------------- | ------ | ----------------------------------------------------------------- |
| `artifacts/message_detector.joblib`          | joblib | Final message RandomForest with its feature builder and threshold |
| `artifacts/isolation_forest_detector.joblib` | joblib | Stream Isolation Forest detector (Parts 6-7)                      |
| `artifacts/test_scored_results.csv`          | CSV    | Per-event scores and alerts for all 10,000 test events            |
| `artifacts/model_results.json`               | JSON   | Metrics, parameters, threshold and cross-validation summary       |
| `artifacts/alerts.csv`                       | CSV    | The 153 alerts from the stream Isolation Forest                   |

Format choice: both models are scikit-learn objects, so joblib is the natural format. The `.ubj` format only exists for XGBoost models.
To reload a model, first define the `FeatureBuilder`, `AnomalyDetector`, `MsgFeatures` and `MessageDetector` classes (and helpers) from the notebook, because pickled objects refer to them by name.
