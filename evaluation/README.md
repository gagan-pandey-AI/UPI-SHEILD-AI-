# Offline evaluation data and method

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe evaluation\run_evaluation.py --output evaluation\results\stage3.json
```

The runner is deterministic and makes no network requests. It reports accuracy, precision, recall, F1, confusion counts, false positive rate, and false negative rate. A metric is `null` when its denominator is zero, such as precision on a dataset containing only legitimate messages. Per-file reports remain separate; combined reports are grouped by input type. The synthetic fixtures are never pooled with the public dataset.

## Public dataset

`data/uci-sms-spam-collection.zip` contains the original UCI archive. UCI identifies it as 5,574 labeled SMS messages and licenses it under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Attribution: Almeida, T. & Hidalgo, J. (2011), *SMS Spam Collection* [Dataset], UCI Machine Learning Repository, [DOI 10.24432/C5CC84](https://doi.org/10.24432/C5CC84). UCI's page reports a donation date of 2012-06-21; the underlying collection dates are not fully specified.

The runner maps `ham` to negative and `spam` to positive, then passes the unmodified message to the current detector. The corpus includes English messages from older UK and Singapore research sources. Spam is not equivalent to fraud, and this corpus does not represent Indian UPI scams. Its results are an out-of-domain stress check, not a product accuracy estimate.

The UCI *Phishing Websites* dataset is listed in `manifest.json` as reviewed but excluded. Its 30 engineered features are not original URL strings, so they cannot evaluate this application's URL parser. UCI lists the dataset under CC BY 4.0.

## Synthetic scenario sets

The JSONL files under `datasets/` are authored fixtures dated 2026-11-23. They contain no real payment details, people, or live destinations. URL examples use reserved `.test` names, documentation-only IP addresses, or intentionally unusual structures. Each file includes a `data_origin` field. The runner rejects rows that are not explicitly marked synthetic.

Files cover legitimate SMS, fraudulent SMS, UPI scams, Hindi and Hinglish scam examples, phishing-like URL structures, ordinary URL structures, and suspicious QR payload scenarios. URL and QR fixture results measure structural checks only; no reputation provider is queried. The QR payload fixtures do not measure camera/image decoding quality, which is covered by deterministic QR decoder tests.

Synthetic metrics are sanity checks that the listed rules fire on their author-written examples. Perfect scores on these examples would not establish real-world accuracy. Results and the class counts are written to `results/stage3.json`.

## Recorded results

The current offline rules produced the following results on 2026-11-23. Confusion counts use `TP/TN/FP/FN`. `N/A` means the one-class dataset has no denominator for that metric.

| Dataset | n (positive / negative) | TP / TN / FP / FN | Accuracy | Precision | Recall | F1 | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Synthetic SMS combined | 48 (36 / 12) | 36 / 12 / 0 / 0 | 1.000000 | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 0.000000 |
| Synthetic URL combined | 16 (8 / 8) | 7 / 8 / 0 / 1 | 0.937500 | 1.000000 | 0.875000 | 0.933333 | 0.000000 | 0.125000 |
| Synthetic QR payload combined | 8 (4 / 4) | 4 / 4 / 0 / 0 | 1.000000 | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 0.000000 |
| UCI SMS Spam Collection | 5,574 (747 / 4,827) | 7 / 4,824 / 3 / 740 | 0.866703 | 0.700000 | 0.009371 | 0.018494 | 0.000622 | 0.990629 |

The separate authored fixture categories are also reported individually in `results/stage3.json`; their current counts are:

| Synthetic category | n (positive / negative) | TP / TN / FP / FN | Accuracy | Precision | Recall | F1 | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Fraudulent SMS | 12 (12 / 0) | 12 / 0 / 0 / 0 | 1.000000 | 1.000000 | 1.000000 | 1.000000 | N/A | 0.000000 |
| UPI scam messages | 8 (8 / 0) | 8 / 0 / 0 / 0 | 1.000000 | 1.000000 | 1.000000 | 1.000000 | N/A | 0.000000 |
| Hindi scam messages | 8 (8 / 0) | 8 / 0 / 0 / 0 | 1.000000 | 1.000000 | 1.000000 | 1.000000 | N/A | 0.000000 |
| Hinglish scam messages | 8 (8 / 0) | 8 / 0 / 0 / 0 | 1.000000 | 1.000000 | 1.000000 | 1.000000 | N/A | 0.000000 |
| Legitimate SMS | 12 (0 / 12) | 0 / 12 / 0 / 0 | 1.000000 | N/A | N/A | N/A | 0.000000 | N/A |
| Phishing-like URLs | 8 (8 / 0) | 7 / 0 / 0 / 1 | 0.875000 | 1.000000 | 0.875000 | 0.933333 | N/A | 0.125000 |
| Legitimate URLs | 8 (0 / 8) | 0 / 8 / 0 / 0 | 1.000000 | N/A | N/A | N/A | 0.000000 | N/A |
| QR suspicious scenarios | 8 (4 / 4) | 4 / 4 / 0 / 0 | 1.000000 | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 0.000000 |

The one false negative in the phishing-like URL fixtures is `url-bad-008` (`https://notice.example.test/account/update`): its host and path do not match the current structural warning rules. This fixture shows the limits of URL-only heuristics when a URL looks ordinary. Do not add a rule for this single synthetic example without testing likely legitimate lookalikes.

The UCI result means the detector flags only 7 of 747 rows labeled spam. Its 3 false positives and high overall accuracy mainly reflect the large ham class. Spam is not the same target as payment fraud, so this is not an accuracy estimate for UPI Shield AI. The strong synthetic fixture scores measure the fixed examples written to exercise the rules and must not be summarized as product accuracy.
