# Alert Grouping Pipeline — AIT-ADS Implementation

This repository contains an implementation of the original [Alert Grouping Pipeline](https://github.com/MeteTurhan/Alert-grouping-pipeline) developed by Mete Turhan. The pipeline was inspired by and built upon the [AIT Alert Data Set (AIT-ADS)](https://github.com/ait-aecid/alert-data-set). This repository provides the implementation and experimental results obtained by applying the Alert Grouping Pipeline to AIT-ADS for the research paper:

**“Reducing Alert Fatigue in Security Operations Centers via a Multi-Stage Alert Grouping Pipeline.”**

The repository is intended to support the reproducibility of the implementation, preprocessing, analysis, and results presented in the paper.

## Pre-processing the AIT-ADS

To preprocess the AIT-ADS and transform the raw dataset into a format suitable for the Alert Grouping Pipeline, the following Jupyter notebooks are provided:

1. **`AIT-ADS_pre-processed_exploratory analysis.ipynb`**
   Used for exploring and analyzing the AIT-ADS data and understanding its structure prior to preprocessing.

2. **`AIT-ADS_pre_processed_expanded.ipynb`**
   Used to preprocess the AIT-ADS files, transform them into CSV format, and generate the column structure required by the Alert Grouping Pipeline. The preprocessing implementation is heavily based on the `preprocess.py` implementation from [AlertBERT](https://github.com/ait-aecid/AlertBERT/).

### Acknowledgement of AlertBERT Components

We acknowledge and make use of the following files and resources from the [AlertBERT repository](https://github.com/ait-aecid/AlertBERT/):

* `abbrvs.py`
* `preprocess.py`
* `timestampExtractor.py`
* `server_configs/` (complete directory)

These components were utilized as part of the AIT-ADS preprocessing workflow and adapted where necessary to produce the representation required by the Alert Grouping Pipeline.

## Utilizing the Alert Grouping Pipeline for Analysis and Results

The preprocessed AIT-ADS datasets are subsequently provided as input to the original Alert Grouping Pipeline developed by Mete Turhan. The pipeline groups related alerts according to its configured grouping parameters, after which the resulting datasets are analyzed to obtain the metrics reported in the research paper.

The Jupyter notebooks serve the following purposes:

1. **`run_pipeline.ipynb`**
   Runs the original Alert Grouping Pipeline using its default parameter values and stores the resulting grouped datasets in the `/output` directory.

2. **`analyze_pipeline_output.ipynb`**
   Analyzes the generated output files to obtain the relevant metric values and calculate alert reduction and coverage.

3. **`analyze_pipeline_output_part2.ipynb`**
   Provides IDS-level analysis of the generated pipeline output, allowing the results to be examined separately for the different intrusion detection systems represented in AIT-ADS.

The `zipped_output.zip` archive contains the resulting datasets generated during the pipeline execution. These correspond to the output files stored in the `/output` directory.




### Default Parameters

The configurable parameters utilized to run this pipeline resort to default values as presented here.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_time_gap` | 5 | Maximum seconds between alerts in same group |
| `cohesion_threshold` | 0.3 | Minimum similarity score for group cohesion |
| `entropy_threshold` | 1.35 | Maximum entropy allowed in groups |
| `ip_weight` | 0.3 | Weight for IP similarity (0.0-1.0) |
| `consider_subnets` | True | Whether to consider subnet relationships |
| `time_label` | None | Dataframe column useable as an input if available, to identify and exclude alerts labeled as false_positive during preprocessing  |


### Acknowledgments
```
@software{alertbert,
  title={AlertBERT},
  author={{AIT Austrian Institute of Technology -- AECID}},
  year={2026},
  url={https://github.com/ait-aecid/AlertBERT}
}
@software{alert_grouping_pipeline,
  title={Alert Grouping Pipeline},
  author={Mete Turhan},
  year={2025},
  url={https://github.com/MeteTurhan/alert-grouping-pipeline}
}
```


## Related Repositories

* **Original Alert Grouping Pipeline:** [Mete Turhan — Alert Grouping Pipeline](https://github.com/MeteTurhan/Alert-grouping-pipeline)
* **AIT Alert Data Set:** [AIT-ADS](https://github.com/ait-aecid/alert-data-set)
* **AlertBERT:** [AIT AlertBERT](https://github.com/ait-aecid/AlertBERT/)
