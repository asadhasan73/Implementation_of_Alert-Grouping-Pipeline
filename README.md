This is the implementation of the original [Alert Grouping Pipeline](https://github.com/MeteTurhan/Alert-grouping-pipeline) developed by Mete Turhan. The pipeline was inspired and built upon [AIT Alert Data Set](https://github.com/ait-aecid/alert-data-set) and this repository covers its implementation on the AIT-ADS for the research paper titled: Reducing Alert Fatigue in Security Operations Centers via a Multi-Stage Alert Grouping Pipeline.

The jupyter notebook files serve the following purpose:
1. run_pipeline.ipynb: Runs the original Alert Grouping Pipeline with default parameter values and stores the resulting datasets in the /output folder
2. analyze_pipeline_output.ipynb: Inspects the generated output files to gather metric values and calculate Alert Reduction and Coverage
3. analyze_pipeline_output_part2.ipynb: Provides IDS level analytical results for the generated output




## Default Parameters

The configurable parameters utilized to run this pipeline resort to default values as presented here.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_time_gap` | 5 | Maximum seconds between alerts in same group |
| `cohesion_threshold` | 0.3 | Minimum similarity score for group cohesion |
| `entropy_threshold` | 1.35 | Maximum entropy allowed in groups |
| `ip_weight` | 0.3 | Weight for IP similarity (0.0-1.0) |
| `consider_subnets` | True | Whether to consider subnet relationships |
| `time_label` | None | Dataframe column useable as an input if available, to identify and exclude alerts labeled as false_positive during preprocessing  |


## Acknowledgments
```
@software{alert_grouping_pipeline,
  title={Alert Grouping Pipeline},
  author={Mete Turhan},
  year={2025},
  url={https://github.com/MeteTurhan/alert-grouping-pipeline}
}
```
