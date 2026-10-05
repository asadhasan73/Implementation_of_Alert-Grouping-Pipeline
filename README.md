# Alert Grouping Pipeline
A baseline pipeline for grouping security alerts based on temporal patterns, content similarity, and IP address relationships. This system helps security analysts by reducing alert fatigue and identifying related security incidents.

## Overview

The Alert Grouping Pipeline uses advanced clustering techniques to group related security alerts while maintaining strict temporal constraints. It combines multiple similarity metrics including text analysis, IP address patterns, and entropy calculations to create meaningful alert groupings.

## Key Features

- **Strict Temporal Grouping**: Enforces maximum time gaps between alerts in the same group
- **Multi-dimensional Similarity**: Analyzes alert names, hosts, descriptions, and IP addresses
- **IP-Aware Clustering**: Considers IP addresses and subnet relationships for enhanced grouping
- **Entropy-Based Validation**: Uses information entropy to validate group quality
- **Memory Efficient**: Handles large datasets with streaming similarity calculations
- **Configurable Thresholds**: Adjustable parameters for different use cases

### Install Dependencies

```bash
pip install pandas numpy scikit-learn scipy
```

### Clone Repository

```bash
git clone https://github.com/MeteTurhan/alert-grouping-pipeline.git
cd alert-grouping-pipeline
```

## Usage

### Basic Usage

```python
from alert_grouping import AlertGroupingPipeline
import pandas as pd

# Load your alerts data
alerts_df = pd.read_csv('your_alerts.csv')

# Initialize the pipeline
pipeline = AlertGroupingPipeline()

# Run the analysis
grouped_df, validity_results = pipeline.analyze(alerts_df)

# View results
print(f"Grouped {len(alerts_df)} alerts into {grouped_df['timely_alert_group'].nunique()} groups")
print(validity_results.head())
```

### Advanced Configuration

```python
# Custom configuration for high-volume environments
pipeline = AlertGroupingPipeline(
    max_time_gap=10,
    cohesion_threshold=0.2,
    entropy_threshold=2.0,
    ip_weight=0.5,
    consider_subnets=True
)

```

## Data Format

Your input DataFrame should contain the following columns:

| Column | Type | Description | Required |
|--------|------|-------------|----------|
| `time` | int/float | Unix timestamp | ✅ |
| `name` | string | Alert name/type | ✅ |
| `host` | string | Source hostname | ✅ |
| `short` | string | Alert description | ✅ |
| `ip` | string | Source IP address | ⚠️ Recommended |
| `time_label` | string | Label (exclude 'false_positive') | ⚠️ Optional |

### Example Data

```csv
time,name,host,short,ip,time_label
1640995200,malware_detected,server01,Trojan found in /tmp,192.168.1.100,malicious
1640995205,malware_detected,server01,Trojan quarantined,192.168.1.100,malicious
1640995300,port_scan,firewall,Port scan from external IP,10.0.0.50,suspicious
```

## Algorithm Details

### 1. Temporal Grouping
- Groups alerts with time gaps ≤ `max_time_gap` seconds
- Creates the foundation for all subsequent grouping operations
- Ensures chronological relationships are preserved

### 2. Content Similarity Analysis
- Uses TF-IDF vectorization for text analysis
- Calculates cosine similarity between alert descriptions
- Identifies outliers using statistical thresholds

### 3. IP-Based Clustering
- Analyzes IP address patterns and subnet relationships
- Supports both IPv4 and IPv6 addresses
- Configurable subnet-level grouping

### 4. Entropy Validation
- Calculates information entropy for each group
- Validates group diversity and cohesion
- Helps identify over-clustered or under-clustered groups

### 5. Cohesion Scoring
- Multi-dimensional similarity scoring
- Weighted combination of text and IP similarities
- Configurable weights for different alert attributes

## Configuration Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_time_gap` | 5 | Maximum seconds between alerts in same group |
| `cohesion_threshold` | 0.3 | Minimum similarity score for group cohesion |
| `entropy_threshold` | 1.35 | Maximum entropy allowed in groups |
| `ip_weight` | 0.3 | Weight for IP similarity (0.0-1.0) |
| `consider_subnets` | True | Whether to consider subnet relationships |

## Performance

### Benchmarks

- **Small datasets** (< 1K alerts): < 1 second
- **Medium datasets** (1K-10K alerts): 5-30 seconds  
- **Large datasets** (10K-100K alerts): 1-5 minutes
- **Very large datasets** (> 100K alerts): Automatic sampling and chunking

### Memory Usage

- Streaming similarity calculations for memory efficiency
- Automatic sampling for datasets > 10K alerts
- Configurable chunk sizes for processing large groups

## Output Format

The pipeline returns two main outputs:

### 1. Grouped DataFrame
Original DataFrame with additional columns:
- `timely_alert_group`: Final group ID
- `readable_time`: Human-readable timestamp
- `ip_subnet`: Extracted subnet (if applicable)

### 2. Validity Results DataFrame
Statistics for each group:
- `group_id`: Group identifier
- `group_size`: Number of alerts in group
- `cohesion_score`: Similarity score (0.0-1.0)
- `max_time_gap`: Largest time gap in group
- `time_span`: Total time span of group
- `entropy_score`: Information entropy of group
## Acknowledgments
This project was inspired by and builds upon the [AIT Alert Data Set](https://github.com/ait-aecid/alert-data-set). I highly recommend it for further analysis, experimentation, and improvement.
## Citation
If you use this project in your research, please cite:
```bibtex
@software{alert_grouping_pipeline,
  title={Alert Grouping Pipeline},
  author={Mete Turhan},
  year={2025},
  url={https://github.com/MeteTurhan/alert-grouping-pipeline}
}
```
