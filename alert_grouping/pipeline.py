from sklearn.feature_extraction.text import TfidfVectorizer
import pandas as pd
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from scipy.stats import entropy

class AlertGroupingPipeline:
    def __init__(self, max_time_gap=5, cohesion_threshold=0.3, entropy_threshold=1.35, 
                 ip_weight=0.3, consider_subnets=True, time_label=None):
        self.max_time_gap = max_time_gap
        self.cohesion_threshold = cohesion_threshold
        self.entropy_threshold = entropy_threshold
        self.vectorizer = TfidfVectorizer()
        self.ip_weight = ip_weight
        self.consider_subnets = consider_subnets
        self.time_label = time_label
        
    def preprocess_data(self, alerts_df):
        alerts_df = alerts_df.copy()
    
        alerts_df['readable_time'] = pd.to_datetime(
            alerts_df['time'],
            unit='s'
        )
    
        if self.time_label in alerts_df.columns:
            alerts_df = alerts_df[
                alerts_df[self.time_label] != 'false_positive'
            ]
    
        if self.consider_subnets and 'ip' in alerts_df.columns:
            alerts_df['ip_subnet'] = alerts_df['ip'].apply(
                self.extract_subnet
            )
    
        return alerts_df.sort_values(
            by='readable_time'
        ).reset_index(drop=True)
    
    def extract_subnet(self, ip):
        """Extract subnet from IP (first 3 octets for IPv4)"""
        try:
            if '.' in ip:  # IPv4
                return '.'.join(ip.split('.')[:3])
            elif ':' in ip:  # IPv6
                return ':'.join(ip.split(':')[:4])
            return ip
        except:
            return ip

    def group_alerts_by_max_time_gap(self, df):
        """
        Enhanced temporal grouping function that strictly enforces max_time_gap
        between consecutive alerts in the same group
        """
        print(f"Grouping alerts with max time gap of {self.max_time_gap} seconds...")
        
        df = df.sort_values(by='readable_time').reset_index(drop=True)
        df['time_diff'] = df['readable_time'].diff().dt.total_seconds()
        
        group_ids = [1]  # First alert is always in group 1
        current_group = 1
        
        for i in range(1, len(df)):
            if df.iloc[i]['time_diff'] > self.max_time_gap:
                current_group += 1
                print(f"New group {current_group} created at index {i} with time gap {df.iloc[i]['time_diff']:.2f}s")
            group_ids.append(current_group)
        
        df['timely_alert_group'] = group_ids
        
        group_counts = df['timely_alert_group'].value_counts().sort_index()
        print(f"Created {len(group_counts)} time-based groups with sizes: {dict(group_counts)}")
        
        return df.drop(columns=['time_diff'])

    def calculate_text_similarity_streaming(self, texts, chunk_size=1000):
        """Calculate average similarity score using streaming for memory efficiency"""
        if len(texts) <= 1:
            return 1.0, []
        
        if len(texts) > 10000:
            sample_size = min(10000, int(len(texts) * 0.1))
            indices = np.random.choice(len(texts), sample_size, replace=False)
            texts = [texts[i] for i in indices]
        
        tfidf_matrix = self.vectorizer.fit_transform(texts)
        n_samples = len(texts)
        
        avg_similarities = np.zeros(n_samples)
        count = np.zeros(n_samples)
        
        for i in range(0, n_samples, chunk_size):
            end = min(i + chunk_size, n_samples)
            chunk = tfidf_matrix[i:end]
            
            chunk_similarities = cosine_similarity(chunk, tfidf_matrix)
            
            for idx, row in enumerate(chunk_similarities):
                row[i + idx] = 0
                avg_similarities[i + idx] = np.sum(row) / (n_samples - 1)
                
                mask = np.ones(len(row), dtype=bool)
                mask[i + idx] = False
                avg_similarities[mask] += row[mask] / (n_samples - 1)
        
        similarity_threshold = np.mean(avg_similarities) - np.std(avg_similarities)
        outlier_indices = np.where(avg_similarities < similarity_threshold)[0]
        
        return np.mean(avg_similarities), outlier_indices.tolist()
    
    def calculate_ip_similarity(self, ips):
        """Calculate similarity based on IP addresses"""
        if len(ips) <= 1:
            return 1.0, []
            
        if self.consider_subnets:
            subnet_counts = pd.Series([self.extract_subnet(ip) for ip in ips]).value_counts()
            probabilities = subnet_counts / len(ips)
            
            ip_cohesion = probabilities.max()
            
            main_subnet = subnet_counts.idxmax()
            outlier_indices = [i for i, ip in enumerate(ips) 
                              if self.extract_subnet(ip) != main_subnet]
        else:
            ip_counts = pd.Series(ips).value_counts()
            probabilities = ip_counts / len(ips)
            
            ip_cohesion = probabilities.max()
            
            threshold = max(0.1, 1.0/len(ips))  # At least 10% or single occurrence
            minority_ips = ip_counts[ip_counts/len(ips) <= threshold].index
            outlier_indices = [i for i, ip in enumerate(ips) if ip in minority_ips]
            
        return ip_cohesion, outlier_indices

    def evaluate_group_cohesion(self, group_df, columns=['name', 'host', 'short', 'ip']):
        if len(group_df) <= 1:
            return 1.0, []
            
        if len(group_df) > 10000:
            return self.evaluate_large_group_cohesion(group_df, columns)
        
        weights = {'name': 0.3, 'host': 0.2, 'short': 0.2, 'ip': self.ip_weight}
        scores = []
        all_outliers = set()
        
        for column in columns:
            if column not in group_df.columns:
                continue
                
            weight = weights.get(column, 1.0 / len(columns))
            
            if column == 'ip':
                score, outliers = self.calculate_ip_similarity(group_df[column].astype(str).values)
            else:
                texts = group_df[column].astype(str).values
                score, outliers = self.calculate_text_similarity_streaming(texts)
                
            scores.append(score * weight)
            all_outliers.update(outliers)
        
        if not scores:
            return 1.0, []
            
        return sum(scores) / sum([weights.get(col, 1.0 / len(columns)) for col in columns if col in group_df.columns]), list(all_outliers)

    def evaluate_large_group_cohesion(self, group_df, columns):
        """Handle very large groups by splitting them into smaller chunks"""
        chunk_size = 10000
        n_chunks = len(group_df) // chunk_size + 1
        
        scores = []
        all_outliers = []
        
        for i in range(n_chunks):
            start_idx = i * chunk_size
            end_idx = min((i + 1) * chunk_size, len(group_df))
            chunk_df = group_df.iloc[start_idx:end_idx]
            
            score, outliers = self.evaluate_group_cohesion(chunk_df, columns)
            scores.append(score)
            all_outliers.extend([o + start_idx for o in outliers])
        
        return np.mean(scores), all_outliers

    def calculate_group_entropy(self, group_df, columns=['name', 'host', 'short', 'ip']):
        if len(group_df) > 10000:
            group_df = group_df.sample(n=10000, random_state=42)
            
        entropies = {}
        for column in columns:
            if column not in group_df.columns:
                continue
            
            if column == 'ip' and self.consider_subnets:
                value_counts = group_df[column].apply(self.extract_subnet).value_counts()
            else:
                value_counts = group_df[column].astype(str).value_counts()
                
            probabilities = value_counts / value_counts.sum()
            entropies[column] = entropy(probabilities)
        
        return sum(entropies.values()) / len(entropies) if entropies else 0

    def validate_groups(self, df):
        validity_results = []
        total_groups = df['timely_alert_group'].nunique()
        
        for idx, (group_id, group_df) in enumerate(df.groupby('timely_alert_group')):
            print(f"\rValidating group {idx+1}/{total_groups}", end="")
            
            cohesion_score, outliers = self.evaluate_group_cohesion(group_df)
            time_diffs = group_df['readable_time'].diff().dt.total_seconds()
            max_time_gap = time_diffs.max() if len(time_diffs) > 1 else 0
            time_span = (group_df['readable_time'].max() - group_df['readable_time'].min()).total_seconds()
            
            validity_results.append({
                'group_id': group_id,
                'group_size': len(group_df),
                'cohesion_score': cohesion_score,
                'max_time_gap': max_time_gap,
                'time_span': time_span,
                'num_outliers': len(outliers),
                'entropy_score': self.calculate_group_entropy(group_df)
            })
        
        print() 
        return pd.DataFrame(validity_results)

    def check_time_gap_violation(self, group_df):
        """Check if a group has any time gap violations"""
        if len(group_df) <= 1:
            return False
            
        group_df = group_df.sort_values(by='readable_time')
        time_diffs = group_df['readable_time'].diff().dt.total_seconds().dropna()
        
        return any(time_diffs > self.max_time_gap)

    def split_group_by_time_gaps(self, group_df, group_id, next_group_id):
        """Split a group at points where time gap is violated"""
        if len(group_df) <= 1:
            return group_df, next_group_id
            
        group_df = group_df.sort_values(by='readable_time').reset_index(drop=True)
        group_df['time_diff'] = group_df['readable_time'].diff().dt.total_seconds()
        
        violation_points = group_df[group_df['time_diff'] > self.max_time_gap].index.tolist()
        
        if not violation_points:
            group_df = group_df.drop(columns=['time_diff'])
            return group_df, next_group_id
            
        current_id = group_id
        for point in violation_points:
            group_df.loc[point:, 'timely_alert_group'] = next_group_id
            next_group_id += 1
            
        group_df = group_df.drop(columns=['time_diff'])
        return group_df, next_group_id

    def refine_groups_by_cohesion(self, df, validity_results):
        """
        Refine groups based on cohesion and entropy while preserving time gap constraints
        """
        total_groups = len(validity_results)
        refined_groups = []
        next_group_id = df['timely_alert_group'].max() + 1
        
        for idx, row in validity_results.iterrows():
            print(f"\rRefining group {idx+1}/{total_groups}", end="")
            
            group_mask = df['timely_alert_group'] == row['group_id']
            group_df = df[group_mask].copy()
            
            if (row['cohesion_score'] < self.cohesion_threshold or 
                row['entropy_score'] > self.entropy_threshold):
                
                if 'ip' in group_df.columns:
                    unique_ips = group_df['ip'].nunique()
                    if unique_ips > 1 and unique_ips < len(group_df) * 0.5:
                        _, outlier_indices = self.evaluate_group_cohesion(
                            group_df, columns=['name', 'host', 'short', 'ip'])
                    else:
                        _, outlier_indices = self.evaluate_group_cohesion(group_df)
                else:
                    _, outlier_indices = self.evaluate_group_cohesion(group_df)
                
                if outlier_indices:
                    outlier_rows = group_df.iloc[outlier_indices].copy()
                    group_df = group_df.drop(group_df.iloc[outlier_indices].index)
                    
                    if self.check_time_gap_violation(group_df):
                        group_df, next_group_id = self.split_group_by_time_gaps(
                            group_df, row['group_id'], next_group_id)
                    
                    outlier_rows['timely_alert_group'] = next_group_id
                    
                    if self.check_time_gap_violation(outlier_rows):
                        outlier_rows, next_group_id = self.split_group_by_time_gaps(
                            outlier_rows, next_group_id, next_group_id + 1)
                    else:
                        next_group_id += 1
                    
                    refined_groups.append(pd.concat([group_df, outlier_rows]))
                else:
                    if self.check_time_gap_violation(group_df):
                        group_df, next_group_id = self.split_group_by_time_gaps(
                            group_df, row['group_id'], next_group_id)
                    refined_groups.append(group_df)
            else:
                if self.check_time_gap_violation(group_df):
                    group_df, next_group_id = self.split_group_by_time_gaps(
                        group_df, row['group_id'], next_group_id)
                refined_groups.append(group_df)
        
        print() 
        result = pd.concat(refined_groups, ignore_index=True) if refined_groups else df
        return result
    
    def perform_ip_based_grouping(self, df):
        """
        Additional step to refine groups based on IP patterns while preserving
        time gap constraints
        """
        print("Refining groups based on IP patterns...")
        
        total_groups = df['timely_alert_group'].nunique()
        refined_groups = []
        next_group_id = df['timely_alert_group'].max() + 1
        
        for idx, (group_id, group_df) in enumerate(df.groupby('timely_alert_group')):
            print(f"\rIP-based refinement: group {idx+1}/{total_groups}", end="")
            
            if len(group_df) <= 1 or 'ip' not in group_df.columns:
                refined_groups.append(group_df)
                continue
                
            if group_df['ip'].nunique() > 1 and len(group_df) >= 5:
                ip_counts = group_df['ip'].value_counts()
                probabilities = ip_counts / ip_counts.sum()
                ip_entropy = entropy(probabilities)
                
                if ip_entropy > 1.0 and len(group_df) > 10:
                    refined_ip_groups = []
                    
                    for ip, ip_group in group_df.groupby('ip'):
                        if len(ip_group) >= 3:  # Only create new groups if enough alerts
                            ip_group = ip_group.copy()
                            ip_group['timely_alert_group'] = next_group_id
                            
                            if self.check_time_gap_violation(ip_group):
                                ip_group, next_group_id = self.split_group_by_time_gaps(
                                    ip_group, next_group_id, next_group_id + 1)
                            else:
                                next_group_id += 1
                                
                            refined_ip_groups.append(ip_group)
                        else:
                            refined_ip_groups.append(ip_group)
                    
                    if refined_ip_groups:
                        group_df = pd.concat(refined_ip_groups)
            
            refined_groups.append(group_df)
        
        print()
        result = pd.concat(refined_groups, ignore_index=True) if refined_groups else df
        return result

    def analyze(self, alerts_df):
        """
        Modified main analysis pipeline that prioritizes time gap grouping first,
        then applies other grouping methods while strictly preserving time gap constraints
        """
        print("Starting enhanced analysis with strict time gap enforcement...")
        df = self.preprocess_data(alerts_df)
        print(f"Preprocessed {len(df)} alerts")
        
        # STEP 1: Strict temporal grouping by maximum time gap
        df = self.group_alerts_by_max_time_gap(df)
        print(f"Created {df['timely_alert_group'].nunique()} initial groups based on strict time gaps")
        
        df['initial_time_group'] = df['timely_alert_group']
        
        initial_validity_results = self.validate_groups(df)
        print("Validated initial time-based groups")
        
        # STEP 2: Refine groups by cohesion and entropy while preserving time gaps
        df = self.refine_groups_by_cohesion(df, initial_validity_results)
        print(f"Refined into {df['timely_alert_group'].nunique()} groups based on cohesion")
        
        # STEP 3: IP-based grouping if available, preserving time gaps
        if 'ip' in df.columns:
            df = self.perform_ip_based_grouping(df)
            print(f"After IP-based refinement: {df['timely_alert_group'].nunique()} groups")
        
        final_validity_results = self.validate_groups(df)
        self.verify_time_gap_constraints(df)
        
        return df, final_validity_results
        
    def verify_time_gap_constraints(self, df):
        """
        Verify that the final grouping still respects the maximum time gap constraints
        """
        violation_count = 0
        
        for group_id, group_df in df.groupby('timely_alert_group'):
            group_df = group_df.sort_values(by='readable_time')
            time_diffs = group_df['readable_time'].diff().dt.total_seconds().dropna()
            
            violations = time_diffs[time_diffs > self.max_time_gap]
            if len(violations) > 0:
                violation_count += len(violations)
                print(f"WARNING: Group {group_id} has {len(violations)} time gap violations!")
                print(f"Max time gap in group: {time_diffs.max():.2f}s (limit: {self.max_time_gap}s)")
        
        if violation_count == 0:
            print("All groups respect the maximum time gap constraint.")
        else:
            print(f"Found {violation_count} time gap constraint violations across all groups.")
