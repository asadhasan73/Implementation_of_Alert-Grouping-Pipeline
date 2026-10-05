"""
Similarity calculation utilities for the Alert Grouping Pipeline.

This module contains functions for calculating various types of similarity
between alerts, including text similarity, IP address similarity, and 
combined multi-dimensional similarity scores.
"""

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from scipy.stats import entropy
from typing import List, Tuple, Optional


class TextSimilarityCalculator:
    """Handles text-based similarity calculations using TF-IDF and cosine similarity."""
    
    def __init__(self):
        self.vectorizer = TfidfVectorizer()
    
    def calculate_streaming_similarity(self, texts: List[str], chunk_size: int = 1000) -> Tuple[float, List[int]]:
        """
        Calculate average similarity score using streaming for memory efficiency.
        
        Args:
            texts: List of text strings to analyze
            chunk_size: Size of chunks for streaming processing
            
        Returns:
            Tuple of (average_similarity, outlier_indices)
        """
        if len(texts) <= 1:
            return 1.0, []

        if len(texts) > 10000:
            sample_size = min(10000, int(len(texts) * 0.1))
            indices = np.random.choice(len(texts), sample_size, replace=False)
            texts = [texts[i] for i in indices]
        
        tfidf_matrix = self.vectorizer.fit_transform(texts)
        n_samples = len(texts)
        avg_similarities = np.zeros(n_samples)
        
        for i in range(0, n_samples, chunk_size):
            end = min(i + chunk_size, n_samples)
            chunk = tfidf_matrix[i:end]
            
            # similarity calculation for each chunk
            chunk_similarities = cosine_similarity(chunk, tfidf_matrix)
            
            for idx, row in enumerate(chunk_similarities):
                row[i + idx] = 0  # self-similarity excluded
                avg_similarities[i + idx] = np.sum(row) / (n_samples - 1)
        
        similarity_threshold = np.mean(avg_similarities) - np.std(avg_similarities)
        outlier_indices = np.where(avg_similarities < similarity_threshold)[0]
        
        return np.mean(avg_similarities), outlier_indices.tolist()
    
    def calculate_pairwise_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between two text strings."""
        try:
            tfidf_matrix = self.vectorizer.fit_transform([text1, text2])
            similarity = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0][0]
            return similarity
        except:
            return 0.0


class IPSimilarityCalculator:
    """Handles IP address-based similarity calculations."""
    
    def __init__(self, consider_subnets: bool = True):
        self.consider_subnets = consider_subnets
    
    def extract_subnet(self, ip: str) -> str:
        """
        Extract subnet from IP address.
        
        Args:
            ip: IP address string
            
        Returns:
            Subnet string (first 3 octets for IPv4, first 4 groups for IPv6)
        """
        try:
            if '.' in ip:  # IPv4
                return '.'.join(ip.split('.')[:3])
            elif ':' in ip:  # IPv6
                return ':'.join(ip.split(':')[:4])
            return ip
        except:
            return ip
    
    def calculate_ip_similarity(self, ips: List[str]) -> Tuple[float, List[int]]:
        """
        Calculate similarity based on IP addresses.
        
        Args:
            ips: List of IP address strings
            
        Returns:
            Tuple of (cohesion_score, outlier_indices)
        """
        if len(ips) <= 1:
            return 1.0, []
        
        if self.consider_subnets:
            subnets = [self.extract_subnet(ip) for ip in ips]
            subnet_counts = pd.Series(subnets).value_counts()
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
    
    def calculate_subnet_diversity(self, ips: List[str]) -> float:
        """
        Calculate diversity of subnets in IP list.
        
        Args:
            ips: List of IP addresses
            
        Returns:
            Diversity score (entropy-based)
        """
        if len(ips) <= 1:
            return 0.0
            
        subnets = [self.extract_subnet(ip) for ip in ips]
        subnet_counts = pd.Series(subnets).value_counts()
        probabilities = subnet_counts / len(ips)
        
        return entropy(probabilities)


class MultiDimensionalSimilarity:
    """Combines multiple types of similarity for comprehensive analysis."""
    
    def __init__(self, ip_weight: float = 0.3, consider_subnets: bool = True):
        self.text_calculator = TextSimilarityCalculator()
        self.ip_calculator = IPSimilarityCalculator(consider_subnets)
        self.ip_weight = ip_weight
    
    def evaluate_group_cohesion(self, group_df: pd.DataFrame, 
                               columns: List[str] = ['name', 'host', 'short', 'ip']) -> Tuple[float, List[int]]:
        """
        Evaluate cohesion of a group using multiple similarity metrics.
        
        Args:
            group_df: DataFrame containing group data
            columns: Columns to analyze for similarity
            
        Returns:
            Tuple of (cohesion_score, outlier_indices)
        """
        if len(group_df) <= 1:
            return 1.0, []

        if len(group_df) > 10000:
            return self._evaluate_large_group_cohesion(group_df, columns)
        
        weights = {
            'name': 0.3,
            'host': 0.2, 
            'short': 0.2,
            'ip': self.ip_weight
        }
        
        scores = []
        all_outliers = set()
        
        for column in columns:
            if column not in group_df.columns:
                continue
            
            weight = weights.get(column, 1.0 / len(columns))
            
            if column == 'ip':
                score, outliers = self.ip_calculator.calculate_ip_similarity(
                    group_df[column].astype(str).values
                )
            else:
                texts = group_df[column].astype(str).values
                score, outliers = self.text_calculator.calculate_streaming_similarity(texts)
            
            scores.append(score * weight)
            all_outliers.update(outliers)
        
        if not scores:
            return 1.0, []
        
        total_weight = sum([weights.get(col, 1.0 / len(columns)) 
                           for col in columns if col in group_df.columns])
        
        return sum(scores) / total_weight, list(all_outliers)
    
    def _evaluate_large_group_cohesion(self, group_df: pd.DataFrame, 
                                      columns: List[str]) -> Tuple[float, List[int]]:
        """Handle very large groups by splitting them into smaller chunks."""
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
    
    def calculate_feature_similarity(self, values1: List[str], values2: List[str]) -> float:
        """
        Calculate similarity between two sets of feature values.
        
        Args:
            values1: First set of values
            values2: Second set of values
            
        Returns:
            Similarity score between 0 and 1
        """
        if not values1 or not values2:
            return 0.0
        
        set1 = set(values1)
        set2 = set(values2)
        
        # Jaccard similarity
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0
    
    def calculate_temporal_similarity(self, timestamps1: List[float], 
                                    timestamps2: List[float]) -> float:
        """
        Calculate temporal similarity between two groups of timestamps.
        
        Args:
            timestamps1: First set of timestamps
            timestamps2: Second set of timestamps
            
        Returns:
            Temporal similarity score
        """
        if not timestamps1 or not timestamps2:
            return 0.0
        
        span1 = max(timestamps1) - min(timestamps1)
        span2 = max(timestamps2) - min(timestamps2)
        
        min_start = max(min(timestamps1), min(timestamps2))
        max_end = min(max(timestamps1), max(timestamps2))
        
        if min_start <= max_end:
            overlap = max_end - min_start
            total_span = max(max(timestamps1), max(timestamps2)) - min(min(timestamps1), min(timestamps2))
            return overlap / total_span if total_span > 0 else 1.0
        
        return 0.0


class SimilarityMetrics:
    """Collection of utility functions for various similarity calculations."""
    
    @staticmethod
    def jaccard_similarity(set1: set, set2: set) -> float:
        """Calculate Jaccard similarity between two sets."""
        if not set1 and not set2:
            return 1.0
        if not set1 or not set2:
            return 0.0
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union
    
    @staticmethod
    def dice_coefficient(set1: set, set2: set) -> float:
        """Calculate Dice coefficient between two sets."""
        if not set1 and not set2:
            return 1.0
        if not set1 or not set2:
            return 0.0
        
        intersection = len(set1.intersection(set2))
        return 2.0 * intersection / (len(set1) + len(set2))
    
    @staticmethod
    def overlap_coefficient(set1: set, set2: set) -> float:
        """Calculate overlap coefficient between two sets."""
        if not set1 and not set2:
            return 1.0
        if not set1 or not set2:
            return 0.0
        
        intersection = len(set1.intersection(set2))
        min_size = min(len(set1), len(set2))
        
        return intersection / min_size
    
    @staticmethod
    def normalized_edit_distance(str1: str, str2: str) -> float:
        """Calculate normalized Levenshtein distance between two strings."""
        def levenshtein_distance(s1: str, s2: str) -> int:
            if len(s1) < len(s2):
                return levenshtein_distance(s2, s1)
            
            if len(s2) == 0:
                return len(s1)
            
            previous_row = list(range(len(s2) + 1))
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            
            return previous_row[-1]
        
        max_len = max(len(str1), len(str2))
        if max_len == 0:
            return 1.0
        
        distance = levenshtein_distance(str1, str2)
        return 1.0 - (distance / max_len)


def create_similarity_calculator(similarity_type: str = 'multi', **kwargs):
    """
    Factory function to create different types of similarity calculators.
    
    Args:
        similarity_type: Type of calculator ('text', 'ip', 'multi')
        **kwargs: Additional parameters for the calculator
        
    Returns:
        Appropriate similarity calculator instance
    """
    if similarity_type == 'text':
        return TextSimilarityCalculator()
    elif similarity_type == 'ip':
        return IPSimilarityCalculator(**kwargs)
    elif similarity_type == 'multi':
        return MultiDimensionalSimilarity(**kwargs)
    else:
        raise ValueError(f"Unknown similarity type: {similarity_type}")
