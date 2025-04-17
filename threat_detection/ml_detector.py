import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from django.core.cache import cache
from django.utils import timezone
from log_ingestion.models import ParsedLog
import logging
import json
import math

# Configure logger
logger = logging.getLogger(__name__)

class AnomalyDetector:
    """Machine learning-based anomaly detection"""
    
    def __init__(self, model_type='isolation_forest'):
        self.model_type = model_type
        self.model = self._get_model()
        self.scaler = StandardScaler()
        
    def _get_model(self):
        """Get or create ML model"""
        if self.model_type == 'isolation_forest':
            return IsolationForest(contamination=0.01, random_state=42)
        # Add more model types as needed
        return None
        
    def train(self, force=False):
        """Train model on historical data"""
        # Check if model was recently trained
        last_trained = cache.get('anomaly_detector_last_trained')
        if last_trained and not force and (timezone.now() - last_trained).total_seconds() < 86400:
            return False  # Skip if trained in the last 24 hours
            
        # Get training data
        logs = ParsedLog.objects.filter(
            timestamp__gte=timezone.now() - timezone.timedelta(days=7)
        ).values(
            'source_ip', 'request_method', 'status_code', 'response_size', 
            'execution_time', 'timestamp'
        )[:10000]  # Limit to prevent memory issues
        
        if not logs:
            return False
            
        # Convert to DataFrame
        df = pd.DataFrame(list(logs))
        
        # Feature engineering
        df['hour_of_day'] = df['timestamp'].apply(lambda x: x.hour)
        df['day_of_week'] = df['timestamp'].apply(lambda x: x.weekday())
        df['is_weekend'] = df['day_of_week'].apply(lambda x: 1 if x >= 5 else 0)
        
        # Handle categorical variables
        if 'request_method' in df.columns:
            method_dummies = pd.get_dummies(df['request_method'], prefix='method')
            df = pd.concat([df, method_dummies], axis=1)
            
        # Select numerical features
        features = df.select_dtypes(include=['int64', 'float64']).columns.tolist()
        features = [f for f in features if f not in ['timestamp', 'source_ip']]
        
        # Scale features
        X = self.scaler.fit_transform(df[features])
        
        # Train model
        self.model.fit(X)
        
        # Save model state
        cache.set('anomaly_detector_scaler', self.scaler, 86400 * 7)
        cache.set('anomaly_detector_features', features, 86400 * 7)
        cache.set('anomaly_detector_last_trained', timezone.now(), 86400 * 7)
        
        return True
        
    def detect_anomalies(self, logs):
        """Detect anomalies in a batch of logs"""
        if not logs:
            return []
            
        # Get saved model state
        features = cache.get('anomaly_detector_features')
        if not features:
            self.train()
            features = cache.get('anomaly_detector_features')
            if not features:
                return []
                
        # Convert logs to DataFrame
        df = pd.DataFrame([{
            'source_ip': log.source_ip,
            'request_method': log.request_method,
            'status_code': log.status_code,
            'response_size': log.response_size,
            'execution_time': log.execution_time,
            'timestamp': log.timestamp,
            'hour_of_day': log.timestamp.hour,
            'day_of_week': log.timestamp.weekday(),
            'is_weekend': 1 if log.timestamp.weekday() >= 5 else 0,
        } for log in logs])
        
        # Handle categorical variables
        if 'request_method' in df.columns:
            method_dummies = pd.get_dummies(df['request_method'], prefix='method')
            df = pd.concat([df, method_dummies], axis=1)
            
        # Ensure all expected features are present
        for feature in features:
            if feature not in df.columns:
                df[feature] = 0
                
        # Scale features
        X = self.scaler.transform(df[features])
        
        # Detect anomalies
        predictions = self.model.predict(X)
        anomaly_scores = self.model.decision_function(X)
        
        # Return logs with anomalies
        anomalies = []
        for i, pred in enumerate(predictions):
            if pred == -1:  # Anomaly
                anomalies.append({
                    'log': logs[i],
                    'anomaly_score': anomaly_scores[i]
                })
                
        return sorted(anomalies, key=lambda x: x['anomaly_score'])

class SimpleAnomalyDetector:
    """Simple statistical anomaly detection"""
    
    def __init__(self):
        self.baseline = self._get_baseline()
        
    def _get_baseline(self):
        """Get or compute baseline statistics"""
        baseline = cache.get('anomaly_detector_baseline')
        if baseline:
            return json.loads(baseline)
        
        # Default baseline if none exists
        return {
            'status_code': {'mean': 200, 'stddev': 100},
            'response_size': {'mean': 5000, 'stddev': 2000},
            'execution_time': {'mean': 100, 'stddev': 50},
            'request_counts': {'GET': 70, 'POST': 20, 'PUT': 5, 'DELETE': 5}
        }
        
    def train(self, force=False):
        """Train simple statistical model on historical data"""
        last_trained = cache.get('anomaly_detector_last_trained')
        if last_trained and not force and (timezone.now() - timezone.datetime.fromisoformat(last_trained)).total_seconds() < 86400:
            return False  # Skip if trained in the last 24 hours
            
        # Get training data
        logs = ParsedLog.objects.filter(
            timestamp__gte=timezone.now() - timezone.timedelta(days=7)
        ).values('request_method', 'status_code', 'response_size', 'execution_time')
        
        if not logs:
            return False
            
        # Simple statistics
        status_codes = [log['status_code'] for log in logs if log['status_code']]
        response_sizes = [log['response_size'] for log in logs if log['response_size']]
        execution_times = [log['execution_time'] for log in logs if log['execution_time']]
        
        # Count request methods
        methods = {}
        total_requests = 0
        for log in logs:
            if log['request_method']:
                method = log['request_method']
                methods[method] = methods.get(method, 0) + 1
                total_requests += 1
        
        # Calculate percentages
        request_counts = {}
        for method, count in methods.items():
            request_counts[method] = (count / total_requests) * 100 if total_requests else 0
        
        # Compute baseline
        baseline = {
            'status_code': {
                'mean': sum(status_codes) / len(status_codes) if status_codes else 200,
                'stddev': self._stddev(status_codes) if len(status_codes) > 1 else 100
            },
            'response_size': {
                'mean': sum(response_sizes) / len(response_sizes) if response_sizes else 5000,
                'stddev': self._stddev(response_sizes) if len(response_sizes) > 1 else 2000
            },
            'execution_time': {
                'mean': sum(execution_times) / len(execution_times) if execution_times else 100,
                'stddev': self._stddev(execution_times) if len(execution_times) > 1 else 50
            },
            'request_counts': request_counts
        }
        
        # Save baseline
        cache.set('anomaly_detector_baseline', json.dumps(baseline), 86400 * 7)
        cache.set('anomaly_detector_last_trained', timezone.now().isoformat(), 86400 * 7)
        
        self.baseline = baseline
        return True
    
    def _stddev(self, values):
        """Calculate standard deviation"""
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return math.sqrt(variance)
        
    def detect_anomalies(self, logs):
        """Detect anomalies using simple statistical methods"""
        if not logs:
            return []
        
        # Make sure baseline is loaded
        if not self.baseline:
            self.train()
        
        anomalies = []
        for log in logs:
            score = 0
            anomaly_factors = []
            
            # Check status code
            if log.status_code:
                status_mean = self.baseline['status_code']['mean']
                status_stddev = self.baseline['status_code']['stddev']
                if status_stddev > 0:
                    z_score = abs(log.status_code - status_mean) / status_stddev
                    if z_score > 2:  # More than 2 standard deviations
                        score += z_score
                        anomaly_factors.append(f"Unusual status code: {log.status_code}")
            
            # Check response size
            if log.response_size:
                size_mean = self.baseline['response_size']['mean']
                size_stddev = self.baseline['response_size']['stddev']
                if size_stddev > 0:
                    z_score = abs(log.response_size - size_mean) / size_stddev
                    if z_score > 3:  # More than 3 standard deviations
                        score += z_score
                        anomaly_factors.append(f"Unusual response size: {log.response_size}")
            
            # Check execution time
            if log.execution_time:
                time_mean = self.baseline['execution_time']['mean']
                time_stddev = self.baseline['execution_time']['stddev']
                if time_stddev > 0:
                    z_score = abs(log.execution_time - time_mean) / time_stddev
                    if z_score > 3:  # More than 3 standard deviations
                        score += z_score
                        anomaly_factors.append(f"Unusual execution time: {log.execution_time}")
            
            # Check request method frequency
            if log.request_method and log.request_method in self.baseline['request_counts']:
                if self.baseline['request_counts'][log.request_method] < 5:  # Rare method
                    score += 2
                    anomaly_factors.append(f"Unusual request method: {log.request_method}")
            
            if score > 5:  # Arbitrary threshold
                anomalies.append({
                    'log': log,
                    'anomaly_score': score,
                    'factors': anomaly_factors
                })
                
        return sorted(anomalies, key=lambda x: x['anomaly_score'], reverse=True)