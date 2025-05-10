import numpy as np
from datetime import datetime, timedelta
from django.utils import timezone
import logging
from django.db.models import Avg, Max
from log_ingestion.models import LogAgent, AgentResourceMetric
from scipy import stats
import pandas as pd
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

class ResourcePredictor:
    """
    Predicts potential resource exhaustion based on historical usage patterns.
    Uses linear regression and trend analysis to make predictions.
    """
    
    # Define thresholds for different resources
    THRESHOLDS = {
        'cpu': 85,  # 85% CPU usage is critical
        'memory': 90,  # 90% memory usage is critical
        'disk': 95,  # 95% disk usage is critical
        'log_volume': 90  # 90% of allocated log space
    }
    
    def __init__(self, time_window=24):
        """Initialize with default time window for predictions (in hours)"""
        self.time_window = time_window
    
    def predict_resource_exhaustion(self, agent_id, time_window=None):
        """
        Analyze resource utilization patterns to predict potential
        exhaustion within the specified time window (hours)
        
        Args:
            agent_id: The ID of the agent to analyze
            time_window: Override the default time window (in hours)
            
        Returns:
            Dictionary of resources with predicted time to exhaustion
        """
        if time_window is not None:
            self.time_window = time_window
            
        # Get the agent
        try:
            agent = LogAgent.objects.get(id=agent_id)
        except LogAgent.DoesNotExist:
            logger.error(f"Agent with ID {agent_id} not found")
            return {
                'error': f"Agent with ID {agent_id} not found",
                'predictions': {}
            }
            
        # Get historical metrics (last 7 days as baseline)
        now = timezone.now()
        history_start = now - timedelta(days=7)
        
        try:
            metrics = AgentResourceMetric.objects.filter(
                agent=agent,
                timestamp__gte=history_start
            ).order_by('timestamp')
            
            if not metrics.exists():
                logger.warning(f"No metrics found for agent {agent_id}")
                return {
                    'warning': f"No metrics found for agent {agent_id}",
                    'predictions': {}
                }
                
            # Process the data for prediction
            return self._make_predictions(agent, metrics, now)
            
        except Exception as e:
            logger.exception(f"Error predicting resource exhaustion: {str(e)}")
            return {
                'error': f"Error predicting resource exhaustion: {str(e)}",
                'predictions': {}
            }
    
    def _make_predictions(self, agent, metrics, now):
        """Generate predictions based on metrics data"""
        predictions = {}
        resources = ['cpu', 'memory', 'disk', 'log_volume']
        
        # Convert QuerySet to pandas DataFrame for easier analysis
        data = []
        for metric in metrics:
            data.append({
                'timestamp': metric.timestamp,
                'cpu': metric.cpu_usage,
                'memory': metric.memory_usage,
                'disk': metric.disk_usage,
                'log_volume': metric.log_volume
            })
            
        if not data:
            return {'predictions': {}}
            
        df = pd.DataFrame(data)
        
        # Add time features for trend analysis
        df['hours_since_start'] = (df['timestamp'] - df['timestamp'].min()).dt.total_seconds() / 3600
        
        for resource in resources:
            try:
                # Skip resources with insufficient data
                if df[resource].isna().sum() > len(df) * 0.3:  # More than 30% missing
                    continue
                    
                # Fill missing values with interpolation
                df[resource] = df[resource].interpolate(method='linear')
                
                # Get current usage
                current_usage = df[resource].iloc[-1]
                
                # Skip resources that are already at a low level
                if current_usage < self.THRESHOLDS[resource] * 0.5:  # Less than 50% of threshold
                    predictions[resource] = {
                        'current_usage': current_usage,
                        'threshold': self.THRESHOLDS[resource],
                        'status': 'normal',
                        'message': f"Current usage is normal at {current_usage:.1f}%",
                        'time_to_threshold': None,
                        'confidence': None
                    }
                    continue
                
                # Simple linear regression for prediction
                X = df['hours_since_start'].values.reshape(-1, 1)
                y = df[resource].values
                
                # Standardize features
                scaler = StandardScaler()
                X_scaled = scaler.fit_transform(X)
                
                # Train linear regression model
                model = LinearRegression()
                model.fit(X_scaled, y)
                
                # Calculate slope to determine trend
                slope = model.coef_[0]
                
                # If trend is decreasing, no immediate concern
                if slope <= 0:
                    predictions[resource] = {
                        'current_usage': current_usage,
                        'threshold': self.THRESHOLDS[resource],
                        'status': 'stable',
                        'message': f"Usage is stable or decreasing",
                        'time_to_threshold': None,
                        'trend': 'decreasing',
                        'confidence': None
                    }
                    continue
                
                # Predict time to reach threshold
                if current_usage < self.THRESHOLDS[resource]:
                    # Calculate hours until threshold is reached
                    hours_to_threshold = (self.THRESHOLDS[resource] - current_usage) / slope
                    
                    if hours_to_threshold > self.time_window:
                        status = 'normal'
                        message = f"No exhaustion predicted within {self.time_window} hours"
                    else:
                        # Format the time prediction nicely
                        if hours_to_threshold < 1:
                            time_str = f"{int(hours_to_threshold * 60)} minutes"
                        elif hours_to_threshold < 24:
                            time_str = f"{int(hours_to_threshold)} hours"
                        else:
                            days = hours_to_threshold / 24
                            time_str = f"{int(days)} days"
                            
                        status = 'warning'
                        message = f"Predicted to reach {self.THRESHOLDS[resource]}% in {time_str}"
                    
                    # Calculate R-squared as confidence measure
                    confidence = model.score(X_scaled, y) * 100
                    
                    predictions[resource] = {
                        'current_usage': current_usage,
                        'threshold': self.THRESHOLDS[resource],
                        'status': status,
                        'message': message,
                        'time_to_threshold': hours_to_threshold,
                        'time_display': time_str if status == 'warning' else None,
                        'trend': 'increasing',
                        'confidence': confidence
                    }
                else:
                    # Already over threshold
                    predictions[resource] = {
                        'current_usage': current_usage,
                        'threshold': self.THRESHOLDS[resource],
                        'status': 'critical',
                        'message': f"Already exceeds threshold ({current_usage:.1f}% > {self.THRESHOLDS[resource]}%)",
                        'time_to_threshold': 0,
                        'trend': 'increasing',
                        'confidence': None
                    }
            
            except Exception as e:
                logger.exception(f"Error predicting {resource} exhaustion: {str(e)}")
                predictions[resource] = {
                    'status': 'error',
                    'message': f"Error predicting {resource} exhaustion: {str(e)}"
                }
        
        # Return the predictions
        return {
            'agent': {
                'id': agent.id,
                'name': agent.name,
                'status': agent.status
            },
            'predictions': predictions,
            'timestamp': now.isoformat(),
            'time_window': self.time_window
        }
    
    def get_overall_status(self, predictions):
        """Determine the overall status based on all predictions"""
        if not predictions or 'predictions' not in predictions:
            return 'unknown'
            
        resource_predictions = predictions['predictions']
        
        if any(p.get('status') == 'critical' for p in resource_predictions.values()):
            return 'critical'
        elif any(p.get('status') == 'warning' for p in resource_predictions.values()):
            return 'warning'
        elif any(p.get('status') == 'error' for p in resource_predictions.values()):
            return 'error'
        elif all(p.get('status') in ('normal', 'stable') for p in resource_predictions.values()):
            return 'normal'
        else:
            return 'unknown'


def predict_resource_exhaustion(agent_id, time_window=24):
    """
    Analyze resource utilization patterns to predict potential
    exhaustion within the specified time window (hours)
    
    This is a wrapper around the ResourcePredictor class for easier access.
    """
    predictor = ResourcePredictor(time_window)
    return predictor.predict_resource_exhaustion(agent_id, time_window)


# For batch prediction of all agents
def predict_all_agents(time_window=24):
    """
    Predict resource exhaustion for all active agents
    
    Returns:
        Dictionary of agent IDs with their predictions
    """
    predictor = ResourcePredictor(time_window)
    results = {}
    
    try:
        # Get all active agents
        agents = LogAgent.objects.filter(status='active')
        
        for agent in agents:
            results[agent.id] = predictor.predict_resource_exhaustion(agent.id, time_window)
            
        return results
    except Exception as e:
        logger.exception(f"Error in batch prediction: {str(e)}")
        return {'error': str(e)}